'use strict';

(() => {

 const $=id=>document.getElementById(id),NS='http://www.w3.org/2000/svg';

 const statuses={todo:'À faire',ready:'Prête',scheduled:'Planifiée',running:'En cours',in_progress:'En cours',blocked:'Bloquée',triage:'À qualifier',review:'En revue',done:'Terminée',cancelled:'Annulée',unknown:'Inconnue'};

 const roleStates={unknown:'Observation inconnue',recent:'Activité récente',session_closed:'Session clôturée',task_running:'Carte en cours',waiting:'En attente'};

 const agentColors={cto:'#f1bc50',assa:'#d675c3',pm:'#35c8d0',dev:'#63a8ff',qa:'#a6cf55',security:'#e16a64',ops:'#a98bff',designer:'#ff9d55','cl-producer':'#63d6a7'};

 const bubbleTimers=new Map();

 const store={world:null,activity:null,workers:null,private:null,privateAccess:'unknown',view:null,role:null,room:null,page:0,query:'',status:'all',agent:'all',events:[],lastKey:null,selectedTask:null};
 /* AWEMA public canonical appearance refresh begin. */
 const APPEARANCE_LIMIT=128*1024,APPEARANCE_ID=/^[a-z][a-z0-9-]{0,47}$/,APPEARANCE_HEX=/^#[0-9a-f]{6}$/i;
 function appearanceMap(data){
  if(!data||data.version!==1||!Array.isArray(data.agents)||data.agents.length>50)throw Error('Apparences invalides.');
  const map=new Map();
  for(const agent of data.agents){
   if(!agent||typeof agent.id!=='string'||!APPEARANCE_ID.test(agent.id)||map.has(agent.id)||typeof agent.color!=='string'||!APPEARANCE_HEX.test(agent.color)||typeof agent.skin!=='string'||!APPEARANCE_HEX.test(agent.skin))throw Error('Apparences invalides.');
   map.set(agent.id,{color:agent.color.toLowerCase(),skin:agent.skin.toLowerCase()});
  }
  return map;
 }
 async function appearancePayload(signal){
  const response=await fetch('/ruche/world.json',{method:'GET',cache:'no-store',credentials:'omit',redirect:'error',headers:{Accept:'application/json'},signal});
  if(!response.ok||response.url!==new URL('/ruche/world.json',location.origin).href)throw Error('Apparences indisponibles.');
  const length=response.headers.get('Content-Length');
  if(length!==null&&(!/^\d+$/.test(length)||Number(length)>APPEARANCE_LIMIT))throw Error('Apparences trop volumineuses.');
  if(!/^application\/json(?:\s*;|$)/i.test(response.headers.get('Content-Type')||'')||!response.body)throw Error('Apparences invalides.');
  const reader=response.body.getReader(),decoder=new TextDecoder('utf-8',{fatal:true});let bytes=0,text='';
  try{while(true){const chunk=await reader.read();if(chunk.done)break;bytes+=chunk.value.byteLength;if(bytes>APPEARANCE_LIMIT)throw Error('Apparences trop volumineuses.');text+=decoder.decode(chunk.value,{stream:true});}text+=decoder.decode();}
  catch(error){try{await reader.cancel();}catch{}throw error;}
  finally{reader.releaseLock();}
  const data=JSON.parse(text);return {data,appearances:appearanceMap(data)};
 }
 function watchAppearances(apply){
  let alive=true,busy=false,controller=null,timeout=null;
  async function refresh(force=false){
   if(!alive||busy||(!force&&document.hidden))return null;
   busy=true;controller=new AbortController();timeout=setTimeout(()=>controller?.abort(),8000);
   try{const result=await appearancePayload(controller.signal);if(!alive)return null;apply(result.appearances);return result.data;}
   catch{controller?.abort();return null;}
   finally{clearTimeout(timeout);timeout=null;controller=null;busy=false;}
  }
  const focus=()=>{refresh();},visible=()=>{if(!document.hidden)refresh();},timer=setInterval(()=>{refresh();},30000);
  window.addEventListener('focus',focus);document.addEventListener('visibilitychange',visible);
  return {refresh,dispose(){if(!alive)return;alive=false;clearInterval(timer);clearTimeout(timeout);controller?.abort();window.removeEventListener('focus',focus);document.removeEventListener('visibilitychange',visible);}};
 }


 let appearanceWatcher=null;const appearanceDefaults=new Map();
 function applyPublicAppearances(next){
  if(!store.world)return;
  for(const agent of store.world.agents){
   const value=next.get(agent.id)||appearanceDefaults.get(agent.id);if(!value)continue;
   agent.color=value.color;agent.skin=value.skin;
   const actor=[...$('actors').children].find(node=>node.dataset.role===agent.id);if(!actor)continue;
   for(const pixel of actor.querySelectorAll('[data-appearance-channel]')){
    const channel=pixel.getAttribute('data-appearance-channel'),fill=channel==='h'?value.skin:value.color;
    pixel.setAttribute('fill',fill);if(channel==='a')pixel.style.setProperty('fill',fill,'important');
   }
  }
 }
 function stopAppearanceRefresh(){appearanceWatcher?.dispose();appearanceWatcher=null;}
 function startAppearanceRefresh(refresh=false){
  stopAppearanceRefresh();
  if(!appearanceDefaults.size)for(const agent of store.world.agents)appearanceDefaults.set(agent.id,{color:agent.color,skin:agent.skin});
  appearanceWatcher=watchAppearances(applyPublicAppearances);if(refresh)appearanceWatcher.refresh();
 }
 window.addEventListener('pagehide',stopAppearanceRefresh);
 window.addEventListener('pageshow',event=>{if(event.persisted&&store.world)startAppearanceRefresh(true);});
 /* AWEMA public canonical appearance refresh end. */


 let contextPage=0;

 let expiry,privateExpiry,pending=false,privatePending=false,privateGeneration=0,returnFocus=null,zoom=1,pan=[0,0],drag=null,dragged=false,cameraTouched=false;

 const make=(tag,cls,text)=>{const e=document.createElement(tag);if(cls)e.className=cls;if(text!==undefined)e.textContent=text;return e;};

 const sv=(tag,attrs={},parent)=>{const e=document.createElementNS(NS,tag);for(const[k,v]of Object.entries(attrs))e.setAttribute(k,v);if(parent)parent.append(e);return e;};

 const point=(x,y,z=0)=>[800+(x-y)*29,100+(x+y)*14.5-z];

 const polygon=(p,attrs,parent)=>sv('polygon',{points:p.map(p=>p.join(',')).join(' '),...attrs},parent);

 const rect=(x,y,w,h,fill,parent,attrs={})=>sv('rect',{x,y,width:w,height:h,fill,...attrs},parent);

 const label=(x,y,text,parent,attrs={})=>{const e=sv('text',{x,y,...attrs},parent);e.textContent=text;return e;};

 function box(parent,x,y,w,d,h,top='#c3a475',left='#a18458',right='#8e7350'){

  const a=point(x,y),b=point(x+w,y),c=point(x+w,y+d),e=point(x,y+d),t=[a,b,c,e].map(([x,y])=>[x,y-h]);

  polygon([e,c,t[2],t[3]],{fill:left,stroke:'#554937','stroke-width':.8},parent);polygon([b,c,t[2],t[1]],{fill:right,stroke:'#554937','stroke-width':.8},parent);polygon(t,{fill:top,stroke:'#655c40','stroke-width':.8},parent);

 }

 function plant(g,x,y){box(g,x-.3,y-.3,.6,.6,17,'#dfb27d','#b78056','#98693e');const[p,q]=point(x,y,17);sv('path',{d:`M${p} ${q}v-50 M${p} ${q-20}l-17-23 M${p} ${q-27}l18-25`,stroke:'#497246','stroke-width':3,fill:'none'},g);for(const[a,b,w,h,c]of [[-17,-42,19,10,'#6c9855'],[2,-59,20,11,'#638e51'],[-6,-68,13,18,'#83a85f'],[-24,-58,21,11,'#4d7846'],[4,-35,22,11,'#789c5c']])rect(p+a,q+b,w,h,c,g);}

 function desk(g,x,y){box(g,x-.8,y-1.1,1.8,.85,31,'#e6c593','#b89465','#a07a51');const[p,q]=point(x,y-.7,32);rect(p-10,q-33,28,24,'#26392f',g);rect(p-7,q-30,22,16,'#6f9990',g);rect(p-4,q-27,16,2,'#d8e5b9',g);rect(p-4,q-22,9,2,'#cbb778',g);rect(p+1,q-9,5,9,'#334337',g);rect(p-4,q-1,15,3,'#4a5b47',g);rect(p-4,q+6,18,4,'#b8b4a0',g);rect(p+24,q-1,6,7,'#f0ebd5',g);box(g,x-.4,y+.5,.8,.7,17,'#5e7056','#465741','#374a35');const[cx,cy]=point(x,y+.85,17);rect(cx-9,cy-22,18,19,'#556c4d',g);rect(cx-7,cy-20,14,3,'#7b8c65',g);}

 function furniture(o){const g=sv('g',{'data-object':o.id||o.type});const x=o.x,y=o.y,[p,q]=point(x,y);switch(o.type){

  case'plant':plant(g,x,y);break;

  case'board':{box(g,x,y,2.3,.2,86,'#dbb97c','#996f48','#755333');const[a,b]=point(x+.05,y+.23,84);polygon([point(x+.05,y+.23,82),point(x+2.25,y+.23,82),point(x+2.25,y+.23,22),point(x+.05,y+.23,22)],{fill:'#466457',stroke:'#d6b77b','stroke-width':3,class:'board-frame'},g);for(let col=0;col<3;col++){const[c,d]=point(x+.23+col*.66,y+.24,71);rect(c,d,13,2,'#e8d99c',g);for(let row=0;row<3;row++)rect(c,d+9+row*12,11,8,['#e0bf66','#b6c6a0','#d6a285'][col],g);}g.classList.add('object-hit');g.setAttribute('role','button');g.setAttribute('tabindex','0');g.setAttribute('aria-label',o.label);g.addEventListener('click',()=>{if(!dragged)openTasks();});g.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();openTasks();}});const[c,d]=point(x+1.1,y+.7);label(c,d+14,'TOUTES LES TÂCHES ↗',g,{'text-anchor':'middle',fill:'#647153','font-size':8,'font-weight':700});break;}

  case'reception':box(g,x,y,2.7,1,38,'#f2d293','#b68b58','#987448');label(p+12,q-17,'AWEMA',g,{'font-size':12,'font-weight':800,fill:'#fff2ce'});plant(g,x+2.3,y+.2);break;

  case'books':case'archives':{box(g,x,y,2,.45,65,'#ba9b6b','#ac8f63','#8c754e');for(let row=0;row<3;row++){const[a,b]=point(x+.15,y+.48,55-row*19);for(let k=0;k<6;k++)rect(a+k*8,b+k*4,6,12,['#788e60','#b5754e','#cfb777','#677f7d','#a59581','#d9c38c'][k],g);}break;}

  case'armchair':box(g,x,y,1.3,1.2,26,'#8b9e77','#6e835f','#5e7353');box(g,x,y,.25,1.2,44,'#94a980','#7b8e69','#657b58');box(g,x+1.05,y,.25,1.2,44,'#94a980','#7b8e69','#657b58');break;

  case'meeting':{box(g,x,y,3.8,1.4,29,'#cfa66b','#a58253','#927047');for(let i=0;i<3;i++){box(g,x+.3+i*1.15,y-.4,.6,.6,15,'#7e8f6e','#66765d','#52634b');box(g,x+.3+i*1.15,y+1.6,.6,.6,15,'#7e8f6e','#66765d','#52634b');}rect(p+23,q-22,17,4,'#e7e5cb',g);break;}

  case'coffee':box(g,x,y,2.1,.8,39,'#f0d59f','#b78d61','#906d46');const[a,b]=point(x+.35,y+.3,40);rect(a,b-22,21,22,'#556054',g);rect(a+3,b-17,15,12,'#859081',g);rect(a+26,b-10,9,10,'#e5d5b1',g);break;

  case'cafe-table':box(g,x,y,1.4,1.4,26,'#ebcd93','#c2a473','#a38760');for(const[a,b]of [[-.65,.3],[1.6,.3]])box(g,x+a,y+b,.6,.6,14,'#b69362','#957847','#7f693e');break;

  case'finance-desk':desk(g,x,y);break;

  case'sofa':box(g,x,y,2.9,1,18,'#b7b48a','#96936d','#838164');box(g,x,y,2.9,.25,44,'#9da17b','#8a9167','#787f59');box(g,x,y,.3,1,30,'#a9ad84','#8b946b','#757d59');box(g,x+2.6,y,.3,1,30,'#a9ad84','#8b946b','#757d59');break;

  case'art':{const[a,b]=point(x,y);rect(a,b-63,27,44,'#936f4f',g);rect(a+3,b-60,21,38,'#e4c583',g);rect(a+5,b-53,17,10,'#ba744b',g);rect(a+9,b-43,9,18,'#617a55',g);rect(a+13,b-57,4,35,'#efdbad',g);break;}

  case'camera':{sv('path',{d:`M${p} ${q-29}l-15 30 M${p} ${q-29}l15 30 M${p} ${q-29}v32`,stroke:'#4c574b','stroke-width':3},g);rect(p-14,q-50,29,19,'#3b493e',g);rect(p+15,q-47,8,12,'#758475',g);rect(p-8,q-46,12,9,'#a1b3a0',g);break;}

  case'server':box(g,x,y,1,.8,72,'#748173','#4e6154','#3c5247');for(let k=0;k<5;k++){rect(p-16,q-63+k*11,23,7,'#273f35',g);rect(p+2,q-61+k*11,3,3,'#a5bb82',g);}break;

  case'bench':box(g,x,y,2.3,.7,18,'#c7aa76','#a78b5f','#8b7551');box(g,x,y,2.3,.15,37,'#c7aa76','#a78b5f','#8b7551');break;

 }return g;}

  function actor(r){const g=sv('g',{class:'agent-hit',role:'button',tabindex:'0','data-role':r.id,'data-process':'unknown','aria-label':r.name+' : ouvrir sa fiche'});g.style.setProperty('--agent-accent',agentColors[r.id]||'#f1bc50');let phase=0;for(const ch of r.id)phase=(phase*31+ch.charCodeAt(0))%4000;g.style.setProperty('--idle-delay',`-${phase/1000}s`);g.style.setProperty('--idle-period',`${5+phase%4}s`);const[p,q]=point(r.x,r.y);sv('ellipse',{cx:p,cy:q+9,rx:20,ry:10,fill:'#a18665',opacity:.2,class:'actor-shadow'},g);sv('ellipse',{cx:p,cy:q+8,rx:23,ry:12,fill:'none',stroke:'#eac255','stroke-width':2,class:'selection-ring'},g);

  const palette={'.':null,k:'#303b2d',h:r.skin,a:r.color,l:'#d7a76d',s:'#caa05a',w:'#dce7cc',b:'#a2bda7',g:'#e2bf64'};

  const rows=['......k.....k.......','......kk...kk.......','.......ggggg........','......ggggggg.......','.....kghhhhggk......','......hhhhhhh.......','......hkhkhhh.......','......hhhhhhh.......','.......hhhhh........','..wwww..aaa..wwww...','.wwwwwaaaaaaawwwww..','..wwwkaaaaaaakwww...','.....haaaa aaah.....','.....haaaaaaah......','......kkkkkk........','......gggggg........','......kkkkkk........','......gggggg........','......kkkkkk........','......kk..kk........','......kk..kk........','.....kkk..kkk.......'];

   const body=sv('g',{class:'actor-sprite','shape-rendering':'crispEdges',transform:`translate(${p-30},${q-76}) scale(3)`},g);rows.forEach((row,y)=>[...row].forEach((v,x)=>{if(palette[v]){const pixel=rect(x,y,1,1,palette[v],body);if(v==='h'||v==='a')pixel.setAttribute('data-appearance-channel',v);if(v==='a'){pixel.classList.add('agent-shirt');pixel.style.setProperty('fill',r.color,'important');}}}));

  const bubble=sv('g',{class:'agent-bubble',hidden:'hidden','aria-hidden':'true'},g);rect(p-59,q-111,118,24,'',bubble,{rx:8,class:'agent-bubble-bg'});label(p,q-95,'',bubble,{'text-anchor':'middle',class:'agent-bubble-text'});

  const chip=sv('g',{class:'actor-label'},g);rect(p-49,q+18,98,36,'',chip,{rx:5});label(p,q+33,r.name,chip,{'text-anchor':'middle',class:'agent-name'});sv('circle',{cx:p-40,cy:q+44,r:2.5,class:'agent-dot'},chip);label(p+2,q+47,'À vérifier',chip,{'text-anchor':'middle',class:'agent-state'});

  g.addEventListener('click',()=>{if(!dragged)openAgent(r.id);});g.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();openAgent(r.id);}});return g;

 }

 function buildWorld(w){store.world=w;const floors=$('rooms'),objects=[];for(const room of w.rooms){const{x,y,w:rw,d}=room;box(floors,x,y,rw,d,11,room.color,'#a99168','#8a7755');for(let xx=x;xx<x+rw;xx++)for(let yy=y;yy<y+d;yy++)polygon([point(xx,yy,11),point(xx+1,yy,11),point(xx+1,yy+1,11),point(xx,yy+1,11)],{fill:(xx+yy)%3===0?'#ffffff08':'none',stroke:'#fff5df25','stroke-width':.8},floors);

   if(y===0){box(floors,x,y,rw,.13,90,'#e8dcc0','#e7d8b5','#bba87e');for(let t=x+.8;t<x+rw-.8;t+=2){const[a,b]=point(t,y+.14,81);polygon([point(t,y+.14,81),point(t+1.1,y+.14,81),point(t+1.1,y+.14,37),point(t,y+.14,37)],{fill:'#b1c9c2',stroke:'#738d72','stroke-width':4},floors);sv('path',{d:`M${a+9} ${b+6}l-5 22`,stroke:'#f0f4d8','stroke-width':2,opacity:.6},floors);}}

   if(x===0)box(floors,x,y,.12,d,68,'#e6d5ae','#d7c298','#b39e75');

   if(y>0)box(floors,x,y,rw,.1,9,'#d4bf96','#aa976e','#958362');

   const[a,b]=point(...room.label,12);label(a,b,room.name.toUpperCase(),floors,{class:'room-label','text-anchor':'middle'});

  }

  for(const r of w.agents){objects.push({z:r.x+r.y-.3,node:furniture({type:'finance-desk',x:r.x,y:r.y})});}

  for(const o of w.objects)objects.push({z:o.x+o.y,node:furniture(o)});objects.sort((a,b)=>a.z-b.z).forEach(o=>$('furniture').append(o.node));

  w.agents.slice().sort((a,b)=>a.x+a.y-b.x-b.y).forEach(r=>$('actors').append(actor(r)));

  for(const room of w.rooms.filter(r=>['dev','studio','infra','garden'].includes(r.id))){const b=make('button','',room.name);b.setAttribute('aria-pressed','false');b.addEventListener('click',()=>focusRoom(room));$('room-chips').append(b);}

 }

 function focusRoom(room){cameraTouched=true;store.room=room.id;zoom=1.55;const[p,q]=point(room.x+room.w/2,room.y+room.d/2);pan=[985-p,405-q];camera();$('notice').textContent=room.name+' · emplacement de présentation du bureau';[...$('room-chips').children].forEach(b=>b.setAttribute('aria-pressed',String(b.textContent===room.name)));}

 function camera(){ $('camera').setAttribute('transform',`translate(${985+pan[0]} ${405+pan[1]}) scale(${zoom}) translate(-985 -405)`);}

 function fit(){cameraTouched=true;zoom=1;pan=[0,0];store.room=null;camera();[...$('room-chips').children].forEach(b=>b.setAttribute('aria-pressed','false'));}

 function role(id){return store.world?.agents.find(a=>a.id===id);}

 function time(t){return new Date(t*1000).toLocaleTimeString('fr-FR',{hour:'2-digit',minute:'2-digit',second:'2-digit'});}

 async function read(url,credentials='omit'){const c=new AbortController(),t=setTimeout(()=>c.abort(),4000);try{const r=await fetch(url,{credentials,cache:'no-store',signal:c.signal});if(!r.ok){const e=new Error('unavailable');e.status=r.status;throw e;}return await r.json();}finally{clearTimeout(t);}}

 const fresh=v=>v&&v.available===true&&Number.isInteger(v.observed_at)&&v.observed_at>Date.now()/1000-30&&v.observed_at<=Date.now()/1000+5;

 function validRoles(v){return Array.isArray(v.roles)&&v.roles.length===9&&new Set(v.roles.map(r=>r.role)).size===9&&v.roles.every(r=>role(r.role));}

 function clearPublic(){clearTimeout(expiry);store.activity=null;store.workers=null;updatePublic();}

 function process(id){const r=store.workers?.roles.find(r=>r.role===id);return r?.worker_running===true?'running':r?.worker_running===false?'stopped':'unknown';}

 function showActivityBubble(id,text){const g=document.querySelector('[data-role="'+id+'"] .agent-bubble');if(!g)return;const node=g.querySelector('.agent-bubble-text');node.textContent=text;g.removeAttribute('hidden');g.setAttribute('aria-hidden','false');clearTimeout(bubbleTimers.get(id));bubbleTimers.set(id,setTimeout(()=>{g.setAttribute('hidden','');g.setAttribute('aria-hidden','true');bubbleTimers.delete(id);},9000));}

 function activity(id){return store.activity?.roles.find(r=>r.role===id);}

 function updatePublic(){window.dispatchEvent(new CustomEvent('awema-public-workers',{detail:store.workers}));const a=store.activity,w=store.workers;const running=w?w.roles.filter(r=>r.worker_running===true).length:null,blocked=a?.sources.kanban?a.roles.reduce((n,r)=>n+(r.counts.blocked||0),0):null;

  $('metric-agents').textContent=a?'9':'—';$('metric-workers').textContent=running===null?'—':running;$('metric-blocked').textContent=blocked===null?'—':blocked;

  $('connection').dataset.state=a&&w?'live':a||w?'partial':'unknown';$('connection').lastChild.textContent=a&&w?' Observations à jour':a||w?' Observation partielle':' Observation indisponible';

  $('summary').textContent=running===null?'Aucun processus actuel confirmé.':running?running+' processus natif'+(running>1?'s':'')+' en cours · choisissez un agent.':'Le bureau est calme · aucun processus natif en cours.';

  $('freshness').textContent=a||w?'Observé à '+time(Math.min(...[a,w].filter(Boolean).map(v=>v.observed_at))):'Observation à vérifier';

  for(const r of store.world?.agents||[]){const g=document.querySelector('[data-role="'+r.id+'"]');if(!g)continue;const p=process(r.id);g.dataset.process=p;g.classList.toggle('working',p==='running');g.querySelector('.agent-state').textContent=p==='running'?'Processus en cours':p==='stopped'?'Processus arrêté':'Inconnu';g.setAttribute('aria-label',r.name+' : '+(p==='running'?'processus en cours':p==='stopped'?'processus arrêté':'observation inconnue')+', ouvrir sa fiche');}

  if(store.view==='team')renderTeam();if(store.view==='agent')renderAgent();

 }

 function trackChanges(before,after){if(!before){for(const r of store.world.agents){const cur=after.roles.find(x=>x.role===r.id);if(cur?.worker_running===true)showActivityBubble(r.id,'Processus en cours');}return;}for(const r of store.world.agents){const old=before.roles.find(x=>x.role===r.id),cur=after.roles.find(x=>x.role===r.id);if(old&&cur&&old.worker_running!==cur.worker_running&&cur.worker_running!==null){const verb=cur.worker_running?'démarré':'arrêté',message=r.name+' · processus '+verb+' observé';store.events.unshift({at:after.observed_at,text:message});showActivityBubble(r.id,cur.worker_running?'Travail démarré':'Processus arrêté');$('notice').textContent=message;}}store.events=store.events.slice(0,8);if(store.view==='events')renderEvents();}

 async function refresh(){if(pending||document.hidden||!store.world)return;pending=true;const old=store.workers;try{const results=await Promise.allSettled([read('/api/public/activity'),read('/api/public/workers')]);const av=results[0].status==='fulfilled'?results[0].value:null,wv=results[1].status==='fulfilled'?results[1].value:null;

   store.activity=fresh(av)&&av.version===2&&validRoles(av)&&av.roles.every(r=>r.counts&&Object.values(r.counts).every(n=>Number.isInteger(n)&&n>=0&&n<=99))?av:null;

   store.workers=fresh(wv)&&wv.version===1&&validRoles(wv)&&wv.roles.every(r=>['running','finished','unknown'].includes(r.state)&&[true,false,null].includes(r.worker_running))?wv:null;

   if(store.workers)trackChanges(old,store.workers);clearTimeout(expiry);const clocks=[store.activity,store.workers].filter(Boolean).map(v=>v.observed_at*1000+30000-Date.now());if(clocks.length)expiry=setTimeout(clearPublic,Math.max(0,Math.min(...clocks)));updatePublic();

  }finally{pending=false;}

 }

 function purgePrivate(){clearTimeout(privateExpiry);store.private=null;store.selectedTask=null;privateGeneration++;}

 function authorizedTasks(){return store.private?.tasks||[];}

 async function refreshPrivate(){if(privatePending||document.hidden||!['tasks','agent','task'].includes(store.view))return;privatePending=true;const generation=privateGeneration;try{const v=await read('/private/api/team','same-origin');if(generation!==privateGeneration)return;if(!fresh(v)||!Array.isArray(v.tasks)||v.tasks.length>200||v.tasks.some(t=>typeof t.title!=='string'||!/^t_[a-f0-9]{8}$/.test(t.id)||typeof t.role!=='string'||typeof t.status!=='string'))throw new Error('stale');store.private=v;store.privateAccess='authorized';clearTimeout(privateExpiry);privateExpiry=setTimeout(()=>{purgePrivate();store.privateAccess='stale';renderCurrent();},Math.max(0,v.observed_at*1000+30000-Date.now()));renderCurrent();}catch(e){if(generation===privateGeneration){purgePrivate();store.privateAccess=e.status===401?'locked':'unavailable';renderCurrent();}}finally{privatePending=false;}}

 function openPanel(view,title,kicker='LE BUREAU'){contextPage=0;if($('panel').hidden)returnFocus=document.activeElement;store.view=view;$('panel').hidden=false;$('panel').classList.toggle('wide',view==='tasks');$('panel-title').textContent=title;$('panel-kicker').textContent=kicker;$('panel-content').replaceChildren();for(const b of $('workspace').querySelectorAll('.agent-hit'))b.classList.toggle('selected',view==='agent'&&b.dataset.role===store.role);const active={agent:'team-button',team:'team-button',tasks:'tasks-button',task:'tasks-button',events:'events-button',help:'office-button'}[view];document.querySelectorAll('.dock nav button').forEach(b=>b.classList.toggle('active',b.id===active));$('panel-close').focus();}

 function closePanel(){store.view=null;store.role=null;purgePrivate();store.privateAccess='unknown';$('panel').hidden=true;$('panel-content').replaceChildren();document.querySelectorAll('.agent-hit').forEach(g=>g.classList.remove('selected'));document.querySelectorAll('.dock nav button').forEach(b=>b.classList.toggle('active',b.id==='office-button'));returnFocus?.focus();}

 function openAgent(id){store.role=id;openPanel('agent',role(id).name,'UN AGENT · UN MÉTIER');renderAgent();refreshPrivate();}

 function renderAgent(){const r=role(store.role);if(!r)return;const host=$('panel-content');host.replaceChildren();const a=activity(r.id),p=process(r.id),box=make('div','agent-summary');box.style.setProperty('--agent-accent',agentColors[r.id]||'#f1bc50');box.classList.toggle('is-agent-working',p==='running');box.append(make('h3','',r.title),make('p','',store.world.rooms.find(x=>x.id===r.room).name+' · bureau de présentation'),make('p','',p==='running'?'Processus natif confirmé en cours':p==='stopped'?'Processus natif confirmé arrêté':'Processus inconnu'),make('p','',a?roleStates[a.state]||'État inconnu':'Activité indisponible'));host.append(box);

  if(a&&store.activity.sources.kanban){const counts=make('div','mini-counts');for(const[k,v]of Object.entries(a.counts))if(v)counts.append(make('span','tag '+k,v+' '+(statuses[k]||k)));host.append(counts);}

  const tasks=authorizedTasks().filter(t=>t.role===r.id);if(store.private&&innerHeight>=550){host.append(make('p','panel-note',tasks.length+' cartes accessibles'+(store.private.truncated?' · source partielle':'')));for(const t of tasks.slice(0,2))host.append(taskCard(t));}else if(!store.private) host.append(make('p','protected',store.privateAccess==='locked'?'Les titres et détails demandent une session privée. Les observations anonymisées restent visibles.':store.privateAccess==='unavailable'?'Vue privée indisponible. Aucun ancien titre conservé.':'Vérification de votre accès aux tâches…'));

  const b=make('button','primary','Voir ses tâches ↗');b.addEventListener('click',()=>openTasks(r.id));host.append(b,make('p','panel-note','Carte et processus sont deux observations différentes. Aucune conversation ni réflexion privée affichée.'));

 }

 function openTasks(agent='all'){store.agent=agent;store.query='';store.status='all';store.page=0;openPanel('tasks',agent==='all'?'Toutes les tâches':role(agent).name+' · tâches','LE TABLEAU DU BUREAU');renderTasks();refreshPrivate();}

 function lockedState(host){const e=make('div','empty');e.append(make('div','empty-symbol','▤'),make('h3','',store.privateAccess==='locked'?'Votre tableau est privé':store.privateAccess==='unavailable'||store.privateAccess==='stale'?'Observation indisponible':'Ouverture du tableau…'),make('p','panel-note','Les titres et projets sont servis uniquement après authentification côté serveur. Aucun détail privé n’est exposé aux visiteurs.'));if(store.privateAccess==='locked'){const a=make('a','primary','Ouvrir ma session privée ↗');a.href='/private';e.append(a);}else if(store.privateAccess!=='unknown'){const b=make('button','secondary','Réessayer');b.addEventListener('click',refreshPrivate);e.append(b);}host.append(e);}

 function taskCard(t){const card=make('button','task-card');card.type='button';card.style.setProperty('--agent-accent',agentColors[t.role]||'#f1bc50');card.dataset.agentRole=t.role||'';card.classList.toggle('is-agent-working',process(t.role)==='running');card.append(make('span','tag '+t.status,statuses[t.status]||'État inconnu'),make('h3','',t.title));const meta=make('div','meta');meta.append(make('span','',role(t.role)?.name||'Attribution inconnue'),make('span','',t.id));card.append(meta);card.addEventListener('click',()=>openTask(t.id));return card;}

 function pageSize(){return innerHeight<500?2:innerHeight<680?4:innerWidth<700?6:8;}

 function renderTasks(){const host=$('panel-content');const focus=document.activeElement?.dataset.filter,selection=focus==='query'?document.activeElement.selectionStart:null;host.replaceChildren();if(!store.private){lockedState(host);return;}

  host.append(make('p','panel-note',store.private.tasks.length+' cartes accessibles · '+time(store.private.observed_at)+(store.private.truncated?' · Source tronquée : certaines cartes ne sont pas transmises.':'')));

  const tools=make('div','task-tools'),search=make('input');search.type='search';search.placeholder='Rechercher une tâche…';search.setAttribute('aria-label','Rechercher une tâche');search.dataset.filter='query';search.value=store.query;search.addEventListener('input',()=>{store.query=search.value;store.page=0;renderTasks();});tools.append(search);

  const agents=make('select');agents.setAttribute('aria-label','Filtrer par agent');agents.dataset.filter='agent';for(const r of [{id:'all',name:'Tous les agents'},...store.world.agents,{id:'unknown',name:'Sans attribution'}]){const o=make('option','',r.name);o.value=r.id;agents.append(o);}agents.value=store.agent;agents.addEventListener('change',()=>{store.agent=agents.value;store.page=0;renderTasks();});tools.append(agents);

  const states=make('select');states.dataset.filter='status';states.setAttribute('aria-label','Filtrer par statut');for(const[id,text]of [['all','Tous les statuts'],...Object.entries(statuses)]){const o=make('option','',text);o.value=id;states.append(o);}states.value=store.status;states.addEventListener('change',()=>{store.status=states.value;store.page=0;renderTasks();});tools.append(states);host.append(tools);

  const priority={running:0,in_progress:0,blocked:1,review:2,ready:3,todo:4,scheduled:5,triage:6,done:8,cancelled:9};const tasks=authorizedTasks().filter(t=>(store.agent==='all'||t.role===store.agent)&&(store.status==='all'||t.status===store.status)&&(!store.query||[t.title,t.id,t.role].join(' ').toLocaleLowerCase('fr').includes(store.query.toLocaleLowerCase('fr')))).sort((a,b)=>(priority[a.status]??7)-(priority[b.status]??7)||b.created_at-a.created_at);const size=pageSize(),pages=Math.max(1,Math.ceil(tasks.length/size));store.page=Math.min(store.page,pages-1);const list=make('div','task-list');if(!tasks.length)list.append(make('p','panel-note','Aucune carte ne correspond à ces filtres.'));for(const t of tasks.slice(store.page*size,(store.page+1)*size))list.append(taskCard(t));host.append(list);

  const nav=make('div','pager'),previous=make('button','','←'),next=make('button','','→');previous.setAttribute('aria-label','Page précédente');next.setAttribute('aria-label','Page suivante');previous.disabled=store.page===0;next.disabled=store.page===pages-1;previous.addEventListener('click',()=>{store.page--;renderTasks();});next.addEventListener('click',()=>{store.page++;renderTasks();});nav.append(previous,make('span','',tasks.length+' cartes · '+(store.page+1)+' / '+pages),next);host.append(nav);

  if(focus){const input=host.querySelector('[data-filter="'+focus+'"]');input?.focus();if(selection!==null)try{input.setSelectionRange(selection,selection);}catch{}}

 }

 function openTask(id){store.selectedTask=id;openPanel('task','La carte','UNE TÂCHE RÉELLE');renderTask();}

 function renderTask(){const host=$('panel-content');host.replaceChildren();const t=authorizedTasks().find(t=>t.id===store.selectedTask);if(!t){lockedState(host);return;}const section=make('div','task-detail');section.style.setProperty('--agent-accent',agentColors[t.role]||'#f1bc50');section.classList.toggle('is-agent-working',process(t.role)==='running');section.append(make('span','tag '+t.status,statuses[t.status]||'État inconnu'),make('h3','',t.title),make('p','panel-note',(role(t.role)?.name||'Attribution inconnue')+' · '+t.id+' · '+t.run_count+' runs enregistrés'));const events=make('ol','event-list');for(const e of (t.events||[]).slice(-(innerHeight<550?1:4))){const row=make('li','',({created:'Carte créée',run_started:'Run démarré',run_ended:'Run terminé'}[e.kind]||'Événement enregistré')+' · '+e.profile+' · run '+e.run_id);row.prepend(make('time','',time(e.at)));events.append(row);}section.append(events,make('p','panel-note','Les messages, résultats détaillés et noms de projets ne sont pas fournis par cette projection. Un run terminé ne certifie pas le résultat.'));const b=make('button','secondary','← Revenir au tableau');b.addEventListener('click',()=>{openPanel('tasks','Toutes les tâches','LE TABLEAU DU BUREAU');renderTasks();});section.append(b);host.append(section);}

 function renderTeam(){const host=$('panel-content');host.replaceChildren();host.append(make('p','panel-note','Neuf profils enregistrés. Les états ci-dessous proviennent des observations du serveur.'));const list=make('div','team-list');const size=innerHeight<500?2:innerHeight<680?6:10,pages=Math.ceil(store.world.agents.length/size);contextPage=Math.min(contextPage,pages-1);for(const r of store.world.agents.slice(contextPage*size,(contextPage+1)*size)){const b=make('button','team-card');b.style.setProperty('--agent-accent',agentColors[r.id]||'#f1bc50');b.dataset.agentRole=r.id;b.classList.toggle('is-agent-working',process(r.id)==='running');b.append(make('b','',r.name),make('span','',r.title),make('span','',process(r.id)==='running'?'Processus en cours':process(r.id)==='stopped'?'Processus arrêté':'Processus inconnu'));b.addEventListener('click',()=>openAgent(r.id));list.append(b);}host.append(list);if(pages>1)host.append(contextPager(pages,renderTeam));}

 function renderEvents(){const host=$('panel-content');host.replaceChildren();host.append(make('p','panel-note','Changements de processus reçus depuis l’ouverture de cette page. Aucun historique complet ni message privé n’est déduit.'));const list=make('ol','event-list');for(const e of store.events.slice(0,5)){const r=make('li','',e.text);r.prepend(make('time','',time(e.at)));list.append(r);}if(!store.events.length)list.append(make('li','','Le bureau est calme. Aucun nouveau changement observé pendant cette visite.'));host.append(list);}

 function renderCurrent(){if(store.view==='tasks')renderTasks();if(store.view==='agent')renderAgent();if(store.view==='task')renderTask();}

 function contextPager(pages,render){const nav=make('div','pager'),prev=make('button','','←'),next=make('button','','→');prev.setAttribute('aria-label','Page précédente');next.setAttribute('aria-label','Page suivante');prev.disabled=contextPage===0;next.disabled=contextPage===pages-1;prev.addEventListener('click',()=>{contextPage--;render();});next.addEventListener('click',()=>{contextPage++;render();});nav.append(prev,make('span','',(contextPage+1)+' / '+pages),next);return nav;}

 function renderHelp(){const host=$('panel-content');host.replaceChildren();const steps=[['Choisir un agent','Cliquez sur une abeille pour voir son état. Le tableau mural ouvre toutes les tâches accessibles en un clic. Les filtres permettent de retrouver un agent, une carte ou un statut.'],['Explorer le bureau','Glissez le bureau ou utilisez le clic droit pour le déplacer ; la molette zoome autour du pointeur. Les boutons + et − et ⌖ ajustent le cadrage. Les flèches du clavier déplacent la scène lorsqu’elle est sélectionnée. Échap ferme le panneau.'],['Comprendre les observations','Le processus en cours est confirmé par le serveur. Un emplacement représente un bureau de présentation. Les déplacements d’ambiance sont des animations de présentation. Seul un processus observé active le badge de travail ; aucun message privé n’est exposé.'],['Respecter les accès','Les détails privés nécessitent une session autorisée. Les observations expirent après 30 secondes. Affectation, réunion et conversation ne sont pas encore raccordées à une API d’action.']];host.append(make('h3','',steps[contextPage][0]),make('p','lead-note',steps[contextPage][1]));const spacer=make('div','flex-space');host.append(spacer,contextPager(4,renderHelp));const a=make('a','secondary','Laboratoire historique ↗');a.href='/laboratoire?laboratoire=1';host.append(a);}

 function help(){openPanel('help','Un bureau, pas une simulation','COMMENT SE REPÉRER');renderHelp();}



  const required=['panel-close','office-button','board-shortcut','tasks-button','team-button','events-button','help-button','world','viewport','zoom-fit','zoom-in','zoom-out','fullscreen-button','panel','panel-title','panel-kicker','panel-content','notice','actors','rooms','furniture','room-chips'];const missing=required.filter(id=>!$(id));if(missing.length){console.error('La Ruche : HTML et app.js désynchronisés.',missing);$('notice')&&($('notice').textContent='Interface en cours de réparation : rechargez la page.');return;}

  $('panel-close').addEventListener('click',closePanel);$('office-button').addEventListener('click',()=>{closePanel();fit();});$('board-shortcut').addEventListener('click',()=>openTasks());$('tasks-button').addEventListener('click',()=>openTasks());$('team-button').addEventListener('click',()=>{openPanel('team','Les neuf métiers','L’ÉQUIPE AWEMA');renderTeam();});$('events-button').addEventListener('click',()=>{openPanel('events','Au fil du bureau','ACTIVITÉ OBSERVÉE');renderEvents();});$('help-button').addEventListener('click',help);const animationButton=$('animation-button');if(animationButton){const paused=()=>document.body.classList.contains('animations-paused');const paint=()=>{animationButton.textContent=paused()?'Reprendre les animations':'Pause animations';animationButton.setAttribute('aria-pressed',String(paused()));};try{if(localStorage.getItem('awema-office-animations-paused')==='true')document.body.classList.add('animations-paused');}catch{}paint();animationButton.addEventListener('click',()=>{document.body.classList.toggle('animations-paused');try{localStorage.setItem('awema-office-animations-paused',String(paused()));}catch{}paint();});}document.addEventListener('keydown',e=>{if(e.key==='Escape')closePanel();});

 $('world').addEventListener('keydown',e=>{const directions={ArrowLeft:[40,0],ArrowRight:[-40,0],ArrowUp:[0,40],ArrowDown:[0,-40]};if(e.target===$('world')&&directions[e.key]){e.preventDefault();cameraTouched=true;pan=[pan[0]+directions[e.key][0],pan[1]+directions[e.key][1]];camera();}});

 $('zoom-fit').addEventListener('click',fit);$('zoom-in').addEventListener('click',()=>{cameraTouched=true;zoom=Math.min(2.5,zoom+.2);camera();});$('zoom-out').addEventListener('click',()=>{cameraTouched=true;zoom=Math.max(.65,zoom-.2);camera();});$('fullscreen-button').addEventListener('click',()=>{if(document.fullscreenElement)document.exitFullscreen?.().catch(()=>{});else document.documentElement.requestFullscreen?.().catch(()=>{$('notice').textContent='Plein écran non disponible dans cette fenêtre.';});});

 $('viewport').addEventListener('pointerdown',e=>{if(e.button!==0&&e.button!==2)return;if(e.button===2)e.preventDefault();drag={id:e.pointerId,x:e.clientX,y:e.clientY,pan:[...pan]};dragged=false;try{$('viewport').setPointerCapture(e.pointerId);}catch{}});$('viewport').addEventListener('contextmenu',e=>e.preventDefault());$('viewport').addEventListener('pointermove',e=>{if(!drag||drag.id!==e.pointerId)return;const dx=e.clientX-drag.x,dy=e.clientY-drag.y;if(Math.abs(dx)+Math.abs(dy)>8)dragged=true;if(dragged){cameraTouched=true;const bounds=$('world').getBoundingClientRect(),scale=Math.min(bounds.width/1410,bounds.height/830);pan=[Math.max(-1000,Math.min(1000,drag.pan[0]+dx/scale)),Math.max(-650,Math.min(650,drag.pan[1]+dy/scale))];camera();}});$('viewport').addEventListener('wheel',e=>{e.preventDefault();cameraTouched=true;const svg=$('world'),matrix=svg.getScreenCTM();if(!matrix)return;const cursor=svg.createSVGPoint();cursor.x=e.clientX;cursor.y=e.clientY;const point=cursor.matrixTransform(matrix.inverse()),next=Math.max(.55,Math.min(3.2,zoom*(e.deltaY<0?1.12:.89))),baseX=985+(point.x-985-pan[0])/zoom,baseY=405+(point.y-405-pan[1])/zoom;pan=[point.x-985-next*(baseX-985),point.y-405-next*(baseY-405)];zoom=next;camera();},{passive:false});window.addEventListener('pointerup',()=>{drag=null;setTimeout(()=>{dragged=false;},0);});window.addEventListener('pointercancel',()=>{drag=null;});window.addEventListener('resize',()=>{if(!cameraTouched){zoom=window.innerWidth<760?1.18:1;pan=[0,0];camera();}if(store.view==='tasks')renderTasks();if(store.view==='team')renderTeam();if(store.view==='agent')renderAgent();if(store.view==='task')renderTask();});

 document.addEventListener('visibilitychange',()=>{if(!document.hidden){refresh();refreshPrivate();}else{purgePrivate();if(['tasks','agent','task'].includes(store.view)){store.privateAccess='stale';renderCurrent();}}});

 read('/ruche/world.json').then(w=>{if(w.version!==1||w.agents.length!==9)throw new Error('world');buildWorld(w);startAppearanceRefresh();if(window.innerWidth<760){zoom=1.18;camera();}refresh();setInterval(()=>{refresh();refreshPrivate();},5000);}).catch(()=>{$('notice').textContent='Le bureau ne peut pas être chargé. Réessayez ou ouvrez l’espace privé.';});

})();



// Public welcome guide: answers only general navigation questions and never reads private mission data.

(() => {

 const $=id=>document.getElementById(id),panel=$('voice-guide');if(!panel)return;

 const question=$('voice-guide-question'),answer=$('voice-guide-answer'),mic=$('voice-guide-mic');let recognition=null;

 const clean=s=>String(s||'').normalize('NFD').replace(/[\u0300-\u036f]/g,'').toLowerCase();

 function reply(raw){const q=clean(raw);if(/mission|objectif|demarrer|lancer|travailler|donner.*tache/.test(q))return 'Pour confier un vrai objectif à l’équipe, ouvrez l’espace privé. Le CTO y prépare un plan et les tâches restent soumises aux contrôles prévus.';if(/resultat|livrable|relecture|rejouer|replay|site.*tester/.test(q))return 'Les résultats et la relecture sont dans l’espace privé, dans la vue Résultats et missions. Une prévisualisation dépend des fichiers réellement livrés.';if(/agent|equipe|metier|qui fait|cto|comptable|designer|developpeur|personnage|mouvement|travail.*reel|reellement/.test(q))return 'La Ruche présente les métiers de l’équipe dans les bureaux. Sélectionnez un personnage pour consulter sa fiche et les informations disponibles. Les animations d’ambiance ne représentent pas du travail réel.';if(/prive|connexion|compte|finance|budget|telegram/.test(q))return 'Les missions, conversations, finances et détails de compte demandent une session autorisée. Ouvrez l’espace privé pour poursuivre.';if(/carte|bureau|navig|deplac|zoom|ruche|ou suis|ou se trouve/.test(q))return 'Vous êtes dans la vue publique du bureau AWEMA. Glissez la carte pour la déplacer, utilisez la molette pour zoomer et choisissez un personnage ou le tableau pour explorer.';return 'Je peux expliquer la navigation, les métiers, les missions et les résultats. Pour une question liée à un projet ou à une mission privée, poursuivez dans l’espace privé.';}

 function speak(text){if(!('speechSynthesis'in window)){answer.dataset.voice='indisponible';return;}window.speechSynthesis.cancel();const utterance=new SpeechSynthesisUtterance(text);utterance.lang='fr-FR';window.speechSynthesis.speak(utterance);}

 function ask(raw,readAloud=false){const text=String(raw||'').trim();if(!text){answer.textContent='Écrivez une question ou utilisez le bouton Parler.';return;}answer.textContent=reply(text);if(readAloud)speak(answer.textContent);}

 function open(){panel.hidden=false;$('voice-guide-close').focus();}

 $('voice-guide-open').addEventListener('click',open);$('voice-greeting-open').addEventListener('click',open);$('voice-guide-close').addEventListener('click',()=>{panel.hidden=true;$('voice-guide-open').focus();});$('voice-greeting-dismiss').addEventListener('click',()=>{$('voice-greeting').hidden=true;});

 $('voice-guide-welcome').addEventListener('click',()=>speak('Bonjour et bienvenue dans la Ruche AWEMA. Vous êtes dans le bureau public. Je peux vous expliquer les espaces, les agents et les missions. Pour échanger avec l’équipe ou retrouver des résultats privés, ouvrez votre espace privé.'));

 $('voice-guide-speak').addEventListener('click',()=>speak(answer.textContent));

 $('voice-guide-form').addEventListener('submit',e=>{e.preventDefault();ask(question.value);});

 mic.addEventListener('click',()=>{const Engine=window.SpeechRecognition||window.webkitSpeechRecognition;if(!Engine){answer.textContent='La dictée vocale n’est pas prise en charge ici. Vous pouvez écrire votre question.';return;}if(recognition){recognition.stop();return;}recognition=new Engine();recognition.lang='fr-FR';recognition.interimResults=false;recognition.maxAlternatives=1;mic.textContent='Écoute…';recognition.onresult=e=>{const transcript=e.results?.[0]?.[0]?.transcript||'';question.value=transcript;ask(transcript,true);};recognition.onerror=e=>{const errors={network:'Le service vocal du navigateur est inaccessible (erreur réseau). Essayez dans Chrome avec une connexion Internet, ou écrivez votre question.', 'audio-capture':'Aucun microphone n’est accessible. Vérifiez le micro et son autorisation dans Windows et dans le navigateur.', 'no-speech':'Aucune parole détectée. Parlez près du micro puis réessayez.', 'not-allowed':'L’accès au microphone est bloqué. Autorisez-le pour laruche.awema.cloud dans votre navigateur et Windows.', 'service-not-allowed':'Le navigateur a bloqué son service de reconnaissance vocale. Essayez Chrome ou écrivez votre question.', 'language-not-supported':'La reconnaissance vocale française n’est pas disponible dans ce navigateur.', aborted:'La dictée a été interrompue. Réessayez ou écrivez votre question.'};answer.textContent=errors[e.error]||`La dictée a échoué (code ${e.error||'inconnu'}). Écrivez votre question ou réessayez.`;};recognition.onend=()=>{recognition=null;mic.textContent='Parler';};try{recognition.start();}catch{recognition=null;mic.textContent='Parler';answer.textContent='Impossible de démarrer le microphone. Vérifiez son autorisation, puis réessayez.';}});

 document.addEventListener('keydown',e=>{if(e.key==='Escape'&&!panel.hidden){panel.hidden=true;$('voice-guide-open').focus();}});

})();



'use strict';

(()=>{

 const $=id=>document.getElementById(id),world=$('world');if(!world)return;

 const privateView=location.pathname.startsWith('/private');let data=null,selected=null,walking=false,epoch=0;const positions=new Map(),manualLayout=new Map(),manualRoles=new Set(),idleHistory=new Map();let officeAlive=true,officeTimer=null,backgroundMode=false,quietUntil=0,nextAmbientAt=0,lastAmbientRoles=[];
 function quietOffice(){quietUntil=Date.now()+12000;if(backgroundMode)epoch++;}
 world.addEventListener('pointerdown',quietOffice,true);world.addEventListener('keydown',quietOffice,true);dockGestureSetup();
 function dockGestureSetup(){document.addEventListener('visibilitychange',()=>{if(document.hidden&&backgroundMode)epoch++;});}

 // Ambient motion consumes the same public worker projection as the visible status.

 // The first office module owns that projection; it never exposes its private store.

 let observedWorkers=null;

 window.addEventListener('awema-public-workers',event=>{const v=event.detail;observedWorkers=v&&v.version===1&&v.available===true&&Number.isInteger(v.observed_at)&&Array.isArray(v.roles)&&v.roles.length===9&&new Set(v.roles.map(r=>r.role)).size===9&&v.roles.every(r=>typeof r.role==='string'&&[true,false,null].includes(r.worker_running))?{observed_at:v.observed_at,roles:v.roles.map(r=>({role:r.role,worker_running:r.worker_running}))}:null;if(data)ambientWalk();});

 const workersFresh=()=>observedWorkers&&observedWorkers.observed_at>Date.now()/1000-30&&observedWorkers.observed_at<=Date.now()/1000+5;



 const point=(x,y)=>[800+(x-y)*29,100+(x+y)*14.5];

 const el=(tag,text)=>{const n=document.createElement(tag);if(text)n.textContent=text;return n;};

 const dock=el('section');dock.className='office-conversation';dock.id='office-chat-dock';dock.setAttribute('aria-label','Conversation avec les agents');dock.addEventListener('pointerdown',quietOffice,true);dock.addEventListener('keydown',quietOffice,true);

 const head=el('div'),title=el('strong',privateView?'Conversation privée':'CTO · conversation de la Ruche');title.className='office-chat-title';const who=el('select');who.setAttribute('aria-label','Agent à contacter');const hint=el('span','Sélectionnez un agent puis cliquez sur une case libre.'),chat=el('a','Échanger');const toggle=el('button','Ouvrir le chat');toggle.type='button';toggle.className='office-chat-toggle';toggle.setAttribute('aria-controls','office-chat-dock');toggle.setAttribute('aria-expanded','false');head.append(title,who,hint,chat,toggle);dock.append(head);toggle.addEventListener('click',()=>{const open=dock.classList.toggle('is-open');toggle.setAttribute('aria-expanded',String(open));toggle.textContent=open?'Réduire le chat':'Ouvrir le chat';});

 if(privateView){hint.hidden=true;chat.hidden=true;const resizer=el('div');resizer.className='office-chat-resizer';resizer.setAttribute('role','separator');resizer.setAttribute('aria-orientation','horizontal');resizer.setAttribute('aria-label','Ajuster la hauteur du chat privé');resizer.setAttribute('aria-valuemin','35');resizer.setAttribute('aria-valuemax','82');resizer.setAttribute('aria-valuenow','64');resizer.setAttribute('aria-valuetext','Chat 64 % de la fenêtre');resizer.tabIndex=0;let resizePointer=null,resizeStartY=0,resizeStartHeight=0;const resizeTo=height=>{const max=Math.min(780,Math.round(innerHeight*.82)),min=Math.min(320,max),next=Math.max(min,Math.min(max,Math.round(height)));dock.style.setProperty('--chat-height',next+'px');resizer.setAttribute('aria-valuenow',String(Math.round(next/innerHeight*100)));resizer.setAttribute('aria-valuetext','Chat '+Math.round(next)+' pixels de haut');};resizer.addEventListener('pointerdown',e=>{if(!dock.classList.contains('is-open'))return;resizePointer=e.pointerId;resizeStartY=e.clientY;resizeStartHeight=dock.getBoundingClientRect().height;dock.classList.add('is-resizing');resizer.setPointerCapture(e.pointerId);e.preventDefault();});resizer.addEventListener('pointermove',e=>{if(resizePointer===e.pointerId)resizeTo(resizeStartHeight+resizeStartY-e.clientY);});const endResize=e=>{if(resizePointer===e.pointerId){resizePointer=null;dock.classList.remove('is-resizing');if(resizer.hasPointerCapture(e.pointerId))resizer.releasePointerCapture(e.pointerId);}};resizer.addEventListener('pointerup',endResize);resizer.addEventListener('pointercancel',endResize);resizer.addEventListener('keydown',e=>{if(!dock.classList.contains('is-open')||!['ArrowUp','ArrowDown','Home','End'].includes(e.key))return;e.preventDefault();const current=dock.getBoundingClientRect().height;resizeTo(e.key==='Home'?Math.min(780,innerHeight*.82):e.key==='End'?320:current+(e.key==='ArrowUp'?40:-40));});const frame=el('iframe');frame.title='Chat personnel AWEMA';frame.src='/finance?vue=chat';frame.className='office-chat-frame';dock.append(resizer,frame);who.addEventListener('change',()=>pick(who.value));frame.addEventListener('load',()=>{if(selected)frame.contentWindow?.postMessage({type:'awema-focus',agent:selected.id},location.origin);});dock._frame=frame;}

 else{const input=el('textarea');input.disabled=true;input.rows=1;input.placeholder='Connectez-vous à votre espace personnel pour échanger et donner des missions.';dock.append(input);who.addEventListener('change',()=>pick(who.value));}

 function pick(id){const found=data?.agents.find(a=>a.id===id);if(!found)return;selected=found;who.value=id;chat.href='/finance?agent='+encodeURIComponent(id);chat.textContent='Échanger avec '+found.name;$('actors').querySelectorAll('[data-role]').forEach(n=>n.classList.toggle('office-selected',n.dataset.role===id));hint.textContent=found.name+' sélectionné · cliquez au sol pour le faire marcher.';if(dock._frame&&dock._frame.dataset.agent!==id){dock._frame.dataset.agent=id;dock._frame.contentWindow?.postMessage({type:'awema-focus',agent:id},location.origin);}}

 function tile(e){const p=world.createSVGPoint();p.x=e.clientX;p.y=e.clientY;const q=p.matrixTransform($('camera').getScreenCTM().inverse()),a=(q.x-800)/29,b=(q.y-100)/14.5;return[Math.floor((a+b)/2),Math.floor((b-a)/2)];}

 function obstacles(except){const out=new Set();for(const a of data.agents){if(a.id!==except)out.add((positions.get(a.id)||[Math.round(a.x),Math.round(a.y)]).join(','));out.add(Math.round(a.x)+','+(Math.round(a.y)-1));out.add((Math.round(a.x)-1)+','+(Math.round(a.y)-1));}for(const o of data.objects){const[w,d]=({board:[3,1],reception:[3,1],books:[2,1],archives:[2,1],meeting:[4,2],sofa:[3,1],server:[1,1],coffee:[2,1],'cafe-table':[2,2],bench:[2,1]}[o.type]||[1,1]);for(let x=Math.floor(o.x);x<Math.floor(o.x)+w;x++)for(let y=Math.floor(o.y);y<Math.floor(o.y)+d;y++)out.add(x+','+y);}return out;}

 function route(start,end,blocked){const q=[start],prev=new Map(),seen=new Set([start.join(',')]);for(let i=0;i<q.length;i++){const p=q[i],k=p.join(',');if(k===end.join(',')){const out=[];let key=k;while(key!==start.join(',')){out.unshift(key.split(',').map(Number));key=prev.get(key);}return out;}for(const[dX,dY]of[[1,0],[-1,0],[0,1],[0,-1]]){const n=[p[0]+dX,p[1]+dY],key=n.join(',');if(seen.has(key)||blocked.has(key)||!data.rooms.some(r=>n[0]>=r.x&&n[0]<r.x+r.w&&n[1]>=r.y&&n[1]<r.y+r.d))continue;seen.add(key);prev.set(key,k);q.push(n);}}return null;}

 function place(id,pos){const a=data.agents.find(a=>a.id===id),n=$('actors').querySelector('[data-role="'+id+'"]');if(!n)return;const to=point(...pos),base=point(a.x,a.y);n.setAttribute('transform',`translate(${to[0]-base[0]} ${to[1]-base[1]})`);positions.set(id,pos);}

 function paused(){return !officeAlive||document.hidden||document.body.classList.contains('animations-paused')||document.body.classList.contains('is-replaying');}
 const station=agent=>[Math.round(agent.x),Math.round(agent.y)];
 async function move(end){if(!selected||(walking&&!backgroundMode)||paused())return;quietOffice();const ticket=++epoch,id=selected.id,start=positions.get(id)||station(selected),steps=route(start,end,obstacles(id));if(!steps){hint.textContent='Cette destination est inaccessible.';return;}manualRoles.add(id);backgroundMode=false;walking=true;try{for(const pos of steps){if(ticket!==epoch||paused())return;place(id,pos);await new Promise(r=>setTimeout(r,matchMedia('(prefers-reduced-motion: reduce)').matches?0:90));}manualLayout.set(id,end);try{localStorage.setItem('awema-office-layout-v2',JSON.stringify([...manualLayout]));}catch{}hint.textContent='Position visuelle enregistrée · responsabilités inchangées.';}finally{if(ticket===epoch)walking=false;}}
 function idleSpots(){const spots=[[3,13],[5,9],[13,12],[20,12],[26,10]];for(const o of data.objects)if(['coffee','books','bench','sofa','board'].includes(o.type))spots.push([Math.floor(o.x)-1,Math.floor(o.y)+1]);return spots;}
 async function ambientWalk(){if(walking||paused()||!data||!workersFresh())return;const running=observedWorkers.roles.filter(r=>r.worker_running===true).map(r=>r.role);let agent,target,kind='station';
  if(running.length){agent=data.agents.find(a=>running.includes(a.id)&&!manualRoles.has(a.id)&&(positions.get(a.id)||station(a)).join(',')!==station(a).join(',')&&route(positions.get(a.id)||station(a),station(a),obstacles(a.id)));if(!agent)return;target=station(agent);}
  else{if(Date.now()<quietUntil||Date.now()<nextAmbientAt||matchMedia('(prefers-reduced-motion: reduce)').matches)return;const candidates=data.agents.filter(a=>!manualRoles.has(a.id)&&!lastAmbientRoles.includes(a.id)&&observedWorkers.roles.some(r=>r.role===a.id&&r.worker_running===false));if(!candidates.length)return;agent=candidates[Math.floor(Math.random()*candidates.length)];const recent=idleHistory.get(agent.id)||[],spots=idleSpots().filter(p=>!recent.includes(p.join(','))&&p.join(',')!==(positions.get(agent.id)||station(agent)).join(',')&&route(positions.get(agent.id)||station(agent),p,obstacles(agent.id)));if(!spots.length){nextAmbientAt=Date.now()+4000;return;}target=spots[Math.floor(Math.random()*spots.length)];kind='ambience';idleHistory.set(agent.id,[target.join(','),...recent].slice(0,3));lastAmbientRoles=[agent.id,...lastAmbientRoles].slice(0,Math.min(2,data.agents.length-1));nextAmbientAt=Date.now()+9000+Math.random()*16000;}
  const id=agent.id,steps=route(positions.get(id)||station(agent),target,obstacles(id));if(!steps)return;walking=true;backgroundMode=true;const ticket=++epoch,actor=$('actors').querySelector('[data-role="'+id+'"]');actor?.setAttribute('data-office-motion',kind);
  try{for(const pos of steps){if(ticket!==epoch||paused()||!workersFresh()||(kind==='ambience'&&Date.now()<quietUntil)||(kind==='station'?!observedWorkers.roles.some(r=>r.role===id&&r.worker_running===true):observedWorkers.roles.some(r=>r.worker_running===true)))return;place(id,pos);await new Promise(r=>setTimeout(r,matchMedia('(prefers-reduced-motion: reduce)').matches?0:kind==='station'?100:140));}}finally{actor?.removeAttribute('data-office-motion');if(ticket===epoch){walking=false;backgroundMode=false;}else if(backgroundMode){walking=false;backgroundMode=false;}}
 }
 function stopOffice(){officeAlive=false;epoch++;clearInterval(officeTimer);officeTimer=null;walking=false;backgroundMode=false;}
 function startOffice(){if(officeTimer)return;officeAlive=true;officeTimer=setInterval(ambientWalk,2000);}
 window.addEventListener('pagehide',stopOffice);window.addEventListener('pageshow',event=>{if(event.persisted&&data)startOffice();});
 world.addEventListener('click',e=>{const actor=e.target.closest('[data-role]');if(actor){e.stopImmediatePropagation();pick(actor.dataset.role);return;}if(e.target.closest('[data-object]'))return;if(selected){e.stopImmediatePropagation();move(tile(e));}},true);

 world.addEventListener('keydown',e=>{const actor=e.target.closest('[data-role]');if(!actor)return;if(e.key==='Enter'||e.key===' '){e.preventDefault();e.stopImmediatePropagation();pick(actor.dataset.role);}const delta={ArrowUp:[0,-1],ArrowDown:[0,1],ArrowLeft:[-1,0],ArrowRight:[1,0]}[e.key];if(delta){e.preventDefault();e.stopImmediatePropagation();pick(actor.dataset.role);const pos=positions.get(selected.id)||[Math.round(selected.x),Math.round(selected.y)];move([pos[0]+delta[0],pos[1]+delta[1]]);}},true);

 fetch('/ruche/world.json',{cache:'no-store'}).then(r=>{if(!r.ok)throw Error();return r.json();}).then(w=>{data=w;w.agents.forEach(a=>who.append(new Option(a.name,a.id)));document.body.append(dock);document.body.classList.add('office-unified');chat.href='/finance';const restore=()=>{if($('actors').querySelectorAll('[data-role]').length!==data.agents.length)return;try{for(const[id,pos]of JSON.parse(localStorage.getItem('awema-office-layout-v2')||'[]')){if(!data.agents.some(a=>a.id===id)||!Array.isArray(pos)||pos.length!==2||!pos.every(Number.isInteger)||obstacles(id).has(pos.join(',')))continue;if(data.rooms.some(r=>pos[0]>=r.x&&pos[0]<r.x+r.w&&pos[1]>=r.y&&pos[1]<r.y+r.d)){place(id,pos);manualLayout.set(id,pos);manualRoles.add(id);}}}catch{}observer.disconnect();};const observer=new MutationObserver(restore);observer.observe($('actors'),{childList:true});restore();const note=document.querySelector('.ambient-disclaimer');if(note)note.textContent='Ambiance visuelle · déplacements de présentation, séparés des processus réels.';startOffice();}).catch(()=>{hint.textContent='Bureau indisponible.';});

})();

