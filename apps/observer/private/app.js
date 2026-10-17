'use strict';
const el = id => document.getElementById(id);
let csrf = '';
function unavailable(message) {
  el('tasks').replaceChildren();el('sources').textContent='';
  el('freshness').textContent='Observation indisponible. Aucun ancien résultat affiché.';
  el('message').textContent=message;
}
const states = {triage:'À qualifier',todo:'À faire',running:'En cours',review:'En revue',done:'Terminée',blocked:'Bloquée',cancelled:'Annulée',unknown:'Inconnu'};
const date = value => value ? new Date(value * 1000).toLocaleString('fr-FR') : 'Non renseignée';
async function api(path, options = {}) {
  const controller=new AbortController();
  const timer=setTimeout(() => controller.abort(),8000);
  let response;
  try { response = await fetch('/private/api/' + path, {credentials:'same-origin',cache:'no-store',...options,signal:controller.signal}); }
  finally { clearTimeout(timer); }
  if (!response.ok) {
    if (response.status === 401) { csrf=''; tracePanel.clear('Connexion privée requise.'); el('tasks').replaceChildren();el('dashboard').hidden=true; el('login').hidden=false; }
    throw new Error(response.status === 429 ? 'Trop de demandes. Réessaie dans une minute.' : response.status === 401 ? 'Connexion requise ou clé incorrecte.' : 'Demande refusée ou service indisponible.');
  }
  return response.json();
}
async function refresh() {
  const data = await api('activity');
  if(!csrf)return;
  el('tasks').replaceChildren();
  if (!data.available) { el('freshness').textContent='Observation indisponible ou périmée. Aucun ancien résultat affiché.'; el('sources').textContent=''; return; }
  el('freshness').textContent='Observation : ' + date(data.observed_at) + (data.truncated ? ' · 200 tâches récentes maximum (liste partielle).' : '');
  el('sources').textContent=Object.entries(data.sources).map(([name,ok]) => name + ' : ' + (ok?'lu':'indisponible')).join(' · ');
  for (const task of data.tasks) {
    const row=document.createElement('tr');
    for (const value of [task.ref,task.board,task.role,states[task.status] || 'Inconnu',date(task.created_at),date(task.last_event_at)]) {
      const cell=document.createElement('td');cell.textContent=value;row.append(cell);
    }
    el('tasks').append(row);
  }
}
async function session() {
  const data=await api('session');csrf=data.csrf;el('login').hidden=true;el('dashboard').hidden=false;el('message').textContent='Session privée · expiration : '+date(data.expires);await refresh();await tracePanel.refresh();
}
el('login').addEventListener('submit',async event => {
  event.preventDefault();const password=el('password').value;el('password').value='';
  try { await api('login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password})});await session(); }
  catch(error){el('message').textContent=error.message;}
});
el('refresh').addEventListener('click',() => refresh().catch(error => unavailable(error.message)));
setInterval(() => {if(csrf) refresh().catch(error => unavailable(error.message));},20000);
el('logout').addEventListener('click',async () => {
  try {await api('logout',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:'{}'});csrf='';tracePanel.clear('Déconnecté.');el('tasks').replaceChildren();el('dashboard').hidden=true;el('login').hidden=false;el('message').textContent='Déconnecté.';}
  catch(error){el('message').textContent=error.message;}
});
session().catch(error => {el('message').textContent=error.message;});

function installRealTraces(fetchData,host,isPrivate,allowed){
 const make=(tag,text,cls)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=text;if(cls)n.className=cls;return n;};
 const section=make('section',undefined,'real-traces private-replay');
 const title=make('h2','Le bureau des missions'),intro=make('p','Reconstitution des événements enregistrés. Les explications sont des résumés relus, pas des citations. Une réponse d’outil ne prouve pas sa réussite.'),select=make('select'),mode=make('select'),speed=make('select');
 const notice=make('p','Connexion privée requise.','trace-notice'),stage=make('div',undefined,'trace-office'),room=make('div',undefined,'trace-desks'),traveller=make('div',undefined,'trace-traveller');
 const badge=make('span','Aucune étape sélectionnée','trace-tool-badge'),explanation=make('div',undefined,'trace-explanation'),frameTitle=make('h3','Choisir une mission'),frameText=make('p'),frameMeta=make('p',undefined,'trace-frame-meta');
 const previous=make('button','← Précédente'),play=make('button','Lire'),nextButton=make('button','Suivante →'),replay=make('button','Recommencer'),controls=make('div',undefined,'trace-controls'),timeline=make('ol',undefined,'trace-timeline'),details=make('details',undefined,'trace-tools'),summary=make('section',undefined,'trace-story');
 const labelled=(text,input)=>{const label=make('label',text+' ');label.append(input);return label;};
 select.setAttribute('aria-label','Mission à revoir');mode.setAttribute('aria-label','Type de déroulé');speed.setAttribute('aria-label','Vitesse de lecture');
 for(const [value,text]of [['story','Récit relu'],['technical','Tous les événements techniques']]){const option=make('option',text);option.value=value;mode.append(option);}
 for(const [value,text]of [['1','1×'],['.5','0,5×'],['2','2×']]){const option=make('option',text);option.value=value;speed.append(option);}
 for(const button of [previous,play,nextButton,replay])button.type='button';
 notice.setAttribute('role','status');frameText.setAttribute('aria-live','polite');stage.setAttribute('aria-label','Bureau : mise en scène des journaux enregistrés');traveller.setAttribute('aria-hidden','true');
 stage.append(make('div','LA RUCHE · RELECTURE PRIVÉE','trace-room-label'),room,traveller,badge);
 explanation.append(frameTitle,frameMeta,frameText);controls.append(previous,play,nextButton,replay,labelled('Vitesse',speed));
 details.append(make('summary','Journal technique complet de cet extrait'),timeline);
 section.append(title,intro,labelled('Mission',select),labelled('Afficher',mode),controls,notice,stage,explanation,summary,details);host.append(section);
 const actions={session:'Session',delegate:'Délégation',read:'Lecture',write:'Écriture',execute:'Commande',search:'Recherche',task:'Tableau de tâches',other:'Action non classée',review:'Revue documentaire',none:'Aucun outil'};
 const kinds={tool_call:'Appel enregistré',tool_result:'Réponse enregistrée — succès non certifié',session_start:'Ouverture de session',session_end:'Fermeture de session'};
 const sceneNames={read:'Consultation du dossier',delegate:'Transmission de la mission',return:'Retour de la contribution',review:'Vérification documentaire',close:'Conclusion enregistrée'};
 const names={cto:'CTO',mentor:'Mentor',qa:'QA'};
 const reduced=window.matchMedia('(prefers-reduced-motion: reduce)');
 let items=[],chosen=null,key='',index=0,playing=false,deadline=0,remaining=0,expires=0,animations=[],generation=0;
 function bee(){
  const svg=document.createElementNS('http://www.w3.org/2000/svg','svg');svg.setAttribute('viewBox','0 0 80 70');svg.setAttribute('aria-hidden','true');
  const add=(tag,attrs)=>{const n=document.createElementNS(svg.namespaceURI,tag);for(const [k,v]of Object.entries(attrs))n.setAttribute(k,v);svg.append(n);};
  add('ellipse',{cx:28,cy:20,rx:14,ry:10,fill:'#eefaff',stroke:'#718883'});add('ellipse',{cx:51,cy:19,rx:14,ry:10,fill:'#eefaff',stroke:'#718883'});
  add('ellipse',{cx:40,cy:40,rx:25,ry:19,fill:'#eac05c',stroke:'#4f4935','stroke-width':2});
  add('path',{d:'M30 23 Q24 40 30 57 M43 22 Q37 40 43 58',fill:'none',stroke:'#514d3c','stroke-width':7});
  add('circle',{cx:57,cy:36,r:3,fill:'#252e2a'});add('path',{d:'M56 47 Q61 51 65 45',fill:'none',stroke:'#252e2a','stroke-width':2});return svg;
 }
 function actorName(actor){return actor?.role==='cto'?'CTO':actor?.parent?'Sous-agent '+actor.id.slice(1):'Session '+(actor?.id||'?');}
 function steps(){return mode.value==='story'&&chosen?.story?.steps?.length?chosen.story.steps:chosen?.steps||[];}
 function cancelAnimations(){for(const animation of animations)animation.cancel();animations=[];traveller.replaceChildren();}
 function pause(){if(playing)remaining=Math.max(0,deadline-Date.now());playing=false;play.textContent='Reprendre';section.classList.add('is-paused');for(const animation of animations)animation.pause();}
 function clear(text){generation++;pause();cancelAnimations();items=[];chosen=null;key='';expires=0;index=0;remaining=0;select.replaceChildren();room.replaceChildren();summary.replaceChildren();timeline.replaceChildren();frameTitle.textContent='Aucune mission affichée';frameText.textContent='';frameMeta.textContent='';badge.textContent='Aucune étape';notice.textContent=text;for(const b of [play,previous,nextButton,replay])b.disabled=true;}
 function stations(){
  room.replaceChildren();const storyMode=mode.value==='story'&&chosen?.story?.steps?.length;
  const roster=storyMode?[...new Set(chosen.story.steps.flatMap(s=>[s.scene?.speaker,s.scene?.recipient]).filter(r=>Object.hasOwn(names,r)))].map(id=>({id,label:names[id]})):(chosen?.actors||[]).map(a=>({id:a.id,label:actorName(a)}));
  for(const actor of roster){const desk=make('div',undefined,'trace-desk');desk.dataset.actor=actor.id;desk.append(bee(),make('strong',actor.label),make('span','Bureau','trace-desk-caption'));room.append(desk);}
 }
 function duration(step){const words=(step?.text||'Événement technique enregistré').split(/\s+/).length;return Math.max(6000,(2200+words*330)/Number(speed.value));}
 function showFrame(){
  cancelAnimations();const current=steps()[index];if(!current){frameTitle.textContent='Aucune étape disponible';frameText.textContent='';frameMeta.textContent='';badge.textContent='Aucune étape';previous.disabled=nextButton.disabled=true;return;}
  const isStory=mode.value==='story'&&chosen.story?.steps?.length,scene=isStory?current.scene:null;
  const speaker=scene&&Object.hasOwn(names,scene.speaker)?scene.speaker:current.actor;
  const recipient=scene&&Object.hasOwn(names,scene.recipient)?scene.recipient:null;
  const actor=chosen.actors.find(a=>a.id===current.actor);
  frameTitle.textContent='Étape '+(index+1)+' / '+steps().length+' · '+(sceneNames[scene?.kind]||kinds[current.kind]||'Résumé relu');
  frameText.textContent=isStory?current.text:actorName(actor)+' · '+(kinds[current.kind]||'Événement enregistré')+' · '+(actions[current.action]||'Action non classée')+(current.tool_name?' · Outil : '+current.tool_name:'')+'. Aucune instruction ni aucun argument privé n’est reproduit.';
  frameMeta.textContent=new Date(current.at*1000).toLocaleString('fr-FR')+(isStory?' · Explication résumée, pas un dialogue cité.':' · Source : '+(current.source_session_id||'session non renseignée')+(current.source_message_id?' / message '+current.source_message_id:''));
  badge.textContent=(actions[scene?.tool||current.action]||'Événement')+(current.kind==='tool_result'?' · réponse reçue':'');
  const desks=[...room.children];for(const desk of desks){desk.classList.toggle('current',desk.dataset.actor===speaker);desk.classList.toggle('recipient',desk.dataset.actor===recipient);}
  const from=desks.find(d=>d.dataset.actor===speaker),to=desks.find(d=>d.dataset.actor===recipient);
  if(from){traveller.append(bee(),make('span',names[speaker]||actorName(actor)));const roomBox=stage.getBoundingClientRect(),a=from.getBoundingClientRect(),b=(to||from).getBoundingClientRect();const start={x:a.left-roomBox.left+a.width/2-28,y:a.top-roomBox.top+8},end={x:b.left-roomBox.left+b.width/2-28,y:b.top-roomBox.top+8};traveller.style.left=start.x+'px';traveller.style.top=start.y+'px';if(!reduced.matches&&to&&to!==from){const animation=traveller.animate([{transform:'translate(0,0)'},{transform:'translate('+(end.x-start.x)+'px,'+(end.y-start.y)+'px)'}],{duration:2200,fill:'forwards',easing:'ease-in-out'});animations.push(animation);if(!playing)animation.pause();}}
  timeline.querySelectorAll('li').forEach((li,i)=>li.classList.toggle('current',mode.value==='technical'&&i===index));
  previous.disabled=index===0;nextButton.disabled=index>=steps().length-1;remaining=duration(current);deadline=Date.now()+remaining;
 }
 function render(){pause();index=0;chosen=items[Number(select.value)]||null;summary.replaceChildren();timeline.replaceChildren();if(!chosen){clear('Aucun journal disponible.');return;}
  const hasStory=Boolean(chosen.story?.steps?.length);mode.options[0].disabled=!hasStory;if(!hasStory)mode.value='technical';
  if(hasStory){for(const [field,label]of [['objective','Objectif'],['result','Résultat déclaré'],['limitations','Limites']]){const p=make('p');p.append(make('strong',label+' : '),document.createTextNode(chosen.story[field]||''));summary.append(p);}summary.append(make('p','Les noms des intervenants du récit proviennent des scènes relues. Les autres sessions restent pseudonymisées.'));}
  else summary.append(make('p','Aucun récit métier relu. Ce mode montre uniquement les événements effectivement reliés à la mission.'));
  for(const step of chosen.steps){const li=make('li');li.append(make('span',new Date(step.at*1000).toLocaleString('fr-FR')+' · '+actorName(chosen.actors.find(a=>a.id===step.actor))+' · '+(kinds[step.kind]||'Événement')+' · '+(actions[step.action]||'Action non classée')));if(step.tool_name)li.append(make('small','Outil : '+step.tool_name));timeline.append(li);}
  notice.textContent=chosen.coverage==='linked'?'Relecture de preuves enregistrées, pas une activité en direct. Les étapes absentes ne sont pas inventées.':'Aucune session reliée : aucun scénario reconstruit.';
  if(chosen.truncated)notice.textContent+=' Extrait tronqué.';
  if(chosen.source)notice.textContent+=' Source : '+chosen.source.board+' / '+chosen.source.task_id+'.';
  play.disabled=replay.disabled=chosen.coverage!=='linked'||!steps().length;stations();showFrame();play.textContent='Lire';
 }
 async function refresh(){if(document.hidden||!allowed())return;const ticket=generation;try{const data=await fetchData();if(!allowed()||ticket!==generation)return;if(!data.available||!Number.isFinite(data.observed_at)||Date.now()/1000-data.observed_at>90||!Array.isArray(data.traces)){clear('Journaux indisponibles ou périmés.');return;}expires=data.observed_at*1000+90000;const clean=data.traces.slice(0,20).filter(t=>t&&Array.isArray(t.actors)&&Array.isArray(t.steps)),newKey=JSON.stringify(clean);if(newKey===key)return;const selected=chosen?.ref;key=newKey;items=clean;select.replaceChildren();items.forEach((t,i)=>{const option=make('option',t.title||'Mission '+(i+1));option.value=String(i);select.append(option);});if(!items.length){clear('Aucun journal disponible.');return;}let target=items.findIndex(t=>t.ref===selected);if(target<0)target=items.findIndex(t=>t.story?.steps?.length);select.value=String(Math.max(0,target));render();}catch{if(ticket===generation)clear('Journaux indisponibles. Aucun ancien résultat conservé.');}}
 function start(){if(play.disabled||!steps().length)return;playing=true;section.classList.remove('is-paused');play.textContent='Pause';deadline=Date.now()+(remaining||duration(steps()[index]));for(const animation of animations)animation.play();}
 play.addEventListener('click',()=>playing?pause():start());
 previous.addEventListener('click',()=>{pause();index=Math.max(0,index-1);showFrame();});nextButton.addEventListener('click',()=>{pause();index=Math.min(steps().length-1,index+1);showFrame();});
 replay.addEventListener('click',()=>{pause();index=0;showFrame();start();});select.addEventListener('change',render);mode.addEventListener('change',render);speed.addEventListener('change',()=>{remaining=duration(steps()[index]);deadline=Date.now()+remaining;});
 setInterval(()=>{if(!allowed()){if(items.length)clear('Connexion privée requise.');return;}if(expires&&Date.now()>expires){clear('Journal périmé : nouvelle observation requise.');return;}if(!playing||Date.now()<deadline)return;if(index>=steps().length-1){pause();remaining=0;notice.textContent='Fin du déroulé. Le dernier état reste affiché ; aucun succès opérationnel n’est déduit.';return;}index++;showFrame();},200);
 setInterval(refresh,20000);document.addEventListener('visibilitychange',()=>{if(document.hidden)pause();else refresh();});reduced.addEventListener('change',()=>{pause();cancelAnimations();});refresh();return {refresh,clear};
}

const tracePanel=installRealTraces(()=>api('traces'),el('dashboard'),true,()=>Boolean(csrf));
