/* Live worker status merged into each observed agent card. No synthetic activity. */
(()=>{'use strict';
 if(new URLSearchParams(location.search).get('laboratoire')==='1')return;
 const roles=['cto','pm','dev','qa','security','ops','designer','assa','cl-producer'];
 const host=document.querySelector('.activity-panel');if(!host)return;
 const section=document.createElement('section');section.className='worker-observation';
 const title=document.createElement('h3');title.textContent='Processus agents';
 const freshness=document.createElement('p');freshness.setAttribute('role','status');
 section.append(title,freshness);host.append(section);
 let pending=false,expiry;
 function clear(){
  clearTimeout(expiry);
  document.querySelectorAll('.activity-agent[data-role] .worker-signal').forEach(n=>n.remove());
  document.querySelectorAll('.station').forEach(n=>delete n.dataset.workerRunning);
  freshness.textContent='Processus inconnus · observation indisponible ou périmée.';
 }
 async function refresh(){
  if(pending||document.hidden)return;pending=true;
  const abort=new AbortController(),timer=setTimeout(()=>abort.abort(),4000);
  try{
   const response=await fetch('/api/public/workers',{cache:'no-store',credentials:'omit',signal:abort.signal});
   if(!response.ok)throw Error('unavailable');
   const v=await response.json(),now=Date.now()/1000;
   if(v.available!==true||v.version!==1||!Number.isInteger(v.observed_at)||v.observed_at<now-30||v.observed_at>now+5||!Array.isArray(v.roles)||v.roles.length!==9)throw Error('stale');
   const seen=new Set();
   for(const r of v.roles){if(!roles.includes(r.role)||seen.has(r.role)||!['running','finished','unknown'].includes(r.state)||!(r.worker_running===null||typeof r.worker_running==='boolean'))throw Error('row');seen.add(r.role);}
   clear();const running=v.roles.filter(r=>r.worker_running===true).length,unknown=v.roles.filter(r=>r.worker_running===null).length;
   const time=new Date(v.observed_at*1000).toLocaleTimeString('fr-FR',{hour:'2-digit',minute:'2-digit',second:'2-digit'});
   freshness.textContent='Vérifiés à '+time+' · '+running+'/9 processus actifs'+(unknown?' · '+unknown+' état(s) inconnu(s)':'');
   expiry=setTimeout(clear,Math.max(0,v.observed_at*1000+30000-Date.now()));
   for(const r of v.roles){
    const card=document.querySelector('.activity-agent[data-role="'+r.role+'"]');
    const badge=document.createElement('small');badge.className='worker-signal';
    badge.textContent=r.worker_running===true?'Processus actif confirmé':r.worker_running===false?'Processus arrêté':'Processus inconnu';
    if(card)card.append(badge);
    const actor=document.querySelector('.station[data-role="'+r.role+'"]');if(actor)actor.dataset.workerRunning=r.worker_running===null?'unknown':String(r.worker_running);
   }
  }catch{clear();}finally{clearTimeout(timer);pending=false;}
 }
 clear();setInterval(refresh,5000);document.addEventListener('visibilitychange',()=>{if(!document.hidden)refresh();});refresh();
})();
