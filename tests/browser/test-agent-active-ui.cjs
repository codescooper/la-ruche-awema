const fs=require('fs'),path=require('path'),assert=require('node:assert/strict');
const {chromium}=require('C:/Users/BEJ technologie/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright');
(async()=>{
 const browser=await chromium.launch({headless:true,executablePath:'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe'});
 const page=await browser.newPage({viewport:{width:1440,height:900}}),errors=[];page.on('pageerror',e=>errors.push(e.message));
 const dir=path.resolve(__dirname),roleNames=['pm','dev','qa','security','cto'],flow={id:'f_active_fixture',objective:'Préparer le site de présentation de la Ruche',state:'running',created:Date.now()/1000,updated:Date.now()/1000,steps:roleNames.map((role,ordinal)=>({role,ordinal,state:role==='pm'?'dispatching':'waiting',task:role==='pm'?'Définir les pages du site':'',summary:''})),events:[],artifacts:[]};
 await page.route('https://ruche-active.invalid/**',async route=>{
  const url=new URL(route.request().url());
  if(url.pathname.startsWith('/finance/api/')){
   const op=url.pathname.split('/').pop();let result={};
   if(op==='session')result={user:'fixture',name:'TEST INTERFACE',role:'owner',agent:'assistant',csrf:'fixture',totp_enabled:false};
   if(op==='state')result={projects:[],records:[],jobs:[],users:[]};
   if(op==='studio')result={agents:['cto','pm','dev','qa','security','ops','designer','assa','cl-producer','assistant','accounting','finance'],threads:[],messages:[],positions:[],missions:[],flows:[flow],board:{available:true,active_roles:['pm'],counts:{running:1,blocked:0}}};
   if(op==='studio-board')result={available:true,observed_at:Date.now()/1000,total:1,pages:1,page:0,tasks:[{id:'t_fixture',title:'Définir les pages du site',role:'pm',status:'running'}],active_roles:['pm']};
   return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(result)});
  }
  const name=url.pathname==='/finance'?'index.html':path.basename(url.pathname),file=path.join(dir,name);
  if(!fs.existsSync(file))return route.fulfill({status:404,body:'not found'});
  return route.fulfill({status:200,body:fs.readFileSync(file),contentType:name.endsWith('.css')?'text/css':name.endsWith('.js')?'text/javascript':name.endsWith('.json')?'application/json':'text/html'});
 });
 await page.goto('https://ruche-active.invalid/finance');
 const active=page.locator('.agent-hit.working[data-role="pm"]');await active.waitFor();
 assert.equal(await active.getAttribute('style'),'--agent-accent:#35c8d0');
 assert.equal(await active.locator('.agent-state').textContent(),'Mission en cours');
 await page.locator('.office-bubble').waitFor();
 assert.match(await page.locator('.office-bubble').textContent(),/Travail en cours/);
 assert.equal(errors.length,0,errors.join('\n'));
 const css=await page.evaluate(async()=>{const r=await fetch('/finance/studio.css');return {status:r.status,text:await r.text()};});assert.equal(css.status,200);assert.match(css.text,/\.studio-task-row\.is-agent-working/);
 console.log(JSON.stringify({workingAgentColor:true,missionStateLabel:true,liveTaskBubble:true,cssDelivered:true,noJavascriptErrors:true}));
 await browser.close();
})().catch(e=>{console.error(e.stack||e);process.exitCode=1;});

