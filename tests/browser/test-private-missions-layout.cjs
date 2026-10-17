const fs=require('fs'),path=require('path'),assert=require('node:assert/strict');
const {chromium}=require('C:/Users/BEJ technologie/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright');
(async()=>{
 const browser=await chromium.launch({headless:true,executablePath:'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe'});
 const dir=path.resolve('work/ruche-studio');let pageErrors=[];
 const flow=(id,state,objective)=>({id,objective,criteria:'Résultat vérifiable',state,created:Date.now()/1000,updated:Date.now()/1000,steps:[{role:'pm',ordinal:0,state:state==='blocked'?'blocked':'done',task:'Définir les pages',summary:'Plan prêt'}],events:[],artifacts:[],blocker:state==='blocked'?'Le Kanban n’a pas confirmé la tâche.' : ''});
 const flows=[flow('f_review_fixture','review','Livraison du site de présentation'),flow('f_block_fixture','blocked','Mission avec une étape bloquée')];
 async function open(url,viewport){
  const page=await browser.newPage({viewport});page.on('pageerror',e=>pageErrors.push(e.message));
  await page.route('https://ruche-ux.invalid/**',async route=>{
   const u=new URL(route.request().url());
   if(u.pathname.startsWith('/finance/api/')){const op=u.pathname.split('/').pop();let result={};
    if(op==='auth-policy')result={mfa_required:false};
    if(op==='session')result={user:'fixture',name:'TEST',role:'owner',agent:'assistant',csrf:'fixture',totp_enabled:false};
    if(op==='state')result={projects:[],records:[],jobs:[],users:[]};
    if(op==='studio')result={agents:['cto','pm','dev','qa','security','ops','designer','assa','assistant','accounting','finance'],threads:[],messages:[],positions:[],missions:[],flows,mission_capacity:{available:8,limit:10},board:{available:true,active_roles:['pm'],counts:{running:1,blocked:1}}};
    if(op==='studio-board')result={available:true,observed_at:Date.now()/1000,total:1,pages:1,page:0,tasks:[{id:'t_fixture',title:'Définir les pages du site',role:'pm',status:'running'}],active_roles:['pm']};
    return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(result)});
   }
   const name=u.pathname==='/finance'?'index.html':path.basename(u.pathname),file=path.join(dir,name);
   if(!fs.existsSync(file))return route.fulfill({status:404,body:'not found: '+u.pathname});
   const contentType=name.endsWith('.css')?'text/css':name.endsWith('.js')?'text/javascript':name.endsWith('.json')?'application/json':'text/html';
   return route.fulfill({status:200,body:fs.readFileSync(file),contentType});
  });
  await page.goto(url);await page.locator('.studio.chat-only').waitFor();return page;
 }
 const desktop=await open('https://ruche-ux.invalid/finance?vue=missions',{width:1440,height:900});
 const workspace=desktop.locator('.studio-chat'),missions=desktop.locator('.studio-mission-list');
 assert.equal(await desktop.locator('.sidebar').isVisible(),false,'embedded mission view hides duplicate navigation');
 assert.equal(await desktop.locator('.content>.topline').isVisible(),false,'embedded mission view hides redundant page header');
 assert.equal(await desktop.locator('.studio-scene').isVisible(),false,'embedded mission view keeps the outer Ruche as the sole office map');
 assert.equal(await desktop.locator('.studio-toolbar').isVisible(),false,'embedded mission view removes duplicate toolbar');
 assert.equal(await desktop.getByRole('heading',{name:'Résultats et missions'}).isVisible(),true);
 assert.equal(await desktop.getByText('1 livraison(s) attend(ent) votre relecture.').isVisible(),true);
 assert.equal(await desktop.getByRole('button',{name:'Ouvrir les résultats et relire'}).count(),1);
 assert.equal(await desktop.locator('.studio-results-ready').evaluate(e=>getComputedStyle(e).backgroundColor),'rgb(255, 244, 201)','delivery details use a light high-contrast surface');
 assert.equal((await workspace.evaluate(e=>e.getBoundingClientRect().height))>700,true,'mission panel uses full available iframe height');
 assert.equal((await missions.evaluate(e=>getComputedStyle(e).overflowY)),'auto','mission list owns scrolling');
 await desktop.screenshot({path:'outputs/ruche-private-missions-ux-desktop.png',fullPage:true});
 await desktop.close();
 const mobile=await open('https://ruche-ux.invalid/finance?vue=missions',{width:390,height:844});
 assert.equal(await mobile.locator('.sidebar').isVisible(),false);
 assert.equal(await mobile.getByRole('button',{name:'Ouvrir les résultats et relire'}).isVisible(),true);
 const mobileChatWidth=await mobile.locator('.studio-chat').evaluate(e=>e.getBoundingClientRect().width);assert.equal(mobileChatWidth<=390,true,'mobile results fit viewport width, measured '+mobileChatWidth);
 await mobile.screenshot({path:'outputs/ruche-private-missions-ux-mobile.png',fullPage:true});
 await mobile.close();
 const chat=await open('https://ruche-ux.invalid/finance?vue=chat',{width:1280,height:800});
 assert.equal(await chat.locator('.studio-chat').isVisible(),true,'chat-only mode is visible');
 assert.equal(await chat.locator('.studio-scene').isVisible(),false);
 assert.equal(await chat.locator('.studio-chat textarea').isVisible(),true,'chat composer is visible in dock');
 await chat.screenshot({path:'outputs/ruche-private-chat-ux.png',fullPage:true});
 assert.equal(pageErrors.length,0,pageErrors.join('\n'));
 const source=fs.readFileSync(path.join(dir,'private/app.js'),'utf8');
 assert.match(source,/className='office-missions-toggle'/,'private dock has a direct results action');
 assert.match(source,/unlockDock\('missions',true\)/,'persistent navigation returns to mission results even after switching the iframe to chat');
 console.log(JSON.stringify({desktopMissionView:true,mobileMissionView:true,chatOnlyView:true,oneScrollRegion:true,privateResultsShortcut:true,noJavaScriptErrors:true,screenshots:['outputs/ruche-private-missions-ux-desktop.png','outputs/ruche-private-missions-ux-mobile.png','outputs/ruche-private-chat-ux.png']}));
 await browser.close();
})().catch(e=>{console.error(e.stack||e);process.exitCode=1;});
