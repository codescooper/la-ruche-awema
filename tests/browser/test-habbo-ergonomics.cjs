const http=require('http'),fs=require('fs'),path=require('path');
const {chromium}=require('C:/Users/BEJ technologie/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright');
const root=path.resolve('work/ruche-studio'),now=Math.floor(Date.now()/1000);
const mime={'.html':'text/html','.js':'text/javascript','.css':'text/css','.json':'application/json','.png':'image/png'};
const server=http.createServer((req,res)=>{const u=new URL(req.url,'http://localhost');let file;
 if(u.pathname==='/ruche/world.json')file=path.join(root,'world.json');
 else if(u.pathname==='/api/public/activity'||u.pathname==='/api/public/workers'){res.writeHead(503);return res.end('{}');}
 else if(u.pathname==='/private/api/session')return json({csrf:'fixture',expires:now+3600});
 else if(u.pathname==='/private/api/activity'||u.pathname==='/private/api/traces'||u.pathname==='/private/api/team')return json({available:false,observed_at:now,tasks:[],traces:[]});
 else if(u.pathname==='/finance'||u.pathname==='/finance/')file=path.join(root,'index.html');
 else if(u.pathname==='/ruche/awema-logo.png')file=path.join(root,'public','awema-logo.png');
 else if(u.pathname.startsWith('/private/'))file=path.join(root,'private',path.basename(u.pathname));
 else if(u.pathname==='/private'||u.pathname==='/private/')file=path.join(root,'private','index.html');
 else if(u.pathname==='/ruche/style.css')file=path.join(root,'public','style.css');
 else if(u.pathname==='/ruche/app.js')file=path.join(root,'public','app.js');
 else if(u.pathname==='/ruche/world.json')file=path.join(root,'world.json');
 else if(u.pathname.startsWith('/ruche/'))file=path.join(root,'public',path.basename(u.pathname));
 else if(u.pathname==='/')file=path.join(root,'public','index.html');
 else if(u.pathname==='/studio.js')file=path.join(root,'studio.js');
 else if(u.pathname==='/studio.css')file=path.join(root,'studio.css');
 else if(u.pathname==='/office-renderer.js')file=path.join(root,'office-renderer.js');
 else if(u.pathname==='/office-interactions-v2.js')file=path.join(root,'office-interactions-v2.js');
 if(!file||!fs.existsSync(file)){res.writeHead(404);return res.end();}res.writeHead(200,{'Content-Type':mime[path.extname(file)]||'application/octet-stream','Cache-Control':'no-store'});fs.createReadStream(file).pipe(res);
 function json(v){res.writeHead(200,{'Content-Type':'application/json'});res.end(JSON.stringify(v));}
});
server.listen(18767,'127.0.0.1',async()=>{const browser=await chromium.launch({headless:true,executablePath:'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe'});const report={checks:{},errors:[]};
 try{for(const [label,url] of [['public','http://127.0.0.1:18767/'],['private','http://127.0.0.1:18767/private']]){const page=await browser.newPage({viewport:{width:1365,height:850}});page.on('pageerror',e=>report.errors.push(label+': '+e.message));await page.goto(url);await page.locator('.office-conversation').waitFor();await page.locator('#actors [data-role="dev"]').waitFor();if(label==='private')await page.waitForFunction(()=>document.body.classList.contains('office-unified')&&!document.body.classList.contains('locked'));
 report.checks[label+'HabboActors']=await page.locator('#actors .agent-hit').count()===9;
 report.checks[label+'NoHeaderOverlap']=await page.evaluate(()=>document.querySelector('.topbar').getBoundingClientRect().bottom<=document.querySelector('#workspace').getBoundingClientRect().top+1);
 await page.locator('#fullscreen-button').click();report.checks[label+'FullscreenControl']=await page.evaluate(()=>document.fullscreenElement===document.documentElement);if(await page.evaluate(()=>Boolean(document.fullscreenElement)))await page.evaluate(()=>document.exitFullscreen());
 report.checks[label+'FullscreenStage']=await page.evaluate(()=>{const w=document.querySelector('.world-viewport').getBoundingClientRect(),s=document.querySelector('#workspace').getBoundingClientRect();return w.width>s.width*.95&&w.height>s.height*.88;});
 await page.screenshot({path:path.join(root,'tmp','habbo-'+label+'-desktop-closed.png')});
 const beforeWheel=await page.locator('#camera').getAttribute('transform');await page.locator('#viewport').hover({position:{x:500,y:400}});await page.mouse.wheel(0,-120);const afterWheel=await page.locator('#camera').getAttribute('transform');report.checks[label+'CursorWheelZoom']=beforeWheel!==afterWheel;
 const beforePan=afterWheel;await page.mouse.move(500,400);await page.mouse.down({button:'right'});await page.mouse.move(552,432,{steps:3});await page.mouse.up({button:'right'});const afterPan=await page.locator('#camera').getAttribute('transform');report.checks[label+'BlenderRightDrag']=beforePan!==afterPan;
 const toggle=page.getByRole('button',{name:'Ouvrir le chat'});await toggle.click();report.checks[label+'RetractableChat']=await page.locator('#office-chat-dock').evaluate(n=>n.classList.contains('is-open'))&&await page.locator('.office-chat-toggle').getAttribute('aria-expanded')==='true';
 if(label==='public'){await page.locator('.office-chat-toggle').click();const sprite=page.locator('#actors [data-role="dev"] .actor-sprite');report.checks.publicIdleMotion=await sprite.evaluate(n=>getComputedStyle(n).animationName==='awema-idle');await page.getByRole('button',{name:'Pause animations'}).click();report.checks.publicAnimationPause=await page.locator('body').evaluate(n=>n.classList.contains('animations-paused'));await page.locator('#actors [data-role="dev"]').evaluate(n=>n.dispatchEvent(new MouseEvent('click',{bubbles:true})));report.checks.publicAgentSelectable=await page.locator('#actors [data-role="dev"]').evaluate(n=>n.classList.contains('office-selected'));const beforeMove=await page.locator('#actors [data-role="dev"]').getAttribute('transform');const target=await page.evaluate(()=>{const world=document.querySelector('#world'),camera=document.querySelector('#camera');for(let y=0;y<6;y++)for(let x=8;x<17;x++){const p=world.createSVGPoint();p.x=800+(x-y)*29;p.y=100+(x+y+1)*14.5;const q=p.matrixTransform(camera.getScreenCTM()),hit=document.elementFromPoint(q.x,q.y);if(hit?.closest('#rooms')&&!hit.closest('[data-role]'))return{x:q.x,y:q.y,cell:[x,y]};}return null;});report.targetCell=target?.cell||null;if(target){await page.evaluate(({x,y})=>document.elementFromPoint(x,y).dispatchEvent(new MouseEvent('click',{bubbles:true,clientX:x,clientY:y})),target);await page.waitForTimeout(900);}report.walkHint=await page.locator('.office-conversation').innerText();report.hintSpans=await page.locator('.office-conversation span').allInnerTexts();report.afterMove=await page.locator('#actors [data-role="dev"]').getAttribute('transform');report.beforeMove=beforeMove;report.checks.publicAgentWalk=Boolean(target)&&beforeMove!==report.afterMove;}
 if(label==='private'){await page.waitForFunction(()=>{const n=document.querySelector('.office-chat-frame');return n&&getComputedStyle(n).display!=='none'&&n.getBoundingClientRect().height>100;});report.checks.privateChatLoaded=await page.locator('.office-chat-frame').isVisible();}
 await page.locator('.office-chat-toggle').click();await page.setViewportSize({width:390,height:844});await page.waitForTimeout(260);report.checks[label+'MobileNoPageScroll']=await page.evaluate(()=>document.documentElement.scrollHeight===innerHeight&&document.documentElement.scrollWidth===innerWidth);
 await page.screenshot({path:path.join(root,'tmp','habbo-'+label+'-390.png')});await page.close();}
 report.all_pass=Object.values(report.checks).every(Boolean)&&report.errors.length===0;fs.writeFileSync(path.resolve('outputs/RUCHE-HABBO-ERGONOMIE-TESTS.json'),JSON.stringify(report,null,2));console.log(JSON.stringify(report));if(!report.all_pass)process.exitCode=1;
 }catch(e){report.errors.push(e.stack||e.message);report.all_pass=false;fs.writeFileSync(path.resolve('outputs/RUCHE-HABBO-ERGONOMIE-TESTS.json'),JSON.stringify(report,null,2));console.error(JSON.stringify(report));process.exitCode=1;}finally{await browser.close();server.close();}});
