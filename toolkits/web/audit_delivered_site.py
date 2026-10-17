"""Independent operator browser audit of one immutable delivered web package."""
import hashlib,http.server,json,sys,threading,time
from pathlib import Path
sys.path.insert(0,'/web-toolkit');import web_project,mission_preview
from playwright.sync_api import sync_playwright
ART=Path('/input/WEB_PROJECT.json');OUT=Path('/results');OUT.mkdir(exist_ok=True)
raw=ART.read_bytes();project=web_project.load_project(raw);html=web_project.render_project(project);checks=[];facts=[]
def check(name,value,detail=None):checks.append({'name':name,'pass':bool(value),'detail':detail})
class Handler(http.server.BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def do_GET(self):
  if self.path!='/':self.send_error(404);return
  self.send_response(200);self.send_header('Content-Type','text/html; charset=utf-8');self.send_header('Content-Security-Policy',mission_preview.INLINE_SCRIPT_CSP);self.end_headers();self.wfile.write(html)
server=http.server.HTTPServer(('127.0.0.1',0),Handler);threading.Thread(target=server.serve_forever,daemon=True).start();origin='http://127.0.0.1:'+str(server.server_port)
try:
 with sync_playwright()as pw:
  browser=pw.chromium.launch(headless=True,chromium_sandbox=False,args=['--disable-dev-shm-usage','--disable-background-networking','--use-angle=swiftshader','--enable-unsafe-swiftshader'])
  for label,width,height,reduced,fallback in [('desktop',1440,900,False,False),('mobile',390,844,False,False),('small-phone',320,700,False,False),('compact-phone',360,780,False,False),('reduced-motion',1440,900,True,False),('no-webgl',390,844,False,True)]:
   context=browser.new_context(viewport={'width':width,'height':height},locale='fr-FR',reduced_motion='reduce'if reduced else'no-preference');page=context.new_page();errors=[];external=[]
   context.route('**/*',lambda r:r.continue_()if r.request.url==origin+'/'else(external.append(r.request.url.split('?')[0]),r.abort())[-1])
   context.add_init_script("window.__OPERATOR_AUDIT__={draws:0,webglAttempts:0};for(const type of ['WebGLRenderingContext','WebGL2RenderingContext']){const p=window[type]?.prototype;if(p)for(const name of ['drawArrays','drawElements','drawArraysInstanced','drawElementsInstanced']){const original=p[name];if(original)p[name]=function(...a){window.__OPERATOR_AUDIT__.draws++;return original.apply(this,a)}}}")
   if fallback:context.add_init_script("const get=HTMLCanvasElement.prototype.getContext;HTMLCanvasElement.prototype.getContext=function(t,...a){if(/^webgl/.test(t)){window.__OPERATOR_AUDIT__.webglAttempts++;return null}return get.call(this,t,...a)}")
   page.on('pageerror',lambda e:errors.append(str(e)))
   page.goto(origin+'/',wait_until='networkidle');page.wait_for_timeout(1400)
   check(label+':readable-content',len(page.locator('body').inner_text().strip())>=300)
   check(label+':no-horizontal-overflow',page.evaluate('document.documentElement.scrollWidth<=innerWidth+2'))
   small_targets=page.evaluate("[...document.querySelectorAll('header a, footer a, main button')].map(e=>{const r=e.getBoundingClientRect();return {text:e.textContent.trim().slice(0,70),width:r.width,height:r.height}}).filter(r=>r.width>0&&r.height>0&&(r.width<43.5||r.height<43.5))")
   check(label+':touch-targets-at-least-44px',not small_targets,small_targets)
   initial=page.evaluate('({...window.__OPERATOR_AUDIT__})');page.wait_for_timeout(1000);later=page.evaluate('({...window.__OPERATOR_AUDIT__})')
   if reduced:check('reduced-motion:canvas-rendering-settled',initial['draws']==later['draws'],{'before':initial['draws'],'after':later['draws']})
   if fallback:
    check('no-webgl:context-forced-unavailable',later['webglAttempts']>0,later)
    check('no-webgl:svg-alternative-visible',page.locator('figure svg:visible, .HeroScene svg:visible, .hero-scene svg:visible').count()>0)
   elif not reduced:check(label+':actual-webgl-draw',later['draws']>0,later)
   # Let on-entry reveals run before judging their screenshot; no injected page styling.
   total=page.evaluate('document.documentElement.scrollHeight')
   for y in range(0,min(total,24000),600):page.evaluate('(y)=>scrollTo({top:y,left:0,behavior:"instant"})',y);page.wait_for_timeout(70)
   page.evaluate('scrollTo({top:0,left:0,behavior:"instant"})');page.wait_for_timeout(650)
   button=page.locator('#bouton-demo');before=page.get_by_text('Démonstration réussie',exact=True).count();button.focus();page.keyboard.press('Enter');page.wait_for_timeout(600)
   status=page.get_by_text('Démonstration réussie',exact=True);check(label+':demo-keyboard',status.count()==1 and status.is_visible(),{'nodes_before':before})
   # Native details/summary and button/aria-expanded are both supported.
   summaries=page.locator('details summary')
   faq=page.locator('button[aria-expanded][aria-controls]')
   if summaries.count():
    item=summaries.first;item.focus();page.keyboard.press('Enter');check(label+':faq-keyboard',item.evaluate('(el)=>el.parentElement.open'))
   elif faq.count():
    item=faq.first;old=item.get_attribute('aria-expanded');item.focus();page.keyboard.press('Enter');page.wait_for_timeout(300);check(label+':faq-keyboard',item.get_attribute('aria-expanded')!=old)
   else:check(label+':faq-keyboard',False,'No accessible FAQ control found')
   page.evaluate('scrollTo({top:0,left:0,behavior:"instant"})');page.wait_for_timeout(200)
   png=page.screenshot(full_page=False);(OUT/(label+'.png')).write_bytes(png)
   if label in ('desktop','mobile'):(OUT/(label+'-full.png')).write_bytes(page.screenshot(full_page=True))
   check(label+':no-javascript-errors',not errors,errors[:5]);check(label+':no-external-request',not external,external[:5])
   facts.append({'context':label,'viewport':{'width':width,'height':height},'reduced_motion':reduced,'forced_webgl_unavailable':fallback,'draw_counters':later,'title':page.title(),'screenshot_sha256':hashlib.sha256(png).hexdigest()})
   context.close()
  browser.close()
finally:server.shutdown();server.server_close()
report={'schema':'awema-operator-advanced-site-audit-v1','artifact_sha256':hashlib.sha256(raw).hexdigest(),'source_sha256':project.source_sha256,'dist_sha256':project.dist_sha256,'renderer_sha256':web_project.renderer_identity(mission_preview.__file__),'all_pass':all(c['pass']for c in checks),'checks':checks,'facts':facts,'limitations':['Independent operator audit, separate from QA native receipt.','Chromium uses software SwiftShader; no hardware FPS or all-device performance certification.','Motion check observes settled canvas draws for one second, not all animation mechanisms.','Artistic quality requires inspection of actual screenshots.'],'epoch':time.time()}
(OUT/'REPORT.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n');print(json.dumps({'all_pass':report['all_pass'],'checks':len(checks),'failed':[c for c in checks if not c['pass']]}));raise SystemExit(0 if report['all_pass']else 1)
