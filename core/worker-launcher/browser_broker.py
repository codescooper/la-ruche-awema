"""Operator-side browser capability. No model-selected URL, path or Docker action."""
from pathlib import Path
import web_build_receipt
import base64,hashlib,json,os,re,secrets,socket,struct,subprocess,threading,time
import web_project
MAX_REPLY=1024*1024
MAX_BROWSER_INPUT=2*web_project.MAX_BUNDLE_BYTES+4*1024*1024+65536
SOCKET_NAME='browser.sock'
EXPECTED_CSP="sandbox allow-scripts; default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; media-src data:; font-src data:; connect-src 'none'; frame-src 'none'; object-src 'none'; form-action 'none'; base-uri 'none'; frame-ancestors 'self' https://web.telegram.org"

def sha(raw):return hashlib.sha256(raw).hexdigest()
def read_regular(path,limit=1024*1024):
 if path.is_symlink() or not path.is_file() or not 1<=path.stat().st_size<=limit:raise ValueError('invalid_regular_file')
 return path.read_bytes()
def interaction_valid(value):
 return isinstance(value,dict) and set(value) in ({'selector','expect_text'},{'selector','expect_fragment'}) and all(isinstance(value[k],str) and 1<=len(value[k])<=256 and '\x00' not in value[k] for k in value) and ('expect_fragment' not in value or bool(re.fullmatch(r'#[A-Za-z0-9_-]{1,128}',value['expect_fragment'])))
def source_bundle(inputs):
 files={};legacy_bytes=0
 for path in inputs.iterdir():
  name=path.name
  if not name.startswith('dev-'):continue
  name=name[4:]
  if name.endswith(('.html.txt','.css.txt','.js.txt','.mjs.txt','.svg.txt')):name=name[:-4]
  if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}',name):raise ValueError('source_name_denied')
  if Path(name).suffix.lower() not in {'.html','.css','.js','.mjs','.svg','.md','.json','.txt'}:continue
  if name in files:raise ValueError('source_name_duplicate')
  limit=web_project.MAX_BUNDLE_BYTES if name==web_project.ARTIFACT_NAME else 1024*1024
  raw=read_regular(path,limit)
  files[name]={'content':raw.decode('utf-8'),'sha256':sha(raw)}
  if name!=web_project.ARTIFACT_NAME:legacy_bytes+=len(raw)
 if len(files)>12 or legacy_bytes>4*1024*1024:raise ValueError('website_bundle_missing')
 if web_project.ARTIFACT_NAME in files:
  item=files[web_project.ARTIFACT_NAME]
  web_project.render_project(web_project.load_project(item['content'],item['sha256']))
 elif not {'index.html','styles.css','app.js'}<=set(files):raise ValueError('website_bundle_missing')
 return files

def qa_runtime_budget(launcher):
 limits=getattr(launcher,'worker_limits',None)
 if limits is None:return 300
 value=limits.role_budget('qa').get('seconds')
 if type(value) is not int or not 60<=value<=3600:raise ValueError('qa_budget_unavailable')
 return value

def find_context(launcher,task,pid,uid):
 if uid!=25003:raise ValueError('qa_uid_required')
 if not re.fullmatch(r't_[a-f0-9]{8}',str(task)):raise ValueError('invalid_task')
 states=[]
 for p in (launcher.ROOT/'states').glob('*.json'):
  s=json.loads(p.read_text())
  if s.get('task')==task and s.get('role')=='qa' and s.get('status')=='running':states.append(s)
 if len(states)!=1:raise ValueError('active_qa_run_required')
 state=states[0]
 if state.get('cancel') or state.get('effect_uncertain') or time.time()-state.get('started',0)>qa_runtime_budget(launcher):raise ValueError('run_revoked')
 launcher.check_claim(state['q'])
 lease=json.loads((launcher.MODEL/'leases'/'qa.json').read_text())
 if lease.get('run')!=state['run'] or lease.get('task')!=task or lease.get('expires',0)<=time.time():raise ValueError('lease_revoked')
 info=json.loads(subprocess.check_output(['docker','inspect',state['container']],timeout=10))[0]
 if not info['State']['Running'] or info['Config']['User']!='25003:25003':raise ValueError('worker_identity_mismatch')
 cgroup=Path('/proc/'+str(pid)+'/cgroup').read_text()
 if info['Id'] not in cgroup:raise ValueError('caller_container_mismatch')
 return state

def still_active(launcher,state):
 actual=json.loads((launcher.ROOT/'states'/(state['operation']+'.json')).read_text())
 if actual.get('status')!='running' or actual.get('cancel') or actual.get('run')!=state['run']:raise ValueError('run_revoked')
 launcher.check_claim(state['q'])
 lease=json.loads((launcher.MODEL/'leases'/'qa.json').read_text())
 if lease.get('run')!=state['run'] or lease.get('expires',0)<=time.time():raise ValueError('lease_revoked')

def validate_report(report,files,renderer_digest,renderer_dependencies=None):
 if not isinstance(report,dict) or report.get('schema')!='awema-worker-browser-v1' or report.get('status') not in ('pass','fail'):raise ValueError('browser_report_schema')
 if report.get('csp')!=EXPECTED_CSP:raise ValueError('browser_csp_mismatch')
 if report.get('engine')!='chromium' or report.get('executor')!='isolated-browser-tool' or not report.get('engine_version'):raise ValueError('browser_engine_missing')
 if report.get('source_sha256')!={k:v['sha256'] for k,v in files.items()} or report.get('renderer_sha256')!=renderer_digest:raise ValueError('browser_source_mismatch')
 if renderer_dependencies is not None and report.get('renderer_dependencies_sha256')!=renderer_dependencies:raise ValueError('browser_renderer_dependency_mismatch')
 if web_project.ARTIFACT_NAME in files:
  item=files[web_project.ARTIFACT_NAME];project=web_project.load_project(item['content'],item['sha256']);rendered=web_project.render_project(project)
  if report.get('web_project')!=web_project.project_metadata(project,rendered) or report.get('preview_sha256')!=sha(rendered):raise ValueError('browser_project_mismatch')
 checks=report.get('checks')
 if not isinstance(checks,list) or not checks or not all(isinstance(c,dict) and type(c.get('pass')) is bool for c in checks):raise ValueError('browser_checks_missing')
 required={v+':'+c for v in ('desktop','mobile') for c in ('http','content','title','heading','no-horizontal-overflow','keyboard-focus','control-visible','interaction-result','no-browser-errors')}|{'network:no-external-request'}
 if not required<=set(c.get('name') for c in checks):raise ValueError('browser_checks_incomplete')
 if report['status']=='pass' and not all(c['pass'] for c in checks):raise ValueError('browser_false_pass')
 screenshots=report.get('screenshots',[])
 if len(screenshots)!=2 or {x.get('name') for x in screenshots}!={'BROWSER-DESKTOP.png','BROWSER-MOBILE.png'}:raise ValueError('browser_screenshots_missing')
 for shot in screenshots:
  raw=base64.b64decode(shot['base64'],validate=True)
  if not raw.startswith(b'\x89PNG\r\n\x1a\n') or sha(raw)!=shot['sha256'] or len(raw)!=shot['bytes'] or len(raw)>400000:raise ValueError('browser_screenshot_invalid')

def check_handoff(root,folder,output,role,result):
 if role!='qa' or not any((folder/'inputs'/name).is_file() for name in ('dev-index.html.txt','dev-WEB_PROJECT.json')):return None
 source=folder/'browser'/'receipt.json'
 report=json.loads(read_regular(source))
 state=json.loads(read_regular(root/'states'/(folder.name+'.json')))
 if report.get('task')!=state['task'] or report.get('run')!=state['run']:raise ValueError('browser_receipt_stale')
 files=source_bundle(folder/'inputs')
 if report.get('operation')!=folder.name or report.get('source_sha256')!={k:v['sha256'] for k,v in files.items()}:raise ValueError('browser_receipt_stale')
 artifact=read_regular(output/'BROWSER.json')
 if sha(artifact)!=sha(json.dumps(report,ensure_ascii=False,sort_keys=True).encode()):raise ValueError('browser_receipt_forged')
 review=json.loads(read_regular(output/'REVIEW.json',65536))
 if isinstance(review.get('verdict'),str) and review['verdict'].strip().casefold()=='pass' and report.get('status')!='pass':raise ValueError('browser_negative_verdict')
 if 'BROWSER.json' not in result.get('artifacts',[]):raise ValueError('browser_artifact_missing')
 return {'receipt_id':report['receipt_id'],'sha256':sha(artifact),'source_sha256':report['source_sha256'],'renderer_sha256':report['renderer_sha256'],'status':report['status']}

def handle(launcher,request,pid,uid):
 if not isinstance(request,dict) or set(request)!={'op','task','interaction'} or request.get('op')!='check-site' or not interaction_valid(request['interaction']):raise ValueError('request_denied')
 state=find_context(launcher,request['task'],pid,uid)
 folder=launcher.ROOT/'runs'/state['operation'];inputs=folder/'inputs';files=source_bundle(inputs)
 # Inputs were copied and hashed by launcher before worker start. Rebind each one now.
 authorization=json.loads((launcher.ROOT/'tasks'/(state['task']+'.json')).read_text())
 for source in authorization.get('inputs',[]):
  if Path(source['name']).name!=source['name'] or source['name'].startswith('.'):raise ValueError('input_path_denied')
  path=inputs/source['name']
  limit=web_project.MAX_BUNDLE_BYTES if source['name']=='dev-WEB_PROJECT.json' else 1024*1024
  if sha(read_regular(path,limit))!=source['sha256']:raise ValueError('input_version_changed')
 browser=folder/'browser';browser.mkdir(mode=0o700,exist_ok=True)
 count_path=browser/'count.json';count=json.loads(count_path.read_text()) if count_path.exists() else 0
 if type(count) is not int or count>=3:raise ValueError('browser_quota_reached')
 count_path.write_text(json.dumps(count+1));count_path.chmod(0o600)
 attempt=browser/('attempt-'+str(count+1));attempt.mkdir(mode=0o700)
 bundle=attempt/'bundle';bundle.mkdir(mode=0o755);bundle.chmod(0o755)
 raw_bundle=json.dumps({'files':files,'interaction':request['interaction']},ensure_ascii=False).encode('utf-8')
 if len(raw_bundle)>MAX_BROWSER_INPUT:raise ValueError('browser_input_too_large')
 (bundle/'bundle.json').write_bytes(raw_bundle);(bundle/'bundle.json').chmod(0o444)
 output=attempt/'output';output.mkdir(mode=0o700);os.chown(output,25003,25003)
 image=json.loads((launcher.ROOT/'runtime.json').read_text())['image'];name='awema-browser-'+state['operation']+'-'+str(count+1)
 expected_renderer=sha(read_regular(Path('/opt/awema-jury/finance/source/mission_preview.py')))
 expected_dependencies={'mission_preview.py':expected_renderer,'web_project.py':sha(read_regular(Path('/opt/awema-jury/finance/source/web_project.py')))}
 command=['docker','run','--rm','--name',name,'--network','none','--user','25003:25003','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','1536m','--cpus','2','--pids-limit','256','--shm-size','128m','--tmpfs','/tmp:rw,nosuid,nodev,size=128m','--mount','type=bind,src='+str(bundle)+',dst=/bundle,readonly','--mount','type=bind,src='+str(output)+',dst=/results','--entrypoint','/opt/awema-browser/venv/bin/python',image,'/opt/awema-browser/check-site.py','/bundle/bundle.json','/results']
 for filename in ('check-site.py','mission_preview.py','web_project.py'):
  command[2:2]=['--mount','type=bind,src='+str(web_build_receipt.TOOLKIT/filename)+',dst=/opt/awema-browser/'+filename+',readonly']
 process=None
 try:
  with (attempt/'execution.log').open('wb') as log:
   process=subprocess.Popen(command,stdout=log,stderr=log);started=time.monotonic()
   while process.poll() is None:
    if time.monotonic()-started>75:raise ValueError('browser_timeout')
    still_active(launcher,state);time.sleep(.5)
  if process.returncode not in (0,1):raise ValueError('browser_process_failed')
  if not (output/'report.json').is_file():raise ValueError('browser_engine_report_missing: inspect operator execution log for this run')
  report=json.loads(read_regular(output/'report.json'))
  validate_report(report,files,expected_renderer,expected_dependencies);still_active(launcher,state)
  report.update(receipt_id=secrets.token_hex(16),task=state['task'],run=state['run'],operation=state['operation'],checked_at_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),network='none',image=image,caller_uid=uid)
  raw=json.dumps(report,ensure_ascii=False,sort_keys=True).encode()
  if len(raw)>MAX_REPLY-2048:raise ValueError('browser_report_too_large')
  receipt=browser/'receipt.json';tmp=browser/'receipt.tmp';tmp.write_bytes(raw);tmp.chmod(0o600);os.replace(tmp,receipt)
  launcher.audit('worker_browser_checked',state['task'],state['run'],{'status':report['status'],'receipt_id':report['receipt_id'],'source_sha256':report['source_sha256'],'checks':len(report['checks'])})
  return {'ok':True,'report':report}
 finally:
  subprocess.run(['docker','rm','-f',name],capture_output=True,timeout=15)
  if process is not None:
   try:process.wait(timeout=10)
   except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)

def serve(launcher):
 path=launcher.ROOT/SOCKET_NAME
 if path.exists():path.unlink()
 sock=socket.socket(socket.AF_UNIX);sock.bind(str(path));os.chown(path,0,25003);path.chmod(0o660);sock.listen(2)
 while True:
  conn,_=sock.accept();conn.settimeout(5)
  try:
   pid,uid,gid=struct.unpack('3i',conn.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12));raw=b'';deadline=time.monotonic()+5
   while b'\n' not in raw:
    if time.monotonic()>=deadline:raise ValueError('request_timeout')
    conn.settimeout(max(.01,deadline-time.monotonic()))
    chunk=conn.recv(1024)
    if not chunk:break
    raw+=chunk
    if len(raw)>2048:raise ValueError('request_too_large')
   reply=handle(launcher,json.loads(raw.splitlines()[0]),pid,uid)
  except Exception as exc:reply={'ok':False,'reason':str(exc)[:120]}
  try:conn.sendall((json.dumps(reply,ensure_ascii=False)+'\n').encode())
  except OSError:pass
  conn.close()
