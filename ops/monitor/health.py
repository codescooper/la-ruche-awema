"""Read-only availability and version-bound readiness; no credentials or messages."""
from pathlib import Path
import json,os,subprocess,shutil,sqlite3,time,hashlib,stat,re
from datetime import datetime,timezone
BASE=Path('/opt/awema-ai');VERDICT=Path('/opt/awema-ops/readiness/verdict.json')
CODE={
 '/usr/local/lib/awema-worker-launcher/awema-worker-launcher',
 '/usr/local/lib/awema-model-gateway/awema-model-gateway',
 '/usr/local/sbin/awema-worker-authorize','/usr/local/sbin/awema-worker-dispatch',
 '/usr/local/sbin/awema-ops-broker','/usr/local/sbin/awema-host-approve',
 '/usr/local/lib/awema-broker/awema_broker_lib.py',
 '/usr/local/lib/awema-activity-v2/worker_collector.py',
 '/usr/local/lib/awema-activity-v2/activity_collector.py',
 '/opt/awema-ai/registry/execution-v2.json',
 '/opt/awema-ai/core/bin/awema-native-transition',
 '/opt/awema-ai/backup-ai.py',
}
CODE.update('/etc/systemd/system/'+n+'.service' for n in ['awema-ops-broker','awema-audit-v2','awema-vault-v2','awema-model-gateway','awema-worker-launcher','awema-worker-network','awema-activity-v2','awema-worker-observer-v2'])
CODE.update({'/usr/local/lib/awema-model-gateway/network.py','/usr/local/lib/awema-broker/prepare-socket.py','/usr/local/lib/awema-activity-v2/worker_schema.py','/usr/local/lib/awema-activity-v2/activity_schema.py'})
CODE.update('/usr/local/lib/awema-activity-v2/'+n for n in ['live_catalog.py','team_collector.py','team_schema.py'])
CODE.add('/usr/local/lib/awema-monitor/health.py')
CODE.update('/opt/awema-ai/core/bin/'+n for n in ['awema-action','awema-agent','awema-approve','awema-audit','awema-auditd','awema-ops','awema-secret','awema-task','awema-taskctl','awema-vaultd','awema-worker-bridge','awema_approval_lib.py','awema_approval_lib_base.py','awema_audit_lib.py','awema_secret_lib.py','coordinator-runtime'])
CODE.update('/opt/awema-ai/core/config/'+n for n in ['approval-contract.json','approval-policy.yaml','secret-policy.json','task-contract.yaml','team.yaml','workflow.yaml'])
PROOFS={n:'/opt/awema-ops/readiness/proofs/'+n+'.json' for n in ['native-e2e','broker-integrated','cold-restore','independent-review']}
IMAGES={'awema-ai-team','awema-jury-office','awema-owner-portal','awema-jury-front'}
def image_id(name):
 if name=='worker-runtime':
  wanted=json.loads(root_read('/opt/awema-ops/worker-launcher/runtime.json',65536))['image']
  if not isinstance(wanted,str) or re.fullmatch(r'sha256:[a-f0-9]{64}',wanted) is None:raise ValueError('worker image reference')
  p=subprocess.run(['docker','image','inspect','--format','{{.Id}}',wanted],capture_output=True,text=True,timeout=5)
  if p.returncode or len(p.stdout)>100 or p.stdout.strip()!=wanted:raise ValueError('worker image missing or changed')
  return wanted
 p=subprocess.run(['docker','inspect','--format','{{.Image}}',name],capture_output=True,text=True,timeout=5)
 if p.returncode or len(p.stdout)>100:raise ValueError('image metadata unavailable')
 return p.stdout.strip()
def root_read(path,maxsize):
 path=Path(path)
 if any(p.is_symlink() or p.stat().st_uid!=0 or p.stat().st_mode&0o022 for p in [path,*path.parents]):raise ValueError('protected metadata boundary')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 with os.fdopen(fd,'rb') as f:
  info=os.fstat(f.fileno())
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022 or info.st_size>maxsize:raise ValueError('protected metadata size')
  raw=f.read(maxsize+1)
  if len(raw)>maxsize:raise ValueError('metadata bound')
  return raw

CURRENT_INDEX=Path('/opt/awema-ops/readiness/current-index.json')
CURRENT_SCOPE='awema-internal-native-v2'
CAMPAIGN_ROOT='/opt/awema-ops/readiness/campaigns/'
RPO_SECONDS=RTO_SECONDS=14400
ROLES={'cto','pm','dev','qa','security','ops','designer','assa','cl-producer'}
CURRENT_IMAGES=IMAGES|{'awema-owner-password','awema-preview-sites','awema-finance','awema-ruche-ui','worker-runtime'}
BROKER='/usr/local/lib/awema-worker-launcher/browser_broker.py'
HEALTH='/usr/local/lib/awema-monitor/health.py'
INSTRUCTIONS=Path('/opt/awema-ops/worker-launcher/instructions')
PROOF_ROOT='/opt/awema-ops/readiness/proofs/current/'
BROWSER_ROOT='/opt/awema-ops/worker-launcher/runs/'
CODE.update({
 '/opt/awema-jury/finance/source/awema-handoff-check.py',
 '/opt/awema-jury/finance/source/awema-mission-runner',
 '/opt/awema-jury/finance/source/mission_runner.py',
 '/opt/awema-jury/finance/source/mission_flow.py',
 '/opt/awema-jury/finance/source/mission_preview.py',
 '/opt/awema-jury/finance/source/portal.py',
 '/opt/awema-ops/worker-launcher/runtime.json',
 '/usr/local/lib/awema-backup-policy/backup_coverage.py',
 '/usr/local/lib/awema-backup-policy/retention.py',
 BROKER
})
PROOF_KINDS={'roles','browser','restore_kvm1','restore_pc','independent_review'}

def _must(ok):
 if not ok:raise ValueError('current qualification evidence refused')
def _sha(value):return isinstance(value,str) and re.fullmatch(r'[a-f0-9]{64}',value) is not None
def _hashes(value):return isinstance(value,dict) and bool(value) and all(isinstance(k,str) and _sha(v) for k,v in value.items())
def _canonical(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
def _number(value):return type(value) in (int,float) and value==value and abs(value)!=float('inf')


CAMPAIGN_FIELDS={'schema','qualification_id','campaign_id','campaign_started_epoch','data_checkpoint_epoch','deadline_epoch','rpo_seconds','rto_seconds','targets','base_archives','overlay_ciphertext_sha256','overlay_manifest_sha256','recipe_sha256','installed_sha256','installed_images','qualification_instructions_sha256','qualification_instruction_manifest_sha256','reused_proofs'}

def _validate_campaign(m):
 """Pure validation of the single sealed, public campaign contract; no clocks or I/O."""
 _must(isinstance(m,dict) and set(m)==CAMPAIGN_FIELDS)
 _must(m['schema']=='awema-readiness-campaign-v1')
 qid=m['qualification_id'];_must(isinstance(qid,str) and re.fullmatch(r'awema-ready-[a-z0-9-]{8,80}',qid) is not None and m['campaign_id']==qid)
 started=m['campaign_started_epoch'];deadline=m['deadline_epoch']
 _must(type(started) is int and started>0 and type(deadline) is int and deadline==started+14400)
 checkpoint=m['data_checkpoint_epoch'];_must(type(checkpoint) is int and checkpoint>0 and 0<=started-checkpoint<14400)
 _must(type(m['rpo_seconds']) is int and type(m['rto_seconds']) is int and m['rpo_seconds']==m['rto_seconds']==14400)
 _must(m['targets']==['kvm1','pc'])
 _must(isinstance(m['base_archives'],dict) and set(m['base_archives'])=={'data.age','images.age'} and _hashes(m['base_archives']))
 _must(_sha(m['overlay_ciphertext_sha256']) and _sha(m['overlay_manifest_sha256']))
 _must(isinstance(m['recipe_sha256'],dict) and set(m['recipe_sha256'])=={'restore','hotfix'} and _hashes(m['recipe_sha256']))
 _must(_hashes(m['installed_sha256']) and set(m['installed_sha256'])==CODE)
 images=m['installed_images'];_must(isinstance(images,dict) and set(images)==CURRENT_IMAGES and len(set(images.values()))==9)
 _must(all(isinstance(v,str) and re.fullmatch(r'sha256:[a-f0-9]{64}',v) is not None for v in images.values()))
 instructions=m['qualification_instructions_sha256'];manifests=m['qualification_instruction_manifest_sha256']
 _must(isinstance(instructions,dict) and set(instructions)==ROLES and _hashes(manifests) and set(manifests)==ROLES)
 for files in instructions.values():
  _must(_hashes(files) and 2<=len(files)<=32 and {'ROLE.md','SOUL.md'}<=set(files))
  _must(all(re.fullmatch(r'[A-Za-z0-9_.-]+\.(md|py)',n) is not None and not n.startswith('.') for n in files))
 reused=m['reused_proofs'];_must(isinstance(reused,dict) and set(reused)=={'roles','browser'})
 for kind,entry in reused.items():
  _must(isinstance(entry,dict) and set(entry)==({'sha256','observed_at_utc','operation'} if kind=='browser' else {'sha256','observed_at_utc'}))
  _must(_sha(entry['sha256']) and isinstance(entry['observed_at_utc'],str))
  stamp=datetime.fromisoformat(entry['observed_at_utc'].replace('Z','+00:00'))
  _must(stamp.tzinfo is not None and stamp.utcoffset().total_seconds()==0 and 0<stamp.timestamp()<=started)
  if kind=='browser':_must(isinstance(entry['operation'],str) and re.fullmatch(r'[a-f0-9]{24}',entry['operation']) is not None)
 return m

def validate_campaign(m):
 try:return _validate_campaign(m)
 except Exception:raise ValueError('sealed campaign contract refused') from None

def _unique_pairs(pairs):
 result={}
 for name,value in pairs:
  if name in result:raise ValueError('duplicate campaign JSON key')
  result[name]=value
 return result

def parse_campaign(raw,expected_sha256):
 """Verify exact bytes against the operator pin before pure contract validation."""
 _must(isinstance(raw,bytes) and 0<len(raw)<=131072 and _sha(expected_sha256))
 _must(hashlib.sha256(raw).hexdigest()==expected_sha256)
 return validate_campaign(json.loads(raw.decode('utf-8'),object_pairs_hook=_unique_pairs))

def read_campaign(path,expected_sha256,read=root_read):
 return parse_campaign(read(path,131072),expected_sha256)

def backup_recent(now=None,read=root_read):
 try:
  stamp=read('/opt/awema-ops/ai-backups/last-success.txt',4096).decode('ascii').split()[0]
  epoch=datetime.strptime(stamp,'%Y%m%dT%H%M%SZ').replace(tzinfo=timezone.utc).timestamp()
  age=(time.time() if now is None else now)-epoch
  return 0<=age<RPO_SECONDS
 except Exception:return False

def qualification(path=CURRENT_INDEX,read=root_read,images=image_id,now=None):
 """Require current protected evidence; historical v1 READY never falls through."""
 try:
  clock=time.time() if now is None else now
  v=json.loads(read(path,2*1024*1024))
  _must(v.get('schema')=='awema-readiness-current-v2' and v.get('version')==2 and v.get('verdict')=='READY' and v.get('scope')==CURRENT_SCOPE)
  qid=v.get('qualification_id')
  _must(isinstance(qid,str) and re.fullmatch(r'awema-ready-[a-z0-9-]{8,80}',qid) is not None)
  campaign_ref=v.get('campaign')
  _must(isinstance(campaign_ref,dict) and set(campaign_ref)=={'path','sha256'} and campaign_ref['path']==CAMPAIGN_ROOT+qid+'.json')
  campaign=read_campaign(campaign_ref['path'],campaign_ref['sha256'],read)
  _must(campaign['qualification_id']==qid)
  started=v.get('campaign_started_epoch')
  _must(started==campaign['campaign_started_epoch'] and started<=clock and v.get('rto_seconds')==RTO_SECONDS and v.get('rpo_seconds')==RPO_SECONDS)
  hashes=v.get('installed_sha256')
  _must(_hashes(hashes) and set(hashes)==CODE and hashes==campaign['installed_sha256'])
  for name,wanted in hashes.items():_must(hashlib.sha256(read(name,2*1024*1024)).hexdigest()==wanted)
  pinned=v.get('installed_images')
  _must(isinstance(pinned,dict) and set(pinned)==CURRENT_IMAGES and len(set(pinned.values()))==9)
  _must(all(isinstance(x,str) and re.fullmatch(r'sha256:[a-f0-9]{64}',x) for x in pinned.values()))
  _must(pinned==campaign['installed_images'])
  for name,wanted in pinned.items():_must(images(name)==wanted)
  chain=v.get('restore_chain')
  _must(isinstance(chain,dict) and chain.get('schema')=='awema-base-plus-correction-v1')
  _must(set(chain.get('base_archives',{}))=={'data.age','images.age'} and _hashes(chain['base_archives']) and _sha(chain.get('overlay_ciphertext_sha256')))
  _must(chain['base_archives']==campaign['base_archives'] and chain['overlay_ciphertext_sha256']==campaign['overlay_ciphertext_sha256'])
  overlay=chain.get('overlay_files')
  _must(isinstance(overlay,dict) and set(overlay)=={BROKER,HEALTH})
  for name,item in overlay.items():
   _must(isinstance(item,dict) and set(item)=={'before','after'} and _sha(item['before']) and _sha(item['after']) and item['after']==hashes[name])
  chain_sha=_canonical(chain)
  refs=v.get('proofs')
  _must(isinstance(refs,dict) and set(refs)==PROOF_KINDS)
  proofs={};proof_hashes={}
  for kind,ref in refs.items():
   _must(isinstance(ref,dict) and set(ref)=={'path','sha256'} and _sha(ref['sha256']))
   name=ref['path'];_must(isinstance(name,str))
   if kind=='browser':_must(re.fullmatch(re.escape(BROWSER_ROOT)+r'[a-f0-9]{24}/browser/receipt\.json',name) is not None)
   else:_must(name.startswith(PROOF_ROOT) and re.fullmatch(r'[a-z0-9-]+\.json',name[len(PROOF_ROOT):]) is not None)
   raw=read(name,524288);_must(hashlib.sha256(raw).hexdigest()==ref['sha256']);proofs[kind]=json.loads(raw);proof_hashes[kind]=ref['sha256']
  _must(proof_hashes['roles']==campaign['reused_proofs']['roles']['sha256'] and proof_hashes['browser']==campaign['reused_proofs']['browser']['sha256'])
  _must(refs['browser']['path']==BROWSER_ROOT+campaign['reused_proofs']['browser']['operation']+'/browser/receipt.json')
  roles=proofs['roles']
  _must(roles.get('schema')=='awema-nine-role-qualification-final-v1' and roles.get('nine_real_roles_completed') is True and roles.get('nine_business_roles_accepted') is True)
  rows=roles.get('roles');_must(isinstance(rows,list) and len(rows)==9 and {r.get('role') for r in rows}==ROLES)
  by_role={}
  for row in rows:
   role=row['role'];by_role[role]=row
   _must(row.get('state')=='real_execution_completed' and isinstance(row.get('task'),str) and re.fullmatch(r't_[a-f0-9]{8}',row['task']) is not None)
   _must(row.get('business_acceptance') in ('accepted_for_tested_scope','accepted_for_tested_scope_with_mandatory_finance_review'))
   _must(row.get('runtime_image')==pinned['worker-runtime'])
   expected=row.get('instructions_sha256');_must(_hashes(expected) and 1<=len(expected)<=32 and {'ROLE.md','SOUL.md'}<=set(expected))
   manifest_raw=read(str(INSTRUCTIONS/role/'manifest.json'),65536)
   current=json.loads(manifest_raw);_must(current==expected and expected==campaign['qualification_instructions_sha256'][role])
   _must(hashlib.sha256(manifest_raw).hexdigest()==campaign['qualification_instruction_manifest_sha256'][role])
   for name,wanted in expected.items():
    _must(re.fullmatch(r'[A-Za-z0-9_.-]+\.(md|py)',name) is not None and not name.startswith('.'))
    _must(hashlib.sha256(read(str(INSTRUCTIONS/role/name),262144)).hexdigest()==wanted)
  profile_hashes={r:by_role[r]['instructions_sha256'] for r in ROLES}
  browser=proofs['browser'];qa=by_role['qa'];dev=by_role['dev']
  _must(browser.get('schema')=='awema-worker-browser-v1' and browser.get('status')=='pass' and browser.get('caller_uid')==25003)
  _must(browser.get('executor')=='isolated-browser-tool' and browser.get('engine')=='chromium' and browser.get('network')=='none' and browser.get('image')==pinned['worker-runtime'])
  _must(browser.get('task')==qa['task'] and browser.get('receipt_id')==qa.get('browser_receipt_id'))
  _must(qa.get('artifact_sha256',{}).get('BROWSER.json')==proof_hashes['browser'])
  _must(browser.get('renderer_sha256')==hashes['/opt/awema-jury/finance/source/mission_preview.py'])
  _must(_hashes(browser.get('source_sha256')) and browser['source_sha256']==dev.get('artifact_sha256'))
  browser_checks=browser.get('checks')
  _must(isinstance(browser_checks,list) and len(browser_checks)>=19 and all(isinstance(x,dict) and x.get('pass') is True for x in browser_checks))
  _must('network:no-external-request' in {x.get('name') for x in browser_checks})
  for target in ('kvm1','pc'):
   proof=proofs['restore_'+target]
   _must(proof.get('schema')=='awema-current-restore-attestation-v2' and proof.get('qualification_id')==qid and proof.get('target')==target and proof.get('all_pass') is True)
   _must(proof.get('campaign_started_epoch')==started and proof.get('chain_sha256')==chain_sha and proof.get('campaign_sha256')==campaign_ref['sha256'])
   elapsed=proof.get('elapsed_seconds');_must(_number(elapsed) and 0<elapsed<=RTO_SECONDS)
   ended=proof.get('finished_epoch');_must(_number(ended) and abs(ended-started-elapsed)<=5 and ended<=clock+300)
   _must(proof.get('installed_images')==pinned)
   restored=proof.get('installed_sha256');_must(restored==hashes)
   _must(proof.get('role_instructions_sha256')==profile_hashes and proof.get('instruction_manifest_sha256')==campaign['qualification_instruction_manifest_sha256'])
   _must(all(proof.get(k) is True for k in ('ciphertext_verified','base_restored','overlay_preimages_verified','overlay_final_hashes_verified','unchanged_sources_verified','sqlite_integrity_pass','services_pass','native_lifecycle_pass')))
   _must(proof.get('key_written_to_disk') is False and proof.get('client_production_modified') is False)
   if target=='pc':_must(proof.get('independent_PC_key_used') is True)
  review=proofs['independent_review']
  _must(review.get('schema')=='awema-current-independent-review-v2' and review.get('qualification_id')==qid and review.get('all_pass') is True)
  _must(review.get('campaign_sha256')==campaign_ref['sha256'])
  _must(review.get('installed_sha256')==hashes and review.get('installed_images')==pinned and review.get('chain_sha256')==chain_sha)
  _must(review.get('reviewed_proof_sha256')=={k:x for k,x in proof_hashes.items() if k!='independent_review'})
  _must(isinstance(review.get('accepted_limits'),list) and bool(review['accepted_limits']))
  _must(backup_recent(clock,read))
  return 'READY'
 except Exception:return 'NOT_READY'

def report():
 checks=[]
 def check(name,fn):
  try:ok=bool(fn())
  except Exception:ok=False
  checks.append({'name':name,'ok':ok})
 def active(unit):return subprocess.run(['systemctl','is-active','--quiet',unit+'.service'],capture_output=True,timeout=5).returncode==0
 for unit in ['awema-ops-broker','awema-audit-v2','awema-vault-v2','awema-model-gateway','awema-worker-launcher','awema-worker-network','awema-activity-v2','awema-worker-observer-v2']:
  check(unit+' service',lambda unit=unit:active(unit))
 def docker(template):
  p=subprocess.run(['docker','inspect','--format',template,'awema-ai-team'],capture_output=True,text=True,timeout=10)
  if p.returncode or len(p.stdout)>65536:raise ValueError('Docker metadata unavailable')
  return json.loads(p.stdout)
 def team():
  s=docker('{{json .State}}');return s.get('Running') is True and s.get('Paused') is False
 check('team container',team)
 check('no docker socket mount',lambda:no_docker_socket(docker('{{json .Mounts}}')))
 check('disk free',lambda:shutil.disk_usage('/').free/shutil.disk_usage('/').total>.15)
 def board():
  with sqlite3.connect('file:'+str(BASE/'data/kanban/boards/awema-agency/kanban.db')+'?mode=ro',uri=True,timeout=2) as c:return c.execute('pragma quick_check').fetchone()[0]=='ok'
 check('kanban integrity',board)
 def projection(name):
  path=Path('/opt/awema-jury/activity')/name
  if path.is_symlink() or path.stat().st_size>262144:return False
  return valid_projection(name,json.loads(path.read_bytes()),int(time.time()))
 for name in ['activity-v2.json','workers-v2.json']:check('fresh '+name,lambda name=name:projection(name))
 def backup():return backup_recent()
 check('AI offsite backup recent',backup)
 available=all(c['ok'] for c in checks);ready=qualification()
 return {'timestamp':datetime.now(timezone.utc).isoformat(),'available':available,'readiness':ready if available else 'NOT_READY','checks':checks}
def no_docker_socket(mounts):
 for m in mounts:
  source=str(m.get('Source','')).rstrip('/')
  destination=str(m.get('Destination','')).rstrip('/')
  if destination in {'/run','/var/run','/var/run/docker.sock','/run/docker.sock'} or source in {'','/','/var','/run','/var/run','/var/run/docker.sock','/run/docker.sock'}:return False
 return True
def valid_projection(name,value,clock):
 try:
  import sys
  sys.path.insert(0,'/usr/local/lib/awema-activity-v2')
  if name=='workers-v2.json':from worker_schema import validate
  elif name=='activity-v2.json':from activity_schema import validate
  else:return False
  checked=validate(value,clock)
  return name=='workers-v2.json' or checked['sources']['hermes']=='available' and checked['sources']['kanban'] is True
 except Exception:return False
if __name__=='__main__':print(json.dumps(report(),ensure_ascii=False))
