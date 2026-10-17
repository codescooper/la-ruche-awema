"""Trusted host-only operator: reads bounded state metadata and State.Running only."""
import json,os,re,stat,subprocess,time
from pathlib import Path
from live_catalog import LIVE_ROLES
from worker_schema import validate
from activity_collector import publish
STATES=Path('/opt/awema-ops/worker-launcher/states')
OUT=Path('/opt/awema-jury/activity/workers-v2.json')
NAME=re.compile(r'awema-worker-[a-f0-9]{24}')
def inspect_running(name,timeout):
 if not NAME.fullmatch(name):raise ValueError('fixed worker name required')
 p=subprocess.run(['/usr/bin/docker','inspect','--type','container','--format','{{.State.Running}}',name],capture_output=True,text=True,timeout=timeout,env={'PATH':'/usr/bin:/bin','DOCKER_HOST':'unix:///var/run/docker.sock','DOCKER_CONFIG':'/run/awema-worker-observer'},check=True)
 if len(p.stdout)>32 or p.stdout.strip() not in {'true','false'}:raise ValueError('bounded inspect state')
 return p.stdout.strip()=='true'
def state_metadata(path,clock):
 if not re.fullmatch(r'[a-f0-9]{24}\.json',path.name):raise ValueError('state filename')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 with os.fdopen(fd,'rb') as f:
  st=os.fstat(f.fileno())
  if not stat.S_ISREG(st.st_mode) or st.st_size>131072:raise ValueError('bounded regular state')
  raw=f.read(131073)
  if len(raw)>131072:raise ValueError('bounded state')
 v=json.loads(raw)
 if not isinstance(v,dict) or v.get('role') not in LIVE_ROLES or v.get('operation')!=path.stem or not isinstance(v.get('container'),str) or not NAME.fullmatch(v['container']) or v['container']!='awema-worker-'+path.stem:raise ValueError('state identity')
 started=v.get('started',0)
 if type(started) not in (int,float) or not 0<=started<=clock+5:raise ValueError('state time')
 if v.get('status') not in {'starting','running','finished','failed'}:raise ValueError('state status')
 return v['role'],v['container'],int(started),st.st_mtime
def collect(states=STATES,clock=None,inspect=inspect_running):
 clock=int(time.time()) if clock is None else clock
 rows={r:{'role':r,'worker_running':None,'started':0,'state':'unknown'} for r in sorted(LIVE_ROLES)}
 candidates={};deadline=time.monotonic()+3
 try:
  if states.is_symlink():raise ValueError('state directory symlink')
  # Refuse overload rather than silently pick arbitrary old records.
  paths=[]
  for p in states.iterdir():
   paths.append(p)
   if len(paths)>2048:raise ValueError('state directory bound')
  for p in paths:
   if time.monotonic()>=deadline:raise ValueError('collection deadline')
   try:
    role,name,started,mtime=state_metadata(p,clock)
    if role not in candidates or mtime>candidates[role][2]:candidates[role]=(name,started,mtime)
   except (OSError,ValueError,TypeError,KeyError,UnicodeError):continue
 except (OSError,ValueError):candidates={}
 for role,(name,started,_) in candidates.items():
  remaining=deadline-time.monotonic()
  if remaining<=0:continue
  try:
   running=inspect(name,min(1,remaining))
   if type(running) is not bool:raise ValueError('inspect type')
   rows[role].update(worker_running=running,started=started,state='running' if running else 'finished')
  except Exception:pass
 return validate({'version':1,'observed_at':clock,'roles':list(rows.values())},clock)
if __name__=='__main__':
 os.umask(0o077)
 while True:
  begin=time.monotonic()
  try:publish(collect(),OUT,0o644)
  except Exception:print('worker_projection_unavailable',flush=True)
  time.sleep(max(.1,5-(time.monotonic()-begin)))
