"""Fixed operator transport: execute metadata reader as container UID, validate output."""
import json,os,subprocess,time
from pathlib import Path
from activity_schema import validate

OUT=Path('/opt/awema-jury/activity/activity.json')
COMMAND=['/usr/bin/docker','exec','--user','10000:10000','--env','AWEMA_ACTIVITY_DATA=/opt/data',
 'awema-ai-team','/opt/hermes/.venv/bin/python','-I','-B','-c',
 "import sys,json;sys.path.insert(0,'/opt/awema-observe');from activity_collector import collect;print(json.dumps(collect()))"]

def install_reader():
 # Fixed, operator-owned code only. /opt is not writable by the agent UID.
 subprocess.run(['/usr/bin/docker','exec','--user','0','awema-ai-team','mkdir','-p','/opt/awema-observe'],check=True,timeout=15,capture_output=True)
 for name in ('activity_collector.py','activity_schema.py','catalog.py'):
  subprocess.run(['/usr/bin/docker','cp',str(Path(__file__).parent/name),'awema-ai-team:/opt/awema-observe/'+name],check=True,timeout=15,capture_output=True)

def once():
 p=subprocess.run(COMMAND,capture_output=True,text=True,timeout=15,check=True)
 if len(p.stdout)>16000:raise ValueError('oversize observation')
 value=validate(json.loads(p.stdout))
 temp=OUT.with_suffix('.tmp');temp.write_text(json.dumps(value,separators=(',',':')));os.chmod(temp,0o644);os.replace(temp,OUT)

def run():
 install_reader(); failures=0
 while True:
  try:once(); failures=0
  except Exception:
   failures+=1
   print('activity_projection_unavailable',flush=True)
   # A recreated container loses the operator-owned reader. Restart the service
   # after three failures so startup reinstalls it, with systemd rate limiting.
   if failures>=3:raise RuntimeError('activity_reader_restart_required') from None
  time.sleep(20)

if __name__=='__main__':run()
