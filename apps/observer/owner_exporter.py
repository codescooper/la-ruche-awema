"""Fixed operator transport for owner metadata, separate from public projection."""
import json, os, subprocess, time
from pathlib import Path
from owner_schema import validate, MAX_BYTES

OUT = Path('/opt/awema-jury/owner-data/activity.json')
COMMAND = ['/usr/bin/docker','exec','--user','10000:10000','awema-ai-team',
 '/opt/hermes/.venv/bin/python','-I','-B','-c',
 "import sys,json;sys.path.insert(0,'/opt/awema-observe');from owner_reader import collect;print(json.dumps(collect()))"]

def install():
    subprocess.run(['/usr/bin/docker','exec','--user','0','awema-ai-team','mkdir','-p','/opt/awema-observe'],check=True,timeout=15,capture_output=True)
    for name in ('owner_reader.py','owner_schema.py'):
        subprocess.run(['/usr/bin/docker','cp',str(Path(__file__).parent/name),'awema-ai-team:/opt/awema-observe/'+name],check=True,timeout=15,capture_output=True)
        subprocess.run(['/usr/bin/docker','exec','--user','0','awema-ai-team','chmod','0444','/opt/awema-observe/'+name],check=True,timeout=15,capture_output=True)

def once():
    p=subprocess.run(COMMAND,capture_output=True,text=True,timeout=15,check=True)
    if len(p.stdout.encode())>MAX_BYTES:raise ValueError('oversize')
    value=validate(json.loads(p.stdout))
    temp=OUT.with_suffix('.tmp')
    temp.write_text(json.dumps(value,separators=(',',':')),encoding='utf-8')
    os.chmod(temp,0o640)
    if temp.stat().st_gid!=10001:raise RuntimeError('owner_projection_group')
    os.replace(temp,OUT)

if __name__=='__main__':
    install();failures=0
    while True:
        try:once();failures=0
        except Exception:
            failures+=1
            print('owner_projection_unavailable',flush=True)
            if failures>=3:raise SystemExit(1)
        time.sleep(20)
