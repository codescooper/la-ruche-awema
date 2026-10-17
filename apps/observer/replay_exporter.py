"""Operator service: bounded lifecycle metadata, no HTTP-triggered reads."""
import hashlib,json,os,subprocess,time
from pathlib import Path
from replay_schema import validate
OUT=Path('/opt/awema-jury/activity/replays.json')
COMMAND=['docker','exec','--user','10000:10000','awema-ai-team','/opt/hermes/.venv/bin/python','-I','-B','-c',"import sys,json;sys.path.insert(0,'/opt/awema-observe');from replay_reader import collect;print(json.dumps(collect()))"]
def install():
    for name in ('owner_reader.py','owner_schema.py','catalog.py'):
        expected=hashlib.sha256((Path(__file__).parent/name).read_bytes()).hexdigest()
        observed=subprocess.check_output(['docker','exec','--user','10000:10000','awema-ai-team','sha256sum','/opt/awema-observe/'+name],timeout=15).decode().split()[0]
        if expected!=observed:raise RuntimeError('shared reader changed')
    for name in ('replay_schema.py','replay_reader.py'):
        subprocess.run(['docker','cp',str(Path(__file__).parent/name),'awema-ai-team:/opt/awema-observe/'+name],check=True,capture_output=True,timeout=15)
def once():
    p=subprocess.run(COMMAND,check=True,capture_output=True,timeout=15)
    if len(p.stdout)>24000:raise ValueError('size')
    value=validate(json.loads(p.stdout));tmp=OUT.with_suffix('.tmp')
    tmp.write_text(json.dumps(value));os.chmod(tmp,0o644);os.replace(tmp,OUT)
if __name__=='__main__':
    install();failed=0
    while True:
        try:once();failed=0
        except Exception:
            failed+=1
            if failed>=3:raise SystemExit('replay_projection_unavailable')
        time.sleep(20)
