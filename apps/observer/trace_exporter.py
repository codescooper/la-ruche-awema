"""Fixed root operator transport; separate public and private projection files."""
import json
import hashlib
import os
import subprocess
import time
from pathlib import Path
from trace_schema import MAX_BYTES, validate, public_projection

PUBLIC=Path('/opt/awema-jury/activity/traces.json')
PRIVATE=Path('/opt/awema-jury/owner-data/traces.json')
COMMAND=['/usr/bin/docker','exec','--user','10000:10000','awema-ai-team',
 '/opt/hermes/.venv/bin/python','-I','-B','-c',
 "import sys,json;sys.path.insert(0,'/opt/awema-observe');from trace_reader import collect;print(json.dumps(collect(),separators=(',',':')))"]


def install():
    subprocess.run(['/usr/bin/docker','exec','--user','0','awema-ai-team','mkdir','-p','/opt/awema-observe'],check=True,timeout=15,capture_output=True)
    for name in ('owner_reader.py','owner_schema.py','replay_schema.py','catalog.py'):
        expected=hashlib.sha256((Path(__file__).parent/name).read_bytes()).hexdigest()
        observed=subprocess.check_output(['/usr/bin/docker','exec','--user','10000:10000',
            'awema-ai-team','sha256sum','/opt/awema-observe/'+name],timeout=15).decode().split()[0]
        if observed!=expected:raise RuntimeError('shared_reader_changed')
    names=['trace_reader.py','trace_schema.py']
    if (Path(__file__).parent/'trace_story.py').is_file():names.append('trace_story.py')
    for name in names:
        subprocess.run(['/usr/bin/docker','cp',str(Path(__file__).parent/name),'awema-ai-team:/opt/awema-observe/'+name],check=True,timeout=15,capture_output=True)
        subprocess.run(['/usr/bin/docker','exec','--user','0','awema-ai-team','chmod','0444','/opt/awema-observe/'+name],check=True,timeout=15,capture_output=True)


def write(path,value,mode):
    temporary=path.with_suffix('.tmp')
    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,mode)
    with os.fdopen(fd,'w',encoding='utf-8') as stream:
        os.fchmod(stream.fileno(),mode)
        if os.fstat(stream.fileno()).st_gid!=10001:raise RuntimeError('projection_group')
        json.dump(value,stream,separators=(',',':'));stream.flush();os.fsync(stream.fileno())
    os.replace(temporary,path)


def once():
    result=subprocess.run(COMMAND,capture_output=True,text=True,timeout=30,check=True)
    if len(result.stdout.encode())>2*MAX_BYTES:raise ValueError('oversize')
    value=json.loads(result.stdout)
    if type(value) is not dict or set(value)!={'public','private'}:raise ValueError('schema')
    private=validate(value['private'],private=True)
    public=public_projection(private)
    if public!=validate(value['public']):raise ValueError('projection_mismatch')
    # Public is ALWAYS reconstructed from the closed allowlist, never copied raw.
    write(PRIVATE,private,0o640);write(PUBLIC,public,0o644)


if __name__=='__main__':
    install();failures=0
    while True:
        try:once();failures=0
        except Exception:
            failures+=1;print('trace_projection_unavailable',flush=True)
            if failures>=3:raise SystemExit(1)
        time.sleep(20)
