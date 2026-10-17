"""Operator-owned narrow bridge. No request-supplied command, path, container or model."""
import json, os, subprocess, tempfile, time, urllib.request, urllib.error
from pathlib import Path
from unix_http import request
BASE=Path('/opt/awema-jury')
CONFIG=json.loads((BASE/'private.json').read_text())
COMMAND=['docker','exec','-i','awema-ai-team','timeout','--signal=TERM','--kill-after=5s','100','/opt/hermes/.venv/bin/python','/tmp/awema-jury-model-entry.py']

def api(payload):
    code,data,_=request('/internal',payload,headers={'Content-Type':'application/json','Authorization':'Bearer '+CONFIG['internal_token']})
    if code!=200:raise urllib.error.HTTPError('local-socket',code,'request_failed',{},None)
    return data

def budget():
    p=BASE/'broker-budget.json';day=time.strftime('%Y-%m-%d',time.gmtime())
    v=json.loads(p.read_text()) if p.exists() else {}
    if v.get('day')!=day:v={'day':day,'used':0}
    if v['used']>=40:return False
    v['used']+=1
    temp=p.with_suffix('.tmp');temp.write_text(json.dumps(v));os.chmod(temp,0o600);os.replace(temp,p)
    return True

def once():
    if (BASE/'PAUSE').exists():return
    job=api({'action':'claim'}).get('job')
    if not job:return
    # Reject any extra envelope. Authentication is never supplied by the app.
    if set(job)!={'id','claim','message','role','history'}:return
    if not isinstance(job['id'],str) or len(job['id'])!=32 or not isinstance(job['claim'],str) or len(job['claim'])>64:return
    finish={'action':'finish','id':job['id'],'claim':job['claim'],'failed':True}
    payload={k:job[k] for k in ('message','role','history')}
    raw=json.dumps(payload,ensure_ascii=False)
    if len(raw)>20000 or not budget():api(finish);return
    # stdout is bounded by the fixed child, errors discarded rather than shown to visitors.
    output_file=tempfile.TemporaryFile(dir=BASE)
    proc=subprocess.Popen(COMMAND,stdin=subprocess.PIPE,stdout=output_file,stderr=subprocess.DEVNULL,text=True)
    proc.stdin.write(raw);proc.stdin.close();proc.stdin=None
    start=time.monotonic();cancelled=False
    while proc.poll() is None and time.monotonic()-start<110:
        time.sleep(2)
        try:api({'action':'check','id':job['id'],'claim':job['claim']})
        except urllib.error.HTTPError as e:
            if e.code==409:cancelled=True;break
        if (BASE/'PAUSE').exists():cancelled=True;break
    # A cancellation prevents publication immediately; child has a fixed hard 100s cap.
    if proc.poll() is None:
        # Exact immutable match: only this bridge's model process, never the gateway.
        subprocess.run(['docker','exec','awema-ai-team','pkill','-TERM','-f','^/opt/hermes/.venv/bin/python /tmp/awema-jury-model-entry.py$'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
        proc.terminate()
        try:proc.wait(timeout=5)
        except subprocess.TimeoutExpired:proc.kill();proc.wait()
    output_file.seek(0)
    output=output_file.read(100001).decode('utf-8',errors='replace')
    output_file.close()
    if len(output)>100000:return
    if cancelled:return
    if proc.returncode==0:
        try:
            result=json.loads(output)
            if result.get('ok') and isinstance(result.get('plan'),dict):finish.update(failed=False,plan=result['plan'])
        except (ValueError,TypeError):pass
    try:api(finish)
    except urllib.error.HTTPError as e:
        if e.code!=409:raise
    print(json.dumps({'event':'mission_finished','ok':not finish['failed']}),flush=True)

if __name__=='__main__':
    while True:
        try:once()
        except Exception:print('{"event":"broker_wait"}',flush=True)
        time.sleep(2)
