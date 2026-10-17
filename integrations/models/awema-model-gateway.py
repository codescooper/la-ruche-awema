#!/usr/bin/env python3
"""Fixed-provider gateway. No arbitrary URLs, no raw request logging."""
import sys,re,fcntl
import os,json,secrets,hmac,urllib.request,urllib.error,threading,time
from pathlib import Path
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
ROOT=Path('/opt/awema-ops/model-gateway');MAX=2*1024*1024
class BoundedServer(ThreadingHTTPServer):
 def __init__(self,*args):
  super().__init__(*args);self.connections=threading.BoundedSemaphore(16)
 def process_request(self,request,address):
  if not self.connections.acquire(blocking=False):self.shutdown_request(request);return
  try:super().process_request(request,address)
  except Exception:self.connections.release();raise
 def process_request_thread(self,request,address):
  try:super().process_request_thread(request,address)
  finally:self.connections.release()
def record(server,entry):
 if hasattr(server,'opposable'):server.opposable(entry)
 with server.stats_lock:
  with (ROOT/'requests.jsonl').open('a') as f:
   f.write(json.dumps(entry)+'\n');f.flush();os.fsync(f.fileno())
class Handler(BaseHTTPRequestHandler):
 def setup(self):
  super().setup();self.connection.settimeout(10)
  self.deadline=threading.Timer(150,self.abort);self.deadline.daemon=True;self.deadline.start()
 def abort(self):
  try:self.connection.shutdown(2)
  except OSError:pass
 def finish(self):
  self.deadline.cancel();super().finish()
 def log_message(self,*args):pass
 def reply(self,code,value):
  data=json.dumps(value).encode();self.send_response(code);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
 def identity(self):
  a=self.headers.get('Authorization','')
  if not a.startswith('Bearer '):return None
  token=a[7:];tokens=json.loads((ROOT/'tokens.json').read_text()) if getattr(self.server,'dynamic_tokens',False) else self.server.tokens;matches=[n for n,v in tokens.items() if hmac.compare_digest(token,v)]
  return matches[0] if len(matches)==1 else None
 def do_GET(self):
  if not self.identity():return self.reply(401,{'error':'unauthorized'})
  if self.path!='/v1/models':return self.reply(404,{'error':'endpoint denied'})
  self.reply(200,{'object':'list','data':[{'id':'deepseek-flash','object':'model','owned_by':'deepseek'}]})
 def do_POST(self):
  role=self.identity()
  if not role:return self.reply(401,{'error':'unauthorized'})
  if self.path!='/v1/chat/completions':return self.reply(404,{'error':'endpoint denied'})
  try:
   size=int(self.headers.get('Content-Length','0'))
   if size<=0 or size>MAX:return self.reply(413,{'error':'request size denied'})
   self.connection.settimeout(15);raw=self.rfile.read(size)
   if len(raw)!=size:raise ValueError()
   req=json.loads(raw)
   if req.get('model')!='deepseek-flash' or not isinstance(req.get('messages'),list):return self.reply(400,{'error':'model/request denied'})
   allowed={'model','messages','max_tokens','max_completion_tokens','temperature','top_p','stream','stream_options','tools','tool_choice','parallel_tool_calls','stop','response_format','frequency_penalty','presence_penalty','reasoning_effort'}
   if set(req)-allowed:return self.reply(400,{'error':'reserved field denied'})
   for field in ['max_tokens','max_completion_tokens']:
    if field in req and (type(req[field]) is not int or not 1<=req[field]<=8192):return self.reply(400,{'error':'token limit denied'})
   if 'max_tokens' not in req and 'max_completion_tokens' not in req:req['max_tokens']=4096
  except Exception:return self.reply(400,{'error':'invalid request'})
  if not self.server.capacity.acquire(blocking=False):return self.reply(429,{'error':'worker capacity occupied'})
  code=400;started=time.monotonic();operation=secrets.token_hex(16)
  try:
   lease=self.server.authorize_run(role,self.client_address[0],size)
  except Exception:
   self.server.capacity.release();return self.reply(403,{'error':'run authorization or quota denied'})
  try:record(self.server,{'event':'model_request_intent','role':role,'operation':operation,'timestamp':time.time(),'task':lease['task'],'run':lease['run']})
  except Exception:
   self.server.capacity.release();return self.reply(503,{'error':'audit unavailable; provider not called'})
  try:
   payload=json.dumps(req).encode();up=urllib.request.Request('https://api.deepseek.com/v1/chat/completions',data=payload,headers={'Authorization':'Bearer '+self.server.provider_key,'Content-Type':'application/json'})
   with urllib.request.urlopen(up,timeout=120) as r:
    body=r.read(8*1024*1024+1)
    if len(body)>8*1024*1024:raise ValueError('response too large')
    code=r.status
    try:record(self.server,{'event':'model_request_confirmed','role':role,'operation':operation,'status':code,'seconds':round(time.monotonic()-started,3)})
    except Exception:return self.reply(400,{'error':'audit confirmation unavailable','effect_uncertain':True,'retry_allowed':False})
    self.send_response(code);self.send_header('Content-Type',r.headers.get('Content-Type','application/json'));self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
  except urllib.error.HTTPError as e:code=400;self.reply(400,{'error':'provider request failed; no automatic retry','provider_status':e.code,'effect_uncertain':e.code>=500 or e.code==429,'retry_allowed':False})
  except Exception:self.reply(400,{'error':'provider result uncertain','effect_uncertain':True,'retry_allowed':False})
  finally:
   self.server.capacity.release()
   try:record(self.server,{'event':'model_request_finished','role':role,'operation':operation,'status':code})
   except Exception:pass
def authorize_run(role,peer,size):
 with (ROOT/'lease.lock').open('a') as lock:
  fcntl.flock(lock,fcntl.LOCK_EX)
  p=ROOT/'leases'/(role+'.json');lease=json.loads(p.read_text())
  if not isinstance(lease.get('task'),str) or not re.fullmatch(r't_[a-f0-9]{8}',lease['task']) or type(lease.get('run')) is not int or lease['run']<1:raise ValueError('run schema denied')
  if lease.get('peer')!=peer or not time.time()<lease.get('expires',0) or lease.get('calls',0)>=40 or lease.get('bytes',0)+size>8*1024*1024:raise ValueError('lease denied')
  lease['calls']=lease.get('calls',0)+1;lease['bytes']=lease.get('bytes',0)+size
  temporary=p.with_suffix('.tmp');temporary.write_text(json.dumps(lease))
  with temporary.open('r+') as f:f.flush();os.fsync(f.fileno())
  os.replace(temporary,p)
  return lease
def serve():
 os.umask(0o077)
 sys.path.insert(0,'/opt/awema-ai/core/bin')
 import awema_audit_lib as audit
 def opposable(e):
  return audit.emettre('/opt/awema-ai/core',e['event'],tool='awema-model-gateway.py',target='model:deepseek-flash',correlation_id=e['operation'],acteur='model-gateway',token=Path('/etc/awema/v2/tokens/model-gateway.token').read_text(),task=e.get('task'),project='awema-ai-team',detail={k:v for k,v in e.items() if k not in ['event','operation']})
 tokens=json.loads((ROOT/'tokens.json').read_text());provider={}
 for line in Path('/opt/awema-ai/data/provider-secrets/deepseek.env').read_text().splitlines():
  if '=' in line and not line.lstrip().startswith('#'):
   k,v=line.split('=',1);provider[k.strip()]=v.strip().strip('"').strip("'")
 bind=os.environ['AWEMA_MODEL_BIND'];server=BoundedServer((bind,18090),Handler);server.daemon_threads=True;server.tokens=tokens;server.provider_key=provider['DEEPSEEK_API_KEY'];server.capacity=threading.BoundedSemaphore(1);server.stats_lock=threading.Lock();server.authorize_run=authorize_run;server.opposable=opposable;server.dynamic_tokens=True;server.serve_forever()
if __name__=='__main__':serve()
