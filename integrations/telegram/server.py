import os,sys,json,socket,struct,socketserver,threading,time,subprocess,urllib.request
from pathlib import Path
F=Path('/opt/awema-jury/finance');R=Path('/opt/awema-jury/telegram-direct');T=R/'transport'
sys.path.insert(0,str(F/'source'))
from engine import Engine
from portal import Denied

def bot_config():
 # Operator-only credential consumption. No value enters a model, log, or reply.
 info=json.loads(subprocess.check_output(['docker','inspect','awema-ai-team']))[0]
 values={}
 for entry in info['Config']['Env']:
  name,_,value=entry.partition('=')
  if name in ('TELEGRAM_BOT_TOKEN','TELEGRAM_ALLOWED_USERS') and value:values[name]=value
 for path in [Path('/opt/awema-ai/data/profiles/cto/.env'),Path('/opt/awema-ai/data/.env')]:
  if path.is_file():
   for line in path.read_text().splitlines():
    name,_,value=line.partition('=')
    if name.strip() in ('TELEGRAM_BOT_TOKEN','TELEGRAM_ALLOWED_USERS') and name.strip() not in values:values[name.strip()]=value.strip().strip('"').strip("'")
 assert values.get('TELEGRAM_BOT_TOKEN') and values.get('TELEGRAM_ALLOWED_USERS'),'operator_bot_configuration_unavailable'
 return values['TELEGRAM_BOT_TOKEN'],{v.strip() for v in values['TELEGRAM_ALLOWED_USERS'].split(',') if v.strip()}

def main():
 assert os.geteuid()==0;os.umask(0o077);key,native_ids=bot_config();engine=Engine(F/'data/finance.sqlite',key,native_ids=native_ids)
 def send(chat,body):
  req=urllib.request.Request('https://api.telegram.org/bot'+key+'/sendMessage',data=json.dumps({'chat_id':chat,'text':body,'link_preview_options':{'is_disabled':True}}).encode(),headers={'Content-Type':'application/json'})
  try:
   with urllib.request.urlopen(req,timeout=10) as response:answer=json.loads(response.read(32768))
   assert answer.get('ok') is True
  except Exception:raise RuntimeError('telegram_send_uncertain') from None
 def mirror():
  p=T/'links.json';tmp=T/('links.'+str(os.getpid())+'.tmp');value=engine.mirror();
  with engine.store.connect() as c:owner=c.execute("select generation from users where id='owner' and role='owner' and active=1").fetchone()
  value['personal_router']=True;value['personal_owners']=[{'telegram_id':next(iter(native_ids)),'user':'owner','generation':owner['generation']}] if owner and len(native_ids)==1 and '*' not in native_ids else [];tmp.write_text(json.dumps(value));tmp.chmod(0o444);os.replace(tmp,p)
 class Handler(socketserver.BaseRequestHandler):
  def handle(self):
   try:
    _,uid,_=struct.unpack('3i',self.request.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12));assert uid in (0,10000)
    self.request.settimeout(3)
    def read(n):
     raw=b''
     while len(raw)<n:
      more=self.request.recv(n-len(raw));assert more;raw+=more
     return raw
    size=int.from_bytes(read(4),'big');assert 0<size<=32768
    envelope=json.loads(read(size));payload=envelope.get('payload',{});
    if payload.get('user')=='owner':
     from personal_transport import forward
     result=forward(envelope,key,native_ids)
    else:result=engine.receive(envelope)
   except Denied as exc:result={'handled':True,'accepted':False,'reason':exc.reason}
   except Exception:result={'handled':True,'accepted':False,'reason':'invalid_transport'}
   try:self.request.sendall(json.dumps(result).encode())
   except Exception:pass
 class Server(socketserver.ThreadingUnixStreamServer):
  daemon_threads=True
  budget=threading.BoundedSemaphore(8)
  def process_request(self,request,address):
   if not self.budget.acquire(blocking=False):self.shutdown_request(request);return
   try:super().process_request(request,address)
   except BaseException:self.budget.release();raise
  def process_request_thread(self,request,address):
   try:super().process_request_thread(request,address)
   finally:self.budget.release()
 T.mkdir(parents=True,exist_ok=True);T.chmod(0o755);mirror();path=T/'bridge.sock'
 if path.exists():
  assert path.is_socket() and path.stat().st_uid==0
  with socket.socket(socket.AF_UNIX) as probe:
   try:probe.connect(str(path))
   except ConnectionRefusedError:path.unlink()
   else:raise RuntimeError('bridge_already_active')
 server=Server(str(path),Handler);os.chown(path,0,10000);path.chmod(0o660)
 def tick():
  while True:
   try:mirror();engine.collect();engine.deliver(send)
   except Exception:print(json.dumps({'bridge_tick':'failed','utc':time.time()}),flush=True)
   time.sleep(2)
 threading.Thread(target=tick,daemon=True).start();print(json.dumps({'bridge':'active','utc':time.time()}),flush=True);server.serve_forever()

if __name__=='__main__':main()
