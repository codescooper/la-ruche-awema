import os,json,struct,socket,socketserver,threading,subprocess,importlib.util,importlib.machinery
from pathlib import Path
from bridge import Bridge,Refused,require
ROOT=Path('/opt/awema-ops/integrations/dev-github')
WORK=Path('/opt/awema-ops/worker-launcher')
SOCKET=WORK/'instructions/dev/github.sock'
def policy():
 p=ROOT/'runtime-policy.json';st=p.stat();require(st.st_uid==0 and not st.st_mode&0o022 and not p.is_symlink(),'policy_trust_invalid');return json.loads(p.read_text())
def api(method,path,data=None):
 env={k:v for k,v in os.environ.items() if k not in ('GH_TOKEN','GITHUB_TOKEN','GH_ENTERPRISE_TOKEN','GITHUB_ENTERPRISE_TOKEN')}
 env['GH_CONFIG_DIR']=str(ROOT/'gh-auth')
 args=['/usr/bin/gh','api','--hostname','github.com','--method',method,path]
 if data is not None:args+=['--input','-']
 r=subprocess.run(args,input=json.dumps(data) if data is not None else None,capture_output=True,text=True,env=env,timeout=25)
 if r.returncode:
  try:status=str(json.loads(r.stdout).get('status',''))
  except Exception:status=''
  raise Refused('github_not_found_or_inaccessible' if status=='404' else 'github_api_refused')
 require(len(r.stdout.encode())<=524288,'github_response_limit');return json.loads(r.stdout)
loader=importlib.machinery.SourceFileLoader('github_native_launcher','/usr/local/lib/awema-worker-launcher/awema-worker-launcher')
spec=importlib.util.spec_from_loader(loader.name,loader);launcher=importlib.util.module_from_spec(spec);loader.exec_module(launcher)
def authorize(peer):
 pid,uid,gid=peer;require(uid==25002,'dev_uid_required')
 cgroup=Path('/proc/'+str(pid)+'/cgroup').read_text()
 for p in (WORK/'states').glob('*.json'):
  state=json.loads(p.read_text())
  if state.get('role')!='dev' or state.get('status')!='running' or state.get('cancel'):continue
  r=subprocess.run(['docker','inspect',state['container']],capture_output=True,text=True,timeout=5)
  if r.returncode:continue
  info=json.loads(r.stdout)[0]
  if not info['State']['Running'] or info['Id'] not in cgroup:continue
  row,grant=launcher.check_claim(state['q'])
  require(row['assignee']=='dev' and grant['role']=='dev','dev_role_required')
  return row['id']
 raise Refused('active_dev_claim_required')
def main():
 require(os.geteuid()==0,'operator_required');os.umask(0o077)
 require(api('GET','user')['login']=='awema-test','github_identity_mismatch')
 engine=Bridge(ROOT/'operations.sqlite',api,authorize,policy)
 budget=threading.BoundedSemaphore(4)
 class Handler(socketserver.BaseRequestHandler):
  def handle(self):
   try:
    self.request.settimeout(10);peer=struct.unpack('3i',self.request.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12));authorize(peer)
    def read(n):
     raw=b''
     while len(raw)<n:
      chunk=self.request.recv(n-len(raw));require(bool(chunk),'transport_eof');raw+=chunk
     return raw
    n=int.from_bytes(read(4),'big');require(0<n<=262144,'request_size_limit')
    result={'ok':True,'result':engine.call(json.loads(read(n)),peer)}
   except Refused as e:result={'ok':False,'error':str(e)}
   except Exception:result={'ok':False,'error':'github_operation_refused'}
   try:
    raw=json.dumps(result).encode();self.request.sendall(len(raw).to_bytes(4,'big')+raw)
   except Exception:pass
 class Server(socketserver.ThreadingUnixStreamServer):
  daemon_threads=True
  def process_request(self,request,address):
   if not budget.acquire(blocking=False):self.shutdown_request(request);return
   try:super().process_request(request,address)
   except BaseException:budget.release();raise
  def process_request_thread(self,request,address):
   try:super().process_request_thread(request,address)
   finally:budget.release()
 if SOCKET.exists():
  with socket.socket(socket.AF_UNIX) as probe:
   try:probe.connect(str(SOCKET))
   except OSError:SOCKET.unlink()
   else:raise Refused('connector_already_running')
 server=Server(str(SOCKET),Handler);os.chown(SOCKET,0,25002);SOCKET.chmod(0o660)
 print('AWEMA Dev GitHub bridge active; credentials operator-only',flush=True)
 try:server.serve_forever()
 finally:server.server_close();SOCKET.unlink(missing_ok=True)
if __name__=='__main__':main()
