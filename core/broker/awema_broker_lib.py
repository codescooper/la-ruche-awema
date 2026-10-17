import fcntl,json,os,time,hashlib,hmac,stat,re,secrets
from pathlib import Path
from contextlib import contextmanager
def canonical(d):return json.dumps(d,sort_keys=True,separators=(',',':')).encode()
def digest(d):return hashlib.sha256(canonical(d)).hexdigest()
def secure_bytes(path,limit=1048576):
 path=Path(path)
 for p in [path,*path.parents]:
  s=p.lstat()
  if stat.S_ISLNK(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022:raise PermissionError('root trust boundary')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 with os.fdopen(fd,'rb') as f:
  s=os.fstat(f.fileno())
  if not stat.S_ISREG(s.st_mode) or s.st_size>limit:raise PermissionError('bounded regular input')
  b=f.read(limit+1)
  if len(b)>limit:raise PermissionError('bounded input')
  return b
def atomic(path,data):
 path=Path(path);temp=path.with_name(path.name+'.'+secrets.token_hex(12)+'.tmp')
 fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
 os.replace(temp,path);fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(fd)
 finally:os.close(fd)
@contextmanager
def lock(path,nonblock=False):
 fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'r+') as f:
  st=os.fstat(f.fileno())
  if st.st_uid!=0 or st.st_mode&0o077 or not stat.S_ISREG(st.st_mode):raise PermissionError('private lock')
  fcntl.flock(f,fcntl.LOCK_EX|(fcntl.LOCK_NB if nonblock else 0));yield
class ApprovalStore:
 def __init__(self,root):self.root=Path(root)
 def _sig(self,d):
  path=self.root.parent/'signing.key'
  if path.lstat().st_mode&0o077:raise PermissionError('private signing key')
  key=secure_bytes(path,4096).strip()
  if len(key)<32:raise PermissionError('signing boundary')
  return hmac.new(key,canonical({k:v for k,v in d.items() if k!='sig'}),hashlib.sha256).hexdigest()
 def _p(self,aid):
  if not isinstance(aid,str) or not re.fullmatch(r'HOSTAPR-[A-Za-z0-9-]{1,80}',aid):raise ValueError('approval id')
  return self.root/(aid+'.json')
 def _write(self,p,d):
  d=dict(d);d['sig']=self._sig(d);atomic(p,canonical(d))
 def create(self,d):
  p=self._p(d['id'])
  with lock(p.with_suffix('.lock')):
   if p.exists():raise PermissionError('existing approval')
   self._write(p,d)
 def reserve(self,aid,action,task,project,verb,artifact_digest):
  p=self._p(aid)
  with lock(p.with_suffix('.lock')):
   d=json.loads(secure_bytes(p,16384))
   if not hmac.compare_digest(str(d.get('sig','')),self._sig(d)):raise PermissionError('signature')
   for k,v in [('action',action),('task',task),('project',project),('verb',verb),('artifact_digest',artifact_digest)]:
    if d.get(k)!=v:raise PermissionError('approval binding')
   if d.get('status')!='approved' or d.get('reserved_at') or d.get('consumed_at'):raise PermissionError('used approval')
   expiry=d.get('expires_at_epoch')
   if type(expiry) not in (int,float) or not time.time()<expiry<=time.time()+3605:raise PermissionError('expired approval')
   d.update(status='reserved',reserved_at=time.time(),consumed_at=time.time());self._write(p,d);return d
 def finish(self,aid,success,error=''):
  p=self._p(aid)
  with lock(p.with_suffix('.lock')):
   d=json.loads(secure_bytes(p,16384))
   if not hmac.compare_digest(str(d.get('sig','')),self._sig(d)) or d.get('status')!='reserved':raise PermissionError('reservation')
   d.update(status='consumed' if success else 'failed',finished_at=time.time());self._write(p,d)
def snapshot(root,target,template):
 if not isinstance(target,str) or not re.fullmatch('[a-f0-9]{64}',target):raise PermissionError('snapshot digest')
 folder=Path(root)/'releases'/target
 manifest=json.loads(secure_bytes(folder/'manifest.json',32768));compose_bytes=secure_bytes(folder/'compose.json');compose=json.loads(compose_bytes)
 if set(manifest)!={'version','project','compose_sha256','template_sha256','images'} or manifest['version']!=3 or manifest['project']!='awema-jury' or digest(manifest)!=target:raise PermissionError('manifest binding')
 template_bytes=secure_bytes(template);allowed=json.loads(template_bytes)
 if manifest['compose_sha256']!=hashlib.sha256(compose_bytes).hexdigest() or manifest['template_sha256']!=hashlib.sha256(template_bytes).hexdigest():raise PermissionError('snapshot mutation')
 if set(compose.get('services',{}))!={'office','owner'} or set(manifest['images'])!={'office','owner'} or compose.get('name')!='awema-jury':raise PermissionError('service scope')
 normalized=json.loads(json.dumps(compose));expected=json.loads(json.dumps(allowed))
 for name in ['office','owner']:
  image=manifest['images'][name]
  if not isinstance(image,str) or not re.fullmatch(r'sha256:[a-f0-9]{64}',image) or compose['services'][name].get('image')!=image or 'build' in compose['services'][name]:raise PermissionError('immutable image')
  normalized['services'][name]['image']='PINNED';expected['services'][name]['image']='PINNED'
 if normalized!=expected:raise PermissionError('template capability change')
 return compose_bytes,manifest
