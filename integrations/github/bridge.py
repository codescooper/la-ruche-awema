"""Fixed GitHub capabilities. GitHub credentials remain in the operator account."""
import hashlib,json,re,sqlite3,time
from contextlib import contextmanager
class Refused(Exception):pass
def require(ok,why):
 if not ok:raise Refused(why)
def repo_name(value):
 require(isinstance(value,str) and re.fullmatch(r'[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}',value),'repository_invalid')
 require(all(x not in ('.','..') for x in value.split('/')),'repository_invalid');return value
def clean_text(value,limit):
 require(isinstance(value,str) and 0<len(value)<=limit and '\x00' not in value,'text_invalid');return value
def files_valid(files):
 require(isinstance(files,list) and 0<len(files)<=20,'files_invalid');total=0;seen=set()
 for f in files:
  require(type(f) is dict and set(f)=={'path','content'},'file_schema_invalid')
  path=f['path'];require(isinstance(path,str) and re.fullmatch(r'[A-Za-z0-9_./-]{1,180}',path),'file_path_invalid')
  parts=path.lower().split('/');require(not path.startswith('/') and all(x not in ('','..','.') for x in parts) and path not in seen,'file_path_invalid')
  require(not any(x in ('.git','.github','.env','auth.json','hosts.yml') or x.endswith(('.pem','.key','.dpapi')) or x.startswith('.env.') for x in parts),'protected_file_denied')
  body=clean_text(f['content'],100000)
  require(not re.search(r'-----BEGIN .*PRIVATE KEY-----|\b(?:ghp_|github_pat_|sk-|xox[baprs]-)[A-Za-z0-9_]{15,}|\bAKIA[0-9A-Z]{16}\b|\b[0-9]{8,12}:[A-Za-z0-9_-]{25,}\b|\beyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|(?i:(?:api[_-]?key|client[_-]?secret|access[_-]?token|refresh[_-]?token|password|passwd|service[_-]?role[_-]?key)\s*[:=]\s*[\"\']?)[A-Za-z0-9_./+=-]{16,}',body),'credential_content_denied')
  total+=len(body.encode());seen.add(path)
 require(total<=200000,'files_size_limit');return files
SOURCE_SUFFIXES={'.css','.html','.js','.json','.jsx','.md','.mjs','.py','.svg','.toml','.ts','.tsx','.txt','.yml','.yaml'}
def source_path(path):
 try: files_valid([{'path':path,'content':'source path'}])
 except Refused:return False
 parts=path.lower().split('/')
 return path_suffix(path) in SOURCE_SUFFIXES and not any(p in ('.github','.git','node_modules','vendor','dist','build','coverage') for p in parts)
def path_suffix(path):
 return '.'+path.rsplit('.',1)[1].lower() if '.' in path.rsplit('/',1)[-1] else ''
class Bridge:
 def __init__(self,path,api,authorize,policy,now=time.time):
  self.path=path;self.api=api;self.authorize=authorize;self.policy=policy;self.now=now
  with self.db() as c:c.execute('create table if not exists operations(id text primary key,task text,digest text,action text,state text,result text,created real)')
 @contextmanager
 def db(self):
  c=sqlite3.connect(self.path,timeout=10)
  try:
   with c:yield c
  finally:c.close()
 def own(self,repo,scope=True):
  repo=repo_name(repo);require(repo.split('/')[0].lower()=='awema-test','repository_owner_denied')
  if scope:
   require(repo.lower() not in [x.lower() for x in self.policy().get('denied_repositories',[])],'repository_revoked')
   allowed=set(x.lower() for x in self.policy().get('repositories',['awema-test/awema-os']))
   with self.db() as c:
    for row in c.execute("select result from operations where action in ('create_repo','fork_repo') and state='done'"):
     allowed.add(json.loads(row[0])['repository'].lower())
   require(repo.lower() in allowed,'repository_scope_denied')
  return repo
 def call(self,q,peer):
  require(type(q) is dict and len(json.dumps(q).encode())<=262144,'request_invalid')
  require(self.policy()['enabled'] is True,'connection_revoked')
  task=self.authorize(peer)
  op=q.get('op');require(op in ('repo_info','read_file','list_files','read_files','create_repo','fork_repo','propose_pr'),'operation_denied')
  if op in ('repo_info','read_file','list_files','read_files'):
   required={'op','repo'} if op in ('repo_info','list_files') else {'op','repo','path'} if op=='read_file' else {'op','repo','paths'}
   require(set(q)==required,'request_fields_invalid')
   repo=repo_name(q['repo'])
   if op=='repo_info':
    if repo.lower().startswith('awema-test/'):self.own(repo)
    info=self.api('GET','repos/'+repo)
    if not repo.lower().startswith('awema-test/'):require(info.get('private') is False,'private_source_requires_separate_mandate')
    return {k:info.get(k) for k in ('full_name','html_url','private','default_branch','fork')}
   self.own(repo)
   if op=='list_files':
    info=self.api('GET','repos/'+repo);branch=info.get('default_branch');require(isinstance(branch,str) and re.fullmatch(r'[A-Za-z0-9_./-]{1,100}',branch),'base_branch_invalid')
    ref=self.api('GET','repos/'+repo+'/git/ref/heads/'+branch);sha=ref.get('object',{}).get('sha');require(isinstance(sha,str) and re.fullmatch(r'[a-f0-9]{40,64}',sha),'base_commit_invalid')
    commit=self.api('GET','repos/'+repo+'/git/commits/'+sha);tree_sha=commit.get('tree',{}).get('sha');require(isinstance(tree_sha,str) and re.fullmatch(r'[a-f0-9]{40,64}',tree_sha),'repository_tree_unavailable')
    tree=self.api('GET','repos/'+repo+'/git/trees/'+tree_sha+'?recursive=1');entries=tree.get('tree');require(isinstance(entries,list) and tree.get('truncated') is not True,'repository_tree_unavailable')
    files=[{'path':e['path'],'sha':e['sha'],'size':e.get('size',0)} for e in entries if type(e) is dict and e.get('type')=='blob' and isinstance(e.get('path'),str) and source_path(e['path']) and type(e.get('size',0)) is int and 0<=e.get('size',0)<=100000]
    require(len(files)<=20 and sum(x['size'] for x in files)<=200000,'repository_snapshot_limit')
    return {'repository':repo,'branch':branch,'commit':sha,'files':files,'total_bytes':sum(x['size'] for x in files)}
   if op=='read_files':
    paths=q['paths'];require(isinstance(paths,list) and 0<len(paths)<=20 and all(isinstance(x,str) and source_path(x) for x in paths) and len(set(paths))==len(paths),'file_list_invalid')
    import base64
    files=[];total=0
    for path in paths:
     info=self.api('GET','repos/'+repo+'/contents/'+path);require(type(info) is dict and info.get('type')=='file' and info.get('size',100001)<=100000 and info.get('encoding')=='base64','file_read_denied')
     try:body=base64.b64decode(info['content'],validate=True).decode('utf-8')
     except Exception:raise Refused('file_read_denied') from None
     files_valid([{'path':path,'content':body}]);total+=len(body.encode());require(total<=200000,'repository_snapshot_limit');files.append({'path':path,'sha':info['sha'],'content':body})
    return {'repository':repo,'files':files,'total_bytes':total}
   path=q['path'];require(source_path(path),'file_path_invalid')
   import base64
   info=self.api('GET','repos/'+repo+'/contents/'+path);require(type(info) is dict and info.get('type')=='file' and info.get('size',100001)<=100000 and info.get('encoding')=='base64','file_read_denied')
   body=base64.b64decode(info['content']).decode('utf-8');files_valid([{'path':path,'content':body}]);return {'path':path,'sha':info['sha'],'content':body}
  operation=q.get('operation');require(isinstance(operation,str) and re.fullmatch(r'[A-Za-z0-9_-]{16,64}',operation),'operation_id_invalid')
  if op=='create_repo':
   require(set(q)=={'op','operation','name','description'},'request_fields_invalid');self.own('awema-test/'+q['name'],scope=False);clean_text(q['description'],300)
  elif op=='fork_repo':
   require(set(q)=={'op','operation','source'},'request_fields_invalid');repo_name(q['source']);require(not q['source'].lower().startswith('awema-test/'),'already_owned_repository')
  else:
   require(set(q)=={'op','operation','repo','title','body','files'},'request_fields_invalid');self.own(q['repo']);clean_text(q['title'],160);clean_text(q['body'],4000);files_valid(q['files'])
  digest=hashlib.sha256(json.dumps(q,sort_keys=True).encode()).hexdigest();key=task+':'+operation
  with self.db() as c:
   c.execute('BEGIN IMMEDIATE');row=c.execute('select digest,state,result from operations where id=?',(key,)).fetchone()
   if row:
    require(row[0]==digest,'operation_version_changed');require(row[1]=='done','operation_uncertain_no_retry');return json.loads(row[2])
   require(c.execute('select count(*) from operations where task=?',(task,)).fetchone()[0]<4,'task_write_limit')
   require(c.execute('select count(*) from operations where created>?',(self.now()-86400,)).fetchone()[0]<12,'daily_write_limit')
   c.execute('insert into operations values(?,?,?,?,?,?,?)',(key,task,digest,op,'pending',None,self.now()))
  try:
   require(self.authorize(peer)==task and self.policy()['enabled'] is True,'authorization_changed')
   # Persist intent before every external write. An interrupted operation is never retried.
   with self.db() as c:c.execute("update operations set state='sending' where id=?",(key,))
   def write(path,data):
    require(self.authorize(peer)==task and self.policy()['enabled'] is True,'authorization_changed')
    if op=='propose_pr':self.own(q['repo'])
    return self.api('POST',path,data)
   if op=='create_repo':
    info=write('user/repos',{'name':q['name'],'description':q['description'],'private':True,'auto_init':True});result={'repository':info['full_name'],'url':info['html_url'],'private':True}
   elif op=='fork_repo':
    source=self.api('GET','repos/'+q['source']);require(source.get('private') is False,'private_source_requires_separate_mandate')
    info=write('repos/'+q['source']+'/forks',{'default_branch_only':True});require(info['full_name'].lower().startswith('awema-test/'),'fork_account_mismatch');result={'repository':info['full_name'],'url':info['html_url'],'source':q['source']}
   else:
    repo=q['repo'];info=self.api('GET','repos/'+repo);branch='awema/dev-'+hashlib.sha256(key.encode()).hexdigest()[:20];base=info['default_branch']
    require(isinstance(base,str) and re.fullmatch(r'[A-Za-z0-9_./-]+',base),'base_branch_invalid')
    ref=self.api('GET','repos/'+repo+'/git/ref/heads/'+base);sha=ref['object']['sha'];commit=self.api('GET','repos/'+repo+'/git/commits/'+sha)
    tree=write('repos/'+repo+'/git/trees',{'base_tree':commit['tree']['sha'],'tree':[{'path':f['path'],'mode':'100644','type':'blob','content':f['content']} for f in q['files']]})
    new=write('repos/'+repo+'/git/commits',{'message':q['title'],'tree':tree['sha'],'parents':[sha]})
    write('repos/'+repo+'/git/refs',{'ref':'refs/heads/'+branch,'sha':new['sha']})
    target=repo;target_base=base;head=branch
    if info.get('fork'):
     parent=info.get('parent',{});require(parent.get('private') is False,'private_upstream_requires_separate_mandate');target=repo_name(parent['full_name']);target_base=parent['default_branch'];head='awema-test:'+branch
    pr=write('repos/'+target+'/pulls',{'title':q['title'],'body':q['body'],'base':target_base,'head':head,'draft':True});result={'pull_request':pr['html_url'],'number':pr['number'],'repository':repo,'target':target,'branch':branch,'draft':True}
   with self.db() as c:c.execute("update operations set state='done',result=? where id=?",(json.dumps(result),key))
   return result
  except Exception:
   with self.db() as c:c.execute("update operations set state='uncertain' where id=?",(key,))
   raise Refused('operation_uncertain_no_retry') from None
