import tempfile,unittest,base64
from pathlib import Path
from bridge import Bridge,Refused,files_valid
class Tests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.calls=[];self.enabled=True;self.active=True;self.fail=False;self.denied=[]
  def api(method,path,data=None):
   self.calls.append((method,path,data))
   if self.fail:raise TimeoutError()
   if method=='GET' and '/git/trees/' in path:return {'tree':[{'path':'README.md','sha':'a'*40,'size':7,'type':'blob'},{'path':'.env','sha':'b'*40,'size':4,'type':'blob'},{'path':'assets/image.png','sha':'c'*40,'size':9,'type':'blob'}],'truncated':False}
   if method=='GET' and '/contents/' in path:
    body=b'Fixture';return {'type':'file','size':len(body),'encoding':'base64','content':base64.b64encode(body).decode(),'sha':'a'*40}
   if path=='user/repos':return {'full_name':'awema-test/new','html_url':'https://github.com/awema-test/new'}
   if path.endswith('/forks'):return {'full_name':'awema-test/source','html_url':'https://github.com/awema-test/source'}
   if path.endswith('/pulls'):return {'html_url':'https://github.com/awema-test/new/pull/1','number':1}
   if '/git/ref/' in path:return {'object':{'sha':'a'*40}}
   if method=='GET' and '/git/commits/' in path:return {'tree':{'sha':'d'*40}}
   if '/git/' in path:return {'sha':'new'}
   return {'full_name':path[6:],'private':False,'default_branch':'main','fork':False,'html_url':'https://github.com/'+path[6:]}
  def authorize(peer):
   if peer!=25002 or not self.active:raise Refused('active_dev_claim_required')
   return 't_01234567'
  self.b=Bridge(Path(self.tmp.name)/'ops.sqlite',api,authorize,lambda:{'enabled':self.enabled,'repositories':['awema-test/new'],'denied_repositories':self.denied})
 def tearDown(self):self.tmp.cleanup()
 def create(self,operation='create-fixture-0001'):return {'op':'create_repo','operation':operation,'name':'new','description':'Private fixture'}
 def propose(self):return {'op':'propose_pr','operation':'propose-fixture-001','repo':'awema-test/new','title':'Fixture improvement','body':'Tests executed in fixture','files':[{'path':'README.md','content':'Fixture'}]}
 def test_create_private(self):
  self.b.call(self.create(),25002);self.assertTrue(self.calls[0][2]['private'])
 def test_duplicate_no_second_effect(self):
  first=self.b.call(self.create(),25002);self.assertEqual(first,self.b.call(self.create(),25002));self.assertEqual(len(self.calls),1)
 def test_changed_operation_refused(self):
  self.b.call(self.create(),25002);q=self.create();q['name']='other'
  with self.assertRaises(Refused):self.b.call(q,25002)
  self.assertEqual(len(self.calls),1)
 def test_timeout_never_retried(self):
  self.fail=True
  for _ in range(2):
   with self.assertRaises(Refused):self.b.call(self.create(),25002)
  self.assertEqual(len(self.calls),1)
 def test_revoked_connection(self):
  self.enabled=False
  with self.assertRaises(Refused):self.b.call(self.create(),25002)
  self.assertFalse(self.calls)
 def test_non_dev_and_expired_claim(self):
  for peer in (0,10000,25003):
   with self.assertRaises(Refused):self.b.call(self.create(),peer)
  self.active=False
  with self.assertRaises(Refused):self.b.call(self.create(),25002)
  self.assertFalse(self.calls)
 def test_merge_delete_admin_denied(self):
  for op in ('merge','delete_repo','set_secret','force_push','add_member'):
   with self.assertRaises(Refused):self.b.call({'op':op},25002)
  self.assertFalse(self.calls)
 def test_repo_owner_boundary(self):
  with self.assertRaises(Refused):self.b.call({'op':'read_file','repo':'client/private','path':'README.md'},25002)
  self.assertFalse(self.calls)
 def test_public_source_metadata_for_fork(self):
  self.assertFalse(self.b.call({'op':'repo_info','repo':'public/source'},25002)['private'])
 def test_list_files_filters_secrets_and_binaries(self):
  result=self.b.call({'op':'list_files','repo':'awema-test/new'},25002)
  self.assertEqual([f['path'] for f in result['files']],['README.md'])
  self.assertEqual(result['commit'],'a'*40)
  self.assertTrue(any(call[1]=='repos/awema-test/new/git/trees/'+('d'*40)+'?recursive=1' for call in self.calls))
 def test_read_files_bounds_and_returns_utf8_snapshot(self):
  result=self.b.call({'op':'read_files','repo':'awema-test/new','paths':['README.md']},25002)
  self.assertEqual(result['files'][0]['content'],'Fixture')
  self.assertEqual(result['total_bytes'],7)
 def test_read_files_rejects_protected_or_duplicate_paths_before_api(self):
  before=len(self.calls)
  for paths in (['.env'],['.github/workflows/a.yml'],['README.md','README.md']):
   with self.assertRaises(Refused):self.b.call({'op':'read_files','repo':'awema-test/new','paths':paths},25002)
  self.assertEqual(len(self.calls),before)
 def test_existing_unassigned_own_repository_denied(self):
  with self.assertRaises(Refused):self.b.call({'op':'repo_info','repo':'awema-test/private-client'},25002)
  self.assertFalse(self.calls)
 def test_new_repository_becomes_authorized(self):
  self.b.call(self.create(),25002);self.assertEqual(self.b.call({'op':'repo_info','repo':'awema-test/new'},25002)['full_name'],'awema-test/new')
 def test_fork_public(self):
  result=self.b.call({'op':'fork_repo','operation':'fork-fixture-00001','source':'public/source'},25002);self.assertEqual(result['repository'],'awema-test/source')
 def test_private_fork_denied(self):
  self.b.api=lambda *args,**kw:{'private':True}
  with self.assertRaises(Refused):self.b.call({'op':'fork_repo','operation':'fork-fixture-00001','source':'client/source'},25002)
 def test_proposal_only_feature_branch_and_draft(self):
  self.b.call(self.propose(),25002)
  writes=[c for c in self.calls if c[0]=='POST'];self.assertTrue(writes[-1][2]['draft']);self.assertTrue(writes[-2][2]['ref'].startswith('refs/heads/awema/dev-'));self.assertFalse(any('/merge' in c[1] or c[0]=='DELETE' for c in self.calls))
 def test_protected_files_and_traversal(self):
  for p in ('.env','x/.env.prod','auth.json','.github/workflows/a.yml','../README.md','a//b','/etc/passwd','private.key','a/../b'):
   with self.assertRaises(Refused):files_valid([{'path':p,'content':'fixture'}])
 def test_credential_content_denied(self):
  with self.assertRaises(Refused):files_valid([{'path':'README.md','content':'ghp_'+'A'*30}])
 def test_write_quota(self):
  for i in range(4):self.b.call(self.create('fixture-operation-'+str(i)),25002)
  with self.assertRaises(Refused):self.b.call(self.create('fixture-operation-5'),25002)
  self.assertEqual(len(self.calls),4)
 def test_no_unknown_fields(self):
  q=self.create();q['private']=False
  with self.assertRaises(Refused):self.b.call(q,25002)
  self.assertFalse(self.calls)
 def test_revoked_between_writes_stops(self):
  original=self.b.api
  def api(method,path,data=None):
   r=original(method,path,data)
   if method=='POST':self.active=False
   return r
  self.b.api=api
  with self.assertRaises(Refused):self.b.call(self.propose(),25002)
  self.assertEqual(len([c for c in self.calls if c[0]=='POST']),1)
 def test_repository_revoked_between_writes_stops(self):
  original=self.b.api
  def api(method,path,data=None):
   r=original(method,path,data)
   if method=='POST':self.denied.append('awema-test/new')
   return r
  self.b.api=api
  with self.assertRaises(Refused):self.b.call(self.propose(),25002)
  self.assertEqual(len([c for c in self.calls if c[0]=='POST']),1)
if __name__=='__main__':unittest.main()
