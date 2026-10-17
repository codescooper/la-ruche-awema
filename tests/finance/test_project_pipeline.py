import json,sqlite3,tempfile,unittest,sys,types
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace
sys.path.insert(0,str(Path(__file__).parent/'project-workspace-release'/'source'))
import mission_flow as flow
if 'fcntl' not in sys.modules:
 fcntl_stub=types.ModuleType('fcntl');fcntl_stub.LOCK_EX=1;fcntl_stub.LOCK_NB=2;fcntl_stub.flock=lambda *args:None;sys.modules['fcntl']=fcntl_stub
import mission_runner as runner
from portal import Store,Denied

REPO='awema-test/awema-dev-workbench'

class PMPlanFormatTests(unittest.TestCase):
 def test_accepts_numbered_or_unumbered_steps_heading(self):
  plan='## 5. Étapes exécutées\n\n1. PM : cadrage\n2. DEV : réalisation\n3. QA : contrôle\n4. Security : revue\n5. CTO : livraison\n'
  self.assertIsNone(runner.pm_plan_problem(plan))
  self.assertIsNone(runner.pm_plan_problem(plan.replace('## 5. ', '## ')))
 def test_rejects_wrong_step_order(self):
  plan='## Étapes exécutées\n1. PM\n2. QA\n3. DEV\n4. Security\n5. CTO\n'
  self.assertIn('exactement les cinq rôles', runner.pm_plan_problem(plan))

class ProjectMissionTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.store=Store(Path(self.tmp.name)/'db.sqlite')
  self.c=sqlite3.connect(self.store.path);self.c.row_factory=sqlite3.Row
  self.c.execute('insert into users values(?,?,?,?,?,?,?,?,?,?)',('owner','Owner','owner',1,1,'p',None,0,'assistant','{}'));self.c.commit()
  self.user=self.c.execute('select * from users where id=?',('owner',)).fetchone()
 def tearDown(self):self.c.close();self.tmp.cleanup()
 def call(self,path,data):
  with self.c:return flow.dispatch(self.store,self.c,self.user,path,data,lambda ok,code=400,reason='invalid_request':None if ok else self.deny(code,reason),self.text)
 @staticmethod
 def deny(code,reason):raise Denied(code,reason)
 @staticmethod
 def text(value,maximum=500):
  if not isinstance(value,str) or not value.strip() or len(value.strip())>maximum:raise Denied(400,'text')
  return value.strip()
 def make_project_plan(self):
  return self.call('mission-create',{'scope':'github-project-sandbox','repository':REPO,'objective':'Corriger une page du bac de travail','criteria':'Tests hors ligne réussis'})
 def test_only_explicitly_allowlisted_private_workbench_can_be_selected(self):
  with self.assertRaises(Denied):self.call('mission-create',{'scope':'github-project-sandbox','repository':'awema-test/afrocodeurs','objective':'x','criteria':'y'})
  plan=self.make_project_plan();self.assertEqual(plan['state'],'plan');self.assertEqual(flow.snapshot(self.c,self.user)[0]['repository'],REPO)
 def test_project_mission_needs_both_explicit_launch_consents(self):
  plan=self.make_project_plan()
  base={'mission':plan['id'],'digest':plan['digest'],'provider_consent':True,'internal_only':True}
  with self.assertRaises(Denied):self.call('mission-launch',base)
  consented={**base,'project_sandbox_consent':True,'draft_pr_consent':True}
  self.assertEqual(self.call('mission-launch',consented)['state'],'queued')
  self.assertTrue(self.call('mission-launch',consented)['duplicate'])
 def test_direct_project_start_requires_explicit_scoped_consent(self):
  request={'scope':'github-project-sandbox','repository':REPO,'objective':'Test une amélioration','criteria':'Tests locaux','operation':'project-operation-001','provider_consent':True,'internal_only':True}
  with self.assertRaises(Denied):self.call('mission-start',request)
  result=self.call('mission-start',{**request,'project_sandbox_consent':True,'draft_pr_consent':True})
  self.assertEqual(result['state'],'queued')

class ProjectPRProofTests(unittest.TestCase):
 def test_project_runner_dispatches_only_the_isolated_internal_worker(self):
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);(root/'handoffs').mkdir();(root/'states').mkdir()
   tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);store=Store(Path(tmp.name)/'db.sqlite');c=sqlite3.connect(store.path);self.addCleanup(c.close);c.row_factory=sqlite3.Row
   c.execute('insert into users values(?,?,?,?,?,?,?,?,?,?)',('owner','Owner','owner',1,1,'p',None,0,'assistant','{}'));c.commit();user=c.execute('select * from users where id=?',('owner',)).fetchone()
   def req(ok,code=400,reason='invalid_request'):
    if not ok:raise Denied(code,reason)
   plan=flow.dispatch(store,c,user,'mission-create',{'scope':'github-project-sandbox','repository':REPO,'objective':'Review a workbench page','criteria':'Run repository tests'},req,ProjectMissionTests.text)
   flow.dispatch(store,c,user,'mission-launch',{'mission':plan['id'],'digest':plan['digest'],'provider_consent':True,'internal_only':True,'project_sandbox_consent':True,'draft_pr_consent':True},req,ProjectMissionTests.text)
   c.commit()
   with patch.object(runner,'WROOT',root), patch.object(runner,'ROOT',root), patch.object(runner,'native_create',return_value='t_1234abcd'), patch.object(runner,'audit'), patch.object(runner,'promote'), patch.object(runner,'dispatch_task'), patch.object(runner.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout='{}',stderr='')):
    result=runner.process(c,SimpleNamespace())
   stage=(root/'handoffs'/('ruche-'+plan['id']+'-0')/'STAGE.md').read_text(encoding='utf-8')
   self.assertEqual(result['state'],'running');self.assertIn(REPO,stage);self.assertIn('projet client',stage.lower());self.assertIn('aucun autre dépôt',stage.lower())

 def test_pr_requires_one_confirmed_draft_in_exact_private_repo(self):
  with tempfile.TemporaryDirectory() as td:
   path=Path(td)/'ops.sqlite'
   db=sqlite3.connect(path)
   with db:
    db.execute('create table operations(task text,action text,state text,result text)')
    db.execute('insert into operations values(?,?,?,?)',('t_1234abcd','propose_pr','done',json.dumps({'repository':REPO,'number':3,'draft':True,'pull_request':'https://github.com/'+REPO+'/pull/3','branch':'awema/dev-example'})))
   db.close()
   with patch.object(runner,'GITHUB_OPERATIONS_DB',path):
    self.assertEqual(runner.verified_project_pr('t_1234abcd',REPO)['number'],3)
    self.assertIsNone(runner.verified_project_pr('t_1234abcd','awema-test/afrocodeurs'))
    self.assertIsNone(runner.verified_project_pr('t_missing',REPO))
 def test_pr_refuses_duplicate_or_uncertain_connector_operations(self):
  with tempfile.TemporaryDirectory() as td:
   path=Path(td)/'ops.sqlite'
   result=json.dumps({'repository':REPO,'number':3,'draft':True,'pull_request':'https://github.com/'+REPO+'/pull/3','branch':'awema/dev-example'})
   db=sqlite3.connect(path)
   with db:
    db.execute('create table operations(task text,action text,state text,result text)')
    db.executemany('insert into operations values(?,?,?,?)',[('t_1234abcd','propose_pr','done',result),('t_1234abcd','propose_pr','done',result)])
   db.close()
   with patch.object(runner,'GITHUB_OPERATIONS_DB',path):self.assertIsNone(runner.verified_project_pr('t_1234abcd',REPO))

if __name__=='__main__':unittest.main()
