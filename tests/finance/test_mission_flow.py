import unittest,tempfile,json,sqlite3,sys,time
import hashlib,concurrent.futures
from unittest.mock import patch
from pathlib import Path
from portal import Store,Denied
import mission_flow as f
class FlowTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.store=Store(Path(self.tmp.name)/'db');self.c=sqlite3.connect(self.store.path);self.c.row_factory=sqlite3.Row
  for name,role in [('a','owner'),('b','director'),('r','reader'),('f','finance-manager')]:self.c.execute('insert into users values(?,?,?,?,?,?,?,?,?,?)',(name,name,role,1,1,'p',None,0,'assistant','{}'))
  self.c.commit();self.user=self.c.execute("select * from users where id='a'").fetchone()
 def tearDown(self):self.c.close();self.tmp.cleanup()
 def call(self,path,data=None,user=None):
  with self.c:return f.dispatch(self.store,self.c,user or self.user,path,data or {},lambda ok,code=400,reason='invalid_request': None if ok else self.denied(code,reason),lambda v,maximum=500:self.text(v,maximum))
 def denied(self,code,reason):raise Denied(code,reason)
 def text(self,v,maximum):
  if not isinstance(v,str) or not 0<len(v.strip())<=maximum:raise Denied(400,'text')
  return v.strip()
 def create(self):return self.call('mission-create',{'objective':'Page interne fictive','criteria':'Un fichier local testé','scope':'awema-internal-sandbox'})
 def launch(self,m):return self.call('mission-launch',{'mission':m['id'],'digest':m['digest'],'internal_only':True,'provider_consent':True})
 def test_create_plan_no_execution(self):
  m=self.create();self.assertEqual(m['state'],'plan');self.assertEqual(len(f.snapshot(self.c,self.user)[0]['steps']),5);self.assertFalse(any(s['task'] for s in f.snapshot(self.c,self.user)[0]['steps']))
 def test_launch_idempotent(self):
  m=self.create();self.assertEqual(self.launch(m)['state'],'queued');self.assertTrue(self.launch(m)['duplicate']);self.assertEqual(self.c.execute("select count(*) from mission_events where event='human_plan_approved'").fetchone()[0],1)
 def test_client_scope_denied(self):
  with self.assertRaises(Denied):self.call('mission-create',{'objective':'x','criteria':'x','scope':'client'})
 def test_other_user_denied(self):
  m=self.create();u=self.c.execute("select * from users where id='b'").fetchone()
  self.assertEqual(len(f.snapshot(self.c,u)),0)
  with self.assertRaises(Denied):self.call('mission-launch',{'mission':m['id'],'digest':m['digest'],'provider_consent':True,'internal_only':True},u)
 def test_owner_can_read_other_users_mission_and_artifact(self):
  director=self.c.execute("select * from users where id='b'").fetchone()
  other=f.dispatch(self.store,self.c,director,'mission-create',{'scope':'awema-internal-sandbox','objective':'Mission interne du directeur','criteria':'Preuve consultable'},lambda ok,code=400,reason='invalid_request':None if ok else self.denied(code,reason),self.text)
  self.c.execute('insert into mission_artifacts values(?,?,?,?,?)',(other['id'],0,'OPERATOR-REPORT.md','fixture-hash','Motif opérateur visible'))
  visible=f.snapshot(self.c,self.user);self.assertTrue(any(m['id']==other['id'] for m in visible))
  result=self.call('mission-artifact',{'mission':other['id'],'ordinal':0,'name':'OPERATOR-REPORT.md'})
  self.assertEqual(result['content'],'Motif opérateur visible')
  with self.assertRaises(Denied):self.call('mission-cancel',{'mission':other['id']})
 def test_reader_and_finance_denied(self):
  for name in ('r','f'):
   with self.assertRaises(Denied):self.call('mission-create',{'objective':'x','criteria':'x','scope':'awema-internal-sandbox'},self.c.execute('select * from users where id=?',(name,)).fetchone())
 def test_generation_denied(self):
  m=self.create();self.c.execute("update users set generation=2 where id='a'");u=self.c.execute("select * from users where id='a'").fetchone()
  self.assertEqual(len(f.snapshot(self.c,u)),1)
  with self.assertRaises(Denied):self.call('mission-launch',{'mission':m['id'],'digest':m['digest'],'provider_consent':True,'internal_only':True},u)
 def test_no_consent_denied(self):
  m=self.create()
  with self.assertRaises(Denied):self.call('mission-launch',{'mission':m['id'],'digest':m['digest'],'internal_only':True})
 def test_changed_plan_denied(self):
  m=self.create()
  with self.assertRaises(Denied):self.call('mission-launch',{'mission':m['id'],'digest':'bad','internal_only':True,'provider_consent':True})
 def test_only_one_pending_per_user(self):
  a=self.create();b=self.create();self.launch(a)
  with self.assertRaises(Denied):self.launch(b)
 def test_cancel_before_launch(self):
  m=self.create();self.assertEqual(self.call('mission-cancel',{'mission':m['id']})['state'],'cancelled')
 def test_cancel_running_requests_stop(self):
  m=self.create();self.c.execute("update mission_flows set state='running' where id=?",(m['id'],));self.assertEqual(self.call('mission-cancel',{'mission':m['id']})['state'],'cancel_requested')
 def test_human_accept_only_after_review(self):
  m=self.create()
  with self.assertRaises(Denied):self.call('mission-review',{'mission':m['id'],'decision':'accepted','comment':'ok'})
  self.c.execute("update mission_flows set state='review' where id=?",(m['id'],));self.assertEqual(self.call('mission-review',{'mission':m['id'],'decision':'accepted','comment':'ok'})['state'],'delivered')
 def test_correction_blocks_no_auto_retry(self):
  m=self.create();self.c.execute("update mission_flows set state='review' where id=?",(m['id'],));self.assertEqual(self.call('mission-review',{'mission':m['id'],'decision':'correction_requested','comment':'Ajouter preuve'})['state'],'blocked')
 def test_artifact_private(self):
  m=self.create();self.c.execute('insert into mission_artifacts values(?,?,?,?,?)',(m['id'],1,'page.html','hash','<script>example</script>'));data={'mission':m['id'],'ordinal':1,'name':'page.html'};self.assertEqual(self.call('mission-artifact',data)['content'],'<script>example</script>')
  with self.assertRaises(Denied):self.call('mission-artifact',data,self.c.execute("select * from users where id='b'").fetchone())
 def test_daily_limit(self):
  for i in range(f.MISSION_DRAFT_DAILY_LIMIT):self.create()
  with self.assertRaises(Denied):self.create()
 def test_sixth_approved_mission_fits_new_daily_limit(self):
  for i in range(6):
   m=self.create();self.assertEqual(self.launch(m)['state'],'queued')
   self.c.execute("update mission_flows set state='delivered' where id=?",(m['id'],))
  cap=f.capacity(self.c);self.assertEqual(cap['limit'],10);self.assertEqual(cap['used'],6);self.assertEqual(cap['available'],4)
 def start(self,**overrides):return self.call('mission-start',dict(scope='awema-internal-sandbox',objective='Outil interne local testé',operation='operation-fixture-123',provider_consent=True,internal_only=True,**overrides))
 def test_objective_start_is_atomic_and_idempotent(self):
  m=self.start();self.assertEqual(m['state'],'queued');self.assertTrue(self.start()['duplicate']);self.assertEqual(self.c.execute('select count(*) from mission_flows').fetchone()[0],1)
 def test_objective_changed_same_operation_denied(self):
  self.start()
  with self.assertRaises(Denied):self.call('mission-start',dict(scope='awema-internal-sandbox',objective='Changement',operation='operation-fixture-123',provider_consent=True,internal_only=True))
 def test_objective_requires_consent_and_internal_scope(self):
  for data in ({'provider_consent':False},{'scope':'client'},{'internal_only':False}):
   with self.assertRaises(Denied):self.call('mission-start',dict(dict(scope='awema-internal-sandbox',objective='x',operation='operation-fixture-123',provider_consent=True,internal_only=True),**data))
  self.assertEqual(self.c.execute('select count(*) from mission_flows').fetchone()[0],0)
 def test_objective_denied_to_reader(self):
  with self.assertRaises(Denied):self.call('mission-start',{},self.c.execute("select * from users where id='r'").fetchone())
 def test_objective_rollback_after_creation(self):
  original=f.stamp
  def fail(c,mid,event):
   if event=='human_plan_approved':raise RuntimeError('Injected before commit')
   original(c,mid,event)
  with patch.object(f,'stamp',side_effect=fail):
   with self.assertRaises(RuntimeError):self.start()
  self.assertEqual(self.c.execute('select count(*) from mission_flows').fetchone()[0],0)
  self.assertEqual(self.c.execute('select count(*) from mission_requests').fetchone()[0],0)
 def test_objective_concurrent_same_key(self):
  token='fixture-session';csrf='fixture-csrf'
  self.c.execute('insert into sessions values(?,?,?,?,?)',(hashlib.sha256(token.encode()).hexdigest(),'a',1,csrf,time.time()+600));self.c.commit()
  data=dict(scope='awema-internal-sandbox',objective='Concurrent fixture',operation='concurrent-fixture-key',provider_consent=True,internal_only=True)
  with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
   results=list(pool.map(lambda _:self.store.dispatch('POST','mission-start',data,token,csrf),range(2)))
  self.assertEqual(results[0]['id'],results[1]['id']);self.assertEqual(sum(bool(r.get('duplicate')) for r in results),1)
  self.assertEqual(self.c.execute('select count(*) from mission_flows').fetchone()[0],1)
 def test_global_capacity_denies_before_approval(self):
  now=time.time()
  for i in range(f.MISSION_DAILY_LIMIT):
   m=self.create();self.c.execute("update mission_flows set state='delivered',approved=? where id=?",(now+i-10,m['id']))
  self.c.commit()
  other=self.c.execute("select * from users where id='b'").fetchone()
  with self.assertRaises(Denied):self.call('mission-start',dict(scope='awema-internal-sandbox',objective='x',operation='capacity-fixture-key',provider_consent=True,internal_only=True),other)
  self.assertEqual(self.c.execute('select count(*) from mission_flows').fetchone()[0],f.MISSION_DAILY_LIMIT)
  cap=f.capacity(self.c);self.assertEqual(cap['available'],0);self.assertEqual(cap['next_available'],now-f.MISSION_DAILY_LIMIT+86400)
if __name__=='__main__':unittest.main()
