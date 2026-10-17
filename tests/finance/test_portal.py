import unittest,tempfile,json,time,secrets,hashlib
from pathlib import Path
from portal import Store,Denied,password_hash,totp
class Tests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.s=Store(Path(self.tmp.name)/'finance.sqlite');self.password=secrets.token_urlsafe(20)
  with self.s.connect() as c:
   for uid,role in [('owner','owner'),('assa','finance-manager'),('other','finance-manager'),('reader','reader')]:c.execute('insert into users values(?,?,?,?,?,?,?,?,?,?)',(uid,uid,role,1,1,password_hash(self.password),None,0,'agent-'+uid,json.dumps({'beneficiary':uid})))
  self.owner,self.owner_token=self.s.login({'user':'owner','password':self.password});self.assa,self.assa_token=self.s.login({'user':'assa','password':self.password})
 def tearDown(self):self.tmp.cleanup()
 def call(self,route,data={},who='owner',method='POST'):
  answer,token=(self.owner,self.owner_token) if who=='owner' else (self.assa,self.assa_token)
  return self.s.dispatch(method,route,data,token,answer['csrf'])
 def project(self):
  p=self.call('projects',{'name':'Fixture internal','currency':'XOF','opening':1000})['id']
  with self.s.connect() as c:c.execute('insert into grants values(?,?)',('assa',p))
  return p
 def test_tracking_exact_approval(self):
  p=self.project();r=self.call('records',{'project':p,'kind':'income','label':'Fixture','amount':200,'source':'fixture-1'},'assa')['id']
  self.assertEqual(self.call('state',who='assa',method='GET')['projects'][0]['balance'],1000)
  self.call('decisions',{'record':r,'version':1,'decision':'approved','reason':'fixture checked'},'assa')
  self.assertEqual(self.call('state',who='assa',method='GET')['projects'][0]['balance'],1200)
  with self.assertRaises(Denied):self.call('decisions',{'record':r,'version':1,'decision':'approved','reason':'duplicate'},'assa')
 def test_project_budget_is_audited_and_scoped(self):
  p=self.call('projects',{'name':'Budget fixture','currency':'XOF','opening':0,'budget':250000})['id']
  with self.s.connect() as c:c.execute('insert into grants values(?,?)',('assa',p))
  self.call('project-budget',{'project':p,'budget':300000},'assa')
  self.assertEqual(self.call('state',who='assa',method='GET')['projects'][0]['budget'],300000)
  self.assertEqual(self.call('state',method='GET')['projects'][0]['budget'],300000)
  with self.s.connect() as c:
   self.assertEqual(c.execute("select event from audit order by id desc limit 1").fetchone()[0],'project_budget_updated')
   c.execute('delete from grants where user=? and project=?',('assa',p))
  with self.assertRaises(Denied):self.call('project-budget',{'project':p,'budget':400000},'assa')
 def test_owner_can_review_financial_agent_activity_across_team(self):
  p=self.project();self.call('jobs',{'project':p,'agent':'accounting','prompt':'fixture review','provider_consent':True},'assa')
  owner_jobs=self.call('state',method='GET')['jobs']
  self.assertEqual(len(owner_jobs),1);self.assertEqual(owner_jobs[0]['requester'],'assa')
  self.assertEqual(len(self.call('state',who='assa',method='GET')['jobs']),1)
 def test_budget_schema_migrates_existing_database(self):
  path=Path(self.tmp.name)/'legacy.sqlite'
  import sqlite3
  c=sqlite3.connect(path);c.execute('create table projects(id text primary key,name text,currency text,opening integer,scope text,created real)');c.close()
  Store(path)
  c=sqlite3.connect(path);self.assertIn('budget',[r[1] for r in c.execute('pragma table_info(projects)')]);c.close()
 def test_cross_project_csrf_anonymous(self):
  p=self.project()
  with self.s.connect() as c:c.execute('delete from grants where user=?',('assa',))
  with self.assertRaises(Denied):self.call('records',{'project':p,'kind':'income','label':'x','amount':1,'source':'x'},'assa')
  self.assertEqual(self.call('state',who='assa',method='GET')['projects'],[])
  with self.assertRaises(Denied):self.s.dispatch('GET','state',{},'')
  with self.assertRaises(Denied):self.s.dispatch('POST','projects',{},self.owner_token,'wrong')
 def test_revoke_session_and_queued_jobs(self):
  p=self.project();j=self.call('jobs',{'project':p,'agent':'finance','prompt':'fixture question','provider_consent':True},'assa')['id']
  self.call('revoke',{'user':'assa'})
  with self.assertRaises(Denied):self.call('state',who='assa',method='GET')
  with self.s.connect() as c:self.assertEqual(c.execute('select state from jobs where id=?',(j,)).fetchone()[0],'cancelled')
 def test_no_payment_no_implicit_provider(self):
  p=self.project()
  for op in ('payment','export','bank','transfer'):
   with self.assertRaises(Denied):self.call(op,{'project':p},'assa')
  with self.assertRaises(Denied):self.call('jobs',{'project':p,'agent':'finance','prompt':'x'},'assa')
 def test_reader_cannot_write(self):
  p=self.project();session,token=self.s.login({'user':'reader','password':self.password})
  with self.s.connect() as c:c.execute('insert into grants values(?,?)',('reader',p))
  with self.assertRaises(Denied):self.s.dispatch('POST','records',{'project':p},token,session['csrf'])
 def test_enrollment_one_time_totp(self):
  invite=self.call('invite',{'user':'new-person','name':'Fixture person','role':'reader','responsibility':'Observe fixture','projects':[]})
  e=self.s.enroll({'step':'prepare','invite':invite['invitation'],'password':self.password})
  with self.assertRaises(Denied):self.s.enroll({'step':'prepare','invite':invite['invitation'],'password':self.password})
  self.s.enroll({'step':'confirm','enrollment':e['enrollment'],'code':totp(e['totp_key'])})
  with self.assertRaises(Denied):self.s.login({'user':'new-person','password':self.password})
 def test_audit_chain(self):
  self.project()
  with self.s.connect() as c:
   prev='0'*64
   for r in c.execute('select * from audit order by id'):
    self.assertEqual(r['previous'],prev);prev=hashlib.sha256(json.dumps([r['actor'],r['event'],r['object'],r['created'],prev],separators=(',',':')).encode()).hexdigest();self.assertEqual(prev,r['digest'])
 def test_archive_restore_retains_history(self):
  p=self.project();r=self.call('records',{'project':p,'kind':'reminder','label':'fixture','amount':0,'source':'fixture'})['id']
  self.call('archive-project',{'project':p});self.assertEqual(self.call('state',method='GET')['projects'],[])
  with self.assertRaises(Denied):self.call('jobs',{'project':p,'agent':'assistant','prompt':'test','provider_consent':True})
  self.call('restore-project',{'project':p});self.assertEqual(self.call('state',method='GET')['records'][0]['id'],r)
 def test_existing_owner_totp_setup_preserves_password_and_revokes_session(self):
  e=self.call('setup-totp',{});self.s.enroll({'step':'confirm','enrollment':e['enrollment'],'code':totp(e['totp_key'])})
  with self.assertRaises(Denied):self.call('state',method='GET')
  with self.s.connect() as c:self.assertTrue(c.execute('select totp from users where id=?',('owner',)).fetchone()[0])
if __name__=='__main__':unittest.main()
