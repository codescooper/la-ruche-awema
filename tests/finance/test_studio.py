import unittest,tempfile,json,secrets,sys,time
from pathlib import Path
from portal import Store,Denied,password_hash
if sys.platform=='win32':
 import types
 sys.modules.setdefault('fcntl',types.SimpleNamespace())
import model_worker
class Tests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.s=Store(Path(self.tmp.name)/'db.sqlite');self.password=secrets.token_urlsafe(20);self.sessions={}
  with self.s.connect() as c:
   for uid,role in [('owner','owner'),('director','director'),('manager','finance-manager'),('other','finance-manager'),('reader','reader')]:c.execute('insert into users values(?,?,?,?,?,?,?,?,?,?)',(uid,uid,role,1,1,password_hash(self.password),None,0,'agent-'+uid,json.dumps({'beneficiary':uid})))
  for uid in ['owner','manager','other','reader','director']:self.sessions[uid]=self.s.login({'user':uid,'password':self.password})
 def tearDown(self):self.tmp.cleanup()
 def call(self,path,data=None,user='owner'):
  ses,token=self.sessions[user];return self.s.dispatch('GET' if data is None else 'POST',path,data or {},token,ses['csrf'])
 def chat(self,agent='dev',user='owner',**kw):return self.call('studio-chat',{'agent':agent,'message':'Synthetic brainstorming','provider_consent':True,'include_context':True,**kw},user)
 def complete(self,response='Fixture answer'):
  with self.s.connect() as c:return model_worker.process(c,lambda req:response)
 def test_no_project_needed(self):
  j=self.chat();self.assertEqual(self.complete()['state'],'done');self.assertEqual(self.call('studio')['messages'][0]['response'],'Fixture answer')
 def test_threads_isolated(self):
  j=self.chat('assistant','manager');self.complete();self.assertEqual(self.call('studio',user='other')['messages'],[])
  with self.assertRaises(Denied):self.chat('assistant','other',thread=j['thread'])
 def test_general_roles_restricted(self):
  with self.assertRaises(Denied):self.chat('dev','manager')
  self.chat('cto','director');self.complete()
 def test_reader_write_denied(self):
  with self.assertRaises(Denied):self.chat('assistant','reader')
 def test_explicit_consent(self):
  with self.assertRaises(Denied):self.chat(provider_consent=False)
 def test_chat_without_optional_context_only_sends_the_typed_message(self):
  job=self.chat(include_context=False)
  with self.s.connect() as c:context=json.loads(c.execute('select context from jobs where id=?',(job['id'],)).fetchone()['context'])
  self.assertNotIn('beneficiary',context);self.assertEqual(context['history'],[]);self.assertEqual(context['mode'],'private_conversation')
 def test_role_switch_denied(self):
  j=self.chat();self.complete()
  with self.assertRaises(Denied):self.chat('cto',thread=j['thread'])
 def test_history_real_messages(self):
  j=self.chat();self.complete();self.chat(thread=j['thread'],message='Second turn');requests=[]
  with self.s.connect() as c:model_worker.process(c,lambda req:requests.append(req) or 'Second answer')
  self.assertEqual([m['role'] for m in requests[0]['messages']],['system','user','assistant','user']);self.assertEqual(requests[0]['messages'][2]['content'],'Fixture answer')
 def test_generation_revocation(self):
  j=self.chat()
  with self.s.connect() as c:c.execute("update users set generation=2 where id='owner'")
  self.assertEqual(self.complete()['state'],'cancelled')
 def test_role_downgrade_cancels_general_chat(self):
  self.chat();self.call('studio-mission',{'agent':'dev','objective':'Synthetic','criteria':'Checked'})
  with self.s.connect() as c:c.execute("update users set role='finance-manager' where id='owner'")
  self.assertEqual(self.complete()['state'],'cancelled');self.assertEqual(self.call('studio')['missions'],[])
 def test_financial_scope_revocation(self):
  p=self.call('projects',{'name':'Fixture','currency':'XOF','opening':0})['id']
  with self.s.connect() as c:c.execute('insert into grants values(?,?)',('manager',p))
  self.chat('accounting','manager',project=p);self.complete()
  with self.s.connect() as c:c.execute('delete from grants where user=?',('manager',))
  self.assertEqual(self.call('studio',user='manager')['messages'],[])
 def test_general_no_financial_context(self):
  with self.assertRaises(Denied):self.chat(project='p_any')
 def test_positions_are_private(self):
  self.call('studio-position',{'agent':'dev','x':4,'y':5});self.assertEqual(self.call('studio',user='other')['positions'],[])
  with self.assertRaises(Denied):self.call('studio-position',{'agent':'dev','x':True,'y':5})
 def test_mission_prepared_no_native_effect(self):
  r=self.call('studio-mission',{'agent':'dev','objective':'Synthetic site','criteria':'A tested preview'});self.assertFalse(r['worker_started']);self.assertEqual(self.call('studio',user='manager')['missions'],[])
 def test_csrf_and_anonymous(self):
  ses,token=self.sessions['owner']
  with self.assertRaises(Denied):self.s.dispatch('POST','studio-position',{'agent':'dev','x':4,'y':5},token,'wrong')
  with self.assertRaises(Denied):self.s.dispatch('GET','studio',{},'','')
 def board_fixture(self,age=0):
  with self.s.connect() as c:
   c.executescript('CREATE TABLE studio_board(id TEXT PRIMARY KEY,title TEXT,role TEXT,state TEXT,created INTEGER,runs INTEGER);CREATE TABLE studio_board_meta(id INTEGER PRIMARY KEY,observed REAL,available INTEGER);')
   c.execute('insert into studio_board_meta values(1,?,1)',(time.time()-age,))
   c.executemany('insert into studio_board values(?,?,?,?,?,?)',[(f't_{i:08x}','Synthetic '+str(i),'dev','blocked',i,0) for i in range(123)])
 def test_board_pagination_complete(self):
  self.board_fixture();pages=[self.call('studio-board',{'page':i}) for i in range(3)]
  self.assertEqual(pages[0]['total'],123);self.assertEqual(len({t['id'] for page in pages for t in page['tasks']}),123)
 def test_board_authorization(self):
  self.board_fixture()
  for role in ['manager','reader','other']:
   with self.assertRaises(Denied):self.call('studio-board',{},role)
  self.assertEqual(self.call('studio-board',{},'director')['total'],123)
 def test_board_stale_hides_tasks(self):
  self.board_fixture(31);self.assertEqual(self.call('studio-board',{}),{'available':False})
 def test_board_filter_literal(self):
  self.board_fixture();self.assertEqual(self.call('studio-board',{'query':'%'})['total'],0)
 def test_board_csrf(self):
  self.board_fixture();ses,token=self.sessions['owner']
  with self.assertRaises(Denied):self.s.dispatch('POST','studio-board',{},token,'wrong')
if __name__=='__main__':unittest.main()
