import unittest,tempfile,secrets,time
from pathlib import Path
from portal import Store,password_hash,Denied,totp

class Tests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.password=secrets.token_urlsafe(20);self.key='JBSWY3DPEHPK3PXP'
  def verify(raw):
   if raw!='signed-fixture':raise ValueError('invalid identity')
   return {'id':'42','proof':'fixture-proof'}
  self.s=Store(Path(self.tmp.name)/'fixture.sqlite',verify,mfa_required=False)
  with self.s.connect() as c:c.execute('insert into users values(?,?,?,?,?,?,?,?,?,?)',('owner','Synthetic owner','owner',1,1,password_hash(self.password),self.key,0,'assistant','{}'))
 def tearDown(self):self.tmp.cleanup()
 def session(self):return self.s.login({'user':'owner','password':self.password})
 def test_pause_keeps_password_required_and_totp_for_reactivation(self):
  answer,token=self.session();self.assertFalse(answer['mfa_required'])
  with self.assertRaises(Denied):self.s.login({'user':'owner','password':'wrong'})
  self.s.mfa_required=True
  with self.assertRaises(Denied):self.session()
  self.s.login({'user':'owner','password':self.password,'code':totp(self.key)})
 def test_invitation_password_only_single_use(self):
  a,t=self.session();invite=self.s.dispatch('POST','invite',{'user':'new-person','name':'Synthetic','role':'director','responsibility':'Fixture','projects':[]},t,a['csrf'])
  data={'step':'prepare','invite':invite['invitation'],'password':self.password};r=self.s.enroll(data)
  self.assertTrue(r['activated']);self.assertNotIn('totp_key',r)
  with self.assertRaises(Denied):self.s.enroll(data)
  self.s.login({'user':'new-person','password':self.password})
 def test_telegram_still_requires_identity_csrf_and_recent_session(self):
  with self.s.connect() as c:c.execute('update users set totp=NULL')
  a,t=self.session()
  def bind(raw='signed-fixture',csrf=None):return self.s.dispatch('POST','telegram-bind',{'init_data':raw},t,a['csrf'] if csrf is None else csrf)
  with self.assertRaises(Denied):bind('forged')
  with self.assertRaises(Denied):bind(csrf='wrong')
  self.assertTrue(bind()['linked'])
  with self.s.connect() as c:c.execute('update sessions set expires=?',(time.time()+2000,))
  with self.assertRaises(Denied):bind()
 def test_revocation_still_rejects_password_and_session(self):
  a,t=self.session()
  with self.s.connect() as c:c.execute('update users set active=0')
  with self.assertRaises(Denied):self.session()
  with self.assertRaises(Denied):self.s.dispatch('GET','state',{},t)

if __name__=='__main__':unittest.main()
