import unittest,tempfile,json,time,base64,hashlib,secrets
from pathlib import Path
from urllib.parse import urlencode,parse_qsl
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from telegram_auth import verify_init_data,BOT_ID
from portal import Store,password_hash,Denied,totp

class TelegramTests(unittest.TestCase):
 def setUp(self):
  self.key=Ed25519PrivateKey.generate();self.public=self.key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
  self.temp=tempfile.TemporaryDirectory();self.store=Store(Path(self.temp.name)/'fixture.sqlite',lambda raw:verify_init_data(raw,public_key=self.public));self.password=secrets.token_urlsafe(24);self.totp='JBSWY3DPEHPK3PXP'
  with self.store.connect() as c:
   for name in ('alice','bob'):c.execute('insert into users values(?,?,?,?,?,?,?,?,?,?)',(name,'Synthetic user','director',1,1,password_hash(self.password),self.totp,0,'agent-'+name,'{}'))
  self.answer,self.token=self.store.login({'user':'alice','password':self.password,'code':totp(self.totp)})
 def tearDown(self):self.temp.cleanup()
 def envelope(self,uid=42,stamp=None,bot=BOT_ID,extra=None):
  values={'auth_date':str(int(time.time()) if stamp is None else stamp),'user':json.dumps({'id':uid,'first_name':'Synthetic'}),'query_id':'fixture-query'};values.update(extra or {})
  check=str(bot)+':WebAppData\n'+'\n'.join(k+'='+values[k] for k in sorted(values))
  values['signature']=base64.urlsafe_b64encode(self.key.sign(check.encode())).decode().rstrip('=');values['hash']='0'*64
  return urlencode(values)
 def bind(self,raw=None):return self.store.dispatch('POST','telegram-bind',{'init_data':raw or self.envelope()},self.token,self.answer['csrf'])
 def denied(self,callback,code):
  with self.assertRaises(Denied) as raised:callback()
  self.assertEqual(raised.exception.code,code)
 def test_valid_signature_and_authenticated_binding(self):
  raw=self.envelope();self.assertEqual(verify_init_data(raw,public_key=self.public)['id'],'42');self.assertTrue(self.bind(raw)['linked'])
  self.assertTrue(self.store.dispatch('GET','telegram-status',{},self.token,telegram={'id':'42'})['matching_telegram'])
 def test_tampered_and_wrong_bot_signatures_refused(self):
  for raw in (self.envelope().replace('fixture-query','tampered'),self.envelope(bot=1234)):
   with self.assertRaises(ValueError):verify_init_data(raw,public_key=self.public)
 def test_expired_future_duplicate_parameters_refused(self):
  for raw in (self.envelope(stamp=int(time.time())-601),self.envelope(stamp=int(time.time())+60),self.envelope()+'&auth_date=0'):
   with self.assertRaises(ValueError):verify_init_data(raw,public_key=self.public)
 def test_group_and_bot_identity_refused(self):
  with self.assertRaises(ValueError):verify_init_data(self.envelope(extra={'chat_type':'group'}),public_key=self.public)
  with self.assertRaises(ValueError):verify_init_data(self.envelope(uid=True),public_key=self.public)
 def test_telegram_requires_link_before_financial_access(self):
  self.denied(lambda:self.store.dispatch('GET','state',{},self.token,telegram={'id':'42'}),403)
  self.bind();self.store.dispatch('GET','state',{},self.token,telegram={'id':'42'})
  self.denied(lambda:self.store.dispatch('GET','state',{},self.token,telegram={'id':'43'}),403)
 def test_link_requires_totp_and_fresh_login(self):
  with self.store.connect() as c:c.execute('update users set totp=NULL where id=?',('alice',))
  self.denied(self.bind,403)
  with self.store.connect() as c:c.execute('update users set totp=? where id=?',(self.totp,'alice'));c.execute('update sessions set expires=?',(time.time()+2500,))
  self.denied(self.bind,403)
 def test_other_account_cannot_take_identity_or_replay_claim(self):
  raw=self.envelope();self.bind(raw);bob,token=self.store.login({'user':'bob','password':self.password,'code':totp(self.totp)})
  self.denied(lambda:self.store.dispatch('POST','telegram-bind',{'init_data':raw},token,bob['csrf']),409)
  self.store.dispatch('POST','telegram-unbind',{},self.token,self.answer['csrf'])
  self.denied(lambda:self.store.dispatch('POST','telegram-bind',{'init_data':raw},token,bob['csrf']),403)
 def test_unlink_and_generation_change_invalidate_link(self):
  self.bind();self.store.dispatch('POST','telegram-unbind',{},self.token,self.answer['csrf'])
  self.denied(lambda:self.store.dispatch('GET','state',{},self.token,telegram={'id':'42'}),403)
  self.bind()
  with self.store.connect() as c:c.execute('update users set generation=2 where id=?',('alice',));c.execute('update sessions set generation=2 where user=?',('alice',))
  self.denied(lambda:self.store.dispatch('GET','state',{},self.token,telegram={'id':'42'}),403)
 def test_anonymous_csrf_and_revocation_refused(self):
  self.denied(lambda:self.store.dispatch('POST','telegram-bind',{'init_data':self.envelope()},'invalid','invalid'),401)
  self.denied(lambda:self.store.dispatch('POST','telegram-bind',{'init_data':self.envelope()},self.token,'invalid'),403)
  self.bind()
  with self.store.connect() as c:c.execute('update users set active=0 where id=?',('alice',))
  self.denied(lambda:self.store.dispatch('GET','state',{},self.token,telegram={'id':'42'}),401)
 def test_raw_telegram_proof_not_written_to_audit(self):
  raw=self.envelope();self.bind(raw)
  with self.store.connect() as c:
   self.assertFalse(any(raw in r[0] or 'auth_date' in r[0] for r in c.execute('select object from audit')))
   self.assertEqual(c.execute('select hash from telegram_claims').fetchone()[0],verify_init_data(raw,public_key=self.public)['proof'])
 def test_equivalent_signed_envelope_cannot_bypass_replay(self):
  raw=self.envelope();self.bind(raw);self.store.dispatch('POST','telegram-unbind',{},self.token,self.answer['csrf'])
  values=dict(parse_qsl(raw));values['hash']='f'*64;equivalent=urlencode(list(reversed(list(values.items()))))
  self.assertEqual(verify_init_data(raw,public_key=self.public)['proof'],verify_init_data(equivalent,public_key=self.public)['proof'])
  bob,token=self.store.login({'user':'bob','password':self.password,'code':totp(self.totp)})
  self.denied(lambda:self.store.dispatch('POST','telegram-bind',{'init_data':equivalent},token,bob['csrf']),403)

if __name__=='__main__':unittest.main()
