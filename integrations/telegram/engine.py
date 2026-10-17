"""Private text chat. No execution, payment, shell, or native CTO delegation."""
import hashlib,hmac,json,time,secrets
import studio,model_worker
from portal import Store,Denied,require,text

BOT=8690224851
ELIGIBLE={'assa-sanwinia'}
SCHEMA='''
CREATE TABLE IF NOT EXISTS tg_direct_updates(id INTEGER PRIMARY KEY,user TEXT,generation INTEGER,created REAL);
CREATE TABLE IF NOT EXISTS tg_direct_settings(user TEXT,generation INTEGER,chat TEXT,agent TEXT,thread TEXT,consent INTEGER,notifications INTEGER,enabled_at REAL,PRIMARY KEY(user,generation));
CREATE TABLE IF NOT EXISTS tg_direct_jobs(job TEXT PRIMARY KEY,user TEXT,generation INTEGER,chat TEXT,created REAL);
CREATE TABLE IF NOT EXISTS tg_direct_outbox(id TEXT PRIMARY KEY,user TEXT,generation INTEGER,chat TEXT,body TEXT,state TEXT,created REAL,sent REAL,kind TEXT,ref TEXT);
'''
HELP='Votre chat privé AWEMA est connecté. Pour autoriser l’envoi de vos messages et des derniers échanges au fournisseur IA DeepSeek, envoyez /oui. Ne transmettez aucun secret ni donnée bancaire. Ensuite, écrivez normalement au CTO, votre interlocuteur par défaut pour la coordination. /agent assistant, /agent cto, /agent accounting ou /agent finance choisit un interlocuteur selon vos droits. /nouveau ouvre un nouvel échange. /notifications non coupe les notifications ; /notifications oui les réactive. /non suspend le chat IA. Ce chat prépare des réponses : il ne déclenche ni paiement, ni déploiement, ni mission exécutée.'

def canonical(data):return json.dumps(data,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()
def sign(data,key):return hmac.new(key.encode(),canonical(data),hashlib.sha256).hexdigest()

class Engine:
 def __init__(self,path,key,eligible=None,now=time.time,native_ids=()):
  self.store=Store(path);self.key=key;self.eligible=ELIGIBLE if eligible is None else set(eligible);self.now=now
  self.native_ids=set(native_ids)
  with self.store.connect() as c:c.executescript(SCHEMA)
 def link(self,c,uid,generation,chat):
  row=c.execute('select u.* from users u join telegram_links t on t.user=u.id and t.generation=u.generation where u.id=? and u.generation=? and t.telegram_id=? and u.active=1',(uid,generation,str(chat))).fetchone()
  return row if row and row['id'] in self.eligible and row['role'] in ('director','finance-manager') and str(chat) not in self.native_ids and '*' not in self.native_ids else None
 def mirror(self):
  with self.store.connect() as c:
   rows=[{'telegram_id':r['telegram_id'],'user':r['id'],'generation':r['generation']} for r in c.execute('select u.id,u.generation,u.role,t.telegram_id from users u join telegram_links t on t.user=u.id and t.generation=u.generation where u.active=1') if r['id'] in self.eligible and r['role'] in ('director','finance-manager') and r['telegram_id'] not in self.native_ids and '*' not in self.native_ids]
   blocked=[r['chat'] for r in c.execute('select distinct user,chat from tg_direct_settings') if r['user'] in self.eligible]
  return {'schema':1,'observed_at':self.now(),'links':rows,'protected_ids':blocked,'native_ids':sorted(self.native_ids)}
 def enqueue(self,c,key,uid,generation,chat,body,kind='notice',ref=''):
  assert type(body) is str and len(body)<=12000
  for n in range(0,len(body),3500):
   c.execute('insert or ignore into tg_direct_outbox values(?,?,?,?,?,?,?,NULL,?,?)',(key+':'+str(n//3500),uid,generation,str(chat),body[n:n+3500],'pending',self.now(),kind,ref))
 def receive(self,envelope):
  data=envelope.get('payload');signature=envelope.get('signature')
  require(type(data) is dict and type(signature) is str and len(signature)==64,403,'invalid_transport')
  require(hmac.compare_digest(sign(data,self.key),signature),403,'invalid_transport')
  require(set(data)=={'schema','bot','update_id','message_id','chat_id','user_id','date','user','generation','text'},400,'invalid_transport')
  require(data['schema']==1 and data['bot']==BOT,403,'invalid_transport')
  for field in ('update_id','message_id','chat_id','user_id','generation','date'):require(type(data[field]) is int and 0<data[field]<2**52,400,'invalid_transport')
  require(data['chat_id']==data['user_id'] and -30<=self.now()-data['date']<=300,403,'invalid_transport')
  require(type(data['user']) is str and type(data['text']) is str and 0<len(data['text'])<=4000,400,'invalid_transport')
  uid=data['user'];generation=data['generation'];chat=str(data['chat_id']);update=data['update_id'];message=data['text'].strip()
  with self.store.connect() as c:
   c.execute('BEGIN IMMEDIATE');user=self.link(c,uid,generation,chat)
   if not user:return {'handled':True,'accepted':False,'reason':'link_revoked'}
   if c.execute('select count(*) from tg_direct_updates where user=? and generation=? and created>?',(uid,generation,self.now()-60)).fetchone()[0]>=20 or c.execute('select count(*) from tg_direct_updates where user=? and generation=? and created>?',(uid,generation,self.now()-86400)).fetchone()[0]>=100:return {'handled':True,'accepted':False,'reason':'ingress_rate_limit'}
   if not c.execute('insert or ignore into tg_direct_updates values(?,?,?,?)',(update,uid,generation,self.now())).rowcount:return {'handled':True,'duplicate':True}
   c.execute('insert or ignore into tg_direct_settings values(?,?,?, ?,NULL,0,0,?)',(uid,generation,chat,'cto' if user['role']=='director' else 'assistant',self.now()))
   setting=c.execute('select * from tg_direct_settings where user=? and generation=?',(uid,generation)).fetchone()
   prefix='update:'+str(update);notice=None
   command=message.split()[0].lower() if message else ''
   if command in ('/start','/aide','/help'):notice=HELP
   elif command=='/oui':
    c.execute('update tg_direct_settings set consent=1,notifications=1,enabled_at=? where user=? and generation=?',(self.now(),uid,generation));notice='Chat IA activé. Écrivez votre question : votre interlocuteur vous répondra ici. Notifications de vos nouvelles demandes activées. /non permet de suspendre.'
   elif command=='/non':
    c.execute('update tg_direct_settings set consent=0,notifications=0 where user=? and generation=?',(uid,generation))
    c.execute("update jobs set state='cancelled',response=NULL where user=? and generation=? and id in(select job from tg_direct_jobs) and state in('queued','processing')",(uid,generation));notice='Chat IA et notifications suspendus. Aucun nouveau message ne sera transmis au modèle. /oui pour réactiver.'
   elif command=='/notifications':
    value=message.split()[-1].lower()
    if value not in ('oui','non'):notice='Usage : /notifications oui ou /notifications non.'
    else:
     c.execute('update tg_direct_settings set notifications=? where user=? and generation=?',(int(value=='oui'),uid,generation));notice='Notifications '+('activées.' if value=='oui' else 'désactivées.')
   elif command=='/nouveau':
    c.execute('update tg_direct_settings set thread=NULL where user=? and generation=?',(uid,generation));notice='Nouvel échange prêt. Écrivez votre question.'
   elif command=='/agent':
    agent=message.split()[-1].lower();agents=studio.FINANCIAL|(studio.GENERAL if user['role']=='director' else set())
    if agent not in agents:notice='Interlocuteur non autorisé. Choisissez avec /agent suivi de : '+', '.join(sorted(agents))+'.'
    else:
     c.execute('update tg_direct_settings set agent=?,thread=NULL where user=? and generation=?',(agent,uid,generation));notice='Interlocuteur : '+agent+'. Écrivez votre question.'
   elif command.startswith('/'):
    notice='Commande non exécutée. /aide donne les commandes du chat privé. Les actions sensibles se valident dans Espace AWEMA.'
   elif not setting['consent']:notice=HELP
   else:
    c.execute('SAVEPOINT chat_request')
    try:
     result=studio.dispatch(self.store,c,user,'POST','studio-chat',{'agent':setting['agent'],'thread':setting['thread'],'message':message,'provider_consent':True},require,text)
     c.execute('insert into tg_direct_jobs values(?,?,?,?,?)',(result['id'],uid,generation,chat,self.now()));c.execute('update tg_direct_settings set thread=? where user=? and generation=?',(result['thread'],uid,generation))
     notice='Demande reçue par '+setting['agent']+'. Je vous réponds ici dès que la réponse est prête.'
    except Denied as exc:
     c.execute('ROLLBACK TO chat_request');notice={'daily_limit':'Le quota de vingt analyses sur 24 heures est atteint.','job_already_pending':'Une réponse est déjà en cours. Attendez sa fin avant une nouvelle demande.'}.get(exc.reason,'Demande refusée par les droits actuels. Ouvrez Espace AWEMA pour vérifier votre accès.')
    finally:c.execute('RELEASE chat_request')
   if notice:self.enqueue(c,prefix,uid,generation,chat,notice)
   self.store.audit(c,uid,'telegram_direct_received',str(update))
  return {'handled':True,'accepted':True}
 def allowed_output(self,c,row):
  user=self.link(c,row['user'],row['generation'],row['chat'])
  if not user:return False
  setting=c.execute('select * from tg_direct_settings where user=? and generation=?',(row['user'],row['generation'])).fetchone()
  if row['kind'] in ('response','job_notice','flow_notice') and (not setting or not setting['consent']):return False
  if row['kind'] in ('job_notice','flow_notice') and not setting['notifications']:return False
  if row['kind'] in ('response','job_notice'):
   job=c.execute('select * from jobs where id=?',(row['ref'],)).fetchone()
   return bool(job and job['user']==row['user'] and job['generation']==row['generation'] and model_worker.allowed(c,job))
  if row['kind']=='flow_notice':
   flow=c.execute('select * from mission_flows where id=?',(row['ref'],)).fetchone()
   return bool(user['role']=='director' and flow and flow['user']==row['user'] and flow['generation']==row['generation'])
  return True
 def collect(self):
  with self.store.connect() as c:
   c.execute('BEGIN IMMEDIATE')
   for r in c.execute("select j.*,t.chat from tg_direct_jobs t join jobs j on j.id=t.job where j.state in ('done','failed','uncertain','cancelled') order by j.created desc limit 100").fetchall():
    body=r['response'] if r['state']=='done' and r['response'] else 'Votre demande à '+r['agent']+' est '+r['state']+'. Aucun nouvel essai automatique ; consultez Espace AWEMA avant de recommencer.'
    self.enqueue(c,'response:'+r['id'],r['user'],r['generation'],r['chat'],body,'response',r['id'])
   for setting in c.execute('select * from tg_direct_settings where consent=1 and notifications=1').fetchall():
    for r in c.execute("select * from jobs where user=? and generation=? and created>=? and state in ('done','failed','uncertain','cancelled') and id not in(select job from tg_direct_jobs) order by created desc limit 50",(setting['user'],setting['generation'],setting['enabled_at'])).fetchall():
     self.enqueue(c,'job_notice:'+r['id'],r['user'],r['generation'],setting['chat'],'Votre demande à '+r['agent']+' est '+r['state']+'. Retrouvez le résultat dans Espace AWEMA.','job_notice',r['id'])
    for r in c.execute("select * from mission_flows where user=? and generation=? and created>=? and state in ('review','delivered','blocked','cancelled') order by updated desc limit 50",(setting['user'],setting['generation'],setting['enabled_at'])).fetchall():
     self.enqueue(c,'flow_notice:'+r['id']+':'+r['state'],r['user'],r['generation'],setting['chat'],'Mission '+r['id']+' : '+r['state']+'. Relecture ou intervention dans Espace AWEMA ; aucune validation par ce message.','flow_notice',r['id'])
 def deliver(self,send):
  # Interrupted/uncertain sends are deliberately never retried automatically.
  with self.store.connect() as c:c.execute("update tg_direct_outbox set state='uncertain' where state='sending'")
  for _ in range(8):
   with self.store.connect() as c:
    c.execute('BEGIN IMMEDIATE');row=c.execute("select * from tg_direct_outbox where state='pending' order by created,id limit 1").fetchone()
    if not row:return
    if not self.allowed_output(c,row):c.execute("update tg_direct_outbox set state='cancelled',body='' where id=?",(row['id'],));continue
    c.execute("update tg_direct_outbox set state='sending' where id=?",(row['id'],));item=dict(row)
   # Live recheck immediately before each API call, including multipart replies.
   with self.store.connect() as c:allowed=self.allowed_output(c,item)
   if not allowed:
    with self.store.connect() as c:c.execute("update tg_direct_outbox set state='cancelled',body='' where id=?",(item['id'],))
    continue
   try:send(item['chat'],item['body']);state='sent'
   except Exception:state='uncertain'
   with self.store.connect() as c:c.execute('update tg_direct_outbox set state=?,sent=? where id=?',(state,self.now(),item['id']))
