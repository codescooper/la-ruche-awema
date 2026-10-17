"""Isolated internal financial workspace. No bank connector, payment or shell tool."""
import base64,hashlib,hmac,json,os,re,secrets,socket,socketserver,sqlite3,stat,struct,time
import sys
import studio
import mission_flow
import mission_preview
import web_project
from http.server import BaseHTTPRequestHandler
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import urlsplit

ORIGIN='https://laruche.awema.cloud'
COOKIE='__Secure-awema_finance'
ROLES={'owner','director','finance-manager','reader'}
AGENTS={'assistant','accounting','finance','qa'}
class Denied(Exception):
 def __init__(self,code,reason):self.code,self.reason=code,reason
def require(value,code=400,reason='invalid_request'):
 if not value:raise Denied(code,reason)
def password_hash(value):
 salt=secrets.token_hex(16);return 'pbkdf2_sha256:600000:'+salt+':'+hashlib.pbkdf2_hmac('sha256',value.encode(),bytes.fromhex(salt),600000).hex()
def password_ok(value,verifier):
 try:
  alg,rounds,salt,digest=verifier.split(':');require(alg=='pbkdf2_sha256' and rounds=='600000')
  return hmac.compare_digest(hashlib.pbkdf2_hmac('sha256',value.encode(),bytes.fromhex(salt),600000).hex(),digest)
 except Exception:return False
def text(value,maximum=500):
 require(isinstance(value,str) and 0<len(value.strip())<=maximum);return value.strip()
def totp(key,at=None):
 digest=hmac.new(base64.b32decode(key),struct.pack('>Q',int((at or time.time())//30)),hashlib.sha1).digest();offset=digest[-1]&15
 return str((struct.unpack('>I',digest[offset:offset+4])[0]&0x7fffffff)%1000000).zfill(6)
def check_totp(key,code,last):
 require(isinstance(code,str) and re.fullmatch(r'\d{6}',code),401,'invalid_code')
 now=int(time.time()//30)
 for step in (now-1,now,now+1):
  if step>last and hmac.compare_digest(totp(key,step*30),code):return step
 raise Denied(401,'invalid_code')

class Connection(sqlite3.Connection):
 def __exit__(self,*args):
  try:return super().__exit__(*args)
  finally:self.close()

class Store:
 def __init__(self,path,telegram_verify=None,mfa_required=None):
  self.path=str(path)
  self.mfa_required=os.environ.get('AWEMA_MFA_REQUIRED','true').lower()!='false' if mfa_required is None else bool(mfa_required)
  self.telegram_verify=telegram_verify
  with self.connect() as c:
   c.executescript('''
   PRAGMA journal_mode=WAL;
   CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,name TEXT,role TEXT,active INTEGER,generation INTEGER,password TEXT,totp TEXT,last_totp INTEGER DEFAULT 0,agent TEXT,context TEXT);
   CREATE TABLE IF NOT EXISTS grants(user TEXT,project TEXT,PRIMARY KEY(user,project));
   CREATE TABLE IF NOT EXISTS invites(hash TEXT PRIMARY KEY,user TEXT,expires REAL,used INTEGER DEFAULT 0);
   CREATE TABLE IF NOT EXISTS enrollments(hash TEXT PRIMARY KEY,user TEXT,password TEXT,totp TEXT,expires REAL);
   CREATE TABLE IF NOT EXISTS sessions(hash TEXT PRIMARY KEY,user TEXT,generation INTEGER,csrf TEXT,expires REAL);
   CREATE TABLE IF NOT EXISTS projects(id TEXT PRIMARY KEY,name TEXT,currency TEXT,opening INTEGER,scope TEXT,created REAL,budget INTEGER);
   CREATE TABLE IF NOT EXISTS records(id TEXT PRIMARY KEY,project TEXT,kind TEXT,label TEXT,amount INTEGER,source TEXT,due TEXT,state TEXT,version INTEGER,creator TEXT,approver TEXT,created REAL);
   CREATE TABLE IF NOT EXISTS decisions(id TEXT PRIMARY KEY,record TEXT,version INTEGER,user TEXT,decision TEXT,reason TEXT,created REAL,UNIQUE(record,version));
   CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY,user TEXT,generation INTEGER,project TEXT,agent TEXT,prompt TEXT,context TEXT,state TEXT,response TEXT,created REAL);
   CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,actor TEXT,event TEXT,object TEXT,created REAL,previous TEXT,digest TEXT);
   CREATE TABLE IF NOT EXISTS attempts(id INTEGER PRIMARY KEY,created REAL);
   CREATE TABLE IF NOT EXISTS project_archive(project TEXT PRIMARY KEY,actor TEXT,created REAL);
   CREATE TABLE IF NOT EXISTS telegram_links(user TEXT PRIMARY KEY,telegram_id TEXT UNIQUE,generation INTEGER,created REAL);
   CREATE TABLE IF NOT EXISTS telegram_claims(hash TEXT PRIMARY KEY,user TEXT,generation INTEGER,created REAL);
   ''')
   c.executescript(studio.SCHEMA)
   c.executescript(mission_flow.SCHEMA)
   if 'budget' not in {r['name'] for r in c.execute('pragma table_info(projects)')}:
    c.execute('alter table projects add column budget integer')
 def connect(self):
  c=sqlite3.connect(self.path,timeout=5,factory=Connection);c.row_factory=sqlite3.Row;c.execute('pragma foreign_keys=ON');return c
 def audit(self,c,actor,event,obj):
  last=c.execute('select digest from audit order by id desc limit 1').fetchone();prev=last[0] if last else '0'*64;stamp=time.time()
  digest=hashlib.sha256(json.dumps([actor,event,obj,stamp,prev],separators=(',',':')).encode()).hexdigest()
  c.execute('insert into audit(actor,event,object,created,previous,digest) values(?,?,?,?,?,?)',(actor,event,obj,stamp,prev,digest))
 def authenticate(self,c,token):
  row=c.execute('select u.*,s.csrf,s.expires from sessions s join users u on u.id=s.user where s.hash=? and s.generation=u.generation and s.expires>? and u.active=1',(hashlib.sha256(token.encode()).hexdigest(),time.time())).fetchone()
  require(row is not None,401,'authentication_required');return row
 def project(self,c,user,project,write=False):
  require(c.execute('select 1 from projects where id=?',(project,)).fetchone(),404,'project_missing')
  require(not c.execute('select 1 from project_archive where project=?',(project,)).fetchone(),403,'project_archived')
  require(user['role'] in ('owner','director') or c.execute('select 1 from grants where user=? and project=?',(user['id'],project)).fetchone(),403,'project_denied')
  if write:require(user['role'] in ('owner','director','finance-manager'),403,'write_denied')
 def login(self,data):
  with self.connect() as c:
   c.execute('BEGIN IMMEDIATE');now=time.time();c.execute('delete from attempts where created<?',(now-60,))
   require(c.execute('select count(*) from attempts').fetchone()[0]<10,429,'login_rate_limited')
   c.execute('insert into attempts(created) values(?)',(now,));c.commit()
   c.execute('BEGIN IMMEDIATE')
   user=c.execute('select * from users where id=? and active=1',(data.get('user'),)).fetchone()
   require(user and password_ok(data.get('password',''),user['password']),401,'invalid_login')
   if self.mfa_required and user['totp']:
    step=check_totp(user['totp'],data.get('code'),user['last_totp']);c.execute('update users set last_totp=? where id=?',(step,user['id']))
   token=secrets.token_urlsafe(32);csrf=secrets.token_hex(24)
   c.execute('insert into sessions values(?,?,?,?,?)',(hashlib.sha256(token.encode()).hexdigest(),user['id'],user['generation'],csrf,now+3600));self.audit(c,user['id'],'login',user['id'])
   return {'csrf':csrf,'user':user['id'],'name':user['name'],'role':user['role'],'agent':user['agent'],'totp_enabled':bool(user['totp']),'mfa_required':self.mfa_required},token
 def enroll(self,data):
  with self.connect() as c:
   c.execute('BEGIN IMMEDIATE')
   if data.get('step')=='prepare':
    invite=c.execute('select i.* from invites i join users u on u.id=i.user where i.hash=? and i.used=0 and i.expires>? and u.active=1',(hashlib.sha256(data.get('invite','').encode()).hexdigest(),time.time())).fetchone()
    require(invite,401,'invalid_invitation');password=text(data.get('password'),128);require(len(password)>=14,400,'password_too_short')
    if not self.mfa_required:
     c.execute('update users set password=?,generation=generation+1 where id=?',(password_hash(password),invite['user']))
     c.execute('delete from invites where user=?',(invite['user'],));c.execute('delete from enrollments where user=?',(invite['user'],));self.audit(c,invite['user'],'account_activated_password_only',invite['user'])
     return {'activated':True,'user':invite['user'],'mfa_required':False}
    token=secrets.token_urlsafe(32);key=base64.b32encode(secrets.token_bytes(20)).decode()
    c.execute('update invites set used=1 where hash=?',(invite['hash'],));c.execute('insert into enrollments values(?,?,?,?,?)',(hashlib.sha256(token.encode()).hexdigest(),invite['user'],password_hash(password),key,time.time()+600))
    return {'enrollment':token,'totp_key':key,'user':invite['user']}
   row=c.execute('select e.* from enrollments e join users u on u.id=e.user where e.hash=? and e.expires>? and u.active=1',(hashlib.sha256(data.get('enrollment','').encode()).hexdigest(),time.time())).fetchone()
   require(row,401,'enrollment_expired');step=check_totp(row['totp'],data.get('code'),0)
   c.execute('update users set password=?,totp=?,last_totp=?,generation=generation+1 where id=?',(row['password'],row['totp'],step,row['user']));c.execute('delete from enrollments where user=?',(row['user'],));c.execute('delete from invites where user=?',(row['user'],));self.audit(c,row['user'],'account_activated',row['user'])
   return {'activated':True,'user':row['user']}
 def verify_telegram(self,raw):
  try:
   if self.telegram_verify:return self.telegram_verify(raw)
   from telegram_auth import verify_init_data
   return verify_init_data(raw)
  except Exception:raise Denied(403,'invalid_telegram_identity')
 def dispatch(self,method,path,data,token,csrf=None,telegram=None):
  with self.connect() as c:
   if method=='POST':c.execute('BEGIN IMMEDIATE')
   else:c.execute('BEGIN')
   user=self.authenticate(c,token)
   if method=='POST':require(hmac.compare_digest(csrf or '',user['csrf']),403,'csrf_denied')
   actor=user['id']
   if telegram is not None and path not in ('session','logout','telegram-status','telegram-bind','telegram-unbind','setup-totp'):
    link=c.execute('select * from telegram_links where user=? and generation=?',(actor,user['generation'])).fetchone()
    require(link and link['telegram_id']==telegram['id'],403,'telegram_link_required')
   if path.startswith('mission-'):return mission_flow.dispatch(self,c,user,path,data,require,text)
   if path.startswith('studio'):return studio.dispatch(self,c,user,method,path,data,require,text)
   if path=='session':return {'user':actor,'name':user['name'],'role':user['role'],'agent':user['agent'],'csrf':user['csrf'],'totp_enabled':bool(user['totp']),'mfa_required':self.mfa_required}
   if path=='telegram-status':
    link=c.execute('select * from telegram_links where user=? and generation=?',(actor,user['generation'])).fetchone()
    return {'linked':bool(link),'bot':'awemaaiteambot','matching_telegram':bool(link and telegram and link['telegram_id']==telegram['id']),'personal_totp_required':self.mfa_required and not bool(user['totp'])}
   if path=='telegram-bind':
    require(not self.mfa_required or user['totp'],403,'personal_totp_required');require(user['expires']>time.time()+3000,403,'fresh_login_required')
    identity=self.verify_telegram(data.get('init_data'));require(telegram is None or identity['id']==telegram['id'],403,'invalid_telegram_identity')
    other=c.execute('select user from telegram_links where telegram_id=?',(identity['id'],)).fetchone();require(not other or other['user']==actor,409,'telegram_already_linked')
    previous=c.execute('select telegram_id from telegram_links where user=?',(actor,)).fetchone();require(not previous or previous['telegram_id']==identity['id'],409,'telegram_already_linked')
    claim=c.execute('select user,generation from telegram_claims where hash=?',(identity['proof'],)).fetchone();require(not claim or (claim['user']==actor and claim['generation']==user['generation']),403,'telegram_proof_replayed')
    c.execute('insert or ignore into telegram_claims values(?,?,?,?)',(identity['proof'],actor,user['generation'],time.time()))
    c.execute('insert or replace into telegram_links values(?,?,?,?)',(actor,identity['id'],user['generation'],time.time()));self.audit(c,actor,'telegram_linked',actor)
    return {'linked':True,'bot':'awemaaiteambot'}
   if path=='telegram-unbind':
    require((not self.mfa_required or user['totp']) and user['expires']>time.time()+3000,403,'fresh_login_required')
    c.execute('delete from telegram_links where user=?',(actor,));self.audit(c,actor,'telegram_unlinked',actor);return {'linked':False}
   if path=='logout':c.execute('delete from sessions where hash=?',(hashlib.sha256(token.encode()).hexdigest(),));return {'ok':True}
   if path=='setup-totp':
    require(self.mfa_required,409,'mfa_temporarily_disabled')
    require(not user['totp'],409,'totp_already_enabled');key=base64.b32encode(secrets.token_bytes(20)).decode();enrollment=secrets.token_urlsafe(32)
    c.execute('delete from enrollments where user=?',(actor,));c.execute('insert into enrollments values(?,?,?,?,?)',(hashlib.sha256(enrollment.encode()).hexdigest(),actor,user['password'],key,time.time()+600));self.audit(c,actor,'totp_setup_started',actor)
    return {'enrollment':enrollment,'totp_key':key,'user':actor}
   if path=='ruche':
    require(user['role'] in ('owner','director'),403,'director_required')
    if '/app' not in sys.path:sys.path.append('/app')
    from team_schema import load
    return load(Path('/observations/team-v2.json'),time.time())
   if path=='state':
    projects=[dict(r) for r in c.execute('select * from projects where id not in (select project from project_archive) order by created') if user['role'] in ('owner','director') or c.execute('select 1 from grants where user=? and project=?',(actor,r['id'])).fetchone()]
    ids={p['id'] for p in projects};marks=','.join('?' for _ in ids) or 'NULL';records=[dict(r) for r in c.execute('select * from records where project in ('+marks+') order by created desc limit 2000',tuple(ids))]
    for p in projects:
     p['balance']=p['opening']+c.execute("select coalesce(sum(case when kind='income' then amount when kind='expense' then -amount else 0 end),0) from records where project=? and state='approved'",(p['id'],)).fetchone()[0]
     p['spent']=c.execute("select coalesce(sum(amount),0) from records where project=? and kind='expense' and state='approved'",(p['id'],)).fetchone()[0]
    job_scope='' if user['role'] in ('owner','director') else ' where user=?'
    job_args=() if not job_scope else (actor,)
    jobs=[dict(r) for r in c.execute('select id,user,project,agent,prompt,state,response,created from jobs'+job_scope+' order by created desc limit 100',job_args) if r['project'] in ids]
    names={r['id']:r['name'] for r in c.execute('select id,name from users')}
    for job in jobs:job['requester']=names.get(job['user'],'Collaborateur');job.pop('user',None)
    return {'projects':projects,'records':records,'jobs':jobs,'users':[{'id':r['id'],'name':r['name'],'role':r['role'],'active':bool(r['active']),'agent':r['agent'],'totp_enabled':bool(r['totp'])} for r in c.execute('select * from users') if not (not r['active'] and r['id'].startswith('test-'))] if user['role']=='owner' else [],'payments_enabled':False,'bank_connected':False,'facturenet_connected':False}
   if path=='projects':
    require(user['role'] in ('owner','director'),403,'director_required');name=text(data.get('name'));currency=data.get('currency');require(currency in ('XOF','EUR','USD'))
    opening=data.get('opening',0);require(type(opening)==int and 0<=opening<=10**12)
    budget=data.get('budget');require(budget is None or (type(budget)==int and 0<=budget<=10**12),400,'invalid_request')
    project='p_'+secrets.token_hex(8);c.execute('insert into projects(id,name,currency,opening,scope,created,budget) values(?,?,?,?,?,?,?)',(project,name,currency,opening,'internal-awema',time.time(),budget))
    self.audit(c,actor,'project_created',project);return {'id':project}
   if path=='project-budget':
    project=data.get('project');self.project(c,user,project,True);budget=data.get('budget')
    require(budget is None or (type(budget)==int and 0<=budget<=10**12),400,'invalid_request')
    c.execute('update projects set budget=? where id=?',(budget,project));self.audit(c,actor,'project_budget_updated',project)
    return {'project':project,'budget':budget}
   if path=='archive-project':
    require(user['role'] in ('owner','director'),403,'director_required');project=data.get('project');self.project(c,user,project,True)
    c.execute('insert into project_archive values(?,?,?)',(project,actor,time.time()));c.execute("update jobs set state='cancelled',response=NULL where project=? and state in ('queued','processing')",(project,));self.audit(c,actor,'project_archived',project);return {'archived':True,'history_preserved':True}
   if path=='restore-project':
    require(user['role'] in ('owner','director'),403,'director_required');project=data.get('project');require(c.execute('select 1 from project_archive where project=?',(project,)).fetchone(),404,'archive_missing')
    c.execute('delete from project_archive where project=?',(project,));self.audit(c,actor,'project_restored',project);return {'restored':True}
   if path=='archives':
    require(user['role'] in ('owner','director'),403,'director_required');return {'projects':[dict(r) for r in c.execute('select p.* from projects p join project_archive a on p.id=a.project order by a.created desc')]}
   if path=='records':
    self.project(c,user,data.get('project'),True);kind=data.get('kind');require(kind in ('income','expense','invoice','reminder'));amount=data.get('amount',0);require(type(amount)==int and 0<=amount<=10**12)
    source=text(data.get('source'),1000);label=text(data.get('label'));due=data.get('due','');require(isinstance(due,str) and (not due or re.fullmatch(r'\d{4}-\d{2}-\d{2}',due)))
    rid='r_'+secrets.token_hex(8);c.execute('insert into records values(?,?,?,?,?,?,?,?,?,?,?,?)',(rid,data['project'],kind,label,amount,source,due,'draft',1,actor,None,time.time()))
    self.audit(c,actor,'draft_created',rid);return {'id':rid}
   if path=='decisions':
    row=c.execute('select * from records where id=?',(data.get('record'),)).fetchone();require(row,404,'record_missing');self.project(c,user,row['project'],True)
    require(type(data.get('version'))==int and row['version']==data['version'],409,'version_conflict');require(row['state']=='draft',409,'already_decided')
    decision=data.get('decision');require(decision in ('approved','rejected'));reason=text(data.get('reason'),2000)
    did=secrets.token_hex(16);c.execute('insert into decisions values(?,?,?,?,?,?,?)',(did,row['id'],row['version'],actor,decision,reason,time.time()))
    c.execute('update records set state=?,version=version+1,approver=? where id=?',(decision,actor,row['id']));self.audit(c,actor,'record_'+decision,row['id']);return {'id':did,'state':decision}
   if path=='jobs':
    require(user['role']!='reader',403,'write_denied')
    self.project(c,user,data.get('project'));agent=data.get('agent');require(agent in AGENTS);prompt=text(data.get('prompt'),4000)
    require(data.get('provider_consent') is True,400,'provider_consent_required')
    require(c.execute('select count(*) from jobs where user=? and created>?',(actor,time.time()-86400)).fetchone()[0]<20,429,'daily_limit')
    require(c.execute("select count(*) from jobs where user=? and state in ('queued','processing')",(actor,)).fetchone()[0]==0,409,'job_already_pending')
    project=c.execute('select * from projects where id=?',(data['project'],)).fetchone();context=json.loads(user['context']);context.update(project={'id':project['id'],'name':project['name'],'currency':project['currency']},specialist=agent,human_role=user['role'])
    jid='j_'+secrets.token_hex(12);c.execute('insert into jobs values(?,?,?,?,?,?,?,?,?,?)',(jid,actor,user['generation'],project['id'],agent,prompt,json.dumps(context), 'queued',None,time.time()))
    self.audit(c,actor,'agent_requested',jid);return {'id':jid,'state':'queued'}
   if path=='cancel':
    row=c.execute('select * from jobs where id=? and user=?',(data.get('id'),actor)).fetchone();require(row,404,'job_missing');c.execute("update jobs set state='cancelled',response=NULL where id=? and state in ('queued','processing')",(row['id'],));self.audit(c,actor,'job_cancelled',row['id']);return {'ok':True}
   if path=='invite':
    require(user['role']=='owner',403,'owner_required');uid=text(data.get('user'),64);require(re.fullmatch('[a-z0-9-]{3,64}',uid));role=data.get('role');require(role in ('director','finance-manager','reader'))
    name=text(data.get('name'));context={'beneficiary':name,'responsibility':text(data.get('responsibility'),2000),'scope':'AWEMA internal only','tools':['read_own_project','propose','ask_human'],'forbidden':['payment','transfer','bank_access','client_access','external_message','change_permissions']}
    require(not c.execute('select 1 from users where id=?',(uid,)).fetchone(),409,'user_exists')
    c.execute('insert into users values(?,?,?,?,?,?,?,?,?,?)',(uid,name,role,1,1,'',None,0,'agent-'+uid,json.dumps(context)))
    for project in data.get('projects',[]):
     self.project(c,user,project);c.execute('insert into grants values(?,?)',(uid,project))
    code=secrets.token_urlsafe(32);c.execute('insert into invites values(?,?,?,0)',(hashlib.sha256(code.encode()).hexdigest(),uid,time.time()+86400));self.audit(c,actor,'invitation_created',uid)
    return {'invitation':code,'user':uid,'expires_in_hours':24}
   if path=='renew-invite':
    require(user['role']=='owner',403,'owner_required');uid=data.get('user');row=c.execute('select * from users where id=? and active=1',(uid,)).fetchone();require(row and row['role']!='owner',404,'user_missing')
    c.execute('delete from invites where user=?',(uid,));c.execute('delete from enrollments where user=?',(uid,));c.execute('update users set generation=generation+1 where id=?',(uid,));c.execute("update jobs set state='cancelled',response=NULL where user=? and state in ('queued','processing')",(uid,))
    code=secrets.token_urlsafe(32);c.execute('insert into invites values(?,?,?,0)',(hashlib.sha256(code.encode()).hexdigest(),uid,time.time()+86400));self.audit(c,actor,'invitation_renewed',uid);return {'invitation':code,'user':uid}
   if path=='revoke':
    require(user['role']=='owner',403,'owner_required');uid=data.get('user');require(uid!=actor,400,'cannot_revoke_self')
    require(c.execute('select 1 from users where id=?',(uid,)).fetchone(),404,'user_missing');c.execute('update users set active=0,generation=generation+1 where id=?',(uid,));c.execute('delete from sessions where user=?',(uid,));c.execute("update jobs set state='cancelled',response=NULL where user=? and state in ('queued','processing')",(uid,));self.audit(c,actor,'user_revoked',uid);return {'ok':True}
   raise Denied(404,'route_missing')

 def preview(self,data,token):
  with self.connect() as c:
   c.execute('BEGIN')
   user=self.authenticate(c,token)
   return mission_preview.artifact_preview(c,user,data,require)

class Handler(BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def setup(self):super().setup();self.connection.settimeout(10)
 def reply(self,code,value,cookie=None,mime='application/json'):
  raw=value if isinstance(value,bytes) else json.dumps(value,ensure_ascii=False).encode();self.send_response(code)
  for key,val in {'Content-Type':mime,'Content-Length':str(len(raw)),'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','Permissions-Policy':'camera=(), microphone=(self), geolocation=()','Content-Security-Policy':"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-src 'self' blob:; img-src 'self' data: blob:; media-src 'self' data: blob:; base-uri 'none'; form-action 'self'; frame-ancestors 'self' https://web.telegram.org"}.items():self.send_header(key,val)
  if cookie:self.send_header('Set-Cookie',cookie)
  self.end_headers();self.wfile.write(raw)
 def reply_preview(self,code,raw,mime,csp):
  self.send_response(code)
  for key,val in {'Content-Type':mime,'Content-Length':str(len(raw)),'Cache-Control':'private, no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','Cross-Origin-Resource-Policy':'same-origin','Permissions-Policy':'camera=(), microphone=(self), geolocation=()','Content-Security-Policy':csp}.items():self.send_header(key,val)
  self.end_headers();self.wfile.write(raw)
 def do_GET(self):self.handle_request('GET')
 def do_POST(self):self.handle_request('POST')
 def handle_request(self,method):
  try:
   path=urlsplit(self.path).path
   if method=='GET' and path=='/finance/mission-preview':
    fetch_site=self.headers.get('Sec-Fetch-Site')
    direct_navigation=(fetch_site=='none' and self.headers.get('Sec-Fetch-Mode')=='navigate' and self.headers.get('Sec-Fetch-Dest')=='document')
    require(fetch_site!='cross-site' and (fetch_site!='none' or direct_navigation),403,'preview_origin_denied')
    from urllib.parse import parse_qs
    query=parse_qs(urlsplit(self.path).query,keep_blank_values=True,strict_parsing=True)
    require(set(query)=={'mission','ordinal','name'} and all(len(v)==1 for v in query.values()),400,'invalid_request')
    fields={k:v[0] for k,v in query.items()}
    require(re.fullmatch(r'(?:0|[1-9]|[1-5][0-9]|6[0-3])',fields['ordinal']) is not None,400,'invalid_request')
    jar=SimpleCookie();jar.load(self.headers.get('Cookie',''));token=jar[COOKIE].value if COOKIE in jar else ''
    mime,csp,raw=self.server.store.preview({'mission':fields['mission'],'ordinal':int(fields['ordinal']),'name':fields['name']},token)
    return self.reply_preview(200,raw,mime,csp)
   if method=='GET' and path in ('/finance','/finance/','/finance/app.js','/finance/style.css','/finance/telegram-web-app.js','/finance/telegram-bootstrap.js','/finance/studio.js','/finance/studio.css'):
    file={'/finance':'index.html','/finance/':'index.html','/finance/app.js':'app.js','/finance/style.css':'style.css','/finance/telegram-web-app.js':'telegram-web-app.js','/finance/telegram-bootstrap.js':'telegram-bootstrap.js','/finance/studio.js':'studio.js','/finance/studio.css':'studio.css'}[path]
    return self.reply(200,(Path(__file__).parent/file).read_bytes(),mime={'index.html':'text/html; charset=utf-8','app.js':'text/javascript; charset=utf-8','telegram-web-app.js':'text/javascript; charset=utf-8','telegram-bootstrap.js':'text/javascript; charset=utf-8','style.css':'text/css; charset=utf-8','studio.css':'text/css; charset=utf-8','studio.js':'text/javascript; charset=utf-8'}[file])
   require(path.startswith('/finance/api/'),404,'route_missing');route=path.removeprefix('/finance/api/');data={}
   if route=='auth-policy' and method=='GET':return self.reply(200,{'mfa_required':self.server.store.mfa_required})
   if method=='POST':
    require(self.headers.get('Origin')==ORIGIN,403,'origin_denied');require(self.headers.get('Content-Type','').split(';')[0]=='application/json',415,'json_required')
    require(not self.headers.get('Transfer-Encoding'),400,'transfer_denied');size=int(self.headers.get('Content-Length','0'));require(0<size<=16000,413,'body_too_large');data=json.loads(self.rfile.read(size));require(isinstance(data,dict))
   telegram=None
   if self.headers.get('X-AWEMA-Telegram-Init') is not None:telegram=self.server.store.verify_telegram(self.headers['X-AWEMA-Telegram-Init'])
   if route=='login' and method=='POST':
    answer,token=self.server.store.login(data);return self.reply(200,answer,COOKIE+'='+token+'; Path=/finance; Secure; HttpOnly; SameSite=Strict; Max-Age=3600')
   if route=='enroll' and method=='POST':return self.reply(200,self.server.store.enroll(data))
   require((method=='GET' and route in ('session','state','ruche','archives','telegram-status','studio')) or (method=='POST' and route in ('logout','setup-totp','projects','project-budget','archive-project','restore-project','records','decisions','jobs','cancel','invite','renew-invite','revoke','telegram-bind','telegram-unbind','studio-board','studio-position','studio-chat','studio-mission','mission-start','mission-create','mission-launch','mission-cancel','mission-review','mission-artifact','mission-recover')),405,'method_denied')
   jar=SimpleCookie();jar.load(self.headers.get('Cookie',''));token=jar[COOKIE].value if COOKIE in jar else ''
   result=self.server.store.dispatch(method,route,data,token,self.headers.get('X-CSRF-Token'),telegram);self.reply(200,result)
  except Denied as e:self.reply(e.code,{'error':e.reason})
  except (ValueError,TypeError,json.JSONDecodeError):self.reply(400,{'error':'invalid_request'})
  except Exception:self.reply(503,{'error':'temporarily_unavailable'})

class Server(getattr(socketserver,'UnixStreamServer',socketserver.TCPServer)):allow_reuse_address=False
def main():
 os.umask(0o077);path=Path('/run/finance/finance.sock')
 if path.exists():
  st=path.lstat();require(stat.S_ISSOCK(st.st_mode) and st.st_uid==os.geteuid(),503,'unsafe_socket')
  with socket.socket(socket.AF_UNIX) as probe:
   try:probe.connect(str(path))
   except ConnectionRefusedError:path.unlink()
   else:raise RuntimeError('active_socket')
 server=Server(str(path),Handler);os.chmod(path,0o660);server.store=Store('/data/finance.sqlite');server.serve_forever()
if __name__=='__main__':main()
