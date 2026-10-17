"""Authenticated, internal sandbox missions. Native execution remains operator-owned."""
import hashlib,json,time,secrets,re,unicodedata
from project_policy import PROJECT_REPOSITORIES
ROLES=('pm','dev','qa','security','cto')
MISSION_DAILY_LIMIT=10
MISSION_DRAFT_DAILY_LIMIT=20
PLAN=[{'role':r,'label':l} for r,l in zip(ROLES,('Cadrer le besoin','Réaliser les fichiers','Tester le résultat','Contrôler les frontières','Consolider la livraison'))]
WEB_ROLES=('pm','designer','dev','qa','security','cto')
WEB_PLAN=[{'role':r,'label':l} for r,l in zip(WEB_ROLES,('Cadrer le besoin','Concevoir l’interface','Réaliser les fichiers','Tester le résultat','Contrôler les frontières','Consolider la livraison'))]
AUTOMATIC_CORRECTION_LIMITS={'web-v1':4,'general-v1':2,'legacy-v1':2}
PIPELINE_SCHEMA='CREATE TABLE IF NOT EXISTS mission_pipeline_specs(mission TEXT PRIMARY KEY,version TEXT NOT NULL,mission_type TEXT NOT NULL,plan TEXT NOT NULL,plan_sha256 TEXT NOT NULL);'

def infer_mission_type(objective,criteria):
 text=unicodedata.normalize('NFKD',(str(objective)+' '+str(criteria)).lower())
 text=''.join(ch for ch in text if not unicodedata.combining(ch))
 return 'web' if re.search(r'\b(?:site\s+(?:web|internet|vitrine)|website|html\s*/?\s*css|page\s+web)\b',text) else 'general'

def canonical_plan(plan):return json.dumps(plan,ensure_ascii=False,sort_keys=True,separators=(',',':'))

def new_pipeline(mission_type):
 if mission_type not in ('general','web'):raise ValueError('mission_type_invalid')
 return {'version':'web-v1' if mission_type=='web' else 'general-v1','mission_type':mission_type,'plan':json.loads(canonical_plan(WEB_PLAN if mission_type=='web' else PLAN))}

def pipeline_spec(c,mid):
 # Absence means the immutable historical five-step contract, never inference.
 c.execute(PIPELINE_SCHEMA)
 record=c.execute('select version,mission_type,plan,plan_sha256 from mission_pipeline_specs where mission=?',(mid,)).fetchone()
 if record is None:return {'version':'legacy-v1','mission_type':None,'plan':json.loads(canonical_plan(PLAN))}
 version,kind,raw,digest=record
 expected=new_pipeline(kind)
 if version!=expected['version'] or raw!=canonical_plan(expected['plan']) or hashlib.sha256(raw.encode()).hexdigest()!=digest:raise ValueError('mission_pipeline_changed')
 return expected

def roles_for(c,mid):return tuple(item['role'] for item in pipeline_spec(c,mid)['plan'])

def role_ordinal(c,mid,role):
 roles=roles_for(c,mid)
 if roles.count(role)!=1:raise ValueError('mission_role_invalid')
 ordinal=roles.index(role)
 row=c.execute('select role from mission_steps where mission=? and ordinal=?',(mid,ordinal)).fetchone()
 if row is None or row[0]!=role:raise ValueError('mission_step_plan_changed')
 return ordinal

def mission_type(c,row):
 spec=pipeline_spec(c,row['id'])
 return spec['mission_type'] or infer_mission_type(row['objective'],row['criteria'])

def mission_digest(objective,criteria,spec,scope,repository):
 parts=[objective,criteria,spec['plan'],scope,repository]
 if spec['version']!='legacy-v1':parts.extend([spec['version'],spec['mission_type']])
 return hashlib.sha256(json.dumps(parts,sort_keys=True).encode()).hexdigest()

def approved_digests(c,row,scope,repository):
 spec=pipeline_spec(c,row['id']);values=[mission_digest(row['objective'],row['criteria'],spec,scope,repository)]
 if spec['version']=='legacy-v1' and scope=='awema-internal-sandbox':values.append(hashlib.sha256(json.dumps([row['objective'],row['criteria'],spec['plan'],scope],sort_keys=True).encode()).hexdigest())
 return tuple(values)
SCHEMA='''
CREATE TABLE IF NOT EXISTS mission_flows(id TEXT PRIMARY KEY,user TEXT,generation INTEGER,objective TEXT,criteria TEXT,digest TEXT,state TEXT,created REAL,updated REAL,approved REAL,blocker TEXT);
CREATE TABLE IF NOT EXISTS mission_steps(mission TEXT,ordinal INTEGER,role TEXT,task TEXT,state TEXT,summary TEXT,operation TEXT,PRIMARY KEY(mission,ordinal));
CREATE TABLE IF NOT EXISTS mission_events(id INTEGER PRIMARY KEY,mission TEXT,event TEXT,created REAL);
CREATE TABLE IF NOT EXISTS mission_artifacts(mission TEXT,ordinal INTEGER,name TEXT,sha256 TEXT,content TEXT,PRIMARY KEY(mission,ordinal,name));
CREATE TABLE IF NOT EXISTS mission_requests(user TEXT,generation INTEGER,operation TEXT,digest TEXT,mission TEXT,PRIMARY KEY(user,generation,operation));
CREATE TABLE IF NOT EXISTS mission_project_targets(mission TEXT PRIMARY KEY,scope TEXT NOT NULL,repository TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS mission_step_attempts(mission TEXT NOT NULL,ordinal INTEGER NOT NULL,attempt INTEGER NOT NULL,task TEXT,status TEXT NOT NULL,cause TEXT NOT NULL DEFAULT '',operator_note TEXT NOT NULL DEFAULT '',auto_retry INTEGER NOT NULL DEFAULT 0,retry_after REAL,created REAL NOT NULL,updated REAL NOT NULL,PRIMARY KEY(mission,ordinal,attempt));
CREATE TABLE IF NOT EXISTS mission_recovery_requests(mission TEXT PRIMARY KEY,ordinal INTEGER NOT NULL,decision TEXT NOT NULL,note TEXT NOT NULL,requested_by TEXT NOT NULL,created REAL NOT NULL,state TEXT NOT NULL DEFAULT 'pending');
CREATE TABLE IF NOT EXISTS mission_correction_cycles(mission TEXT NOT NULL,cycle INTEGER NOT NULL,source_ordinal INTEGER NOT NULL,reason TEXT NOT NULL,automatic INTEGER NOT NULL,created REAL NOT NULL,PRIMARY KEY(mission,cycle));
'''
def ensure_recovery_schema(c):
 c.execute(PIPELINE_SCHEMA)
 c.execute('CREATE TABLE IF NOT EXISTS mission_step_attempts(mission TEXT NOT NULL,ordinal INTEGER NOT NULL,attempt INTEGER NOT NULL,task TEXT,status TEXT NOT NULL,cause TEXT NOT NULL DEFAULT "",operator_note TEXT NOT NULL DEFAULT "",auto_retry INTEGER NOT NULL DEFAULT 0,retry_after REAL,created REAL NOT NULL,updated REAL NOT NULL,PRIMARY KEY(mission,ordinal,attempt))')
 c.execute('CREATE TABLE IF NOT EXISTS mission_recovery_requests(mission TEXT PRIMARY KEY,ordinal INTEGER NOT NULL,decision TEXT NOT NULL,note TEXT NOT NULL,requested_by TEXT NOT NULL,created REAL NOT NULL,state TEXT NOT NULL DEFAULT "pending")')
 c.execute('CREATE TABLE IF NOT EXISTS mission_correction_cycles(mission TEXT NOT NULL,cycle INTEGER NOT NULL,source_ordinal INTEGER NOT NULL,reason TEXT NOT NULL,automatic INTEGER NOT NULL,created REAL NOT NULL,PRIMARY KEY(mission,cycle));')
def latest_correction(c,mid):
 ensure_recovery_schema(c)
 row=c.execute('select * from mission_correction_cycles where mission=? order by cycle desc limit 1',(mid,)).fetchone()
 return dict(row) if row else None

def queue_correction(c,row,source_ordinal,reason,automatic=False):
 """Reopen DEV and every dependent review, keeping PM, approval and history.

 The caller owns the transaction. Only purely local internal outputs can be
 changed automatically: the existing GitHub broker cannot update an open PR.
 """
 ensure_recovery_schema(c);mid=row['id']
 if not isinstance(reason,str) or not 0<len(reason.strip())<=4000:return {'scheduled':False,'reason_code':'correction_reason_invalid'}
 reason=reason.strip()
 if target(c,mid)['scope']!='awema-internal-sandbox':return {'scheduled':False,'reason_code':'project_correction_operator_required'}
 latest=c.execute('select * from mission_flows where id=?',(mid,)).fetchone()
 if not latest or latest['state'] not in ('running','review') or not c.execute("select 1 from users where id=? and generation=? and active=1 and role in ('owner','director')",(latest['user'],latest['generation'])).fetchone():return {'scheduled':False,'reason_code':'correction_activation_changed'}
 steps=list(c.execute('select ordinal,state from mission_steps where mission=? order by ordinal',(mid,)))
 roles=roles_for(c,mid);dev_ordinal=role_ordinal(c,mid,'dev')
 if type(source_ordinal) is not int or source_ordinal not in [i for i,r in enumerate(roles) if r in ('qa','security','cto')] or len(steps)!=len(roles) or [step['ordinal'] for step in steps]!=list(range(len(roles))) or any(steps[i]['state']!='done' for i in range(source_ordinal)):return {'scheduled':False,'reason_code':'correction_source_not_ready'}
 if not automatic and (latest['state']!='review' or any(step['state']!='done' for step in steps)):return {'scheduled':False,'reason_code':'correction_source_not_ready'}
 if any(step['state'] in ('running','dispatching') for step in steps[source_ordinal+1:]):return {'scheduled':False,'reason_code':'correction_downstream_active'}
 correction_limit=AUTOMATIC_CORRECTION_LIMITS[pipeline_spec(c,mid)['version']]
 if automatic and c.execute('select count(*) from mission_correction_cycles where mission=? and automatic=1',(mid,)).fetchone()[0]>=correction_limit:return {'scheduled':False,'reason_code':'correction_cycle_limit'}
 last_attempt=c.execute('select coalesce(max(attempt),0) from mission_step_attempts where mission=? and ordinal=?',(mid,dev_ordinal)).fetchone()[0]
 if last_attempt>=5:return {'scheduled':False,'reason_code':'correction_attempt_limit'}
 cycle=c.execute('select coalesce(max(cycle),0)+1 from mission_correction_cycles where mission=?',(mid,)).fetchone()[0]
 # Old deliverables remain downloadable as history but cannot be mistaken for
 # the new current package, inherited by a reviewer, or reused as fresh proof.
 prefix='ARCHIVE-CYCLE-'+str(cycle).zfill(2)+'-'
 for artifact in list(c.execute('select ordinal,name from mission_artifacts where mission=? and ordinal>=?',(mid,dev_ordinal))):
  if not artifact['name'].startswith('ARCHIVE-CYCLE-'):
   c.execute('update mission_artifacts set name=? where mission=? and ordinal=? and name=?',(prefix+artifact['name'],mid,artifact['ordinal'],artifact['name']))
 now=time.time();c.execute('insert into mission_correction_cycles values(?,?,?,?,?,?)',(mid,cycle,source_ordinal,reason[:4000],int(automatic),now))
 c.execute("update mission_steps set task=NULL,operation=NULL,state='waiting',summary='' where mission=? and ordinal>=?",(mid,dev_ordinal))
 c.execute("update mission_recovery_requests set state='superseded' where mission=? and state='pending'",(mid,))
 if c.execute("select 1 from sqlite_master where type='table' and name='mission_control_retries'").fetchone():
  c.execute('update mission_control_retries set resolved=1 where mission=? and ordinal>=?',(mid,dev_ordinal))
 message='Correction transmise à DEV ; QA, Security et CTO reliront les nouveaux fichiers. Motif : '+reason[:1400]
 c.execute("update mission_flows set state='queued',blocker=?,updated=? where id=?",(message,now,mid))
 stamp(c,mid,'automatic_correction_scheduled' if automatic else 'human_correction_scheduled')
 return {'scheduled':True,'reason_code':'review_correction_scheduled','cycle':cycle}

def target(c,mid):
 c.execute('CREATE TABLE IF NOT EXISTS mission_project_targets(mission TEXT PRIMARY KEY,scope TEXT NOT NULL,repository TEXT NOT NULL)')
 r=c.execute('select scope,repository from mission_project_targets where mission=?',(mid,)).fetchone()
 return dict(r) if r else {'scope':'awema-internal-sandbox','repository':''}
def stamp(c,mid,event):c.execute('insert into mission_events(mission,event,created) values(?,?,?)',(mid,event,time.time()))
def valid(row,user):return row and row['user']==user['id'] and row['generation']==user['generation']
def capacity(c):
 stamps=[r[0] for r in c.execute('select approved from mission_flows where approved>? order by approved',(time.time()-86400,))]
 return {'limit':MISSION_DAILY_LIMIT,'used':len(stamps),'available':max(0,MISSION_DAILY_LIMIT-len(stamps)),'next_available':stamps[len(stamps)-MISSION_DAILY_LIMIT]+86400 if len(stamps)>=MISSION_DAILY_LIMIT else None}
def snapshot(c,user):
 if user['role'] not in ('owner','director'):return []
 ensure_recovery_schema(c)
 rows=[]
 source=c.execute('select * from mission_flows order by created desc limit 50') if user['role']=='owner' else c.execute('select * from mission_flows where user=? order by created desc limit 50',(user['id'],))
 for row in source:
  try:spec=pipeline_spec(c,row['id']);pipeline_error=''
  except ValueError:spec={'version':'invalid','mission_type':None,'plan':[]};pipeline_error='mission_pipeline_changed'
  m=dict(row);m.update(target(c,row['id']));m['pipeline_version']=spec['version'];m['pipeline_valid']=not bool(pipeline_error);m['pipeline_error']=pipeline_error;m['mission_type']=spec['mission_type'] or infer_mission_type(row['objective'],row['criteria']);m['plan']=spec['plan'];m['steps']=[dict(r) for r in c.execute('select ordinal,role,task,state,summary from mission_steps where mission=? order by ordinal',(row['id'],))];m['events']=[dict(r) for r in c.execute('select event,created from mission_events where mission=? order by id desc limit 30',(row['id'],))];m['artifacts']=[dict(r) for r in c.execute('select ordinal,name,sha256 from mission_artifacts where mission=?',(row['id'],))];m['attempts']=[dict(r) for r in c.execute('select ordinal,attempt,task,status,cause,operator_note,auto_retry,retry_after,created,updated from mission_step_attempts where mission=? order by ordinal,attempt',(row['id'],))];m['corrections']=[dict(r) for r in c.execute('select cycle,source_ordinal,reason,automatic,created from mission_correction_cycles where mission=? order by cycle desc limit 10',(row['id'],))];rows.append(m)
 return rows
def dispatch(store,c,user,path,data,require,text):
 require(user['role'] in ('owner','director'),403,'director_required')
 ensure_recovery_schema(c)
 c.execute('CREATE TABLE IF NOT EXISTS mission_project_targets(mission TEXT PRIMARY KEY,scope TEXT NOT NULL,repository TEXT NOT NULL)')
 if path=='mission-start':
  scope=data.get('scope','awema-internal-sandbox');repo=data.get('repository','')
  require(scope in ('awema-internal-sandbox','github-project-sandbox'),403,'mission_scope_denied')
  if scope=='github-project-sandbox':require(repo in PROJECT_REPOSITORIES and data.get('project_sandbox_consent') is True and data.get('draft_pr_consent') is True,403,'project_scope_not_authorized')
  else:require(scope=='awema-internal-sandbox' and not repo,403,'internal_scope_required')
  require(data.get('provider_consent') is True and data.get('internal_only') is True,400,'provider_consent_required')
  operation=data.get('operation');require(isinstance(operation,str) and 16<=len(operation)<=80 and all(ch.isalnum() or ch in '-_' for ch in operation))
  objective=text(data.get('objective'),4000)
  criteria=text(data.get('criteria') or 'Livrer des fichiers locaux utilisables répondant à l’objectif ; documenter les hypothèses ; exécuter les tests ; obtenir les revues indépendantes QA et Security ; fournir une synthèse CTO sourcée et les limites. Aucun déploiement, secret, donnée client, donnée financière ou envoi externe.',2000)
  kind=data.get('mission_type',infer_mission_type(objective,criteria));require(kind in ('web','general'),400,'mission_type_invalid')
  digest=hashlib.sha256(json.dumps([objective,criteria,scope,repo,kind],sort_keys=True).encode()).hexdigest()
  existing=c.execute('select * from mission_requests where user=? and generation=? and operation=?',(user['id'],user['generation'],operation)).fetchone()
  if existing:
   legacy_request=hashlib.sha256(json.dumps([objective,criteria,scope,repo],sort_keys=True).encode()).hexdigest()
   require(existing['digest']==digest or (existing['digest']==legacy_request and pipeline_spec(c,existing['mission'])['version']=='legacy-v1'),409,'mission_version_changed')
   row=c.execute('select id,state from mission_flows where id=?',(existing['mission'],)).fetchone();require(row,409,'mission_state_denied')
   return {'id':row['id'],'state':row['state'],'duplicate':True}
  require(c.execute("select count(*) from mission_flows where user=? and state in ('queued','running','cancel_requested')",(user['id'],)).fetchone()[0]==0,409,'mission_already_pending')
  m=dispatch(store,c,user,'mission-create',{'scope':scope,'repository':repo,'objective':objective,'criteria':criteria,'mission_type':kind},require,text)
  result=dispatch(store,c,user,'mission-launch',{'mission':m['id'],'digest':m['digest'],'provider_consent':True,'internal_only':True,'project_sandbox_consent':scope=='github-project-sandbox','draft_pr_consent':scope=='github-project-sandbox'},require,text)
  c.execute('insert into mission_requests values(?,?,?,?,?)',(user['id'],user['generation'],operation,digest,m['id']));stamp(c,m['id'],'objective_execution_requested')
  return result
 if path=='mission-create':
  scope=data.get('scope','awema-internal-sandbox');repo=data.get('repository','')
  require(scope in ('awema-internal-sandbox','github-project-sandbox'),403,'mission_scope_denied')
  if scope=='github-project-sandbox':require(repo in PROJECT_REPOSITORIES,403,'project_repository_denied')
  else:require(scope=='awema-internal-sandbox' and not repo,403,'internal_scope_required')
  objective=text(data.get('objective'),4000);criteria=text(data.get('criteria'),2000)
  require(c.execute('select count(*) from mission_flows where user=? and created>?',(user['id'],time.time()-86400)).fetchone()[0]<MISSION_DRAFT_DAILY_LIMIT,429,'daily_limit')
  kind=data.get('mission_type',infer_mission_type(objective,criteria));require(kind in ('web','general'),400,'mission_type_invalid');spec=new_pipeline(kind)
  mid='f_'+secrets.token_hex(12);digest=mission_digest(objective,criteria,spec,scope,repo);now=time.time()
  c.execute('insert into mission_flows values(?,?,?,?,?,?,?,?,?,?,?)',(mid,user['id'],user['generation'],objective,criteria,digest,'plan',now,now,None,''))
  c.execute('insert into mission_project_targets values(?,?,?)',(mid,scope,repo))
  plan_raw=canonical_plan(spec['plan']);c.execute('insert into mission_pipeline_specs values(?,?,?,?,?)',(mid,spec['version'],kind,plan_raw,hashlib.sha256(plan_raw.encode()).hexdigest()))
  for i,item in enumerate(spec['plan']):c.execute('insert into mission_steps values(?,?,?,?,?,?,?)',(mid,i,item['role'],None,'waiting','',None))
  stamp(c,mid,'plan_created');store.audit(c,user['id'],'mission_plan_created',mid);return {'id':mid,'state':'plan','digest':digest,'scope':scope,'repository':repo}
 row=c.execute('select * from mission_flows where id=?',(data.get('mission'),)).fetchone();require(row and (row['user']==user['id'] or (user['role']=='owner' and path in ('mission-artifact','mission-recover'))),403,'mission_denied');mid=row['id']
 if path=='mission-artifact':
  r=c.execute('select name,sha256,content from mission_artifacts where mission=? and ordinal=? and name=?',(mid,data.get('ordinal'),data.get('name'))).fetchone();require(r,404,'artifact_missing');return dict(r)
 if path=='mission-launch':
  require(valid(row,user),403,'mission_activation_changed')
  selected=target(c,mid)
  if selected['scope']=='github-project-sandbox':
   require(selected['repository'] in PROJECT_REPOSITORIES and data.get('project_sandbox_consent') is True and data.get('draft_pr_consent') is True,403,'project_scope_not_authorized')
  try:approved=approved_digests(c,row,selected['scope'],selected['repository'])
  except ValueError:require(False,409,'mission_pipeline_changed')
  require(row['digest'] in approved,409,'mission_version_changed')
  require(data.get('digest')==row['digest'],409,'mission_version_changed');require(data.get('provider_consent') is True and data.get('internal_only') is True,400,'provider_consent_required')
  if row['state']!='plan':return {'id':mid,'state':row['state'],'duplicate':True}
  require(capacity(c)['available']>0,429,'mission_daily_capacity')
  require(c.execute("select count(*) from mission_flows where user=? and state in ('queued','running','cancel_requested')",(user['id'],)).fetchone()[0]==0,409,'mission_already_pending')
  c.execute("update mission_flows set state='queued',approved=?,updated=? where id=?",(time.time(),time.time(),mid));stamp(c,mid,'human_plan_approved');store.audit(c,user['id'],'mission_plan_approved',mid);return {'id':mid,'state':'queued'}
 if path=='mission-cancel':
  require(valid(row,user),403,'mission_activation_changed')
  require(row['state'] in ('plan','queued','running','cancel_requested'),409,'mission_state_denied');state='cancelled' if row['state'] in ('plan','queued') else 'cancel_requested'
  c.execute('update mission_flows set state=?,updated=? where id=?',(state,time.time(),mid));stamp(c,mid,'human_cancel_requested');store.audit(c,user['id'],'mission_cancel_requested',mid);return {'id':mid,'state':state}
 if path=='mission-recover':
  require(valid(row,user) or user['role']=='owner',403,'mission_activation_changed')
  require(row['state']=='blocked',409,'mission_state_denied')
  decision=data.get('decision');require(decision in ('retry','continue'),400,'recovery_decision_invalid')
  require(data.get('acknowledged') is True,400,'blocker_acknowledgement_required')
  note=data.get('note','');require(isinstance(note,str) and len(note)<=1000,400,'recovery_note_invalid');note=note.strip()
  step=c.execute("select ordinal,role,task,state from mission_steps where mission=? and state='blocked' order by ordinal limit 1",(mid,)).fetchone()
  require(step is not None,409,'recovery_step_missing')
  attempts=c.execute('select count(*) from mission_step_attempts where mission=? and ordinal=?',(mid,step['ordinal'])).fetchone()[0]
  require(attempts<5,409,'recovery_limit_reached')
  pending=c.execute("select 1 from mission_recovery_requests where mission=? and state='pending'",(mid,)).fetchone()
  require(pending is None,409,'recovery_already_pending')
  now=time.time();c.execute('insert or replace into mission_recovery_requests values(?,?,?,?,?,?,?)',(mid,step['ordinal'],decision,note,user['id'],now,'pending'))
  state='queued';message='Reprise demandée : la Ruche vérifie que l’ancienne exécution est terminée avant de continuer.'
  c.execute('update mission_flows set state=?,blocker=?,updated=? where id=?',(state,message,now,mid))
  stamp(c,mid,'human_'+('retry_requested' if decision=='retry' else 'continue_requested'));store.audit(c,user['id'],'mission_'+decision+'_requested',mid)
  return {'id':mid,'state':state,'recovery':'pending','message':message}
 require(path=='mission-review',404,'route_missing');require(valid(row,user),403,'mission_activation_changed');require(row['state']=='review',409,'mission_state_denied');decision=data.get('decision');require(decision in ('accepted','correction_requested'))
 note=text(data.get('comment'),1000)
 if decision=='correction_requested':
  cto_ordinal=role_ordinal(c,mid,'cto');correction=queue_correction(c,row,cto_ordinal,note,automatic=False)
  if correction['scheduled']:
   stamp(c,mid,'human_'+decision);store.audit(c,user['id'],'mission_'+decision,mid);return {'id':mid,'state':'queued','correction':correction}
  # A review rejection must always leave an inspectable step, rather than a
  # blocked mission whose five steps remain done and cannot be recovered.
  message=note+' La reprise automatique des changements de cette proposition nécessite une intervention opérateur ('+correction['reason_code']+').'
  c.execute("update mission_steps set state='blocked',summary=? where mission=? and ordinal=?",(message,mid,cto_ordinal))
  c.execute("update mission_flows set state='blocked',blocker=?,updated=? where id=?",(message,time.time(),mid))
  stamp(c,mid,'human_'+decision);store.audit(c,user['id'],'mission_'+decision,mid);return {'id':mid,'state':'blocked','reason_code':correction['reason_code']}
 c.execute("update mission_flows set state='delivered',blocker='',updated=? where id=?",(time.time(),mid));stamp(c,mid,'human_'+decision);store.audit(c,user['id'],'mission_'+decision,mid);return {'id':mid,'state':'delivered'}
