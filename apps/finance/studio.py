"""Private conversations and mission preparation. No execution authority."""
import json,secrets,time
import mission_flow

GENERAL={'cto','pm','dev','designer','security','ops','assa','cl-producer'}
FINANCIAL={'assistant','accounting','finance','qa'}
def visible(c,user,project):
 if project=='__personal_chat__':return True
 return bool(c.execute('select 1 from projects where id=? and id not in (select project from project_archive)',(project,)).fetchone() and (user['role'] in ('owner','director') or c.execute('select 1 from grants where user=? and project=?',(user['id'],project)).fetchone()))
SCHEMA='''
CREATE TABLE IF NOT EXISTS studio_threads(id TEXT PRIMARY KEY,user TEXT,generation INTEGER,agent TEXT,project TEXT,title TEXT,created REAL);
CREATE TABLE IF NOT EXISTS studio_messages(id TEXT PRIMARY KEY,thread TEXT,job TEXT UNIQUE,prompt TEXT,created REAL);
CREATE TABLE IF NOT EXISTS studio_positions(user TEXT,agent TEXT,x INTEGER,y INTEGER,PRIMARY KEY(user,agent));
CREATE TABLE IF NOT EXISTS studio_missions(id TEXT PRIMARY KEY,user TEXT,generation INTEGER,agent TEXT,objective TEXT,criteria TEXT,state TEXT,created REAL);
'''
def dispatch(store,c,user,method,path,data,require,text):
 actor=user['id'];agents=FINANCIAL | (GENERAL if user['role'] in ('owner','director') else set())
 if path=='studio-board':
  require(user['role'] in ('owner','director'),403,'director_required')
  if not c.execute("select 1 from sqlite_master where name='studio_board_meta'").fetchone():return {'available':False}
  meta=c.execute('select observed,available from studio_board_meta where id=1').fetchone()
  if not meta or not meta['available'] or not time.time()-30<=meta['observed']<=time.time()+5:return {'available':False}
  page=data.get('page',0);require(type(page) is int and 0<=page<=1000)
  query=data.get('query','');require(isinstance(query,str) and len(query)<=160)
  pattern='%'+query.replace('\\','\\\\').replace('%','\\%').replace('_','\\_')+'%'
  clause="where (title like ? escape '\\' or role like ? escape '\\' or id like ? escape '\\')";args=(pattern,pattern,pattern)
  total=c.execute('select count(*) from studio_board '+clause,args).fetchone()[0]
  counts={r['state']:r['n'] for r in c.execute('select state,count(*) n from studio_board group by state')}
  tasks=[dict(r) for r in c.execute('select id,title,role,state as status,created as created_at,runs as run_count from studio_board '+clause+' order by created desc,id limit 50 offset ?',(*args,page*50))]
  active_roles=[r['role'] for r in c.execute("select distinct role from studio_board where state in ('running','in_progress')")]
  return {'available':True,'observed_at':meta['observed'],'total':total,'pages':max(1,(total+49)//50),'page':page,'tasks':tasks,'counts':counts,'active_roles':active_roles,'scope':'awema-internal'}
 if path=='studio':
  threads=[dict(r) for r in c.execute('select * from studio_threads where user=? and generation=? order by created desc limit 100',(actor,user['generation'])) if r['agent'] in agents and visible(c,user,r['project'])]
  ids={r['id'] for r in threads};messages=[]
  for r in c.execute('select m.*,j.state,j.response from studio_messages m join studio_threads t on t.id=m.thread join jobs j on j.id=m.job where t.user=? and t.generation=? order by m.created desc limit 200',(actor,user['generation'])):
   if r['thread'] in ids:messages.append(dict(r))
  return {'agents':sorted(agents),'threads':threads,'messages':messages,'positions':[dict(r) for r in c.execute('select agent,x,y from studio_positions where user=?',(actor,)) if r['agent'] in agents], 'missions':[dict(r) for r in c.execute('select id,agent,objective,criteria,state,created from studio_missions where user=? and generation=? order by created desc limit 50',(actor,user['generation'])) if r['agent'] in agents],'native_execution_enabled':True,'flows':mission_flow.snapshot(c,user),'mission_capacity':mission_flow.capacity(c) if user['role'] in ('owner','director') else None,'execution_scope':'awema-internal-sandbox','project_repositories':sorted(mission_flow.PROJECT_REPOSITORIES) if user['role'] in ('owner','director') else []}
 require(user['role']!='reader',403,'write_denied')
 if path=='studio-position':
  agent=data.get('agent');require(agent in agents,403,'agent_denied');x=data.get('x');y=data.get('y');require(type(x) is int and type(y) is int and 0<=x<=27 and 0<=y<=15)
  c.execute('insert or replace into studio_positions values(?,?,?,?)',(actor,agent,x,y));return {'saved':True,'execution_unchanged':True}
 if path=='studio-mission':
  agent=data.get('agent');require(agent in agents,403,'agent_denied');objective=text(data.get('objective'),4000);criteria=text(data.get('criteria'),2000)
  require(c.execute('select count(*) from studio_missions where user=? and created>?',(actor,time.time()-86400)).fetchone()[0]<20,429,'daily_limit')
  mid='m_'+secrets.token_hex(12);c.execute('insert into studio_missions values(?,?,?,?,?,?,?,?)',(mid,actor,user['generation'],agent,objective,criteria,'prepared',time.time()));store.audit(c,actor,'private_mission_prepared',mid)
  return {'id':mid,'state':'prepared','worker_started':False,'native_execution_enabled':False}
 require(path=='studio-chat',404,'route_missing');agent=data.get('agent');require(agent in agents,403,'agent_denied')
 require(data.get('provider_consent') is True,400,'provider_consent_required');prompt=text(data.get('message'),4000);include_context=data.get('include_context') is True;tid=data.get('thread');project=data.get('project') or '__personal_chat__'
 if agent in GENERAL:require(project=='__personal_chat__',403,'general_financial_context_denied')
 if project!='__personal_chat__':store.project(c,user,project)
 require(c.execute('select count(*) from jobs where user=? and created>?',(actor,time.time()-86400)).fetchone()[0]<20,429,'daily_limit')
 require(c.execute("select count(*) from jobs where user=? and state in ('queued','processing')",(actor,)).fetchone()[0]==0,409,'job_already_pending')
 if tid:
  thread=c.execute('select * from studio_threads where id=? and user=? and generation=?',(tid,actor,user['generation'])).fetchone();require(thread and thread['agent']==agent and thread['project']==project,403,'thread_denied')
 else:
  require(c.execute('select count(*) from studio_threads where user=? and generation=?',(actor,user['generation'])).fetchone()[0]<100,429,'thread_limit');tid='c_'+secrets.token_hex(12)
  c.execute('insert into studio_threads values(?,?,?,?,?,?,?)',(tid,actor,user['generation'],agent,project,prompt[:80],time.time()))
 history=[]
 if include_context:
  rows=list(c.execute("select m.prompt,j.response from studio_messages m join jobs j on j.id=m.job where m.thread=? and j.state='done' order by m.created desc limit 3",(tid,)))
  for row in reversed(rows):history.extend([{'role':'user','content':row['prompt'][:2000]},{'role':'assistant','content':row['response'][:3000]}])
 context=json.loads(user['context']) if include_context else {}
 context.update(human_role=user['role'],specialist=agent,mode='private_conversation',history=history,scope='AWEMA internal conversation only; no terminal, production access or financial effects')
 if project!='__personal_chat__':
  p=c.execute('select * from projects where id=?',(project,)).fetchone();context['project']={'id':p['id'],'name':p['name'],'currency':p['currency']}
 jid='j_'+secrets.token_hex(12);c.execute('insert into jobs values(?,?,?,?,?,?,?,?,?,?)',(jid,actor,user['generation'],project,agent,prompt,json.dumps(context),'queued',None,time.time()))
 c.execute('insert into studio_messages values(?,?,?,?,?)',('s_'+secrets.token_hex(12),tid,jid,prompt,time.time()));store.audit(c,actor,'private_chat_requested',jid)
 return {'thread':tid,'id':jid,'state':'queued','tools_enabled':False}
