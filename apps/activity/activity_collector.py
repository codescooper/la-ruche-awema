"""Persistent host-only read-only metadata projection. Fixed inputs; no credentials."""
import json,os,sqlite3,time,uuid
from contextlib import closing
from pathlib import Path
from activity_schema import validate,STATUSES
from live_catalog import LIVE_UIDS
AI=Path('/opt/awema-ai/data');OUT=Path('/opt/awema-jury/activity/activity-v2.json')
def query(path,sql,args=()):
 for component in [path,*path.parents]:
  if component.is_symlink():raise ValueError('symlink input refused')
 with closing(sqlite3.connect(path.resolve().as_uri()+'?mode=ro',uri=True,timeout=.2)) as db:
  db.execute('PRAGMA query_only=ON');deadline=time.monotonic()+.25
  db.set_progress_handler(lambda:int(time.monotonic()>deadline),1000)
  return db.execute(sql,args).fetchall()
def collect(base=AI,clock=None):
 clock=int(time.time()) if clock is None else clock
 rows={role:{'role':role,'state':'unknown','observed_at':0,'session_available':False,'counts':{s:0 for s in sorted(STATUSES)}} for role in LIVE_UIDS}
 for role,r in rows.items():
  try:
   records=query(base/'profiles'/role/'state.db','SELECT last_activity_at,ended_at FROM sessions WHERE last_activity_at BETWEEN ? AND ? ORDER BY last_activity_at DESC LIMIT 1',(clock-86400,clock+5))
   r['session_available']=True
   if records:
    last,ended=records[0]
    if type(last) in (int,float) and 0<=last<=clock+5:r['observed_at']=int(last);r['state']='session_closed' if ended else 'recent' if clock-last<180 else 'unknown'
  except (OSError,sqlite3.Error,ValueError,TypeError):pass
 kanban=False;unknown=0
 try:
  for role,status,count in query(base/'kanban/boards/awema-agency/kanban.db',"SELECT assignee,status,count(*) FROM tasks WHERE project_id IS NULL OR project_id='awema-ai-team' GROUP BY assignee,status"):
   if role not in rows:unknown=min(99,unknown+count);continue
   if status in STATUSES:rows[role]['counts'][status]=min(99,count)
  kanban=True
 except (OSError,sqlite3.Error,ValueError,TypeError):pass
 if kanban:
  for r in rows.values():
   c=r['counts']
   if c['running']+c['in_progress']:r['state']='task_running'
   elif c['todo']+c['ready']+c['scheduled']+c['blocked']+c['triage']+c['review']:r['state']='waiting'
 available=sum(r['session_available'] for r in rows.values())
 return validate({'version':2,'observed_at':clock,'sources':{'hermes':'available' if available==9 else 'partial' if available else 'unavailable','kanban':kanban},'roles':list(rows.values()),'unknown_assignees':unknown},clock)
def once():
 from team_collector import collect_team
 owner=Path('/opt/awema-jury/owner-data/team-v2.json')
 gid=10001 # Existing reader group, verified by installer before activation.
 publish(collect(),OUT,0o644)
 publish(collect_team(),owner,0o640,gid)
def publish(data,path,mode,gid=None):
 temp=path.with_name(path.name+'-'+uuid.uuid4().hex+'.tmp')
 fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'w') as f:
  json.dump(data,f,separators=(',',':'));f.flush();os.fchmod(f.fileno(),mode)
  if gid is not None:os.fchown(f.fileno(),0,gid)
  os.fsync(f.fileno())
 os.replace(temp,path);fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(fd)
 finally:os.close(fd)
if __name__=='__main__':
 while True:
  started=time.monotonic()
  try:once()
  except Exception:print('activity_projection_unavailable',flush=True)
  time.sleep(max(.1,5-(time.monotonic()-started)))
