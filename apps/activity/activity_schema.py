import json,time
from live_catalog import LIVE_ROLES
TTL=30
STATES={'unknown','recent','session_closed','task_running','waiting'}
STATUSES={'todo','ready','scheduled','running','in_progress','blocked','triage','review','done','cancelled'}
def integer(v,lo,hi):return type(v) is int and lo<=v<=hi
def validate(v,clock=None):
 clock=int(time.time()) if clock is None else clock
 if not isinstance(v,dict) or set(v)!={'version','observed_at','sources','roles','unknown_assignees'}:raise ValueError('schema')
 if type(v['version']) is not int or v['version']!=2 or not integer(v['observed_at'],clock-TTL,clock+5):raise ValueError('freshness')
 if not isinstance(v['sources'],dict) or set(v['sources'])!={'hermes','kanban'}:raise ValueError('sources')
 if v['sources']['hermes'] not in {'available','partial','unavailable'} or type(v['sources']['kanban']) is not bool:raise ValueError('sources')
 if not integer(v['unknown_assignees'],0,99):raise ValueError('unknown')
 if not isinstance(v['roles'],list) or len(v['roles'])!=9:raise ValueError('roles')
 seen=set()
 for r in v['roles']:
  if not isinstance(r,dict) or set(r)!={'role','state','observed_at','session_available','counts'}:raise ValueError('row')
  if r['role'] not in LIVE_ROLES or r['role'] in seen or r['state'] not in STATES:raise ValueError('identity')
  seen.add(r['role'])
  if not integer(r['observed_at'],0,clock+5) or type(r['session_available']) is not bool:raise ValueError('source')
  if not isinstance(r['counts'],dict) or set(r['counts'])!=STATUSES or any(not integer(n,0,99) for n in r['counts'].values()):raise ValueError('counts')
 return v
def load(path,clock=None):
 try:
  with path.open('rb') as f:raw=f.read(16001)
  if len(raw)>16000:raise ValueError('size')
  v=validate(json.loads(raw),clock)
  return {'available':v['sources']['hermes']!='unavailable' or v['sources']['kanban'],**v}
 except (OSError,ValueError,TypeError,KeyError,UnicodeError):return {'available':False,'reason':'unavailable_or_stale'}
