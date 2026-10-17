import json,time
from live_catalog import LIVE_ROLES
from activity_schema import integer
def validate(v,clock=None):
 clock=int(time.time()) if clock is None else int(clock)
 if not isinstance(v,dict) or set(v)!={'version','observed_at','roles'} or type(v['version']) is not int or v['version']!=1 or not integer(v['observed_at'],clock-30,clock+5):raise ValueError('schema/TTL')
 if not isinstance(v['roles'],list) or len(v['roles'])!=9:raise ValueError('roles')
 seen=set()
 for r in v['roles']:
  if not isinstance(r,dict) or set(r)!={'role','worker_running','started','state'}:raise ValueError('row')
  if r['role'] not in LIVE_ROLES or r['role'] in seen or r['state'] not in {'running','finished','unknown'}:raise ValueError('identity')
  seen.add(r['role'])
  if r['worker_running'] is not None and type(r['worker_running']) is not bool:raise ValueError('running')
  if not integer(r['started'],0,clock+5):raise ValueError('time')
  expected='unknown' if r['worker_running'] is None else 'running' if r['worker_running'] else 'finished'
  if r['state']!=expected:raise ValueError('state consistency')
 return v
def load(path,clock=None):
 try:
  with path.open('rb') as f:raw=f.read(8193)
  if len(raw)>8192:raise ValueError('size')
  return {'available':True,**validate(json.loads(raw),clock)}
 except (OSError,ValueError,TypeError,KeyError,UnicodeError):return {'available':False,'reason':'unavailable_or_stale'}
