"""Owner-only native task metadata; not importable as public projection."""
import json,re,time
from live_catalog import LIVE_ROLES
from activity_schema import STATUSES,integer
KINDS={'created','run_started','run_ended'}
def validate(v,clock=None):
 clock=int(time.time()) if clock is None else int(clock)
 if not isinstance(v,dict) or set(v)!={'version','observed_at','available','truncated','tasks'}:raise ValueError('schema')
 if type(v['version']) is not int or v['version']!=1 or not integer(v['observed_at'],clock-30,clock+5):raise ValueError('TTL')
 if type(v['available']) is not bool or type(v['truncated']) is not bool or not isinstance(v['tasks'],list) or len(v['tasks'])>200:raise ValueError('tasks')
 seen=set();title_bytes=0
 for t in v['tasks']:
  if not isinstance(t,dict) or set(t)!={'id','title','role','status','created_at','events','run_count'}:raise ValueError('task')
  if not isinstance(t['id'],str) or not re.fullmatch(r't_[a-f0-9]{8}',t['id']) or t['id'] in seen:raise ValueError('id')
  seen.add(t['id'])
  if not isinstance(t['title'],str) or len(t['title'])>160 or any(ord(c)<32 for c in t['title']):raise ValueError('title')
  title_bytes+=len(t['title'].encode('utf-8'))
  if title_bytes>65536 or '<' in t['title'] or '>' in t['title']:raise ValueError('title bounds')
  if t['role'] not in LIVE_ROLES|{'unknown'} or t['status'] not in STATUSES|{'unknown'} or not integer(t['created_at'],0,clock+5) or not integer(t['run_count'],0,9999):raise ValueError('metadata')
  if not isinstance(t['events'],list) or len(t['events'])>5:raise ValueError('events')
  for e in t['events']:
   if not isinstance(e,dict) or set(e)!={'kind','at','profile','run_id'}:raise ValueError('event')
   if e['kind'] not in KINDS or not integer(e['at'],0,clock+5) or e['profile'] not in LIVE_ROLES|{'unknown'} or not integer(e['run_id'],0,2147483647):raise ValueError('event values')
 return v
def load(path,clock=None):
 try:
  with path.open('rb') as f:raw=f.read(512001)
  if len(raw)>512000:raise ValueError('size')
  return validate(json.loads(raw),clock)
 except (OSError,ValueError,TypeError,KeyError,UnicodeError):return {'available':False,'reason':'unavailable_or_stale'}
