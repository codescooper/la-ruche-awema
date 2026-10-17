"""Closed, anonymous classroom observation. No tasks, names, prompts or results."""
import json,re,time
from catalog import ROLE_IDS
SKINS={'honey','sage','violet','blue'}
KINDS={'step_completed','received','routed','completed','failed','needs_input','refused','cancelled'}
def integer(v,lo,hi):return type(v) is int and lo<=v<=hi
def validate(v,now=None):
 now=int(time.time()) if now is None else now
 if not isinstance(v,dict) or set(v)!={'version','observed_at','source_confirmed','online','visitors','events'}:raise ValueError('schema')
 if type(v['version']) is not int or v['version']!=1 or not integer(v['observed_at'],now-90,now+10):raise ValueError('time')
 if type(v['source_confirmed']) is not bool or type(v['online']) is not bool:raise ValueError('flags')
 if not isinstance(v['visitors'],list) or len(v['visitors'])>8:raise ValueError('visitors')
 seen={'external'}
 for a in v['visitors']:
  if not isinstance(a,dict) or set(a)!={'id','skin','online'}:raise ValueError('visitor')
  if not isinstance(a['id'],str) or not re.fullmatch('[a-f0-9]{12}',a['id']) or a['id'] in seen:raise ValueError('identity')
  if not isinstance(a['skin'],str) or a['skin'] not in SKINS or type(a['online']) is not bool:raise ValueError('skin')
  seen.add(a['id'])
 if not isinstance(v['events'],list) or len(v['events'])>30:raise ValueError('events')
 ids=set()
 for e in v['events']:
  if not isinstance(e,dict) or set(e)!={'id','kind','role','visitor','at'}:raise ValueError('event')
  if not isinstance(e['id'],str) or not re.fullmatch('[a-f0-9]{16}',e['id']) or e['id'] in ids:raise ValueError('event_id')
  ids.add(e['id'])
  if not isinstance(e['kind'],str) or e['kind'] not in KINDS or not isinstance(e['role'],str) or e['role'] not in ROLE_IDS or not isinstance(e['visitor'],str) or e['visitor'] not in seen:raise ValueError('reference')
  if not integer(e['at'],now-86400,now+10):raise ValueError('event_time')
 return v

def save(path,value):
 value=validate(value);temp=path.with_suffix('.tmp');temp.write_text(json.dumps(value,separators=(',',':')),encoding='utf-8');temp.replace(path)

def load(path):
 try:
  with path.open('rb') as f:raw=f.read(16001)
  if len(raw)>16000:raise ValueError('size')
  return {'available':True,**validate(json.loads(raw))}
 except (OSError,ValueError,TypeError,KeyError):return {'available':False}
