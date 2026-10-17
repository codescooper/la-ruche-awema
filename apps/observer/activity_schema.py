"""Closed vocabulary for the read-only activity projection. No free-text field."""
import json, time
from catalog import ROLE_IDS

STATES={'unknown','recent','session_closed','task_running','waiting'}
SOURCES={'hermes','kanban','gateway'}
def integer(v,lo,hi):return type(v) is int and lo<=v<=hi
def validate(value,clock=None):
    clock=int(time.time()) if clock is None else clock
    if not isinstance(value,dict) or set(value)!={'version','observed_at','sources','roles','gateway_busy'}:raise ValueError('schema')
    if type(value['version']) is not int or value['version']!=1 or not integer(value['observed_at'],clock-90,clock+10):raise ValueError('stale')
    if type(value['gateway_busy']) is not bool:raise ValueError('gateway')
    if not isinstance(value['sources'],dict) or set(value['sources'])!=SOURCES or any(type(v) is not bool for v in value['sources'].values()):raise ValueError('sources')
    if not isinstance(value['roles'],list) or len(value['roles'])!=len(ROLE_IDS):raise ValueError('roles')
    seen=set()
    for r in value['roles']:
        if not isinstance(r,dict) or set(r)!={'role','state','observed_minute','running_cards','waiting_cards'}:raise ValueError('row')
        if r['role'] not in ROLE_IDS or r['role'] in seen or r['state'] not in STATES:raise ValueError('role_state')
        seen.add(r['role'])
        if not integer(r['observed_minute'],0,clock//60+1):raise ValueError('timestamp')
        if not integer(r['running_cards'],0,99) or not integer(r['waiting_cards'],0,99):raise ValueError('counts')
    return value

def load(path,clock=None):
    try:
        with path.open('rb') as f:raw=f.read(16001)
        if len(raw)>16000:raise ValueError('size')
        v=validate(json.loads(raw),clock)
        if not any(v['sources'].values()):return {'available':False,'reason':'sources_unavailable'}
        return {'available':True,**v}
    except (OSError,ValueError,TypeError,KeyError,UnicodeError):
        return {'available':False,'reason':'unavailable_or_stale'}
