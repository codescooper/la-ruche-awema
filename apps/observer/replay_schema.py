"""Public replay contains only allowlisted lifecycle metadata, never task text."""
import json
import re
import time
from catalog import ROLE_IDS

STATES = {'triage','todo','running','review','done','blocked','cancelled','unknown'}
KINDS = {'created':0,'started':1,'completed':2}

def validate(value, now=None):
    now = int(time.time() if now is None else now)
    if type(value) is not dict or set(value)!={'observed_at','replays'}:raise ValueError('schema')
    if type(value['observed_at']) is not int or not now-90<=value['observed_at']<=now+10:raise ValueError('stale')
    if type(value['replays']) is not list or len(value['replays'])>20:raise ValueError('size')
    seen=set()
    for row in value['replays']:
        if type(row) is not dict or set(row)!={'ref','role','status','events'}:raise ValueError('row')
        if type(row['ref']) is not str or not re.fullmatch(r'R-[a-f0-9]{24}',row['ref']) or row['ref'] in seen:raise ValueError('ref')
        seen.add(row['ref'])
        if row['role'] not in (*ROLE_IDS,'unknown') or row['status'] not in STATES:raise ValueError('enum')
        if type(row['events']) is not list or not 1<=len(row['events'])<=3:raise ValueError('events')
        previous=-1;stamp=0
        for event in row['events']:
            if type(event) is not dict or set(event)!={'kind','at'}:raise ValueError('event')
            kind=event['kind'];at=event['at']
            if kind not in KINDS or KINDS[kind]<=previous or type(at) is not int or not max(1,stamp)<=at<=now+10:raise ValueError('order')
            previous=KINDS[kind];stamp=at
    return value

def load(path,now=None):
    try:
        with path.open('rb') as f:raw=f.read(24001)
        if len(raw)>24000:raise ValueError('size')
        return {'available':True,**validate(json.loads(raw),now)}
    except (OSError,ValueError,TypeError,KeyError):
        return {'available':False,'reason':'unavailable_or_stale'}
