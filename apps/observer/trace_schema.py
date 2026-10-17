"""Strict public/private evidence projection; text never crosses to public."""
import json
import re
import time
from catalog import ROLE_IDS
from replay_schema import STATES

PROVENANCE = 'hermes-task-traces-v1'
MAX_BYTES = 2000000
ACTIONS = {'session', 'delegate', 'read', 'write', 'execute', 'search', 'task', 'other'}
KINDS = {'session_start', 'session_end', 'tool_call', 'tool_result'}
SOURCE_ID = re.compile(r'[A-Za-z0-9_.:-]{1,128}')


def safe_id(value):
    return type(value) is str and SOURCE_ID.fullmatch(value) is not None


def story_valid(story,now,actors):
    if type(story) is not dict or set(story)!={'title','objective','result','limitations','steps'}:raise ValueError('story')
    for key,maximum in [('title',160),('objective',1000),('result',1000),('limitations',1000)]:
        text=story[key]
        if type(text) is not str or not 1<=len(text)<=maximum or any(ord(c)<32 for c in text):raise ValueError('story_text')
    if type(story['steps']) is not list or len(story['steps'])>20:raise ValueError('story_steps')
    for step in story['steps']:
        if type(step) is not dict or set(step) not in ({'at','actor','text'},{'at','actor','text','scene'}):raise ValueError('story_step')
        if type(step['at']) is not int or not 1<=step['at']<=now+10 or step['actor'] not in actors:raise ValueError('story_actor')
        if type(step['text']) is not str or not 1<=len(step['text'])<=500 or any(ord(c)<32 for c in step['text']):raise ValueError('story_text')
        if 'scene' in step:
            scene=step['scene']
            if type(scene) is not dict or set(scene)!={'kind','speaker','recipient','tool'}:raise ValueError('scene')
            if scene['kind'] not in ('read','delegate','return','review','close') or scene['speaker'] not in ('cto','mentor','qa') or scene['recipient'] not in (None,'cto','mentor','qa') or scene['tool'] not in ('read','delegate','write','review','none'):raise ValueError('scene_enum')


def validate(value, now=None, private=False):
    now=int(time.time() if now is None else now)
    if type(value) is not dict or set(value)!={'version','observed_at','provenance','sources','traces'}:raise ValueError('schema')
    if type(value['version']) is not int or value['version']!=1 or value['provenance']!=PROVENANCE:raise ValueError('version')
    if type(value['observed_at']) is not int or not now-90<=value['observed_at']<=now+10:raise ValueError('stale')
    if type(value['sources']) is not dict or set(value['sources'])!={'B01','B02','B03'} or any(type(v) is not bool for v in value['sources'].values()):raise ValueError('sources')
    if type(value['traces']) is not list or len(value['traces'])>20:raise ValueError('traces')
    seen=set()
    for row in value['traces']:
        keys={'ref','title','role','status','coverage','actors','steps','truncated'}|({'source'} if private else set())
        if type(row) is not dict:raise ValueError('row')
        if 'story' in row:
            if type(row['story']) is not dict:raise ValueError('story')
            keys.add('story')
        if set(row)!=keys:raise ValueError('row')
        if type(row['ref']) is not str or not re.fullmatch(r'R-[a-f0-9]{24}',row['ref']) or row['ref'] in seen:raise ValueError('ref')
        seen.add(row['ref'])
        if type(row['title']) is not str or (not private and row['title']!='Mission observée' and row['title']!=row.get('story',{}).get('title')) or not 1<=len(row['title'])<=160 or any(ord(c)<32 for c in row['title']):raise ValueError('title')
        if type(row['role']) is not str or row['role'] not in (*ROLE_IDS,'unknown') or type(row['status']) is not str or row['status'] not in STATES:raise ValueError('enum')
        if row['coverage'] not in ('linked','unlinked') or type(row['truncated']) is not bool:raise ValueError('coverage')
        if type(row['actors']) is not list or len(row['actors'])>16 or type(row['steps']) is not list or len(row['steps'])>200:raise ValueError('limits')
        if row['coverage']=='unlinked' and (row['actors'] or row['steps']):raise ValueError('unlinked')
        if row['coverage']=='linked' and not row['actors']:raise ValueError('actors')
        actors=set()
        for index,actor in enumerate(row['actors']):
            if type(actor) is not dict or set(actor)!={'id','parent','role'} or actor['id']!='a'+str(index):raise ValueError('actor')
            if (index==0 and (actor['parent'] is not None or actor['role']!=row['role'])) or (index>0 and (type(actor['parent']) is not str or actor['parent'] not in actors or actor['role']!='unknown')):raise ValueError('lineage')
            actors.add(actor['id'])
        if 'story' in row:
            if row['coverage']!='linked':raise ValueError('story_unlinked')
            story_valid(row['story'],now,actors)
        if private:
            source=row['source']
            if type(source) is not dict or set(source)!={'task_id','board','session_ids'} or not safe_id(source['task_id']) or source['board'] not in ('B01','B02','B03'):raise ValueError('source')
            if type(source['session_ids']) is not list or len(source['session_ids'])!=len(actors) or any(not safe_id(s) for s in source['session_ids']) or len(set(source['session_ids']))!=len(actors):raise ValueError('sessions')
        previous=0
        for step in row['steps']:
            keys={'at','actor','kind','action'}|({'source_message_id','source_session_id','tool_name'} if private else set())
            if type(step) is not dict or set(step)!=keys:raise ValueError('step')
            if type(step['at']) is not int or not max(1,previous)<=step['at']<=now+10:raise ValueError('date')
            previous=step['at']
            if type(step['actor']) is not str or step['actor'] not in actors or step['kind'] not in KINDS or step['action'] not in ACTIONS:raise ValueError('step_enum')
            if step['kind'].startswith('session_') and step['action']!='session':raise ValueError('action')
            if private:
                if step['source_session_id']!=source['session_ids'][int(step['actor'][1:])]:raise ValueError('step_source')
                if step['source_message_id'] is not None and not safe_id(step['source_message_id']):raise ValueError('message')
                if step['tool_name'] is not None and (not safe_id(step['tool_name']) or len(step['tool_name'])>80):raise ValueError('tool')
    return value


def public_projection(private_value, now=None):
    validate(private_value,now,private=True)
    value={k:v for k,v in private_value.items() if k!='traces'}
    value['traces']=[]
    for row in private_value['traces']:
        public={k:v for k,v in row.items() if k not in ('source','steps','title')}
        public['title']=row['story']['title'] if 'story' in row else 'Mission observée'
        public['steps']=[{k:s[k] for k in ('at','actor','kind','action')} for s in row['steps']]
        value['traces'].append(public)
    return validate(value,now)


def load(path,now=None,private=False):
    try:
        with path.open('rb') as stream:raw=stream.read(MAX_BYTES+1)
        if len(raw)>MAX_BYTES:raise ValueError('size')
        data=validate(json.loads(raw),now,private)
        if not any(data['sources'].values()):raise ValueError('sources')
        return {'available':True,**data}
    except (OSError,ValueError,TypeError,KeyError,UnicodeError):
        return {'available':False,'reason':'unavailable_or_stale'}
