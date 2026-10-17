"""Fixed metadata-only SQL. No reasoning/system fields or arbitrary content read.

Links: task_runs.metadata.worker_session_id -> kanban root -> exact session parents.
No inference of specialists from time or model prose. Tool responses are records,
not evidence of successful execution. Run as UID10000 via fixed operator transport.
Optional operator-reviewed trace_story verifies hashes of five fixed messages;
its local content reads never export message contents, only reviewed constants.
"""
import hashlib
import json
import os
import re
import sqlite3
import time
from collections import Counter
from contextlib import closing
from pathlib import Path
from catalog import ROLE_IDS
from owner_reader import BOARD_MAP, timestamp
from replay_schema import STATES
from trace_schema import PROVENANCE, safe_id, validate, public_projection
try:
    from trace_story import get_story
except ImportError:
    get_story=None


def connect(path):
    db=sqlite3.connect(path.resolve().as_uri()+'?mode=ro',uri=True,timeout=2)
    db.execute('PRAGMA query_only=ON')
    return db


def category(name):
    if name=='delegate_task':return 'delegate'
    if name in ('read_file','read_files','file_read','list_directory'):return 'read'
    if name in ('write_file','file_write','patch','apply_patch','edit_file'):return 'write'
    if name in ('terminal','execute_code','python','bash'):return 'execute'
    if name in ('web_search','web_extract','search_files','search','grep'):return 'search'
    if name in ('kanban','todo','task','task_create','task_update'):return 'task'
    return 'other'


def title(text):
    # Bounded owner-only title. Obvious credential-like tokens are redacted.
    text=str(text or 'Mission sans titre')[:1000]
    text=re.sub(r'https?://\S+|\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b','[masqué]',text)
    text=re.sub(r'\b(?:sk-|ghp_|gho_|github_pat_|eyJ|re_)[A-Za-z0-9_.-]+|[A-Za-z0-9_+/=-]{32,}','[masqué]',text)
    text=re.sub(r'(?i)(password|token|secret|clé|mot de passe)\s*[:=]\s*\S+',r'\1=[masqué]',text)
    return ''.join(c if ord(c)>=32 else ' ' for c in text).strip()[:160] or 'Mission sans titre'


def session_trace(db,root,role,now):
    sessions=[root];ids={root[0]:'a0'};actors=[{'id':'a0','parent':None,'role':role}];truncated=False
    for current in sessions:
        children=db.execute('SELECT id,parent_session_id,profile_name,started_at,ended_at,source '
                            'FROM sessions WHERE parent_session_id=? ORDER BY started_at,id LIMIT 17',(current[0],)).fetchall()
        for child in children:
            if len(sessions)>=16:truncated=True;break
            if not safe_id(child[0]) or child[0] in ids or child[5]!='kanban':continue
            if timestamp(child[3],now)<timestamp(root[3],now):continue
            actor='a'+str(len(sessions));ids[child[0]]=actor;sessions.append(child)
            actors.append({'id':actor,'parent':ids[current[0]],'role':'unknown'})
    steps=[]
    for session in sessions:
        sid=session[0];actor=ids[sid];calls={}
        def event(at,kind,action,message=None,tool=None):
            if at:steps.append({'at':at,'actor':actor,'kind':kind,'action':action,
                'source_message_id':None if message is None else str(message),
                'source_session_id':sid,'tool_name':tool})
        event(timestamp(session[3],now),'session_start','session')
        # JSON1 projects only function names and call IDs inside SQLite. Never
        # transfer tool_calls arguments or message content into the reader process.
        messages=db.execute("SELECT m.id,m.role,m.tool_name,m.tool_call_id,m.timestamp,"
            "(SELECT json_group_array(json_object('id',json_extract(j.value,'$.id'),"
            "'name',json_extract(j.value,'$.function.name'))) FROM json_each("
            "CASE WHEN json_valid(m.tool_calls) THEN m.tool_calls ELSE '[]' END) j "
            "WHERE j.type='object' AND j.key<32) FROM messages m "
            "WHERE m.session_id=? AND m.role IN ('assistant','tool') "
            "ORDER BY m.timestamp,m.id LIMIT 201",(sid,)).fetchall()
        if len(messages)>200:truncated=True
        for mid,mrole,mtool,callid,stamp,tools in messages[:200]:
            if not safe_id(str(mid)):continue
            at=timestamp(stamp,now)
            if at<timestamp(session[3],now):continue
            if mrole=='assistant':
                for call in json.loads(tools or '[]'):
                    ident,name=call['id'],call['name']
                    if not safe_id(ident) or not safe_id(name) or len(name)>80 or ident in calls:continue
                    calls[ident]=name;event(at,'tool_call',category(name),mid,name)
            elif safe_id(callid) and callid in calls:
                name=calls.pop(callid)
                if mtool and mtool!=name:continue
                event(at,'tool_result',category(name),mid,name)
        event(timestamp(session[4],now),'session_end','session')
    steps.sort(key=lambda s:(s['at'],0 if s['kind']=='session_start' else 3 if s['kind']=='session_end' else 1 if s['kind']=='tool_call' else 2))
    return actors,steps[:200],[s[0] for s in sessions],truncated or len(steps)>200


def collect(base=Path('/opt/data'),now=None):
    now=int(time.time() if now is None else now);candidates=[];sources={a:False for a in BOARD_MAP.values()}
    for board,alias in BOARD_MAP.items():
        try:
            with closing(connect(base/'kanban/boards'/board/'kanban.db')) as db:
                tasks=db.execute('SELECT id,assignee,status,substr(title,1,1000),session_id,created_at,started_at,completed_at '
                    'FROM tasks ORDER BY MAX(COALESCE(created_at,0),COALESCE(started_at,0),COALESCE(completed_at,0)) DESC,id LIMIT 20').fetchall()
                for task in tasks:
                    if not safe_id(task[0]):continue
                    # Exact DB-owned metadata field; no summary/error/result text.
                    run=db.execute("SELECT profile,started_at,ended_at,CASE WHEN json_valid(metadata) "
                        "THEN json_extract(metadata,'$.worker_session_id') ELSE NULL END "
                        "FROM task_runs WHERE task_id=? ORDER BY started_at DESC,id DESC LIMIT 1",(task[0],)).fetchone()
                    candidates.append((board,alias,task,run))
            sources[alias]=True
        except (OSError,sqlite3.Error,ValueError,TypeError):
            candidates=[x for x in candidates if x[1]!=alias]
    candidates.sort(key=lambda c:max(timestamp(v,now) for v in c[2][5:]),reverse=True)
    links=Counter(c[3][3] for c in candidates if c[3] and safe_id(c[3][3]))
    traces=[];used_roots=set()
    for board,alias,task,run in candidates[:20]:
        ident,role,status,label,declared,*_=task
        role=role if type(role) is str and role in ROLE_IDS else 'unknown'
        row={'ref':'R-'+hashlib.sha256(('public-replay\0'+board+'\0'+ident).encode()).hexdigest()[:24],
            'title':title(label),'role':role,'status':status if status in STATES else 'unknown',
            'coverage':'unlinked','actors':[],'steps':[],'truncated':False,
            'source':{'task_id':ident,'board':alias,'session_ids':[]}}
        try:
            if not run or not safe_id(run[3]) or links[run[3]]!=1 or run[3] in used_roots or (declared and declared!=run[3]):raise ValueError('link')
            with closing(connect(base/'profiles/cto/state.db')) as db:
                root=db.execute('SELECT id,parent_session_id,profile_name,started_at,ended_at,source FROM sessions WHERE id=?',(run[3],)).fetchone()
                if not root or root[1] is not None or root[5]!='kanban' or root[2]!=run[0]:raise ValueError('link')
                role=run[0] if run[0] in ROLE_IDS else 'unknown'
                row['role']=role
                start=timestamp(root[3],now)
                if not max(1,timestamp(run[1],now)-30)<=start<=(timestamp(run[2],now) or now)+10:raise ValueError('run_window')
                actors,steps,sids,truncated=session_trace(db,root,role,now)
                if get_story:
                    story=get_story(db,ident,root[0],{sid:'a'+str(i) for i,sid in enumerate(sids)})
                    if story:row['story']=story
            row.update(coverage='linked',actors=actors,steps=steps,truncated=truncated)
            row['source']['session_ids']=sids;used_roots.add(run[3])
        except (OSError,sqlite3.Error,ValueError,TypeError,OverflowError):pass
        traces.append(row)
    private=validate({'version':1,'observed_at':now,'provenance':PROVENANCE,'sources':sources,'traces':traces},now,private=True)
    return {'public':public_projection(private,now),'private':private}


if __name__=='__main__':
    if not hasattr(os,'geteuid') or os.geteuid()!=10000:raise SystemExit('trace_reader_wrong_uid')
    print(json.dumps(collect(),separators=(',',':')))
