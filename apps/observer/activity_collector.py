"""Operator-only projection: SQL metadata only, no message, title, prompt or credentials.

The website cannot execute this script or choose its inputs. Shared-profile sessions
without an explicit routing marker stay attributed to the coordinator.
"""
import datetime,json,os,sqlite3,time
from contextlib import closing
from pathlib import Path
from catalog import ROLE_IDS
from activity_schema import validate

AI=Path(os.environ.get('AWEMA_ACTIVITY_DATA','/opt/awema-ai/data'))
OUT=Path(os.environ.get('AWEMA_ACTIVITY_OUTPUT','/opt/awema-jury/activity/activity.json'))
BOARDS={'awema-migration':'cto','cinelight-production':'cl-producer','external-advisory':'mentor'}

def routed_role(profile,source,cwd):
    if source=='cl-producer':return 'cl-producer'
    if cwd=='/workspace/mentor':return 'mentor'
    return profile if profile in ROLE_IDS else 'cto'

def collect(base=AI,clock=None):
    clock=int(time.time()) if clock is None else clock
    rows={r:{'role':r,'state':'unknown','observed_minute':0,'running_cards':0,'waiting_cards':0} for r in sorted(ROLE_IDS)}
    sources={'hermes':False,'kanban':False,'gateway':False};gateway_busy=False
    try:
        path=base/'profiles/cto/state.db'
        with closing(sqlite3.connect('file:'+str(path)+'?mode=ro',uri=True,timeout=2)) as db:
            db.execute('PRAGMA query_only=ON')
            for profile,source,cwd,last,ended in reversed(db.execute('SELECT profile_name,source,cwd,last_activity_at,ended_at FROM sessions WHERE last_activity_at>? ORDER BY last_activity_at DESC LIMIT 1000',(clock-86400,)).fetchall()):
                role=routed_role(profile,source,cwd);r=rows[role]
                last=int(last or 0)
                if last>clock+10:continue
                r['observed_minute']=last//60
                r['state']='session_closed' if ended else ('recent' if clock-last<180 else 'unknown')
            sources['hermes']=True
    except (OSError,sqlite3.Error,TypeError,ValueError):pass
    boards_ok=True
    for name,default_role in BOARDS.items():
        try:
            path=base/'kanban/boards'/name/'kanban.db'
            with closing(sqlite3.connect('file:'+str(path)+'?mode=ro',uri=True,timeout=2)) as db:
                db.execute('PRAGMA query_only=ON')
                for assignee,status,count in db.execute("SELECT assignee,status,count(*) FROM tasks WHERE status IN ('running','blocked','todo','triage') GROUP BY assignee,status"):
                    role=assignee if assignee in ROLE_IDS and assignee!='cto' else default_role
                    r=rows[role];key='running_cards' if status=='running' else 'waiting_cards'
                    r[key]=min(99,r[key]+count)
                    if r['state'] not in ('recent',):r['state']='task_running' if r['running_cards'] else 'waiting'
        except (OSError,sqlite3.Error,TypeError,ValueError):boards_ok=False
    sources['kanban']=boards_ok
    try:
        p=base/'profiles/cto/gateway_state.json'
        if p.stat().st_size>262144:raise ValueError('size')
        v=json.loads(p.read_text());updated=datetime.datetime.fromisoformat(v['updated_at']).timestamp()
        if 0<=clock-updated<90:
            sources['gateway']=True;gateway_busy=type(v.get('active_agents')) is int and v['active_agents']>0
            # A gateway-wide count is not attributed to an individual specialist.
    except (OSError,ValueError,KeyError,TypeError):pass
    return validate({'version':1,'observed_at':clock,'sources':sources,'roles':list(rows.values()),'gateway_busy':gateway_busy},clock)

def once():
    data=collect();temp=OUT.with_suffix('.tmp')
    temp.write_text(json.dumps(data,separators=(',',':')));os.chmod(temp,0o644);os.replace(temp,OUT)

if __name__=='__main__':
    while True:
        try:once()
        except Exception:print('activity_projection_unavailable',flush=True)
        time.sleep(20)
