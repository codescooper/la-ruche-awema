"""Fixed read-only lifecycle query, executed by operator as agent UID only."""
import hashlib
import sqlite3
import time
from pathlib import Path
from contextlib import closing
from owner_reader import BOARD_MAP, timestamp
from replay_schema import validate, STATES
from catalog import ROLE_IDS

def collect(base=Path('/opt/data'),now=None):
    now=int(time.time() if now is None else now);rows=[];ok=False
    for board in BOARD_MAP:
        try:
            path=base/'kanban/boards'/board/'kanban.db'
            with closing(sqlite3.connect(path.resolve().as_uri()+'?mode=ro',uri=True,timeout=2)) as db:
                db.execute('PRAGMA query_only=ON')
                data=db.execute('SELECT id,assignee,status,created_at,started_at,completed_at FROM tasks ORDER BY MAX(COALESCE(created_at,0),COALESCE(started_at,0),COALESCE(completed_at,0)) DESC LIMIT 20').fetchall()
            for ident,role,status,created,started,completed in data:
                events=[]
                for kind,value in [('created',created),('started',started),('completed',completed)]:
                    at=timestamp(value,now)
                    if at:events.append({'kind':kind,'at':at})
                if not events:continue
                row={'ref':'R-'+hashlib.sha256(('public-replay\0'+board+'\0'+str(ident)).encode()).hexdigest()[:24],
                     'role':role if role in ROLE_IDS else 'unknown','status':status if status in STATES else 'unknown','events':events}
                try:validate({'observed_at':now,'replays':[row]},now)
                except (ValueError,TypeError):continue
                rows.append(row)
            ok=True
        except (OSError,sqlite3.Error,ValueError,TypeError):continue
    if not ok:raise ValueError('sources unavailable')
    rows.sort(key=lambda r:r['events'][-1]['at'],reverse=True)
    return validate({'observed_at':now,'replays':rows[:20]},now)
