"""Operator-installed reader; run as UID 10000 in awema-ai-team, never from HTTP.

Only stdout is exported, then validated and atomically persisted by the operator.
No sessions, messages, titles, prompts, result text or arbitrary database selection.
"""
import datetime
import hashlib
import json
import os
import sqlite3
import time
from contextlib import closing
from pathlib import Path

from owner_schema import PROVENANCE, ROLES, STATES, validate

DATA = Path('/opt/data')
BOARD_MAP = {'awema-migration': 'B01', 'cinelight-production': 'B02',
             'external-advisory': 'B03'}


def timestamp(value, now):
    if value is None:
        return 0
    if type(value) in (int, float):
        result = int(value)
    elif type(value) is str:
        stamp = datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=datetime.timezone.utc)
        result = int(stamp.timestamp())
    else:
        raise ValueError('date')
    if not 0 <= result <= now + 10:
        raise ValueError('date')
    return result


def collect(base=DATA, clock=None):
    now = int(time.time() if clock is None else clock)
    tasks, sources, truncated = [], {}, False
    for name, alias in BOARD_MAP.items():
        sources[alias] = False
        try:
            path = base / 'kanban' / 'boards' / name / 'kanban.db'
            # URI read-only still allows normal SQLite WAL coordination as UID10000.
            with closing(sqlite3.connect(path.resolve().as_uri() + '?mode=ro',
                                         uri=True, timeout=2)) as db:
                db.execute('PRAGMA query_only=ON')
                rows = db.execute('SELECT id,assignee,status,created_at,started_at,'
                                  'completed_at,last_heartbeat_at FROM tasks '
                                  'ORDER BY MAX(COALESCE(created_at,0),COALESCE(started_at,0),'
                                  'COALESCE(completed_at,0),COALESCE(last_heartbeat_at,0)) DESC,id '
                                  'LIMIT 201').fetchall()
            selected = []
            for ident, role, status, created, started, completed, heartbeat in rows[:200]:
                if type(ident) is not str or not 1 <= len(ident) <= 128:
                    raise ValueError('id')
                selected.append({
                    'ref': 'K-' + hashlib.sha256((alias + '\0' + ident).encode()).hexdigest()[:24],
                    'board': alias,
                    'role': role if type(role) is str and role in ROLES else 'unknown',
                    'status': status if type(status) is str and status in STATES else 'unknown',
                    'created_at': timestamp(created, now),
                    'last_event_at': max(timestamp(v, now) for v in (created, started, completed, heartbeat)),
                })
            # Validate a source atomically: malformed rows never imply healthy source.
            validate({'version': 1, 'observed_at': now, 'provenance': PROVENANCE,
                      'sources': {a: a == alias for a in BOARD_MAP.values()},
                      'tasks': selected, 'truncated': False}, now)
            tasks.extend(selected)
            truncated = truncated or len(rows) > 200
            sources[alias] = True
        except (OSError, sqlite3.Error, ValueError, TypeError, OverflowError):
            pass
    tasks.sort(key=lambda row: (row['last_event_at'], row['ref']), reverse=True)
    return validate({'version': 1, 'observed_at': now, 'provenance': PROVENANCE,
                     'sources': sources, 'tasks': tasks[:200],
                     'truncated': truncated or len(tasks) > 200}, now)


if __name__ == '__main__':
    if not hasattr(os, 'geteuid') or os.geteuid() != 10000:
        raise SystemExit('owner_reader_wrong_uid')
    print(json.dumps(collect(), separators=(',', ':')))
