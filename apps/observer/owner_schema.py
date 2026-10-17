"""Closed private metadata contract. Never carry titles, paths or arbitrary text."""
import json
import re
import time

ROLES = frozenset(('cto', 'pm', 'dev', 'qa', 'security', 'ops', 'designer',
                   'cl-producer', 'mentor', 'community-manager', 'unknown'))
STATES = frozenset(('triage', 'todo', 'running', 'review', 'done', 'blocked',
                    'cancelled', 'unknown'))
BOARDS = frozenset(('B01', 'B02', 'B03'))
PROVENANCE = 'hermes-kanban-metadata-v1'
MAX_BYTES = 96000


def integer(value, low, high):
    return type(value) is int and low <= value <= high


def validate(value, clock=None):
    now = int(time.time() if clock is None else clock)
    if type(value) is not dict or set(value) != {
            'version', 'observed_at', 'provenance', 'sources', 'tasks', 'truncated'}:
        raise ValueError('schema')
    if type(value['version']) is not int or value['version'] != 1:
        raise ValueError('version')
    if not integer(value['observed_at'], now - 90, now + 10):
        raise ValueError('stale')
    if value['provenance'] != PROVENANCE or type(value['truncated']) is not bool:
        raise ValueError('provenance')
    if type(value['sources']) is not dict or set(value['sources']) != BOARDS:
        raise ValueError('sources')
    if any(type(v) is not bool for v in value['sources'].values()):
        raise ValueError('sources')
    if type(value['tasks']) is not list or len(value['tasks']) > 200:
        raise ValueError('tasks')
    seen = set()
    for row in value['tasks']:
        if type(row) is not dict or set(row) != {
                'ref', 'board', 'role', 'status', 'created_at', 'last_event_at'}:
            raise ValueError('row')
        if type(row['ref']) is not str or not re.fullmatch(r'K-[a-f0-9]{24}', row['ref']):
            raise ValueError('reference')
        if row['ref'] in seen:
            raise ValueError('duplicate')
        seen.add(row['ref'])
        if type(row['board']) is not str or row['board'] not in BOARDS:
            raise ValueError('board')
        if not value['sources'][row['board']]:
            raise ValueError('failed_source')
        if type(row['role']) is not str or row['role'] not in ROLES:
            raise ValueError('role')
        if type(row['status']) is not str or row['status'] not in STATES:
            raise ValueError('status')
        if any(not integer(row[k], 0, now + 10) for k in ('created_at', 'last_event_at')):
            raise ValueError('date')
        if row['created_at'] and row['last_event_at'] and row['last_event_at'] < row['created_at']:
            raise ValueError('date_order')
    return value


def load(path, clock=None):
    try:
        with path.open('rb') as stream:
            raw = stream.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError('size')
        value = validate(json.loads(raw), clock)
        if not any(value['sources'].values()):
            return {'available': False, 'reason': 'sources_unavailable'}
        return {'available': True, **value}
    except (OSError, ValueError, TypeError, KeyError, UnicodeError):
        return {'available': False, 'reason': 'unavailable_or_stale'}
