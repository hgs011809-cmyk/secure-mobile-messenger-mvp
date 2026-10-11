"""CI-only read-only active-row snapshot. Output contains labels, never identifiers/data."""
import json
import sqlite3
import sys


def classify(raw):
    if raw is None:
        return 'missing'
    try:
        event = json.loads(raw)
        content = event.get('content')
        if event.get('type') != 'm.room.encrypted' or not isinstance(content, dict):
            return 'unexpected'
        if content == {}:
            return 'scrubbed'
        if isinstance(content.get('ciphertext'), str) and content['ciphertext']:
            return 'encrypted'
        return 'unexpected'
    except Exception:
        return 'unexpected'


def probe(db, ids):
    if not isinstance(ids, list) or not 1 <= len(ids) <= 128 or any(
        not isinstance(value, str) or not 1 <= len(value) <= 256 for value in ids
    ) or len(set(ids)) != len(ids):
        raise ValueError('invalid batch')
    db.execute('BEGIN')
    rows = dict(db.execute('SELECT event_id,json FROM event_json WHERE event_id IN (' +
                          ','.join('?' for _ in ids) + ')', ids).fetchall())
    return [classify(rows.get(value)) for value in ids]


def main():
    db = None
    try:
        payload = sys.stdin.read(65537)
        if len(payload) > 65536:
            raise ValueError('oversized input')
        request = json.loads(payload)
        if not isinstance(request, dict) or set(request) != {'event_ids'}:
            raise ValueError('invalid request')
        db = sqlite3.connect('file:/data/homeserver.db?mode=ro', uri=True, timeout=2)
        print(json.dumps({'states': probe(db, request['event_ids'])}, separators=(',', ':')))
    except Exception:
        print('{"error":"probe-error"}')
        sys.exit(1)
    finally:
        if db is not None:
            db.close()


if __name__ == '__main__':
    main()
