"""Read active logical SQLite row. Never print JSON or payload."""
import json
import sqlite3
import sys

try:
    event_id = json.loads(sys.stdin.read())['event_id']
    db = sqlite3.connect('file:/data/homeserver.db?mode=ro', uri=True, timeout=2)
    row = db.execute('SELECT json FROM event_json WHERE event_id = ?', (event_id,)).fetchone()
    db.close()
    if row is None:
        print('missing')
    else:
        event = json.loads(row[0])
        content = event.get('content', {})
        if event.get('type') != 'm.room.encrypted':
            print('unexpected')
        elif content == {}:
            print('scrubbed')
        elif 'ciphertext' in content:
            print('encrypted')
        else:
            print('unexpected')
except Exception:
    print('probe-error')
    sys.exit(1)
