"""CI-only aggregate counts. Never output access tokens or record contents."""
import json
import sqlite3
import sys
payload = json.load(sys.stdin)
user_id = payload['user_id']
if not isinstance(user_id, str) or not user_id.startswith('@pilot_') or not user_id.endswith(':matrix.ci'):
    raise ValueError('count_input_invalid')
connection = sqlite3.connect('file:/data/homeserver.db?mode=ro', uri=True)
result = {}
for table in ('devices', 'access_tokens', 'refresh_tokens'):
    result[table] = connection.execute('SELECT COUNT(*) FROM '+table+' WHERE user_id=?', (user_id,)).fetchone()[0]
print(json.dumps(result))
