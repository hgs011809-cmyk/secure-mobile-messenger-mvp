import json
import sqlite3
import unittest
from probe_rows import classify, probe


class ProbeTests(unittest.TestCase):
    def test_strict_content(self):
        for value in [None, '', 'not-json', '{}', json.dumps({'type':'m.room.encrypted'}),
                      json.dumps({'type':'m.room.encrypted','content':None}),
                      json.dumps({'type':'m.room.encrypted','content':[]}),
                      json.dumps({'type':'m.room.message','content':{}}),
                      json.dumps({'type':'m.room.encrypted','content':{'ciphertext':''}}),
                      json.dumps({'type':'m.room.encrypted','content':{'ciphertext':{}}})]:
            self.assertIn(classify(value), ['missing', 'unexpected'])
        self.assertEqual(classify(json.dumps({'type':'m.room.encrypted','content':{}})), 'scrubbed')
        self.assertEqual(classify(json.dumps({'type':'m.room.encrypted','content':{'ciphertext':'synthetic-private-value'}})), 'encrypted')

    def test_snapshot_order_and_missing(self):
        db=sqlite3.connect(':memory:')
        db.execute('CREATE TABLE event_json(event_id TEXT PRIMARY KEY,json TEXT)')
        db.executemany('INSERT INTO event_json VALUES(?,?)', [('$private-a',json.dumps({'type':'m.room.encrypted','content':{'ciphertext':'private-ciphertext'}})),('$private-b',json.dumps({'type':'m.room.encrypted','content':{}}))])
        db.commit()
        self.assertEqual(probe(db, ['$private-b','$private-a','$missing']), ['scrubbed','encrypted','missing'])
        db.close()

    def test_invalid_batches(self):
        for ids in [None, {}, [], ['a','a'], [None], [''], ['a'*257], [str(i) for i in range(129)]]:
            with self.assertRaises(ValueError):
                probe(None, ids)


if __name__ == '__main__':
    unittest.main()
