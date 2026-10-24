#!/usr/bin/env python3
"""C4: database resilience. SQLite runs in WAL mode with a busy timeout, concurrent writers and readers do not raise
"database is locked", and the data survives a restart. Run:  swarmsentinel-env/bin/python3 backend/tools/test_db_resilience.py"""
import os
import sys
import tempfile
import threading
import unittest

_TMP = tempfile.mkdtemp()
os.environ['DATA_DIR'] = _TMP
os.environ['DATABASE_URL'] = f'sqlite:///{_TMP}/resilience-test.db'
os.environ['SSAI_API_KEY'] = 'resilience-key'
os.environ['SSAI_PROVIDER_CHECK'] = '0'
os.environ['SSAI_STATE_DB'] = os.path.join(_TMP, 'state.db')

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
sys.path[:0] = [os.path.join(BACKEND, 'agents'), BACKEND]

import app as appmod  # noqa: E402
from models import Node, db  # noqa: E402

if _TMP not in appmod.app.config['SQLALCHEMY_DATABASE_URI']:
    raise RuntimeError('refusing to run against a non-test database')


class Resilience(unittest.TestCase):
    def test_connections_use_wal_and_wait_on_a_lock(self):
        with appmod.app.app_context():
            conn = db.engine.raw_connection()
            try:
                cur = conn.cursor()
                self.assertEqual(cur.execute('PRAGMA journal_mode').fetchone()[0].lower(), 'wal')
                self.assertEqual(cur.execute('PRAGMA busy_timeout').fetchone()[0], 5000)
                self.assertEqual(cur.execute('PRAGMA synchronous').fetchone()[0], 1)      # NORMAL
            finally:
                conn.close()

    def test_concurrent_writers_and_readers_never_hit_a_lock_error(self):
        errors, writes = [], 40

        def writer(n):
            try:
                with appmod.app.app_context():
                    for i in range(writes):
                        db.session.add(Node(node_id=f'w{n}-{i}', hostname=f'h{n}'))
                        db.session.commit()
            except Exception as exc:                  # noqa: BLE001
                errors.append(f'writer {n}: {type(exc).__name__}: {exc}')
                db.session.rollback()

        def reader(n):
            try:
                with appmod.app.app_context():
                    for _ in range(writes):
                        Node.query.count()
            except Exception as exc:                  # noqa: BLE001
                errors.append(f'reader {n}: {type(exc).__name__}: {exc}')

        threads = [threading.Thread(target=writer, args=(n,)) for n in range(6)] + \
                  [threading.Thread(target=reader, args=(n,)) for n in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(120)
        self.assertEqual(errors, [])
        with appmod.app.app_context():
            self.assertEqual(Node.query.filter(Node.node_id.like('w%')).count(), 6 * writes)

    def test_data_survives_the_connection_pool_being_dropped(self):
        with appmod.app.app_context():
            db.session.add(Node(node_id='persist-1', hostname='keep'))
            db.session.commit()
            db.session.remove()
            db.engine.dispose()                       # what a restart does to every open connection
            self.assertIsNotNone(Node.query.filter_by(node_id='persist-1').first())


if __name__ == '__main__':
    unittest.main(verbosity=2)
