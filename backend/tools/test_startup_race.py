#!/usr/bin/env python3
"""Several web workers starting at once must all come up, on a new database and on an old one (2026-09-19).
gunicorn runs the app in several workers and each executes the startup block on import. Regression for a first-run
crash: two workers both inserted the hub's own node row and the loser died with a UNIQUE violation ("Worker failed to
boot"). The race window is a few milliseconds, so the deterministic tests drive the exact interleaving; the
multi-process tests are smoke tests.
Run:  swarmsentinel-env/bin/python3 backend/tools/test_startup_race.py"""
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

_TMP = tempfile.mkdtemp()
os.environ['DATA_DIR'] = _TMP
os.environ['DATABASE_URL'] = f'sqlite:///{_TMP}/startup-test.db'
os.environ['SSAI_API_KEY'] = 'startup-test-key'

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
sys.path[:0] = [os.path.join(BACKEND, 'agents'), BACKEND]
PY = sys.executable
WORKERS = 6
BOOT = ("import sys, hashlib; sys.path[:0] = [%r, %r]; import app; "
        "print('booted', hashlib.sha256(app.app.config['SECRET_KEY'].encode()).hexdigest())" % (os.path.join(BACKEND, 'agents'), BACKEND))

OLD_THREAT = ('CREATE TABLE threat (id INTEGER PRIMARY KEY, url VARCHAR(500), type VARCHAR(100), severity VARCHAR(50), '
              'description TEXT, detected_by VARCHAR(100), node_id VARCHAR(200), status VARCHAR(50), timestamp DATETIME, '
              'ai_analyzed BOOLEAN NOT NULL DEFAULT 0, ai_verdict TEXT)')
OLD_NODE = ('CREATE TABLE node (id INTEGER PRIMARY KEY, node_id VARCHAR(200) UNIQUE, hostname VARCHAR(200), platform VARCHAR(50), '
            'tier VARCHAR(50), eula_ver VARCHAR(20), status VARCHAR(50), token VARCHAR(200), last_seen DATETIME, registered DATETIME, '
            'agent_count INTEGER, ai_capabilities TEXT, ai_count INTEGER)')


def boot_together(data_dir, n=WORKERS):
    env = dict(os.environ, DATA_DIR=data_dir, DATABASE_URL=f'sqlite:///{data_dir}/race.db')
    procs = [subprocess.Popen([PY, '-c', BOOT], env=env, cwd=BACKEND, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
             for _ in range(n)]
    return [(p.wait(timeout=180), p.stdout.read(), p.stderr.read()) for p in procs]


class Smoke(unittest.TestCase):
    def assert_all_booted(self, results):
        failed = [(rc, err[-300:]) for rc, out, err in results if rc != 0 or 'booted' not in out]
        self.assertEqual(failed, [], f'{len(failed)} of {len(results)} workers failed to start')

    def test_workers_starting_together_on_a_brand_new_database_all_come_up(self):
        d = tempfile.mkdtemp()
        self.assert_all_booted(boot_together(d))
        con = sqlite3.connect(f'{d}/race.db')
        try:
            self.assertEqual(con.execute('SELECT COUNT(*) FROM node').fetchone()[0], 1)      # one hub row, not one per worker
        finally:
            con.close()

    def test_workers_with_no_configured_secret_all_end_up_with_the_same_session_key(self):
        """Otherwise a cookie signed by one worker would be rejected by another and people would be signed out at random."""
        d = tempfile.mkdtemp()
        env_keys = os.environ.pop('SECRET_KEY', None)
        try:
            results = boot_together(d)
        finally:
            if env_keys is not None:
                os.environ['SECRET_KEY'] = env_keys
        self.assert_all_booted(results)
        keys = {out.split()[1] for rc, out, err in results}
        self.assertEqual(len(keys), 1, keys)
        self.assertEqual(oct(os.stat(os.path.join(d, 'backend', 'instance', 'secret_key')).st_mode & 0o777), '0o600')

    def test_workers_starting_together_on_an_old_schema_all_come_up_and_upgrade_it(self):
        d = tempfile.mkdtemp()
        con = sqlite3.connect(f'{d}/race.db')
        con.execute(OLD_THREAT)
        con.execute(OLD_NODE)
        con.execute("INSERT INTO node (node_id, hostname, token, status) VALUES ('legacy', 'h', 'plaintext', 'active')")
        con.commit()
        con.close()
        self.assert_all_booted(boot_together(d))
        con = sqlite3.connect(f'{d}/race.db')
        try:
            threat_cols = {r[1] for r in con.execute('PRAGMA table_info(threat)')}
            node_cols = {r[1] for r in con.execute('PRAGMA table_info(node)')}
            legacy_token = con.execute("SELECT token FROM node WHERE node_id='legacy'").fetchone()[0]
        finally:
            con.close()
        self.assertIn('real_source', threat_cols)
        self.assertTrue({'token_hash', 'token_hint', 'enrolled_at', 'revoked_at'} <= node_cols)
        self.assertIsNone(legacy_token)


class Interleavings(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import app as appmod
        if _TMP not in appmod.app.config['SQLALCHEMY_DATABASE_URI']:
            raise RuntimeError('refusing to run against a non-test database')
        cls.appmod, cls.app, cls.db = appmod, appmod.app, appmod.db
        from models import Node, EnrollmentCode
        cls.Node, cls.Code = Node, EnrollmentCode
        cls.host = socket.gethostname()

    def setUp(self):
        self.ctx = self.app.app_context()
        self.ctx.push()
        self.db.create_all()
        self.Node.query.delete()
        self.Code.query.delete()
        self.db.session.commit()

    def tearDown(self):
        self.db.session.remove()
        self.ctx.pop()

    def test_losing_the_race_to_register_the_hub_is_not_fatal(self):
        """Worker A read 'no hub row'; worker B inserted it; A's commit hits the UNIQUE constraint."""
        real_commit = self.db.session.commit
        state = {'raced': False}

        def commit_after_the_other_worker_wins():
            if not state['raced']:
                state['raced'] = True
                con = sqlite3.connect(f'{_TMP}/startup-test.db', timeout=10)
                con.execute("INSERT INTO node (node_id, hostname, platform, status, agent_count, ai_count) VALUES (?, ?, 'Linux', 'active', 0, 0)",
                            (self.host, self.host))
                con.commit()
                con.close()
            return real_commit()
        with mock.patch.object(self.db.session, 'commit', side_effect=commit_after_the_other_worker_wins):
            self.appmod._register_hub_node()                     # must not raise
        self.assertTrue(state['raced'])
        rows = self.Node.query.all()
        self.assertEqual([(n.node_id, n.status) for n in rows], [(self.host, 'active')])

    def test_registering_twice_is_idempotent_and_refreshes_the_row(self):
        self.appmod._register_hub_node()
        self.appmod._register_hub_node()
        self.assertEqual(self.Node.query.count(), 1)

    def test_an_enrolled_machine_sharing_the_hubs_hostname_is_not_taken_over(self):
        self.db.session.add(self.Node(node_id=self.host, hostname=self.host, status='active', token_hash='h' * 64))
        self.db.session.commit()
        self.appmod._register_hub_node()
        rows = {n.node_id: n for n in self.Node.query.all()}
        self.assertEqual(set(rows), {self.host, self.host + '-hub'})
        self.assertEqual(rows[self.host].token_hash, 'h' * 64)              # the enrolled machine's credential is untouched
        self.appmod._register_hub_node()                                    # and a restart does not create a third row
        self.assertEqual(self.Node.query.count(), 2)

    def test_adding_a_column_that_another_worker_just_added_is_fine(self):
        eng = self.db.engine
        self.appmod._add_column(eng, 'threat', 'real_source', 'VARCHAR(500)', 'ix_threat_real_source')
        self.appmod._add_column(eng, 'threat', 'real_source', 'VARCHAR(500)', 'ix_threat_real_source')
        with self.assertRaises(Exception):                                  # other errors are still surfaced
            self.appmod._add_column(eng, 'no_such_table', 'x', 'INTEGER')

    def test_a_machine_cannot_enrol_under_the_hubs_own_name_unless_the_admin_binds_a_code(self):
        from datetime import datetime, timedelta, timezone
        import auth
        now = datetime.now(timezone.utc).replace(tzinfo=None)

        def code(node_id=None):
            c = auth.new_code()
            self.db.session.add(self.Code(code_hash=auth.hash_secret(auth.normalize_code(c)), node_id=node_id, created_at=now,
                                          expires_at=now + timedelta(hours=1)))
            self.db.session.commit()
            return c
        self.appmod._register_hub_node()
        client = self.app.test_client()
        r = client.post('/api/node/register', json={'enrollCode': code(), 'nodeId': self.host})
        self.assertEqual(r.status_code, 409)
        self.assertIn("hub's own name", r.get_json()['error'])
        r = client.post('/api/node/register', json={'enrollCode': code(), 'nodeId': 'other'})
        self.assertEqual(r.status_code, 200)


if __name__ == '__main__':
    unittest.main(verbosity=2)
