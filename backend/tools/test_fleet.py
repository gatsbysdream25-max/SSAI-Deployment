#!/usr/bin/env python3
"""Fleet view: machines report their version, and the hub says whether it matches what it expects.
Run:  swarmsentinel-env/bin/python3 backend/tools/test_fleet.py"""
import os
import sys
import tempfile
import unittest
from unittest import mock

# SAFETY: throwaway data dir, database and admin key BEFORE anything imports ssai_config/app.
_TMP = tempfile.mkdtemp()
os.environ['DATA_DIR'] = _TMP
os.environ['DATABASE_URL'] = f'sqlite:///{_TMP}/fleet-test.db'
os.environ['SSAI_API_KEY'] = ADMIN = 'admin-key-for-fleet-tests'
os.environ.pop('SSAI_TRUSTED_PROXIES', None)

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
sys.path[:0] = [os.path.join(BACKEND, 'agents'), BACKEND]
import auth  # noqa: E402
import fleet  # noqa: E402


class Pieces(unittest.TestCase):
    def test_versions_are_cleaned_before_they_are_stored(self):
        self.assertEqual(fleet.clean_version('v0.1.5 (fbecfe4b1eec)'), 'v0.1.5 (fbecfe4b1eec)')
        self.assertEqual(fleet.clean_version('<script>alert(1)</script>'), 'scriptalert(1)script')
        self.assertEqual(len(fleet.clean_version('v' * 500)), 40)
        self.assertEqual(fleet.clean_version(None), '')

    def test_the_state_is_unknown_when_either_side_cannot_say(self):
        self.assertEqual(fleet.version_state('', 'v1'), fleet.UNKNOWN)
        self.assertEqual(fleet.version_state('v1', ''), fleet.UNKNOWN)
        self.assertEqual(fleet.version_state('unknown', 'v1'), fleet.UNKNOWN)
        self.assertEqual(fleet.version_state('v1', 'unknown'), fleet.UNKNOWN)
        self.assertEqual(fleet.version_state('v1', 'v1'), fleet.CURRENT)
        self.assertEqual(fleet.version_state('v1', 'v2'), fleet.DIFFERENT)

    def test_the_bundled_windows_agent_version_is_found(self):
        self.assertRegex(fleet.windows_agent_version(), r'^\d+\.\d+\.\d+$')

    def test_each_platform_is_compared_with_its_own_expectation(self):
        with mock.patch.object(fleet, 'hub_version', return_value='v9.9.9'), \
                mock.patch.object(fleet, 'windows_agent_version', return_value='3.2.1'):
            self.assertEqual(fleet.expected_version('linux'), 'v9.9.9')
            self.assertEqual(fleet.expected_version('windows'), '3.2.1')
            self.assertEqual(fleet.expected_version('Windows'), '3.2.1')
            self.assertEqual(fleet.expected_version(''), 'v9.9.9')


class Flow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import app as appmod
        if _TMP not in appmod.app.config['SQLALCHEMY_DATABASE_URI']:
            raise RuntimeError('refusing to run against a non-test database')
        cls.appmod, cls.app, cls.db = appmod, appmod.app, appmod.db
        from models import Agent, EnrollmentCode, Node
        cls.Agent, cls.Node, cls.Code = Agent, Node, EnrollmentCode
        cls.app.config['TESTING'] = True
        appmod._AUDIT_PATH = os.path.join(_TMP, 'audit.jsonl')

    def setUp(self):
        self.ctx = self.app.app_context()
        self.ctx.push()
        self.db.create_all()
        for model in (self.Agent, self.Node, self.Code):
            model.query.delete()
        self.db.session.commit()
        auth.enroll_failures = auth.SlidingWindow(5, 300)
        auth.node_ingest = auth.SlidingWindow(600, 60)
        self.c = self.app.test_client()

    def tearDown(self):
        self.db.session.remove()
        self.ctx.pop()

    def admin(self, method, path, **kw):
        return getattr(self.c, method)(path, headers={'X-API-Key': ADMIN}, **kw)

    def enroll(self, name, platform):
        code = self.admin('post', '/api/nodes/enrollment-codes', json={}).get_json()['code']
        reply = self.c.post('/api/node/register', json={'enrollCode': code, 'nodeId': name, 'hostname': name,
                                                        'platform': platform})
        self.assertEqual(reply.status_code, 200)
        return reply.get_json()['token']

    def call(self, token, path, **body):
        return self.c.post(path, headers={'X-API-Key': token}, json=body)

    def fleet_row(self, name):
        rows = {r['node_id']: r for r in self.admin('get', '/api/nodes').get_json()}
        return rows[name]

    def test_a_machine_that_reports_nothing_is_unknown_not_outdated(self):
        self.enroll('old1', 'linux')
        row = self.fleet_row('old1')
        self.assertEqual((row['version'], row['version_state']), ('', fleet.UNKNOWN))

    def test_a_linux_machine_matching_the_hub_is_current_and_a_different_one_is_flagged(self):
        token = self.enroll('lin1', 'linux')
        with mock.patch.object(fleet, 'hub_version', return_value='v0.2.0 (abc)'):
            self.call(token, '/api/agents/register', agentId='AuthLogAgent@lin1', version='v0.2.0 (abc)')
            self.assertEqual(self.fleet_row('lin1')['version_state'], fleet.CURRENT)
            self.call(token, '/api/agents/heartbeat', agentId='AuthLogAgent@lin1', version='v0.1.4 (old)')
            row = self.fleet_row('lin1')
            self.assertEqual((row['version'], row['expected_version'], row['version_state']),
                             ('v0.1.4 (old)', 'v0.2.0 (abc)', fleet.DIFFERENT))

    def test_a_windows_pc_is_compared_with_the_windows_agent_version(self):
        token = self.enroll('win1', 'windows')
        with mock.patch.object(fleet, 'windows_agent_version', return_value='0.2.0'), \
                mock.patch.object(fleet, 'hub_version', return_value='v9'):
            self.call(token, '/api/agents/register', agentId='WinPortAgent@win1', version='0.1.0')
            self.assertEqual(self.fleet_row('win1')['version_state'], fleet.DIFFERENT)
            self.call(token, '/api/agents/register', agentId='WinPortAgent@win1', version='0.2.0')
            self.assertEqual(self.fleet_row('win1')['version_state'], fleet.CURRENT)

    def test_a_hostile_version_is_stored_clean(self):
        token = self.enroll('lin2', 'linux')
        self.call(token, '/api/agents/register', agentId='AuthLogAgent@lin2', version='<img src=x onerror=alert(1)>')
        self.assertNotIn('<', self.fleet_row('lin2')['version'])

    def test_one_machine_cannot_set_the_version_of_another(self):
        mine, theirs = self.enroll('mine', 'linux'), self.enroll('theirs', 'linux')
        reply = self.call(mine, '/api/agents/register', agentId='AuthLogAgent@theirs', version='v666')
        self.assertEqual(reply.status_code, 403)
        self.assertEqual(self.fleet_row('theirs')['version'], '')
        self.assertTrue(theirs)

    def test_the_hubs_own_row_shows_the_hubs_version(self):
        with mock.patch.object(fleet, 'hub_version', return_value='v7.7.7'):
            hub = self.Node.hub()
            if hub is None:
                self.appmod._register_hub_node()
                hub = self.Node.hub()
            self.assertEqual(self.fleet_row(hub.node_id)['version'], 'v7.7.7')

    def test_the_list_is_still_admin_only(self):
        self.assertEqual(self.c.get('/api/nodes').status_code, 401)

    def test_an_old_database_gets_the_new_column(self):
        import sqlite3
        from sqlalchemy import create_engine, inspect
        path = os.path.join(_TMP, 'old-fleet.db')
        con = sqlite3.connect(path)
        con.execute('CREATE TABLE node (id INTEGER PRIMARY KEY, node_id VARCHAR(200))')
        con.commit()
        con.close()
        engine = create_engine(f'sqlite:///{path}')
        self.appmod._ensure_schema(engine)
        self.appmod._ensure_schema(engine)
        self.assertIn('agent_version', {c['name'] for c in inspect(engine).get_columns('node')})


if __name__ == '__main__':
    unittest.main(verbosity=2)
