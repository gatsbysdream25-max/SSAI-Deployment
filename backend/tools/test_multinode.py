#!/usr/bin/env python3
"""Portability and multi-machine behaviour: data-dir state, hub/node roles, machine identity (2026-09-19).
Run:  swarmsentinel-env/bin/python3 backend/tools/test_multinode.py"""
import os
import sys
import tempfile
import unittest
from unittest import mock

# SAFETY + PROOF: everything below runs against a throwaway data dir, DB and API key, set BEFORE any import.
_TMP = tempfile.mkdtemp()
os.environ['DATA_DIR'] = _TMP
os.environ['DATABASE_URL'] = f'sqlite:///{_TMP}/multinode-test.db'
os.environ['SSAI_API_KEY'] = KEY = 'testkey-multinode'
os.environ.pop('SSAI_ROLE', None)

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
sys.path[:0] = [os.path.join(BACKEND, 'agents'), BACKEND]
import agent_catalog as C  # noqa: E402
import agent_runner as R  # noqa: E402
import ai_swarm_agent as SW  # noqa: E402
import ssai_config  # noqa: E402


class StateLocation(unittest.TestCase):
    def test_operator_state_lives_under_the_data_dir_not_next_to_the_code(self):
        inst = os.path.join(_TMP, 'backend', 'instance')
        self.assertEqual(ssai_config.INSTANCE_DIR, inst)
        self.assertEqual(C._PATH, os.path.join(inst, 'agents.json'))
        self.assertEqual(SW._PROVIDERS_PATH, os.path.join(inst, 'ai_providers.json'))
        self.assertEqual(SW._WEIGHTS_PATH, os.path.join(inst, 'ai_weights.json'))

    def test_a_choice_survives_because_it_is_written_to_the_data_dir(self):
        C.set_agent_enabled('OllamaAnalyzerAgent', True)
        self.assertTrue(os.path.exists(os.path.join(_TMP, 'backend', 'instance', 'agents.json')))
        C._cache.update(mtime=None, data={})
        self.assertTrue(C.agent_enabled('OllamaAnalyzerAgent'))
        os.remove(C._PATH)
        C._cache.update(mtime=None, data={})


class Roles(unittest.TestCase):
    def setUp(self):
        self._old = os.environ.get('SSAI_ROLE')

    def tearDown(self):
        os.environ.pop('SSAI_ROLE', None)
        if self._old is not None:
            os.environ['SSAI_ROLE'] = self._old

    def test_default_is_hub_and_runs_the_full_default_set(self):
        self.assertEqual(C.role(), 'hub')
        for name in ('NetworkScanAgent', 'SwarmConsensusAgent', 'AuthLogAgent', 'PiHoleAgent'):
            self.assertTrue(C.agent_enabled(name, {}), name)

    def test_node_runs_host_sensors_but_not_the_hub_jobs(self):
        os.environ['SSAI_ROLE'] = 'node'
        self.assertEqual(C.role(), 'node')
        for name in C.HUB_ONLY:
            self.assertFalse(C.agent_enabled(name, {}), name)
        for name in ('AuthLogAgent', 'SyslogAgent', 'PortMonitorAgent', 'ProcessMonitorAgent', 'NetworkConnAgent',
                     'FileIntegrityAgent', 'DiskSpaceAgent', 'ServiceWatchAgent', 'IntelFeedAgent'):
            self.assertTrue(C.agent_enabled(name, {}), name)

    def test_operator_choice_beats_role_and_junk_role_means_hub(self):
        os.environ['SSAI_ROLE'] = 'node'
        self.assertTrue(C.agent_enabled('NetworkScanAgent', {'NetworkScanAgent': True}))
        self.assertFalse(C.agent_enabled('AuthLogAgent', {'AuthLogAgent': False}))
        os.environ['SSAI_ROLE'] = 'banana'
        self.assertEqual(C.role(), 'hub')

    def test_every_hub_only_name_is_a_real_agent(self):
        self.assertEqual(C.HUB_ONLY - set(C.CATALOG), set())
        self.assertEqual({c.name_id for c in R.AGENTS} - set(C.CATALOG), set())

    def test_node_agent_ids_are_qualified_so_machines_do_not_collide(self):
        with mock.patch.object(R, 'ROLE', 'hub'), mock.patch.object(R, 'NODE_ID', 'box1'):
            self.assertEqual(R._agent_id('AuthLogAgent'), 'AuthLogAgent')
        with mock.patch.object(R, 'ROLE', 'node'), mock.patch.object(R, 'NODE_ID', 'box1'):
            self.assertEqual(R._agent_id('AuthLogAgent'), 'AuthLogAgent@box1')

    def test_hub_only_agents_are_not_listed_on_the_hub_once_per_node(self):
        import logging
        log = logging.getLogger('test-note')
        calls = []
        with mock.patch.object(R, 'register', lambda *a, **k: calls.append(('register', a[0]))), \
                mock.patch.object(R, 'heartbeat', lambda name, **k: calls.append(('heartbeat', name, k.get('status')))):
            with mock.patch.object(R, 'ROLE', 'node'):
                self.assertFalse(R._note_disabled(R.SwarmConsensusAgent, log))      # hub-only: not an option on a node
                self.assertEqual(calls, [])
                self.assertTrue(R._note_disabled(R.AuthLogAgent, log))              # a sensor the operator switched off still shows
            with mock.patch.object(R, 'ROLE', 'hub'):
                self.assertTrue(R._note_disabled(R.SwarmConsensusAgent, log))
        self.assertEqual([c[0] for c in calls], ['register', 'heartbeat', 'register', 'heartbeat'])
        self.assertIn(('heartbeat', 'SwarmConsensusAgent', 'disabled'), calls)

    def test_a_replaced_credential_is_picked_up_without_a_restart(self):
        old_api, old_key = R.API, R.API_KEY
        try:
            with mock.patch.dict(os.environ, {'SSAI_API': 'http://hub.example:5000/api', 'SSAI_API_KEY': 'ssn_new'}):
                R._refresh_credentials()
                self.assertEqual((R.API, R.API_KEY), ('http://hub.example:5000/api', 'ssn_new'))
                self.assertEqual(R._headers()['X-API-Key'], 'ssn_new')
            with mock.patch.dict(os.environ, {'SSAI_API_KEY': ''}):
                R._refresh_credentials()
                self.assertNotIn('X-API-Key', R._headers())
        finally:
            R.API, R.API_KEY = old_api, old_key

    def test_a_rejected_credential_is_reported_plainly(self):
        seen = []
        with mock.patch.object(R, '_warn_api', lambda what, exc: seen.append((what, str(exc)))):
            R._note_auth('heartbeat X', mock.Mock(status_code=401))
            R._note_auth('heartbeat X', mock.Mock(status_code=403))
            R._note_auth('heartbeat X', mock.Mock(status_code=200))
            R._note_auth('heartbeat X', None)
        self.assertEqual(len(seen), 2)
        self.assertIn('enroll', seen[0][1].lower())
        self.assertIn('HTTP 401', seen[0][1])

    def test_register_and_heartbeat_send_the_qualified_id(self):
        sent = []
        fake = mock.Mock()
        fake.post = lambda url, json=None, **k: sent.append((url, json))
        with mock.patch.object(R, 'SESSION', fake), mock.patch.object(R, 'ROLE', 'node'), mock.patch.object(R, 'NODE_ID', 'box1'):
            R.register('AuthLogAgent', 'log_monitor', 'd')
            R.heartbeat('AuthLogAgent', status='active')
        for _url, body in sent:
            self.assertEqual((body['agentId'], body['name']), ('AuthLogAgent@box1', 'AuthLogAgent@box1'))


class HubApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import app as appmod
        if _TMP not in appmod.app.config['SQLALCHEMY_DATABASE_URI']:
            raise RuntimeError('refusing to run against a non-test database')
        cls.app, cls.db = appmod.app, appmod.db
        from models import Threat, Agent
        cls.Threat, cls.Agent = Threat, Agent
        cls.app.config['TESTING'] = True

    def setUp(self):
        self.ctx = self.app.app_context()
        self.ctx.push()
        self.db.create_all()
        self.Threat.query.delete()
        self.Agent.query.delete()
        self.db.session.commit()
        self.c = self.app.test_client()

    def tearDown(self):
        self.db.session.remove()
        self.ctx.pop()

    def post(self, path, data):
        return self.c.post(path, json=data, headers={'X-API-Key': KEY})

    def threat(self, node, **kw):
        d = {'url': '/', 'type': 'disk-full', 'severity': 'high', 'description': 'disk 95% full', 'detected_by': 'DiskSpaceAgent'}
        d.update(kw)
        if node:
            d['node_id'] = node
        return self.post('/api/threats/', d)

    def test_threats_record_which_machine_they_came_from(self):
        self.assertEqual(self.threat('box1').status_code, 201)
        self.assertEqual(self.Threat.query.one().node_id, 'box1')
        self.assertEqual(self.c.get('/api/threats/', headers={'X-API-Key': KEY}).get_json()[0]['node_id'], 'box1')

    def test_the_same_condition_on_two_machines_is_two_threats(self):
        self.assertEqual(self.threat('box1').status_code, 201)
        self.assertEqual(self.threat('box2').status_code, 201)
        again = self.threat('box1')
        self.assertEqual((again.status_code, again.get_json().get('deduped')), (200, True))
        self.assertEqual(self.Threat.query.count(), 2)

    def test_a_dismissal_on_one_machine_does_not_silence_another(self):
        self.threat('box1')
        self.Threat.query.update({'status': 'dismissed'})
        self.db.session.commit()
        self.assertEqual(self.threat('box1').get_json().get('suppressed'), True)
        self.assertEqual(self.threat('box2').status_code, 201)

    def test_rows_from_before_machines_were_named_are_adopted_not_duplicated(self):
        self.threat(None)
        self.Threat.query.update({'status': 'dismissed'})
        self.db.session.commit()
        self.assertEqual(self.threat('hub1').get_json().get('suppressed'), True)
        self.assertEqual(self.Threat.query.one().node_id, 'hub1')
        self.assertEqual(self.threat('box2').status_code, 201)

    def test_two_machines_running_the_same_agent_keep_separate_rows(self):
        for node in ('box1', 'box2'):
            self.assertEqual(self.post('/api/agents/register', {'agentId': f'AuthLogAgent@{node}', 'role': 'log_monitor', 'hostname': node}).status_code, 201)
        self.assertEqual(self.post('/api/agents/heartbeat', {'agentId': 'AuthLogAgent@box1', 'scan_count': 7}).status_code, 200)
        rows = {a.name: a for a in self.Agent.query.all()}
        self.assertEqual(set(rows), {'AuthLogAgent@box1', 'AuthLogAgent@box2'})
        self.assertEqual((rows['AuthLogAgent@box1'].scans_count, rows['AuthLogAgent@box2'].scans_count), (7, 0))

    def test_odd_node_ids_are_tolerated(self):
        for val in ('', 42, 'x' * 500):
            self.Threat.query.delete()
            self.db.session.commit()
            self.assertEqual(self.threat(None, node_id=val).status_code, 201)
        self.assertEqual(len(self.Threat.query.one().node_id), 200)


if __name__ == '__main__':
    unittest.main(verbosity=2)
