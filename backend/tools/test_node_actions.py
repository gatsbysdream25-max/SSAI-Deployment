#!/usr/bin/env python3
"""Actions a person approves for a Windows PC: who may queue them, what they may be, how the agent fetches and reports.
Run:  swarmsentinel-env/bin/python3 backend/tools/test_node_actions.py"""
import json
import os
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

_TMP = tempfile.mkdtemp()
os.environ['DATA_DIR'] = _TMP
os.environ['DATABASE_URL'] = f'sqlite:///{_TMP}/nodeactions-test.db'
os.environ['SSAI_API_KEY'] = ADMIN = 'node-actions-admin-key'
os.environ['SSAI_PROVIDER_CHECK'] = '0'
os.environ['SSAI_STATE_DB'] = os.path.join(_TMP, 'state.db')
os.environ.pop('SSAI_APPROVAL_REQUIRES_PERSON', None)
os.environ.pop('SSAI_TRUSTED_PROXIES', None)

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
sys.path[:0] = [os.path.join(BACKEND, 'agents'), BACKEND]
import auth  # noqa: E402
import sso  # noqa: E402

PERSON = 'dana@example.org'
CSRF = 'csrf-token-for-the-test'


class Actions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import app as appmod
        if _TMP not in appmod.app.config['SQLALCHEMY_DATABASE_URI']:
            raise RuntimeError('refusing to run against a non-test database')
        cls.appmod, cls.app, cls.db = appmod, appmod.app, appmod.db
        cls.app.config['TESTING'] = True

    def setUp(self):
        from models import Node, NodeAction
        self.Node, self.NodeAction = Node, NodeAction
        self.ctx = self.app.app_context()
        self.ctx.push()
        self.db.create_all()
        NodeAction.query.delete()
        Node.query.delete()
        self.audit = os.path.join(_TMP, f'audit-{time.time_ns()}.jsonl')
        self.appmod._AUDIT_PATH = self.audit
        auth.node_ingest = auth.SlidingWindow(10000, 60)
        self.tokens = {}
        self.add_node('win-1', 'windows')
        self.add_node('win-2', 'windows')
        self.add_node('lin-1', 'linux')
        self.c = self.app.test_client()
        for p in (mock.patch.object(sso, 'is_admin_subject', lambda subject, cfg=None: subject == PERSON),
                  mock.patch.object(sso, 'only', lambda: False)):
            p.start()
            self.addCleanup(p.stop)

    def tearDown(self):
        self.db.session.remove()
        self.ctx.pop()

    def add_node(self, node_id, platform):
        token = auth.new_token()
        self.tokens[node_id] = token
        self.db.session.add(self.Node(node_id=node_id, hostname=node_id, platform=platform, status='active',
                                      token_hash=auth.hash_secret(token), registered=datetime.now(timezone.utc)))
        self.db.session.commit()

    def sign_in(self):
        with self.c.session_transaction() as s:
            s.update({'adm': True, 'iat': int(time.time()), 'sso': PERSON, 'csrf': CSRF})

    def queue(self, node, action, args=None, **extra):
        body = dict(action=action, args=args or {}, **extra)
        return self.c.post(f'/api/nodes/{node}/actions', json=body, headers={'X-CSRF-Token': CSRF})

    def as_node(self, node, path, body=None):
        return self.c.post(path, json=body or {}, headers={'X-API-Key': self.tokens[node]})

    def audit_lines(self):
        try:
            with open(self.audit, encoding='utf-8') as f:
                return [json.loads(line) for line in f if line.strip()]
        except OSError:
            return []

    # ── who may queue ──
    def test_the_admin_key_alone_cannot_queue_anything(self):
        r = self.c.post('/api/nodes/win-1/actions', json={'action': 'defender-scan'}, headers={'X-API-Key': ADMIN})
        self.assertEqual(r.status_code, 403)
        self.assertIn('signed-in person', r.get_json()['error'])
        self.assertEqual(self.NodeAction.query.count(), 0)

    def test_turning_the_person_rule_off_for_approvals_does_not_open_this_door(self):
        # SSAI_APPROVAL_REQUIRES_PERSON=0 lets the admin key approve a BLOCK on a deployment with no human console. Actions that
        # can isolate or stop things on a PC must always come from a signed-in person.
        with mock.patch.dict(os.environ, {'SSAI_APPROVAL_REQUIRES_PERSON': '0'}):
            for action in ('isolate-host', 'kill-process', 'defender-scan'):
                r = self.c.post('/api/nodes/win-1/actions', json={'action': action, 'args': {'pid': 999, 'image': 'evil.exe'}},
                                headers={'X-API-Key': ADMIN})
                self.assertEqual(r.status_code, 403, action)
        self.assertEqual(self.NodeAction.query.count(), 0)

    def test_a_node_token_cannot_queue_for_itself_or_others(self):
        r = self.c.post('/api/nodes/win-2/actions', json={'action': 'defender-scan'}, headers={'X-API-Key': self.tokens['win-1']})
        self.assertIn(r.status_code, (401, 403))
        self.assertEqual(self.NodeAction.query.count(), 0)

    def test_a_person_queues_an_action_and_the_intent_is_recorded_first(self):
        self.sign_in()
        r = self.queue('win-1', 'block-ip', {'ip': '203.0.113.9'}, reason='C2 seen')
        self.assertEqual(r.status_code, 201, r.get_data(as_text=True))
        a = r.get_json()['action']
        self.assertEqual((a['status'], a['ttl_hours'], a['args']), ('queued', 24, {'ip': '203.0.113.9'}))
        self.assertTrue(a['created_by'].startswith(PERSON))
        lines = [x for x in self.audit_lines() if x['action'] == 'node-action']
        self.assertEqual([x.get('stage') for x in lines], ['intent', None])

    # ── what may be queued ──
    def test_refusals(self):
        self.sign_in()
        cases = [
            ('win-1', 'format-disk', {}, 'action must be one of'),
            ('win-1', 'block-ip', {'ip': '192.168.1.5'}, 'inside the organisation'),
            ('win-1', 'block-ip', {'ip': '100.64.0.9'}, 'inside the organisation'),
            ('win-1', 'block-ip', {'ip': '127.0.0.1'}, 'not a blockable'),
            ('win-1', 'block-ip', {'ip': 'not-an-ip'}, 'valid IP'),
            ('win-1', 'block-domain', {'domain': 'google.com'}, 'protected domain'),
            ('win-1', 'block-domain', {'domain': '203.0.113.9'}, 'domain name'),
            ('win-1', 'kill-process', {'pid': 4, 'image': 'x.exe'}, 'cannot be stopped'),
            ('win-1', 'kill-process', {'pid': 800, 'image': 'lsass.exe'}, 'will not be stopped'),
            ('win-1', 'kill-process', {'pid': 800, 'image': '..\\cmd'}, 'file name'),
            ('win-1', 'undo', {'of': 12345}, 'not an undoable'),
            ('lin-1', 'defender-scan', {}, 'not a Windows PC'),
            ('nobody', 'defender-scan', {}, 'no active machine'),
        ]
        for node, action, args, expect in cases:
            r = self.queue(node, action, args)
            self.assertEqual(r.status_code, 400, (action, args))
            self.assertIn(expect, r.get_json()['error'], (action, args))
        for ttl in (0, -1, 24 * 8, 'soon', True):
            r = self.queue('win-1', 'block-ip', {'ip': '203.0.113.9'}, ttl_hours=ttl)
            self.assertEqual(r.status_code, 400, ttl)
        self.assertEqual(self.NodeAction.query.count(), 0)

    def test_a_network_isolation_always_has_a_short_time_limit(self):
        self.sign_in()
        self.assertEqual(self.queue('win-1', 'isolate-host').get_json()['action']['ttl_hours'], 1)
        self.assertEqual(self.queue('win-1', 'isolate-host', ttl_hours=25).status_code, 400)

    def test_the_never_block_list_is_honoured(self):
        self.sign_in()
        with mock.patch.object(self.appmod, '_never_block_ips', lambda: frozenset({'203.0.113.50'})):
            self.assertEqual(self.queue('win-1', 'block-ip', {'ip': '203.0.113.50'}).status_code, 400)

    def test_the_queue_per_machine_is_bounded(self):
        self.sign_in()
        for _ in range(20):
            self.assertEqual(self.queue('win-1', 'defender-scan').status_code, 201)
        self.assertEqual(self.queue('win-1', 'defender-scan').status_code, 400)

    # ── the agent's side ──
    def test_a_machine_fetches_only_its_own_actions_and_only_once(self):
        self.sign_in()
        self.queue('win-1', 'defender-scan')
        self.queue('win-2', 'defender-remove')
        mine = self.as_node('win-1', '/api/node/actions/poll').get_json()['actions']
        self.assertEqual([a['action'] for a in mine], ['defender-scan'])
        self.assertIn('valid_until', mine[0])
        self.assertEqual(self.as_node('win-1', '/api/node/actions/poll').get_json()['actions'], [])
        self.assertEqual([a['action'] for a in self.as_node('win-2', '/api/node/actions/poll').get_json()['actions']], ['defender-remove'])
        self.assertEqual(self.NodeAction.query.filter_by(node_id='win-1').one().status, 'sent')

    def test_the_admin_key_cannot_poll_as_a_machine(self):
        self.assertEqual(self.c.post('/api/node/actions/poll', json={}, headers={'X-API-Key': ADMIN}).status_code, 401)
        self.assertEqual(self.c.post('/api/node/actions/poll', json={}).status_code, 401)

    def test_results_move_an_action_through_its_life_and_only_its_own_machine_may_report(self):
        self.sign_in()
        aid = self.queue('win-1', 'block-ip', {'ip': '203.0.113.9'}).get_json()['action']['id']
        path = f'/api/node/actions/{aid}/result'
        self.assertEqual(self.as_node('win-1', path, {'ok': True}).status_code, 404)           # not fetched yet
        self.as_node('win-1', '/api/node/actions/poll')
        self.assertEqual(self.as_node('win-2', path, {'ok': True}).status_code, 404)           # someone else's
        self.assertEqual(self.as_node('win-1', path, {'ok': True, 'detail': 'rules added'}).get_json()['status'], 'done')
        self.assertEqual(self.as_node('win-1', path, {'ok': False}).status_code, 404)          # no second verdict
        self.assertEqual(self.as_node('win-1', path, {'ok': True, 'undone': True, 'detail': 'expired'}).get_json()['status'], 'undone')
        row = self.NodeAction.query.get(aid)
        self.assertEqual((row.status, row.result), ('undone', 'expired'))
        self.assertTrue(any(x['action'] == 'node-action-result' for x in self.audit_lines()))

    def test_a_failed_action_is_recorded_as_failed(self):
        self.sign_in()
        aid = self.queue('win-1', 'defender-remove').get_json()['action']['id']
        self.as_node('win-1', '/api/node/actions/poll')
        self.assertEqual(self.as_node('win-1', f'/api/node/actions/{aid}/result', {'ok': False, 'detail': 'no Defender'}).get_json()['status'], 'failed')

    def test_undo_needs_a_finished_action_and_is_queued_like_any_other(self):
        self.sign_in()
        aid = self.queue('win-1', 'isolate-host').get_json()['action']['id']
        self.assertEqual(self.c.post(f'/api/nodes/win-1/actions/{aid}/undo', json={}, headers={'X-CSRF-Token': CSRF}).status_code, 400)
        self.as_node('win-1', '/api/node/actions/poll')
        self.as_node('win-1', f'/api/node/actions/{aid}/result', {'ok': True})
        r = self.c.post(f'/api/nodes/win-1/actions/{aid}/undo', json={}, headers={'X-CSRF-Token': CSRF})
        self.assertEqual(r.status_code, 201, r.get_data(as_text=True))
        got = self.as_node('win-1', '/api/node/actions/poll').get_json()['actions']
        self.assertEqual([(a['action'], a['args']) for a in got], [('undo', {'of': aid})])
        self.assertEqual(self.c.post(f'/api/nodes/win-1/actions/{aid}/undo', json={}, headers={'X-API-Key': ADMIN}).status_code, 403)

    def test_an_action_nobody_fetched_in_time_never_runs(self):
        self.sign_in()
        aid = self.queue('win-1', 'defender-scan').get_json()['action']['id']
        row = self.NodeAction.query.get(aid)
        row.created_at = datetime.now(timezone.utc) - timedelta(minutes=61)
        self.db.session.commit()
        self.assertEqual(self.as_node('win-1', '/api/node/actions/poll').get_json()['actions'], [])
        self.assertEqual(self.NodeAction.query.get(aid).status, 'expired')

    def test_an_action_that_was_fetched_but_never_reported_is_closed_as_failed(self):
        self.sign_in()
        aid = self.queue('win-1', 'defender-scan').get_json()['action']['id']
        self.as_node('win-1', '/api/node/actions/poll')
        row = self.NodeAction.query.get(aid)
        row.sent_at = datetime.now(timezone.utc) - timedelta(minutes=61)
        self.db.session.commit()
        self.as_node('win-1', '/api/node/actions/poll')
        self.assertEqual(self.NodeAction.query.get(aid).status, 'failed')

    def test_the_history_is_listed_for_the_admin_only(self):
        self.sign_in()
        self.queue('win-1', 'defender-scan')
        self.assertEqual(len(self.c.get('/api/nodes/win-1/actions').get_json()), 1)
        fresh = self.app.test_client()
        self.assertEqual(fresh.get('/api/nodes/win-1/actions').status_code, 401)
        self.assertEqual(fresh.get('/api/nodes/win-1/actions', headers={'X-API-Key': self.tokens['win-1']}).status_code, 401)


if __name__ == '__main__':
    unittest.main(verbosity=1)
