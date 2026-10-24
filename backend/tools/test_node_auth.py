#!/usr/bin/env python3
"""Per-node credentials: enrolment, scoping, revocation, and the closed legacy endpoints (2026-09-19).
Run:  swarmsentinel-env/bin/python3 backend/tools/test_node_auth.py"""
import os
import sqlite3
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

# SAFETY: throwaway data dir, database and admin key BEFORE anything imports ssai_config/app.
_TMP = tempfile.mkdtemp()
os.environ['DATA_DIR'] = _TMP
os.environ['DATABASE_URL'] = f'sqlite:///{_TMP}/nodeauth-test.db'
os.environ['SSAI_API_KEY'] = ADMIN = 'admin-key-for-tests'
os.environ.pop('SSAI_TRUSTED_PROXIES', None)

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
sys.path[:0] = [os.path.join(BACKEND, 'agents'), BACKEND]
import auth  # noqa: E402


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


class Pieces(unittest.TestCase):
    def test_codes_are_readable_random_and_forgiving_to_type(self):
        c = auth.new_code()
        self.assertRegex(c, r'^[A-HJ-NP-Z2-9]{4}(-[A-HJ-NP-Z2-9]{4}){3}$')
        self.assertNotEqual(c, auth.new_code())
        raw = c.replace('-', '')
        for typed in (c, c.lower(), raw, ' ' + c.lower().replace('-', ' ') + ' '):
            self.assertEqual(auth.normalize_code(typed), raw, typed)
        for bad in ('', None, 'short', c + 'X', 'O' * 16, '1' * 16, 42):
            self.assertEqual(auth.normalize_code(bad), '', repr(bad))

    def test_tokens_are_prefixed_long_and_hashed_deterministically(self):
        t = auth.new_token()
        self.assertTrue(t.startswith('ssn_') and len(t) > 40)
        self.assertNotEqual(t, auth.new_token())
        self.assertEqual(auth.hash_secret(t), auth.hash_secret(t))
        self.assertEqual(len(auth.hash_secret(t)), 64)
        self.assertNotIn(t, auth.hash_secret(t))

    def test_node_ids_are_made_safe(self):
        self.assertEqual(auth.clean_node_id('web-01.lan'), 'web-01.lan')
        self.assertEqual(auth.clean_node_id('../../etc/passwd; DROP'), 'etc-passwd-DROP')
        self.assertEqual(auth.clean_node_id('a b\nc'), 'a-b-c')
        self.assertEqual(len(auth.clean_node_id('x' * 200)), 64)
        self.assertEqual(auth.clean_node_id('', 'fallback'), 'fallback')
        self.assertEqual(auth.clean_node_id('///', 'fb'), 'fb')
        self.assertEqual(auth.clean_node_id(None), '')

    def test_sliding_window(self):
        clk = Clock()
        w = auth.SlidingWindow(3, 60, clock=clk)
        self.assertEqual([w.hit('a') for _ in range(4)], [True, True, True, False])
        self.assertTrue(w.hit('b'))                                  # keys are independent
        self.assertEqual(w.count('a'), 3)
        clk.t += 61
        self.assertTrue(w.hit('a'))                                  # the window slid
        self.assertEqual(w.count('never'), 0)

    def test_window_memory_is_bounded(self):
        w = auth.SlidingWindow(1, 60, max_keys=50)
        for i in range(500):
            w.hit(f'k{i}')
        self.assertLess(len(w._hits), 200)


class Flow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import app as appmod
        if _TMP not in appmod.app.config['SQLALCHEMY_DATABASE_URI']:
            raise RuntimeError('refusing to run against a non-test database')
        cls.appmod, cls.app, cls.db = appmod, appmod.app, appmod.db
        from models import Threat, Agent, Node, EnrollmentCode
        cls.Threat, cls.Agent, cls.Node, cls.Code = Threat, Agent, Node, EnrollmentCode
        cls.app.config['TESTING'] = True
        appmod._AUDIT_PATH = os.path.join(_TMP, 'audit.jsonl')

    def setUp(self):
        self.ctx = self.app.app_context()
        self.ctx.push()
        self.db.create_all()
        for m in (self.Threat, self.Agent, self.Node, self.Code):
            m.query.delete()
        self.db.session.commit()
        auth.enroll_failures = auth.SlidingWindow(5, 300)
        auth.node_ingest = auth.SlidingWindow(600, 60)
        self.c = self.app.test_client()

    def tearDown(self):
        self.db.session.remove()
        self.ctx.pop()

    # helpers
    def admin(self, method, path, **kw):
        return getattr(self.c, method)(path, headers={'X-API-Key': ADMIN}, **kw)

    def code(self, **body):
        r = self.admin('post', '/api/nodes/enrollment-codes', json=body)
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        return r.get_json()['code']

    def enroll(self, code, **body):
        return self.c.post('/api/node/register', json=dict(body, enrollCode=code))

    def node(self, name='box1', **body):
        r = self.enroll(self.code(), nodeId=name, hostname=name, **body)
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        return r.get_json()

    def as_node(self, token, method, path, **kw):
        return getattr(self.c, method)(path, headers={'X-API-Key': token}, **kw)

    def threat(self, token, **kw):
        d = {'url': '/', 'type': 'disk-full', 'severity': 'high', 'description': 'd', 'detected_by': 'DiskSpaceAgent'}
        d.update(kw)
        return self.as_node(token, 'post', '/api/threats/', json=d)

    # ── enrolment ──
    def test_enrolment_issues_a_token_stored_only_as_a_hash(self):
        n = self.node('box1')
        tok = n['token']
        self.assertEqual((n['nodeId'], tok[:4]), ('box1', 'ssn_'))
        row = self.Node.query.filter_by(node_id='box1').one()
        self.assertEqual(row.token_hash, auth.hash_secret(tok))
        self.assertEqual((row.token, row.token_hint, row.status), (None, tok[:8], 'active'))
        con = sqlite3.connect(f'{_TMP}/nodeauth-test.db')
        try:
            for table in ('node', 'enrollment_code', 'threat', 'agent'):
                dump = repr(con.execute(f'select * from {table}').fetchall())
                self.assertNotIn(tok, dump, table)
        finally:
            con.close()
        listing = self.admin('get', '/api/nodes').get_data(as_text=True)
        self.assertNotIn(tok, listing)
        self.assertNotIn(row.token_hash, listing)
        self.assertIn('"credential":"active"', listing.replace(' ', ''))

    def test_a_code_works_once(self):
        code = self.code()
        self.assertEqual(self.enroll(code, nodeId='a').status_code, 200)
        self.assertEqual(self.enroll(code, nodeId='b').status_code, 401)

    def test_expired_used_wrong_and_malformed_codes_all_get_the_same_answer(self):
        expired = self.code()
        self.Code.query.update({'expires_at': datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=1)})
        self.db.session.commit()
        used = self.code()
        self.enroll(used, nodeId='first')
        bodies = set()
        for c in (expired, used, 'AAAA-BBBB-CCCC-DDDD', 'garbage', '', None):
            auth.enroll_failures = auth.SlidingWindow(100, 300)
            r = self.enroll(c, nodeId='x')
            self.assertEqual(r.status_code, 401, c)
            bodies.add(r.get_data(as_text=True))
        self.assertEqual(len(bodies), 1)                              # nothing tells a guesser which part was wrong
        self.assertEqual(self.c.post('/api/node/register', json={}).status_code, 401)
        self.assertEqual(self.c.post('/api/node/register', data='not json').status_code, 401)

    def test_repeated_wrong_codes_lock_the_address_out_even_for_a_valid_code(self):
        good = self.code()
        for i in range(5):
            self.assertEqual(self.enroll(f'WRONG-CODE-{i}', nodeId='x').status_code, 401)
        self.assertEqual(self.enroll(good, nodeId='x').status_code, 429)

    def test_spoofed_forwarded_for_cannot_reset_the_lockout_unless_the_proxy_is_trusted(self):
        for i in range(5):
            self.c.post('/api/node/register', json={'enrollCode': 'bad'}, headers={'X-Forwarded-For': f'9.9.9.{i}'})
        r = self.c.post('/api/node/register', json={'enrollCode': 'bad'}, headers={'X-Forwarded-For': '8.8.8.8'})
        self.assertEqual(r.status_code, 429)
        with self.app.test_request_context('/', environ_base={'REMOTE_ADDR': '10.0.0.5'}, headers={'X-Forwarded-For': '1.2.3.4'}):
            self.assertEqual(auth.client_ip(), '10.0.0.5')
            with mock.patch.dict(os.environ, {'SSAI_TRUSTED_PROXIES': '10.0.0.5'}):
                self.assertEqual(auth.client_ip(), '1.2.3.4')

    def test_only_the_admin_can_create_codes_and_ttl_is_clamped(self):
        self.assertEqual(self.c.post('/api/nodes/enrollment-codes', json={}).status_code, 401)
        tok = self.node('box1')['token']
        self.assertEqual(self.as_node(tok, 'post', '/api/nodes/enrollment-codes', json={}).status_code, 401)
        for asked, want in ((1, 5), (99999, 1440), ('junk', 60), (None, 60), (90, 90)):
            r = self.admin('post', '/api/nodes/enrollment-codes', json={'ttl_minutes': asked})
            self.assertEqual(r.get_json()['ttl_minutes'], want, asked)

    def test_a_code_for_a_named_machine_fixes_its_name_and_can_replace_its_credential(self):
        first = self.enroll(self.code(node_id='box1'), nodeId='something-else').get_json()
        self.assertEqual(first['nodeId'], 'box1')
        second = self.enroll(self.code(node_id='box1'), nodeId='box1').get_json()
        self.assertNotEqual(first['token'], second['token'])
        self.assertEqual(self.threat(first['token']).status_code, 401)          # the old credential is dead
        self.assertEqual(self.threat(second['token']).status_code, 201)

    def test_a_name_already_in_use_is_refused_without_burning_the_code(self):
        self.node('box1')
        code = self.code()
        r = self.enroll(code, nodeId='box1')
        self.assertEqual(r.status_code, 409)
        self.assertIn('already enrolled', r.get_json()['error'])
        self.assertEqual(self.enroll(code, nodeId='box2').status_code, 200)     # still usable

    def test_machine_names_are_sanitised_with_a_fallback(self):
        self.assertEqual(self.enroll(self.code(), nodeId='../../etc; x').get_json()['nodeId'], 'etc-x')
        self.assertEqual(self.enroll(self.code(), hostname='My Laptop').get_json()['nodeId'], 'My-Laptop')
        self.assertTrue(self.enroll(self.code(), hostname='///').get_json()['nodeId'].startswith('node-'))

    # ── scope ──
    def test_a_node_can_ingest_its_own_data_and_nothing_else(self):
        tok = self.node('box1')['token']
        self.assertEqual(self.threat(tok).status_code, 201)
        self.assertEqual(self.as_node(tok, 'post', '/api/agents/register', json={'agentId': 'AuthLogAgent@box1'}).status_code, 201)
        self.assertEqual(self.as_node(tok, 'post', '/api/agents/heartbeat', json={'agentId': 'AuthLogAgent@box1', 'scan_count': 3}).status_code, 200)
        tid = self.Threat.query.first().id
        for method, path, body in (
                ('post', f'/api/threats/{tid}/block', None), ('post', f'/api/threats/{tid}/unblock', None),
                ('post', f'/api/threats/{tid}/dismiss', None), ('post', f'/api/threats/{tid}/resolve', None),
                ('post', f'/api/threats/{tid}/reopen', None), ('put', f'/api/threats/{tid}', {'status': 'resolved'}),
                ('get', f'/api/threats/{tid}/identify', None), ('get', '/api/identify?target=8.8.8.8', None),
                ('post', '/api/settings/agents', {'agent': 'AuthLogAgent', 'enabled': False}),
                ('post', '/api/setup/enable', {'provider': 'groq', 'enabled': True}),
                ('post', '/api/nodes/enrollment-codes', {}), ('post', '/api/nodes/box1/revoke', None), ('delete', '/api/nodes/box1', None)):
            r = self.as_node(tok, method, path, **({'json': body} if body is not None else {}))
            self.assertEqual(r.status_code, 401, f'{method} {path} -> {r.status_code}')
        self.assertEqual(self.Node.query.filter_by(node_id='box1').one().status, 'active')

    def test_a_node_cannot_speak_for_other_machines_or_the_hubs_own_agents(self):
        tok = self.node('box1')['token']
        for aid in ('AuthLogAgent@box2', 'SwarmConsensusAgent', 'AuthLogAgent', 'AuthLogAgent@box1x', '@box1', 'x@box1@evil'):
            r = self.as_node(tok, 'post', '/api/agents/register', json={'agentId': aid})
            self.assertEqual(r.status_code, 403, aid)
            r = self.as_node(tok, 'post', '/api/agents/heartbeat', json={'agentId': aid})
            self.assertEqual(r.status_code, 403, aid)
        self.assertEqual(self.Agent.query.count(), 0)

    def test_a_nodes_threats_carry_its_identity_whatever_the_request_claims(self):
        tok = self.node('box1')['token']
        self.threat(tok, node_id='someone-else', real_url='192.168.0.5')
        row = self.Threat.query.one()
        self.assertEqual((row.node_id, row.real_source), ('box1', '192.168.0.5'))
        self.assertEqual(self.c.get('/api/threats/', headers={'X-API-Key': ADMIN}).get_json()[0]['node_id'], 'box1')

    def test_the_admin_key_keeps_working_and_bearer_form_is_accepted(self):
        self.assertEqual(self.admin('post', '/api/threats/', json={'url': '/', 'type': 'disk-full', 'description': 'd', 'node_id': 'hub'}).status_code, 201)
        self.assertEqual(self.Threat.query.one().node_id, 'hub')                 # the admin may set it (the hub's own runner does)
        self.assertEqual(self.admin('post', '/api/agents/register', json={'agentId': 'AuthLogAgent'}).status_code, 201)
        tok = self.node('box1')['token']
        r = self.c.post('/api/threats/', json={'url': '/', 'type': 'x', 'description': 'd'}, headers={'Authorization': f'Bearer {tok}'})
        self.assertEqual(r.status_code, 201)
        self.assertEqual(self.c.post('/api/threats/', json={'url': '/'}, headers={'X-API-Key': 'wrong'}).status_code, 401)
        self.assertEqual(self.c.post('/api/threats/', json={'url': '/'}).status_code, 401)

    def test_a_node_token_with_a_lookalike_shape_but_no_record_is_rejected(self):
        for key in ('ssn_' + 'a' * 43, 'ssn_', 'x' * 64, ADMIN + 'x', ADMIN[:-1]):
            self.assertEqual(self.c.post('/api/threats/', json={'url': '/'}, headers={'X-API-Key': key}).status_code, 401, key)

    def test_a_noisy_node_is_rate_limited_on_its_own(self):
        auth.node_ingest = auth.SlidingWindow(3, 60)
        a, b = self.node('box1')['token'], self.node('box2')['token']
        self.assertEqual([self.threat(a, url=f'/{i}').status_code for i in range(5)], [201, 201, 201, 429, 429])
        self.assertEqual(self.threat(b).status_code, 201)                         # another machine is unaffected
        self.assertEqual(self.admin('post', '/api/threats/', json={'url': '/z', 'type': 'x', 'description': 'd'}).status_code, 201)

    # ── revocation ──
    def test_revoking_kills_the_token_at_once_and_keeps_the_history(self):
        n = self.node('box1')
        self.assertEqual(self.threat(n['token']).status_code, 201)
        self.assertEqual(self.c.post('/api/nodes/box1/revoke').status_code, 401)
        r = self.admin('post', '/api/nodes/box1/revoke')
        self.assertEqual((r.status_code, r.get_json()['credential']), (200, 'revoked'))
        self.assertEqual(self.threat(n['token']).status_code, 401)
        self.assertEqual(self.as_node(n['token'], 'post', '/api/agents/heartbeat', json={'agentId': 'A@box1'}).status_code, 401)
        row = self.Node.query.filter_by(node_id='box1').one()
        self.assertEqual((row.status, row.token_hash, row.token_hint), ('revoked', None, None))
        self.assertEqual(self.Threat.query.count(), 1)
        self.assertEqual(self.admin('post', '/api/nodes/nope/revoke').status_code, 404)
        again = self.enroll(self.code(node_id='box1'), nodeId='box1').get_json()  # an admin can bring it back with a new code
        self.assertEqual(self.threat(again['token'], type='ssh-login').status_code, 201)

    def test_deleting_a_node_removes_it(self):
        n = self.node('box1')
        self.assertEqual(self.c.delete('/api/nodes/box1').status_code, 401)
        self.assertEqual(self.admin('delete', '/api/nodes/box1').status_code, 200)
        self.assertEqual(self.threat(n['token']).status_code, 401)
        self.assertEqual(self.admin('delete', '/api/nodes/box1').status_code, 404)

    # ── the legacy protocol ──
    def test_the_old_open_endpoints_no_longer_trust_anyone(self):
        n = self.node('box1')
        public_id = self.admin('get', '/api/nodes').get_json()[0]['node_id']    # a node id must never be usable as a credential
        forged = {'nodeId': public_id, 'severity': 'critical', 'type': 'ransomware', 'source': 'evil'}
        self.assertEqual(self.c.post('/api/signal', json=forged).status_code, 401)
        self.assertEqual(self.admin('post', '/api/signal', json=forged).status_code, 401)   # not an admin endpoint either
        self.assertEqual(self.c.post('/api/signal', json=forged, headers={'X-API-Key': 'a' * 64}).status_code, 401)
        self.assertEqual(self.Threat.query.count(), 0)
        r = self.as_node(n['token'], 'post', '/api/signal', json=dict(forged, nodeId='someone-else'))
        self.assertEqual(r.status_code, 201)
        self.assertEqual(self.Threat.query.one().node_id, 'box1')                # stamped from the token, not the body
        self.assertEqual(self.c.post('/api/node/heartbeat', json={'nodeId': public_id}).status_code, 401)
        self.assertEqual(self.as_node(n['token'], 'post', '/api/node/heartbeat', json={}).status_code, 200)
        self.assertEqual(self.c.post('/api/node/register', json={'hostname': 'evil'}).status_code, 401)   # no free tokens any more

    # ── upgrade path ──
    def test_migration_adds_columns_and_clears_the_retired_plaintext_tokens(self):
        from sqlalchemy import create_engine, inspect
        path = os.path.join(_TMP, 'old-node.db')
        con = sqlite3.connect(path)
        con.execute('CREATE TABLE node (id INTEGER PRIMARY KEY, node_id VARCHAR(200), hostname VARCHAR(200), token VARCHAR(200), status VARCHAR(50))')
        con.execute("INSERT INTO node (node_id, hostname, token, status) VALUES ('legacy', 'h', 'plaintext-token', 'active')")
        con.commit()
        con.close()
        eng = create_engine(f'sqlite:///{path}')
        self.appmod._ensure_schema(eng)
        self.appmod._ensure_schema(eng)
        cols = {c['name'] for c in inspect(eng).get_columns('node')}
        self.assertTrue({'token_hash', 'token_hint', 'enrolled_at', 'revoked_at'} <= cols)
        self.assertIn('ix_node_token_hash', {i['name'] for i in inspect(eng).get_indexes('node')})
        with eng.connect() as conn:
            self.assertEqual(conn.exec_driver_sql("SELECT node_id, token, token_hash FROM node").fetchall(), [('legacy', None, None)])

    def test_the_hubs_own_node_row_holds_no_credential(self):
        rows = self.admin('get', '/api/nodes').get_json()
        self.assertTrue(all(r['credential'] in ('none', 'active', 'revoked') for r in rows))
        n = self.node('box1')
        creds = {r['node_id']: r['credential'] for r in self.admin('get', '/api/nodes').get_json()}
        self.assertEqual(creds['box1'], 'active')
        self.assertTrue(n['apiBase'].endswith('/api'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
