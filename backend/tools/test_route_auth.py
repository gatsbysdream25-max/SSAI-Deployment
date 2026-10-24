#!/usr/bin/env python3
"""Authorization matrix: every route is deliberately classified, and behaves that way (2026-09-20).
A NEW route that is not listed below fails this test, so nothing becomes reachable by accident.
Run:  swarmsentinel-env/bin/python3 backend/tools/test_route_auth.py"""
import os
import re
import stat
import sys
import tempfile
import unittest
from datetime import datetime, timezone

_TMP = tempfile.mkdtemp()
os.environ['DATA_DIR'] = _TMP
os.environ['DATABASE_URL'] = f'sqlite:///{_TMP}/routes-test.db'
os.environ['SSAI_API_KEY'] = ADMIN = 'route-matrix-admin-key'
os.environ['SSAI_VIEWER_KEY'] = VIEWER = 'route-matrix-viewer-key'
os.environ.pop('SSAI_TRUSTED_PROXIES', None)

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
sys.path[:0] = [os.path.join(BACKEND, 'agents'), BACKEND]
import auth  # noqa: E402

# Anyone on the network may call these: pages that hold no data, a health probe, and three aggregate counters that name
# nothing (an uptime probe needs them). Threat data is NOT here: see READER.
ANONYMOUS = {
    ('GET', '/'), ('GET', '/health'), ('GET', '/dashboard'), ('GET', '/login'), ('POST', '/login'), ('POST', '/logout'),
    ('GET', '/api/stats'), ('GET', '/api/status/'), ('GET', '/api/cloud_status'),
    ('GET', '/login/sso'), ('GET', '/login/sso/callback'),   # start and finish a single sign-on; the callback checks state, nonce and the ID token itself
    ('POST', '/api/node/register'),               # public by design: it checks a single-use enrollment code itself
}
# Threat data and the deployment's posture: a signed-in admin, the admin key, or the display's viewer key
# (SSAI_VIEWER_KEY in the X-SSAI-Viewer header, added by the kiosk's proxy). Anonymous callers and node tokens are refused.
READER = {
    ('GET', '/api/summary'), ('GET', '/api/threats/'), ('GET', '/api/threats/collective'), ('GET', '/api/threats/recall'), ('GET', '/api/threats/related'),
    ('GET', '/api/collective'), ('GET', '/api/dashboard_snapshot'), ('GET', '/api/signal/feed'), ('GET', '/api/agents/'),
    ('GET', '/api/ai_swarm'), ('GET', '/api/github_stats'),
}
# Signed-in pages: anonymous visitors are sent to /login.
LOGIN_PAGES = {('GET', '/settings'), ('GET', '/setup')}
# A machine may call these: the admin key or an enrolled node's own token.
MACHINE = {('POST', '/api/threats/'), ('POST', '/api/agents/register'), ('POST', '/api/agents/heartbeat'),
           ('POST', '/api/node/heartbeat'), ('POST', '/api/signal')}
# Only a node token (never the admin key, never anonymous) makes sense here: the node id comes from the token.
NODE_ONLY = {('POST', '/api/signal'), ('POST', '/api/node/heartbeat')}
# Deciding for others needs a signed-in PERSON: an API key is refused with 403 (the agents hold the same key).
PERSON_ONLY = {('POST', '/api/remediation/<int:id>/approve'), ('POST', '/api/autonomy/grants'), ('POST', '/api/threats/<int:threat_id>/block')}
# Teams approvals: the Copilot lane key AND an approver's own Entra token. Neither key alone (not even the admin key)
# is enough; see test_copilot_remediation.py for the token checks.
TEAMS_APPROVER = {('POST', '/api/copilot/remediation/<int:id>/approve'), ('POST', '/api/copilot/remediation/<int:id>/reject')}
# Everything else is admin-only: the API key, or a signed-in session that sends its CSRF token.


def dummy(rule):
    return re.sub(r'<(?:int:)?(\w+)>', lambda m: '999999' if m.group(1) in ('id', 'threat_id', 'entry_id') else 'nonexistent-x', rule)


class Matrix(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import app as appmod
        if _TMP not in appmod.app.config['SQLALCHEMY_DATABASE_URI']:
            raise RuntimeError('refusing to run against a non-test database')
        cls.appmod, cls.app, cls.db = appmod, appmod.app, appmod.db
        cls.app.config['TESTING'] = True
        appmod._AUDIT_PATH = os.path.join(_TMP, 'audit.jsonl')
        cls.pairs = sorted((m, r.rule) for r in cls.app.url_map.iter_rules() if r.endpoint != 'static' for m in r.methods - {'HEAD', 'OPTIONS'})

    def setUp(self):
        self.ctx = self.app.app_context()
        self.ctx.push()
        self.db.create_all()
        from models import Node
        self.Node = Node
        self.Node.query.filter_by(node_id='matrix-node').delete()
        token = auth.new_token()
        self.db.session.add(self.Node(node_id='matrix-node', hostname='m', status='active', token_hash=auth.hash_secret(token),
                                      registered=datetime.now(timezone.utc)))
        self.db.session.commit()
        self.token = token
        auth.node_ingest = auth.SlidingWindow(10000, 60)
        auth.enroll_failures = auth.SlidingWindow(10000, 300)
        auth.set_admin_password('a valid test password')        # a real install always has one

    def tearDown(self):
        self.db.session.remove()
        self.ctx.pop()

    def call(self, method, rule, headers=None):
        c = self.app.test_client()
        kw = {'headers': headers or {}}
        if method != 'GET':
            kw['json'] = {}
        return getattr(c, method.lower())(dummy(rule), **kw)

    def admin_only(self):
        return [p for p in self.pairs if p not in ANONYMOUS and p not in READER and p not in LOGIN_PAGES
                and p not in MACHINE and p not in TEAMS_APPROVER]

    def test_every_route_is_classified_and_the_lists_name_real_routes(self):
        known = set(self.pairs)
        for name, group in (('ANONYMOUS', ANONYMOUS), ('READER', READER), ('LOGIN_PAGES', LOGIN_PAGES),
                            ('MACHINE', MACHINE), ('TEAMS_APPROVER', TEAMS_APPROVER)):
            self.assertEqual(group - known, set(), f'{name} lists a route that no longer exists')
        self.assertEqual(ANONYMOUS & MACHINE, set())
        self.assertEqual(ANONYMOUS & READER, set())
        self.assertEqual({(m, r) for m, r in READER if r not in self.appmod.READ_PROTECTED}, set(),
                         'READER names a route that app.READ_PROTECTED does not guard')
        self.assertEqual({r for r in self.appmod.READ_PROTECTED} - {r for _, r in READER}, set(),
                         'app.READ_PROTECTED guards a route this matrix does not list')
        self.assertGreater(len(self.admin_only()), 20)
        self.assertGreater(len(self.pairs), 45, 'the route table looks unexpectedly small')

    def test_admin_only_routes_refuse_anonymous_callers_and_node_tokens(self):
        for method, rule in self.admin_only():
            for who, headers in (('anonymous', {}), ('a node token', {'X-API-Key': self.token}), ('a wrong key', {'X-API-Key': 'nope'}),
                                 ('an anonymous read-only display', {'X-SSAI-Readonly': '1'}),
                                 ('the viewer key', {'X-SSAI-Viewer': VIEWER})):
                r = self.call(method, rule, headers)
                self.assertIn(r.status_code, (401, 403), f'{method} {rule} answered {r.status_code} to {who}')

    def test_reader_routes_refuse_anonymous_callers_and_node_tokens_but_serve_the_viewer_and_admin(self):
        for method, rule in sorted(READER):
            for who, headers in (('anonymous', {}), ('a node token', {'X-API-Key': self.token}), ('a wrong key', {'X-API-Key': 'nope'}),
                                 ('a wrong viewer key', {'X-SSAI-Viewer': 'nope'}), ('a read-only display with no key', {'X-SSAI-Readonly': '1'}),
                                 ('the viewer key sent as an API key', {'X-API-Key': VIEWER})):
                self.assertEqual(self.call(method, rule, headers).status_code, 401, f'{method} {rule} answered {who}')
            for who, headers in (('the viewer key', {'X-SSAI-Viewer': VIEWER}), ('the admin key', {'X-API-Key': ADMIN}),
                                 ('the viewer key behind a read-only display', {'X-SSAI-Viewer': VIEWER, 'X-SSAI-Readonly': '1'})):
                code = self.call(method, rule, headers).status_code
                self.assertEqual(code, 200, f'{method} {rule} answered {code} to {who}')

    def test_the_viewer_key_does_not_work_when_none_is_configured(self):
        saved = os.environ.pop('SSAI_VIEWER_KEY')
        try:
            for method, rule in sorted(READER):
                for sent in (VIEWER, ''):
                    self.assertEqual(self.call(method, rule, {'X-SSAI-Viewer': sent}).status_code, 401, f'{method} {rule}')
        finally:
            os.environ['SSAI_VIEWER_KEY'] = saved

    def test_teams_approvals_refuse_every_key_on_its_own(self):
        for method, rule in sorted(TEAMS_APPROVER):
            for who, headers in (('anonymous', {}), ('the admin key', {'X-API-Key': ADMIN}), ('a node token', {'X-API-Key': self.token})):
                self.assertIn(self.call(method, rule, headers).status_code, (401, 403), f'{method} {rule} {who}')

    def test_login_pages_redirect_to_the_sign_in_page(self):
        for method, rule in LOGIN_PAGES:
            r = self.call(method, rule)
            self.assertEqual((r.status_code, r.headers['Location'].split('?')[0]), (302, '/login'), rule)

    def test_the_admin_key_is_accepted_on_every_admin_route(self):
        for method, rule in self.admin_only():
            r = self.call(method, rule, {'X-API-Key': ADMIN})
            if rule == '/api/admin/password':          # the key alone is not enough here: the current password is also required
                self.assertEqual(r.status_code, 403)
                self.assertIn('current password', r.get_json()['error'])
                continue
            if (method, rule) in PERSON_ONLY:    # a key is a program, not a person (audit F-04): see test_approval_person.py, test_autonomy.py
                self.assertEqual(r.status_code, 403)
                self.assertIn('signed-in person', r.get_json()['error'])
                continue
            self.assertNotIn(r.status_code, (401, 403), f'{method} {rule} refused the admin key ({r.status_code})')

    def test_machine_routes_take_a_node_token_or_the_admin_key_but_not_strangers(self):
        for method, rule in sorted(MACHINE):
            self.assertEqual(self.call(method, rule).status_code, 401, f'{method} {rule} anonymous')
            self.assertEqual(self.call(method, rule, {'X-API-Key': 'wrong'}).status_code, 401, f'{method} {rule} wrong key')
            node = self.call(method, rule, {'X-API-Key': self.token})
            self.assertNotEqual(node.status_code, 401, f'{method} {rule} refused a valid node token')
            if (method, rule) in NODE_ONLY:
                self.assertEqual(self.call(method, rule, {'X-API-Key': ADMIN}).status_code, 401, f'{method} {rule} accepted the admin key')

    def test_anonymous_routes_never_answer_with_a_server_error(self):
        for method, rule in sorted(ANONYMOUS):
            self.assertLess(self.call(method, rule).status_code, 500, f'{method} {rule}')

    def test_no_anonymous_response_contains_a_configured_secret(self):
        secrets_ = [v for k, v in os.environ.items() if any(t in k for t in ('KEY', 'TOKEN', 'SECRET', 'PASSWORD')) and len(v) >= 8]
        for method, rule in sorted(ANONYMOUS):
            body = self.call(method, rule).get_data(as_text=True)
            for s in secrets_:
                self.assertNotIn(s, body, f'{method} {rule} contains a secret value')

    def test_oversized_bodies_are_refused_before_they_are_read(self):
        c = self.app.test_client()
        r = c.post('/api/threats/', data='x' * (17 * 1024 * 1024), content_type='application/json', headers={'X-API-Key': ADMIN})
        self.assertEqual(r.status_code, 413)
        self.assertEqual(r.get_json()['error'], 'request too large')


class Permissions(unittest.TestCase):
    def test_the_data_directory_and_its_files_are_owner_only_after_startup(self):
        import app as appmod
        inst = appmod.ssai_config.INSTANCE_DIR
        os.makedirs(inst, exist_ok=True)
        loose = os.path.join(inst, 'swarmsentinel.db')
        with open(loose, 'a'):
            pass
        os.chmod(loose, 0o644)
        os.chmod(inst, 0o755)
        public = os.path.join(inst, 'intel_cache.json')
        with open(public, 'w') as f:
            f.write('{}')
        os.chmod(public, 0o644)
        appmod._secure_instance_dir()
        self.assertEqual(stat.S_IMODE(os.stat(inst).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(loose).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(public).st_mode), 0o644)         # public feed data stays readable
        newfile = os.path.join(inst, 'created-later.json')
        with open(newfile, 'w') as f:                                          # the process umask covers files made after startup
            f.write('{}')
        self.assertEqual(stat.S_IMODE(os.stat(newfile).st_mode), 0o600)


if __name__ == '__main__':
    unittest.main(verbosity=2)
