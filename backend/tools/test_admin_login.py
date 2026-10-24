#!/usr/bin/env python3
"""Dashboard admin login: passwords, sessions, CSRF, page access, and that the admin key never reaches a browser.
Run:  swarmsentinel-env/bin/python3 backend/tools/test_admin_login.py"""
import json
import os
import stat
import sys
import tempfile
import time
import unittest
from unittest import mock

# SAFETY: throwaway data dir, database, admin key and (deliberately) NO configured SECRET_KEY, before any import.
_TMP = tempfile.mkdtemp()
os.environ['DATA_DIR'] = _TMP
os.environ['DATABASE_URL'] = f'sqlite:///{_TMP}/login-test.db'
os.environ['SSAI_API_KEY'] = ADMIN_KEY = 'machine-key-must-never-appear-in-a-page'
os.environ.pop('SECRET_KEY', None)
os.environ.pop('SSAI_TRUSTED_PROXIES', None)

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
sys.path[:0] = [os.path.join(BACKEND, 'agents'), BACKEND]
import auth  # noqa: E402

PASSWORD = 'correct horse battery staple'


class Passwords(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(tempfile.mkdtemp(), 'admin.json')

    def test_rules(self):
        self.assertIsNone(auth.password_problem(PASSWORD))
        for bad, why in (('short', 'at least'), ('a' * 12, 'repetitive'), ('x' * 500, 'at most'), (None, 'at least'), (12345678901234, 'at least')):
            self.assertIn(why, auth.password_problem(bad) or '', repr(bad)[:20])

    def test_stored_only_as_a_salted_hash_owner_only_and_atomically(self):
        with mock.patch.object(auth, 'admin_path', lambda: self.path):
            auth.set_admin_password(PASSWORD)
            raw = open(self.path).read()
            self.assertNotIn(PASSWORD, raw)
            self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)
            self.assertEqual(os.listdir(os.path.dirname(self.path)), ['admin.json'])
            self.assertTrue(auth.verify_password(PASSWORD))
            for wrong in ('', 'wrong password here', PASSWORD + 'x', None, 5, 'x' * 5000):
                self.assertFalse(auth.verify_password(wrong), repr(wrong)[:20])
            v1 = auth.load_admin()['version']
            auth.set_admin_password('another perfectly fine phrase')
            self.assertNotEqual(auth.load_admin()['version'], v1)                # sessions tied to the old one die
            with self.assertRaises(ValueError):
                auth.set_admin_password('short')
            self.assertTrue(auth.verify_password('another perfectly fine phrase'))    # a refused change changes nothing

    def test_missing_and_corrupt_files_mean_no_password(self):
        with mock.patch.object(auth, 'admin_path', lambda: self.path):
            self.assertIsNone(auth.load_admin())
            self.assertFalse(auth.verify_password(PASSWORD))
            for junk in ('{bad', '[]', '{"password_hash": 5}', '{"password_hash": ""}', '{}'):
                with open(self.path, 'w') as f:
                    f.write(junk)
                os.utime(self.path, ns=(time.time_ns() + 10**9, time.time_ns() + 10**9))
                auth._admin_cache.update(mtime=None, data=None)
                self.assertIsNone(auth.load_admin(), junk)


class Site(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import app as appmod
        if _TMP not in appmod.app.config['SQLALCHEMY_DATABASE_URI']:
            raise RuntimeError('refusing to run against a non-test database')
        cls.appmod, cls.app, cls.db = appmod, appmod.app, appmod.db
        cls.app.config['TESTING'] = True
        appmod._AUDIT_PATH = os.path.join(_TMP, 'audit.jsonl')

    def setUp(self):
        self.ctx = self.app.app_context()
        self.ctx.push()
        self.db.create_all()
        auth.login_failures = auth.SlidingWindow(5, 300)
        auth.login_failures_all = auth.SlidingWindow(40, 300)
        auth.set_admin_password(PASSWORD)
        self.c = self.app.test_client()

    def tearDown(self):
        self.db.session.remove()
        self.ctx.pop()

    def login(self, client=None, password=PASSWORD, **extra):
        return (client or self.c).post('/login', json=dict({'password': password}, **extra))

    def csrf(self, client=None):
        html = (client or self.c).get('/dashboard').get_data(as_text=True)
        return json.loads(html.split('const CSRF_TOKEN = ')[1].split(';')[0])

    def cookie_headers(self, resp):
        return [h for h in resp.headers.getlist('Set-Cookie') if h.startswith('ssai_session=')]

    # ── sign in ──
    def test_no_password_configured_says_how_to_set_one(self):
        os.remove(auth.admin_path())
        auth._admin_cache.update(mtime=None, data=None)
        r = self.login()
        self.assertEqual(r.status_code, 503)
        self.assertIn('set-password', r.get_json()['error'])
        self.assertIn('set-password.sh', self.c.get('/login').get_data(as_text=True))

    def test_wrong_passwords_are_refused_and_the_right_one_signs_in_with_a_hardened_cookie(self):
        for bad in ('', 'nope', PASSWORD.upper(), PASSWORD + ' '):
            self.assertEqual(self.login(password=bad).status_code, 401, bad)
        auth.login_failures = auth.SlidingWindow(5, 300)
        self.assertEqual(self.c.post('/login', data='not json').status_code, 401)
        self.assertEqual(self.c.post('/login', json=[1, 2]).status_code, 401)
        auth.login_failures = auth.SlidingWindow(5, 300)                               # (6 failures would rightly lock us out)
        r = self.login()
        self.assertEqual((r.status_code, r.get_json()['ok']), (200, True))
        cookie = self.cookie_headers(r)[0]
        self.assertIn('HttpOnly', cookie)
        self.assertIn('SameSite=Lax', cookie)
        self.assertIn('Path=/', cookie)
        self.assertRegex(cookie, r'(Max-Age|Expires)=')                                # not a browser-lifetime-only cookie

    def test_form_posts_work_too(self):
        self.assertEqual(self.c.post('/login', data={'password': PASSWORD}).status_code, 200)

    def test_repeated_failures_lock_out_even_the_right_password_and_spoofed_forwarding_does_not_reset_it(self):
        for i in range(5):
            self.c.post('/login', json={'password': f'wrong password {i}'}, headers={'X-Forwarded-For': f'9.9.9.{i}'})
        r = self.c.post('/login', json={'password': PASSWORD}, headers={'X-Forwarded-For': '8.8.8.8'})
        self.assertEqual(r.status_code, 429)
        self.assertEqual(r.headers.get('Retry-After'), '300')

    def test_a_flood_from_many_addresses_is_also_limited(self):
        auth.login_failures_all = auth.SlidingWindow(3, 300)
        with mock.patch.object(auth, 'client_ip', side_effect=[f'10.0.0.{i}' for i in range(20)]):
            codes = [self.c.post('/login', json={'password': 'wrong password!'}).status_code for _ in range(5)]
        self.assertEqual(codes[:3], [401, 401, 401])
        self.assertEqual(set(codes[3:]), {429})

    # ── what a session may do ──
    def test_a_session_can_read_admin_pages_and_data_but_a_state_change_needs_the_csrf_token(self):
        self.assertEqual(self.c.get('/api/identify?target=8.8.8.8').status_code, 401)          # anonymous
        self.login()
        import identify
        with mock.patch.object(identify, 'default_deps', lambda **k: identify.Deps(rdns=lambda ip: 'x', rdap=lambda ip: {'name': 'N'})):
            self.assertEqual(self.c.get('/api/identify?target=8.8.8.8').status_code, 200)      # GET needs no token
        body = {'agent': 'AuthLogAgent', 'enabled': False}
        self.assertEqual(self.c.post('/api/settings/agents', json=body).status_code, 401)       # cookie alone: a forged cross-site POST
        self.assertEqual(self.c.post('/api/settings/agents', json=body, headers={'X-CSRF-Token': 'guess'}).status_code, 401)
        self.assertEqual(self.c.post('/api/settings/agents', json=body, headers={'X-CSRF-Token': ''}).status_code, 401)
        good = self.csrf()
        self.assertEqual(self.c.post('/api/settings/agents', json=body, headers={'X-CSRF-Token': good}).status_code, 200)
        other = self.app.test_client()
        self.login(other)
        self.assertNotEqual(self.csrf(other), good)                                              # per-session tokens
        self.assertEqual(self.c.post('/api/settings/agents', json=body, headers={'X-CSRF-Token': self.csrf(other)}).status_code, 401)
        self.assertEqual(self.c.delete('/api/nodes/none', headers={'X-CSRF-Token': good}).status_code, 404)   # authorised, just absent
        self.assertEqual(self.c.delete('/api/nodes/none').status_code, 401)

    def test_the_api_key_still_works_for_machines_without_any_session(self):
        r = self.app.test_client().post('/api/settings/agents', json={'agent': 'AuthLogAgent', 'enabled': True}, headers={'X-API-Key': ADMIN_KEY})
        self.assertEqual(r.status_code, 200)
        r = self.app.test_client().post('/api/settings/agents', json={'agent': 'AuthLogAgent', 'enabled': True}, headers={'X-API-Key': 'wrong'})
        self.assertEqual(r.status_code, 401)

    def test_sign_out_ends_the_session_and_expiry_is_enforced(self):
        self.login()
        tok = self.csrf()
        self.assertEqual(self.c.get('/settings').status_code, 200)
        real_time = time.time
        with mock.patch.object(auth.time, 'time', lambda: real_time() + auth.SESSION_MAX_AGE + 5):
            self.assertEqual(self.c.get('/settings').status_code, 302)                           # too old
        self.assertEqual(self.c.post('/logout', headers={'X-CSRF-Token': tok}).status_code, 200)
        self.assertEqual(self.c.get('/settings').status_code, 302)

    def test_changing_the_password_ends_other_sessions_and_needs_the_current_one(self):
        other = self.app.test_client()
        self.login(other)
        self.login()
        tok = self.csrf()
        url, hdr = '/api/admin/password', {'X-CSRF-Token': tok}
        self.assertEqual(self.app.test_client().post(url, json={'current': PASSWORD, 'new': 'a fine new passphrase'}).status_code, 401)
        self.assertEqual(self.c.post(url, json={'current': 'wrong', 'new': 'a fine new passphrase'}, headers=hdr).status_code, 403)
        self.assertEqual(self.c.post(url, json={'current': PASSWORD, 'new': 'short'}, headers=hdr).status_code, 400)
        self.assertEqual(self.c.post(url, json={'current': PASSWORD, 'new': 'a fine new passphrase'}, headers=hdr).status_code, 200)
        self.assertEqual(self.c.get('/settings').status_code, 200)                              # this person stays signed in
        self.assertEqual(other.get('/settings').status_code, 302)                                # everyone else is signed out
        self.assertEqual(self.login(self.app.test_client()).status_code, 401)                    # the old password is dead
        self.assertEqual(self.login(self.app.test_client(), password='a fine new passphrase').status_code, 200)

    def test_a_tampered_cookie_and_one_forged_with_the_old_published_secret_are_rejected(self):
        self.login()
        cookie = self.c.get_cookie('ssai_session').value
        self.c.set_cookie('ssai_session', cookie[:-3] + ('AAA' if cookie[-3:] != 'AAA' else 'BBB'))
        self.assertEqual(self.c.get('/settings').status_code, 302)
        from flask import Flask
        from flask.sessions import SecureCookieSessionInterface
        fake = Flask('fake')
        fake.secret_key = 'swarmsentinel-secret-change-in-prod'          # what the source used to publish
        forged = SecureCookieSessionInterface().get_signing_serializer(fake).dumps(
            {'adm': True, 'iat': int(time.time()), 'pwv': auth.load_admin()['version'], 'csrf': 'x'})
        c2 = self.app.test_client()
        c2.set_cookie('ssai_session', forged)
        self.assertEqual(c2.get('/settings').status_code, 302)
        self.assertEqual(c2.post('/api/settings/agents', json={'agent': 'AuthLogAgent', 'enabled': False}, headers={'X-CSRF-Token': 'x'}).status_code, 401)

    # ── pages ──
    def test_no_page_ever_contains_the_api_key_for_anyone(self):
        kiosk = {'X-SSAI-Readonly': '1'}
        anon = self.app.test_client()
        seen = []
        for path in ('/dashboard', '/login', '/settings', '/setup'):
            for c, hdr in ((anon, {}), (anon, kiosk)):
                seen.append(c.get(path, headers=hdr).get_data(as_text=True))
        self.login()
        for path in ('/dashboard', '/settings', '/setup'):
            seen.append(self.c.get(path).get_data(as_text=True))
        self.assertGreater(len(seen), 10)
        for body in seen:
            self.assertNotIn(ADMIN_KEY, body)
            self.assertNotIn('X-API-Key', body.replace('X-API-Key-gated', ''))

    def test_dashboard_is_view_only_until_signed_in(self):
        anon = self.c.get('/dashboard').get_data(as_text=True)
        self.assertIn('class="readonly"', anon)
        self.assertNotIn(' kiosk"', anon)                    # a signed-out PC still gets the gear (its links go through login)
        self.assertIn('Sign in', anon)
        self.assertIn('const CSRF_TOKEN = "";', anon)
        self.login()
        me = self.c.get('/dashboard').get_data(as_text=True)
        self.assertNotIn('class="readonly"', me)
        self.assertIn('Sign out', me)
        self.assertNotIn('const CSRF_TOKEN = "";', me)
        kiosk = self.c.get('/dashboard', headers={'X-SSAI-Readonly': '1'}).get_data(as_text=True)     # kiosk always wins
        self.assertIn('class="readonly kiosk"', kiosk)       # only the kiosk hides the gear
        self.assertNotIn('Sign in', kiosk)

    def test_settings_and_setup_need_a_login_except_for_the_read_only_kiosk(self):
        for path in ('/settings', '/setup'):
            r = self.c.get(path)
            self.assertEqual(r.status_code, 302)
            self.assertEqual(r.headers['Location'], f'/login?next={path}')
            self.assertEqual(self.c.get(path, headers={'X-SSAI-Readonly': '1'}).status_code, 403)     # the kiosk is refused outright
            self.assertEqual(self.c.post('/api/settings/agents', json={}, headers={'X-SSAI-Readonly': '1', 'X-API-Key': ADMIN_KEY}).status_code, 403)
        self.login()
        self.assertEqual(self.c.get('/settings').status_code, 200)

    def test_login_redirects_stay_on_this_site(self):
        for evil in ('//evil.example', 'https://evil.example', '/\\evil.example', 'javascript:alert(1)', '/login', '', None, '/' + 'a' * 400):
            self.assertEqual(self.login(self.app.test_client(), next=evil).get_json()['next'], '/dashboard', repr(evil)[:30])
        self.assertEqual(self.login(self.app.test_client(), next='/settings').get_json()['next'], '/settings')
        r = self.c.get('/login?next=//evil.example')
        self.assertEqual(r.status_code, 200)
        self.login()
        self.assertEqual(self.c.get('/login?next=//evil.example').headers['Location'], '/dashboard')
        self.assertEqual(self.c.get('/login?next=/settings').headers['Location'], '/settings')

    def test_security_headers_and_no_caching_of_pages_that_carry_a_token(self):
        self.login()
        for path in ('/dashboard', '/settings', '/login', '/api/summary'):
            r = self.c.get(path)
            self.assertEqual(r.headers.get('X-Content-Type-Options'), 'nosniff', path)
            self.assertEqual(r.headers.get('X-Frame-Options'), 'SAMEORIGIN', path)
        for path in ('/dashboard', '/settings'):
            self.assertEqual(self.c.get(path).headers.get('Cache-Control'), 'no-store', path)

    def test_sign_ins_and_failures_are_audited(self):
        self.login(password='wrong password!')
        self.login()
        rows = [json.loads(line) for line in open(self.appmod._AUDIT_PATH) if '"login"' in line]
        self.assertEqual([r['ok'] for r in rows[-2:]], [False, True])
        self.assertNotIn(PASSWORD, open(self.appmod._AUDIT_PATH).read())


class SecretKey(unittest.TestCase):
    def setUp(self):
        import app as appmod
        self.appmod = appmod
        self.key_file = os.path.join(_TMP, 'backend', 'instance', 'secret_key')
        if os.path.exists(self.key_file):
            os.remove(self.key_file)

    def test_a_published_or_weak_secret_is_never_used(self):
        published = 'swarmsentinel-secret-change-in-prod'
        for env in (published, 'changeme', 'short', '', '   '):
            with mock.patch.dict(os.environ, {'SECRET_KEY': env}):
                if os.path.exists(self.key_file):
                    os.remove(self.key_file)
                k = self.appmod._load_secret_key()
                self.assertNotEqual(k, published)
                self.assertGreaterEqual(len(k), 32)
                self.assertEqual(self.appmod._load_secret_key(), k)                       # stable across workers/restarts
        self.assertEqual(stat.S_IMODE(os.stat(self.key_file).st_mode), 0o600)

    def test_a_real_configured_secret_is_used_as_is(self):
        with mock.patch.dict(os.environ, {'SECRET_KEY': 'x' * 8 + 'a-genuinely-long-random-value'}):
            self.assertEqual(self.appmod._load_secret_key(), 'x' * 8 + 'a-genuinely-long-random-value')

    def test_the_running_app_does_not_use_the_published_default(self):
        self.assertNotEqual(self.appmod.app.config['SECRET_KEY'], 'swarmsentinel-secret-change-in-prod')


class Cli(unittest.TestCase):
    def test_generate_to_a_file_and_status(self):
        import adminctl
        out = os.path.join(tempfile.mkdtemp(), 'pw.txt')
        auth._admin_cache.update(mtime=None, data=None)
        fixed = os.path.join(tempfile.mkdtemp(), 'admin.json')
        with mock.patch.object(auth, 'admin_path', lambda: fixed):
            self.assertEqual(adminctl.main(['status']), 0)
            self.assertEqual(adminctl.main(['set-password', '--generate', '--out', out]), 0)
            pw = open(out).read().strip()
            self.assertGreaterEqual(len(pw), 20)
            self.assertEqual(stat.S_IMODE(os.stat(out).st_mode), 0o600)
            self.assertTrue(auth.verify_password(pw))


if __name__ == '__main__':
    unittest.main(verbosity=2)
