#!/usr/bin/env python3
"""Single sign-on for the dashboard admin (2026-10-18): ID-token checks and the sign-in flow.
Run:  swarmsentinel-env/bin/python3 backend/tools/test_sso.py"""
import os
import sys
import tempfile
import time
import unittest
from unittest import mock
from urllib.parse import parse_qs, urlparse

_TMP = tempfile.mkdtemp()
os.environ['DATA_DIR'] = _TMP
os.environ['DATABASE_URL'] = f'sqlite:///{_TMP}/sso-test.db'
os.environ['SSAI_API_KEY'] = 'sso-test-admin-key'
os.environ['SSAI_PROVIDER_CHECK'] = '0'
os.environ['SSAI_STATE_DB'] = os.path.join(_TMP, 'state.db')

TENANT = '11111111-2222-3333-4444-555555555555'
CLIENT = 'app-client-id'
ADMIN_OID = 'aaaaaaaa-0000-0000-0000-000000000001'
ADMIN_UPN = 'admin@bank.example'
REDIRECT = 'https://ssai.bank.example/login/sso/callback'
SSO_ENV = {'SSAI_SSO_TENANT_ID': TENANT, 'SSAI_SSO_CLIENT_ID': CLIENT, 'SSAI_SSO_CLIENT_SECRET': 'shh-secret',
           'SSAI_SSO_REDIRECT_URI': REDIRECT, 'SSAI_SSO_ADMINS': f'{ADMIN_OID}, {ADMIN_UPN.upper()}'}

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
sys.path[:0] = [os.path.join(BACKEND, 'agents'), BACKEND]

import jwt  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402

import entra  # noqa: E402
import sso  # noqa: E402

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def token(nonce='n1', key=KEY, alg='RS256', **over):
    now = int(time.time())
    claims = {'iss': f'https://login.microsoftonline.com/{TENANT}/v2.0', 'aud': CLIENT, 'tid': TENANT, 'sub': 'sub-1',
              'oid': ADMIN_OID, 'preferred_username': ADMIN_UPN, 'name': 'Ada Admin', 'nonce': nonce,
              'iat': now - 5, 'exp': now + 600}
    claims.update(over)
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, key, algorithm=alg)


def key_for(_token, _url):
    return KEY.public_key()


class Settings(unittest.TestCase):
    def test_sso_is_off_until_every_required_setting_is_present(self):
        with mock.patch.dict(os.environ, SSO_ENV):
            self.assertTrue(sso.configured())
            for missing in ('SSAI_SSO_TENANT_ID', 'SSAI_SSO_CLIENT_ID', 'SSAI_SSO_CLIENT_SECRET', 'SSAI_SSO_REDIRECT_URI'):
                env = dict(os.environ)
                env.pop(missing)
                with mock.patch.dict(os.environ, env, clear=True):
                    self.assertFalse(sso.configured(), missing)

    def test_an_empty_admin_list_means_nobody_not_everybody(self):
        with mock.patch.dict(os.environ, dict(SSO_ENV, SSAI_SSO_ADMINS='')):
            with self.assertRaises(sso.SsoError):
                sso.verify_id_token(token(), 'n1', key_for=key_for)

    def test_sso_only_never_applies_while_sso_is_not_configured(self):
        with mock.patch.dict(os.environ, {'SSAI_SSO_ONLY': '1'}):
            self.assertFalse(sso.only())          # a typo in the settings must not lock everyone out
        with mock.patch.dict(os.environ, dict(SSO_ENV, SSAI_SSO_ONLY='1')):
            self.assertTrue(sso.only())


@mock.patch.dict(os.environ, SSO_ENV)
class IdToken(unittest.TestCase):
    def verify(self, tok, nonce='n1'):
        return sso.verify_id_token(tok, nonce, key_for=key_for)

    def test_an_admin_on_the_list_is_accepted_by_object_id_and_by_name_only_when_enabled(self):
        self.assertEqual(self.verify(token())['name'], 'Ada Admin')
        with self.assertRaises(sso.SsoError):                                                 # names are off by default (see test_review_round2.py)
            self.verify(token(oid='other-oid'))
        with mock.patch.dict(os.environ, {'SSAI_SSO_ADMINS_BY_NAME': '1'}):
            self.assertIn(self.verify(token(oid='other-oid'))['subject'], (ADMIN_UPN,))      # case-insensitive list entry
            self.assertEqual(self.verify(token(preferred_username=None, email=ADMIN_UPN.upper()))['subject'], ADMIN_OID)

    def test_a_person_who_is_not_on_the_list_is_refused(self):
        with self.assertRaises(sso.SsoError):
            self.verify(token(oid='bbbbbbbb-0000-0000-0000-000000000002', preferred_username='intern@bank.example'))

    def test_the_wrong_audience_issuer_tenant_or_nonce_is_refused(self):
        for bad in (token(aud='someone-elses-app'), token(iss='https://evil.example/v2.0'), token(tid='99999999-0000-0000-0000-000000000000'),
                    token(exp=int(time.time()) - 3600, iat=int(time.time()) - 7200)):
            with self.assertRaises(sso.SsoError):
                self.verify(bad)
        with self.assertRaises(sso.SsoError):
            self.verify(token(nonce='a-different-attempt'))
        with self.assertRaises(sso.SsoError):
            self.verify(token(nonce=None))

    def test_a_token_signed_by_anyone_else_is_refused(self):
        with self.assertRaises(sso.SsoError):
            self.verify(token(key=OTHER_KEY))

    def test_unsigned_and_symmetric_tokens_are_refused(self):
        now = int(time.time())
        claims = {'iss': f'https://login.microsoftonline.com/{TENANT}/v2.0', 'aud': CLIENT, 'tid': TENANT, 'sub': 's', 'oid': ADMIN_OID,
                  'nonce': 'n1', 'iat': now, 'exp': now + 600}
        for forged in (jwt.encode(claims, None, algorithm='none'), jwt.encode(claims, 'shh-secret', algorithm='HS256')):
            with self.assertRaises(sso.SsoError):
                self.verify(forged)

    def test_a_missing_signing_key_is_a_refusal_not_a_crash(self):
        def no_key(_t, _u):
            raise entra.TokenError('signing key not found')
        with self.assertRaises(sso.SsoError):
            sso.verify_id_token(token(), 'n1', key_for=no_key)


@mock.patch.dict(os.environ, SSO_ENV)
class Exchange(unittest.TestCase):
    class Resp:
        def __init__(self, code, body):
            self.status_code, self._b = code, body

        def json(self):
            return self._b

    def test_the_code_goes_to_the_token_endpoint_with_the_pkce_verifier(self):
        seen = {}

        def post(url, **kw):
            seen.update(url=url, **kw)
            return self.Resp(200, {'id_token': 'the.id.token'})
        self.assertEqual(sso.exchange_code('c0de', 'verifier-1', post=post), 'the.id.token')
        self.assertEqual(seen['data']['code_verifier'], 'verifier-1')
        self.assertEqual(seen['data']['code'], 'c0de')
        self.assertTrue(seen['url'].endswith('/oauth2/v2.0/token'))

    def test_a_refused_code_or_an_unreachable_provider_is_an_sso_error(self):
        with self.assertRaises(sso.SsoError):
            sso.exchange_code('c', 'v', post=lambda *a, **k: self.Resp(400, {'error': 'invalid_grant'}))
        with self.assertRaises(sso.SsoError):
            sso.exchange_code('c', 'v', post=lambda *a, **k: self.Resp(200, {'no': 'id_token'}))

        def down(*a, **k):
            raise OSError('unreachable')
        with self.assertRaises(sso.SsoError):
            sso.exchange_code('c', 'v', post=down)


@mock.patch.dict(os.environ, SSO_ENV)
class Flow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import app as appmod
        if _TMP not in appmod.app.config['SQLALCHEMY_DATABASE_URI']:
            raise RuntimeError('refusing to run against a non-test database')
        cls.appmod, cls.app = appmod, appmod.app
        cls.app.config['TESTING'] = True
        appmod._AUDIT_PATH = os.path.join(_TMP, 'audit.jsonl')

    def setUp(self):
        self.c = self.app.test_client()
        self.patches = [mock.patch.object(entra, '_signing_key', lambda t, u: KEY.public_key())]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()

    def start(self, nxt='/settings'):
        r = self.c.get('/login/sso', query_string={'next': nxt})
        self.assertEqual(r.status_code, 302)
        q = {k: v[0] for k, v in parse_qs(urlparse(r.headers['Location']).query).items()}
        return r.headers['Location'], q

    def finish(self, q, tok, **extra):
        with mock.patch.object(sso, 'exchange_code', return_value=tok):
            return self.c.get('/login/sso/callback', query_string=dict({'code': 'c0de', 'state': q['state']}, **extra))

    def signed_in(self):
        return self.c.get('/settings').status_code == 200

    def test_the_login_page_offers_sso_and_the_start_redirects_with_state_nonce_and_pkce(self):
        self.assertIn('Sign in with your organisation account', self.c.get('/login').get_data(as_text=True))
        url, q = self.start()
        self.assertTrue(url.startswith(f'https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/authorize?'))
        self.assertEqual((q['response_type'], q['client_id'], q['redirect_uri'], q['code_challenge_method']), ('code', CLIENT, REDIRECT, 'S256'))
        for k in ('state', 'nonce', 'code_challenge'):
            self.assertGreaterEqual(len(q[k]), 32, k)
        self.assertNotIn('shh-secret', url)

    def test_a_valid_sign_in_starts_an_admin_session_and_returns_to_the_page(self):
        self.assertFalse(self.signed_in())
        _, q = self.start('/settings')
        r = self.finish(q, token(nonce=q['nonce']))
        self.assertEqual((r.status_code, r.headers['Location']), (302, '/settings'))
        self.assertTrue(self.signed_in())

    def test_the_next_page_is_never_an_off_site_address(self):
        _, q = self.start('https://evil.example/phish')
        self.assertEqual(self.finish(q, token(nonce=q['nonce'])).headers['Location'], '/dashboard')

    def test_a_person_not_on_the_list_gets_no_session(self):
        _, q = self.start()
        r = self.finish(q, token(nonce=q['nonce'], oid='bbbbbbbb-0000-0000-0000-000000000002', preferred_username='intern@bank.example'))
        self.assertEqual(r.headers['Location'], '/login?sso_error=1')
        self.assertFalse(self.signed_in())

    def test_a_wrong_state_a_replay_and_a_callback_nobody_started_are_all_refused(self):
        _, q = self.start()
        r = self.c.get('/login/sso/callback', query_string={'code': 'c0de', 'state': 'forged'})
        self.assertEqual(r.headers['Location'], '/login?sso_error=1')
        self.assertFalse(self.signed_in())
        # the attempt was consumed by the failed callback: even the right state cannot be replayed afterwards
        self.assertEqual(self.finish(q, token(nonce=q['nonce'])).headers['Location'], '/login?sso_error=1')
        fresh = self.app.test_client()
        r = fresh.get('/login/sso/callback', query_string={'code': 'c0de', 'state': q['state']})
        self.assertEqual(r.headers['Location'], '/login?sso_error=1')

    def test_an_error_from_the_identity_provider_is_refused(self):
        _, q = self.start()
        r = self.c.get('/login/sso/callback', query_string={'error': 'access_denied', 'state': q['state']})
        self.assertEqual(r.headers['Location'], '/login?sso_error=1')

    def test_removing_a_person_from_the_admin_list_ends_their_session(self):
        _, q = self.start()
        self.finish(q, token(nonce=q['nonce']))
        self.assertTrue(self.signed_in())
        with mock.patch.dict(os.environ, {'SSAI_SSO_ADMINS': 'someone-else@bank.example'}):
            self.assertFalse(self.signed_in())

    def test_turning_sso_off_ends_sso_sessions(self):
        _, q = self.start()
        self.finish(q, token(nonce=q['nonce']))
        env = {k: v for k, v in os.environ.items() if not k.startswith('SSAI_SSO_')}
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertFalse(self.signed_in())

    def test_sso_only_turns_the_password_form_off_but_not_the_api_key(self):
        with mock.patch.dict(os.environ, {'SSAI_SSO_ONLY': '1'}):
            self.assertNotIn('type="password"', self.c.get('/login').get_data(as_text=True))
            r = self.c.post('/login', json={'password': 'anything at all'})
            self.assertEqual(r.status_code, 403)
            self.assertEqual(self.c.post('/api/setup/reload', headers={'X-API-Key': 'sso-test-admin-key'}).status_code != 401, True)

    def test_a_password_session_stops_working_when_sso_only_is_switched_on(self):
        import auth
        auth.set_admin_password('a valid test password')
        self.assertEqual(self.c.post('/login', json={'password': 'a valid test password'}).status_code, 200)
        self.assertTrue(self.signed_in())
        with mock.patch.dict(os.environ, {'SSAI_SSO_ONLY': '1'}):
            self.assertFalse(self.signed_in())


if __name__ == '__main__':
    unittest.main(verbosity=2)
