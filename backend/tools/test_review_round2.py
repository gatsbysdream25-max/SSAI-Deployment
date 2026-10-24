#!/usr/bin/env python3
"""Fixes from the 2026-10-18 review round (security, consensus, dashboard, deploy). Each test fails on the old code.
Run:  swarmsentinel-env/bin/python3 backend/tools/test_review_round2.py"""
import glob
import os
import re
import sys
import tempfile
import time
import unittest
from unittest import mock

_TMP = tempfile.mkdtemp()
os.environ['DATA_DIR'] = _TMP
os.environ['DATABASE_URL'] = f'sqlite:///{_TMP}/round2-test.db'
os.environ['SSAI_API_KEY'] = 'round2-admin-key'
os.environ['SSAI_PROVIDER_CHECK'] = '0'
os.environ['SSAI_STATE_DB'] = os.path.join(_TMP, 'state.db')
os.environ.pop('SSAI_TRUSTED_PROXIES', None)

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
ROOT = os.path.dirname(BACKEND)
sys.path[:0] = [os.path.join(BACKEND, 'agents'), BACKEND]

import jwt  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402

import entra  # noqa: E402
import sso  # noqa: E402
from agents import ai_swarm_agent as swarm  # noqa: E402
from agents import recall  # noqa: E402

TENANT = '11111111-2222-3333-4444-555555555555'
CLIENT = 'app-client-id'
OID = 'aaaaaaaa-0000-0000-0000-000000000001'
UPN = 'admin@bank.example'
ENV = {'SSAI_SSO_TENANT_ID': TENANT, 'SSAI_SSO_CLIENT_ID': CLIENT, 'SSAI_SSO_CLIENT_SECRET': 'shh',
       'SSAI_SSO_REDIRECT_URI': 'https://ssai.bank.example/login/sso/callback', 'SSAI_SSO_ADMINS': OID}
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def token(nonce='n1', **over):
    now = int(time.time())
    claims = {'iss': f'https://login.microsoftonline.com/{TENANT}/v2.0', 'aud': CLIENT, 'tid': TENANT, 'sub': 's', 'oid': OID,
              'preferred_username': UPN, 'name': 'Ada', 'nonce': nonce, 'iat': now - 5, 'exp': now + 600}
    claims.update(over)
    return jwt.encode({k: v for k, v in claims.items() if v is not None}, KEY, algorithm='RS256')


def key_for(_t, _u):
    return KEY.public_key()


@mock.patch.dict(os.environ, ENV)
class SsoRules(unittest.TestCase):
    def test_a_sign_in_name_alone_is_not_enough_by_default(self):
        with mock.patch.dict(os.environ, {'SSAI_SSO_ADMINS': UPN}):
            with self.assertRaises(sso.SsoError):
                sso.verify_id_token(token(oid='someone-else'), 'n1', key_for=key_for)
        self.assertEqual(sso.verify_id_token(token(), 'n1', key_for=key_for)['subject'], OID)

    def test_names_work_only_when_the_operator_opts_in(self):
        with mock.patch.dict(os.environ, {'SSAI_SSO_ADMINS': UPN, 'SSAI_SSO_ADMINS_BY_NAME': '1'}):
            self.assertEqual(sso.verify_id_token(token(oid='someone-else'), 'n1', key_for=key_for)['subject'], UPN)

    def test_sso_only_needs_someone_on_the_admin_list(self):
        with mock.patch.dict(os.environ, {'SSAI_SSO_ONLY': '1', 'SSAI_SSO_ADMINS': ''}):
            self.assertFalse(sso.only())              # otherwise the password form is off and nobody can sign in
        with mock.patch.dict(os.environ, {'SSAI_SSO_ONLY': '1'}):
            self.assertTrue(sso.only())

    def test_an_unreachable_key_list_is_a_refusal_not_a_server_error(self):
        def boom(_t, _u):
            raise ConnectionError('dns failure')
        with self.assertRaises(sso.SsoError):
            sso.verify_id_token(token(), 'n1', key_for=boom)

    def test_the_sso_session_is_short_and_configurable(self):
        self.assertEqual(sso.session_minutes(), 120)
        with mock.patch.dict(os.environ, {'SSAI_SSO_SESSION_MINUTES': '30'}):
            self.assertEqual(sso.session_minutes(), 30)
        with mock.patch.dict(os.environ, {'SSAI_SSO_SESSION_MINUTES': 'soon'}):
            self.assertEqual(sso.session_minutes(), 120)
        with mock.patch.dict(os.environ, {'SSAI_SSO_SESSION_MINUTES': '99999'}):
            self.assertEqual(sso.session_minutes(), 720)


class AppRules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import app as appmod
        if _TMP not in appmod.app.config['SQLALCHEMY_DATABASE_URI']:
            raise RuntimeError('refusing to run against a non-test database')
        cls.appmod, cls.app = appmod, appmod.app
        cls.app.config['TESTING'] = True

    def test_the_post_login_target_is_never_off_site_even_with_control_characters(self):
        for bad in ('/\t/evil.example', '/\n/evil.example', '/\r/evil.example', '/ /evil.example', '/%09/x'[:0] + '/\x00/evil.example',
                    '//evil.example', '/\\evil.example', 'https://evil.example', '/\x7f/x'):
            self.assertEqual(self.appmod._safe_next(bad), '/dashboard', repr(bad))
        self.assertEqual(self.appmod._safe_next('/settings'), '/settings')
        self.assertEqual(self.appmod._safe_next('/dashboard?tab=ai'), '/dashboard?tab=ai')

    def test_the_client_address_is_the_first_one_our_proxy_did_not_vouch_for(self):
        import auth
        env = {'SSAI_TRUSTED_PROXIES': '10.0.0.5,10.0.0.6'}
        with mock.patch.dict(os.environ, env), self.app.test_request_context(
                '/', environ_base={'REMOTE_ADDR': '10.0.0.5'}, headers={'X-Forwarded-For': '6.6.6.6, 203.0.113.9, 10.0.0.6'}):
            self.assertEqual(auth.client_ip(), '203.0.113.9')          # the client's own forged 6.6.6.6 is ignored
        with mock.patch.dict(os.environ, env), self.app.test_request_context(
                '/', environ_base={'REMOTE_ADDR': '10.0.0.5'}, headers={'X-Forwarded-For': '203.0.113.9'}):
            self.assertEqual(auth.client_ip(), '203.0.113.9')
        with mock.patch.dict(os.environ, env), self.app.test_request_context(
                '/', environ_base={'REMOTE_ADDR': '198.51.100.1'}, headers={'X-Forwarded-For': '1.2.3.4'}):
            self.assertEqual(auth.client_ip(), '198.51.100.1')         # an untrusted caller cannot choose its address


class Consensus(unittest.TestCase):
    A = swarm.AiSwarmAnalyzer

    def vote(self, ai, **extra):
        return dict({'ai': ai, 'verdict': 'malicious', 'confidence': 80, 'severity': 'HIGH'}, **extra)

    def test_garbage_in_the_optional_fields_cannot_cost_a_threat_its_verdict(self):
        results = [self.vote('a', mitre_ttps='T1059', confidence=1e999, recommended_action=['x']),
                   self.vote('b', mitre_ttps=[['T1'], {'x': 1}, 7, 'T1566'], confidence='lots', recommended_action=42),
                   self.vote('c', mitre_ttps=['T1059', 'T1566'], recommended_action='Isolate the host')]
        c = self.A._consensus(results, weights={})
        self.assertEqual(c['consensus_verdict'], 'malicious')
        self.assertEqual(c['mitre_ttps'], ['T1059', 'T1566'])
        self.assertEqual(c['recommended_action'], 'Isolate the host')
        self.assertTrue(0 <= c['confidence'] <= 100)

    def test_a_bad_timeout_setting_never_breaks_the_module_or_makes_every_provider_time_out(self):
        for value, want in (('', 150.0), ('150s', 150.0), ('2.5', 2.5), ('0', 150.0), ('-5', 150.0), ('90', 90.0)):
            with mock.patch.dict(os.environ, {'SSAI_ANALYSIS_TIMEOUT': value}):
                self.assertEqual(swarm._analysis_timeout(), want, value)

    def test_a_text_false_does_not_turn_a_provider_on_by_default(self):
        import model_config
        raw = {'kind': 'openai', 'model': 'm', 'key_env': 'K', 'default_on': 'false', 'verified': 1}
        e = model_config._clean('x', raw)
        self.assertIs(e['default_on'], False)
        self.assertIs(e['verified'], False)
        self.assertIs(model_config._clean('x', dict(raw, default_on=True))['default_on'], True)

    def test_a_thin_verdict_from_part_of_the_panel_is_not_replayed(self):
        full = {'consensus_verdict': 'malicious', 'ai_count': 3, 'quorum': {'complete': True}}
        thin = {'consensus_verdict': 'malicious', 'ai_count': 1, 'quorum': {'complete': False, 'dropped': ['gemini']}}
        fallback = {'consensus_verdict': 'benign', 'ai_count': 1, 'panel_mode': 'fallback'}
        self.assertTrue(recall.reusable_consensus(full))
        self.assertFalse(recall.reusable_consensus(thin))
        self.assertFalse(recall.reusable_consensus(fallback))


class Pages(unittest.TestCase):
    def read(self, rel):
        return open(os.path.join(ROOT, rel), encoding='utf-8').read()

    def test_the_saved_home_mode_is_applied_after_the_page_state_exists(self):
        html = self.read('backend/templates/dashboard.html')
        self.assertIn("document.addEventListener('DOMContentLoaded', function initMode()", html)
        self.assertNotIn('(function initMode()', html)       # an immediate call hit the let/const temporal dead zone

    def test_nothing_keyed_by_a_node_chosen_name_is_a_plain_object(self):
        html = self.read('backend/templates/dashboard.html')
        self.assertIn('const groups = Object.create(null);', html)

    def test_values_from_nodes_are_escaped_in_the_agent_and_node_panels(self):
        html = self.read('backend/templates/dashboard.html')
        for raw in ('${scans} scans', '${found} found', '${status} · Last seen', '>${sev}</span>'):
            self.assertNotIn(raw, html, raw)

    def test_deploy_scripts_probe_the_address_the_hub_listens_on_and_use_utc_for_the_journal(self):
        for rel in ('deploy/update.sh', 'deploy/install.sh', 'deploy/harden.sh'):
            text = self.read(rel)
            self.assertNotRegex(text, r'curl [^\n]*"http://127\.0\.0\.1:\$\{?(?:PORT|p)\b[^\n]*/health', rel)
        self.assertNotIn("date -u '+%Y-%m-%d %H:%M:%S')", self.read('deploy/harden.sh'))
        self.assertIn('must be an IPv4 address', self.read('deploy/install.sh'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
