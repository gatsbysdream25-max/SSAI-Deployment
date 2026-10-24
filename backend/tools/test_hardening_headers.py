#!/usr/bin/env python3
"""Pre-pilot hardening (2026-10-18): the Content-Security-Policy, HSTS only over real HTTPS, and a provider dropping out
of the AI panel being logged at WARNING (it used to be invisible).
Run:  swarmsentinel-env/bin/python3 backend/tools/test_hardening_headers.py"""
import logging
import os
import sys
import tempfile
import unittest
from unittest import mock

_TMP = tempfile.mkdtemp()
os.environ['DATA_DIR'] = _TMP
os.environ['DATABASE_URL'] = f'sqlite:///{_TMP}/headers-test.db'
os.environ['SSAI_API_KEY'] = 'headers-test-admin-key'
os.environ['SSAI_PROVIDER_CHECK'] = '0'
os.environ['SSAI_STATE_DB'] = os.path.join(_TMP, 'state.db')
os.environ.pop('SSAI_HSTS', None)
os.environ.pop('SSAI_TRUSTED_PROXIES', None)
os.environ.pop('SSAI_CSP', None)

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
sys.path[:0] = [os.path.join(BACKEND, 'agents'), BACKEND]


class Headers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import app as appmod
        if _TMP not in appmod.app.config['SQLALCHEMY_DATABASE_URI']:
            raise RuntimeError('refusing to run against a non-test database')
        cls.app = appmod.app
        cls.app.config['TESTING'] = True

    def setUp(self):
        self.c = self.app.test_client()

    def test_every_page_carries_a_policy_that_closes_plugins_base_tags_and_other_origins(self):
        for path in ('/login', '/dashboard', '/health'):
            csp = self.c.get(path).headers.get('Content-Security-Policy', '')
            for directive in ("object-src 'none'", "base-uri 'none'", "frame-ancestors 'self'", "form-action 'self'",
                              "connect-src 'self'", "default-src 'self'"):
                self.assertIn(directive, csp, f'{path} lacks {directive}')
            self.assertNotIn('unsafe-eval', csp)
            self.assertNotIn('*', csp.replace("'self'", ''))        # no wildcard source anywhere

    def script_src(self, resp):
        csp = resp.headers['Content-Security-Policy']
        return next(d for d in csp.split(';') if d.strip().startswith('script-src')).strip()

    def test_scripts_run_only_from_this_site_or_with_this_requests_nonce(self):
        import re
        seen = set()
        for path in ('/login', '/dashboard'):
            r = self.c.get(path)
            directive = self.script_src(r)
            self.assertNotIn('unsafe-inline', directive, path)
            nonce = re.search(r"'nonce-([^']+)'", directive).group(1)
            seen.add(nonce)
            html = r.get_data(as_text=True)
            tags = re.findall(r'<script(?![^>]*\ssrc=)([^>]*)>', html)              # inline scripts
            self.assertTrue(tags, path)
            for attrs in tags:
                self.assertIn(f'nonce="{nonce}"', attrs, f'{path}: an inline script without this request\'s nonce')
        self.assertEqual(len(seen), 2, 'the nonce must differ on every request')

    def test_the_pages_hold_no_inline_event_handlers_and_every_action_they_name_is_registered(self):
        import glob
        import re
        for path in glob.glob(os.path.join(BACKEND, 'templates', '*.html')):
            text = open(path, encoding='utf-8').read()
            name = os.path.basename(path)
            self.assertEqual(re.findall(r'\son[a-z]+\s*=\s*["\']', text), [], f'{name} has an inline event handler')
            self.assertNotIn('javascript:', text, name)
            used = set(re.findall(r'data-on-(?:click|change|keydown)="(\w+)"', text)) | set(re.findall(r"\bda\('(\w+)'", text))
            registered = set()
            for block in re.findall(r'SSAI\.register\(\{(.*?)\}\)', text, re.S):
                registered |= {n.strip() for n in block.split(',') if n.strip()}
            self.assertEqual(used - registered, set(), f'{name}: an action is used but not registered, so its button does nothing')
            for fn in registered:
                self.assertRegex(text, rf'(?:function {fn}\b|const {fn}\b)', f'{name}: {fn} is registered but not defined')

    def test_the_action_script_is_served_from_this_site(self):
        r = self.c.get('/static/ssai-actions.js')
        self.assertEqual(r.status_code, 200)
        body = r.get_data(as_text=True)
        self.assertIn('SSAI', body)
        self.assertNotIn('eval(', body)
        self.assertNotIn('new Function', body)

    def test_the_policy_can_be_switched_to_report_only_or_off_for_debugging(self):
        with mock.patch.dict(os.environ, {'SSAI_CSP': 'report-only'}):
            r = self.c.get('/health')
            self.assertIn('Content-Security-Policy-Report-Only', r.headers)
            self.assertNotIn('Content-Security-Policy', r.headers)
        with mock.patch.dict(os.environ, {'SSAI_CSP': 'off'}):
            r = self.c.get('/health')
            self.assertNotIn('Content-Security-Policy', r.headers)
            self.assertNotIn('Content-Security-Policy-Report-Only', r.headers)

    def test_hsts_is_off_by_default_even_over_https(self):
        with mock.patch.dict(os.environ, {'SSAI_TRUSTED_PROXIES': '127.0.0.1'}):
            r = self.c.get('/health', headers={'X-Forwarded-Proto': 'https'})
            self.assertNotIn('Strict-Transport-Security', r.headers)

    def test_hsts_is_sent_only_when_enabled_and_the_request_really_was_https(self):
        with mock.patch.dict(os.environ, {'SSAI_HSTS': '1', 'SSAI_TRUSTED_PROXIES': '127.0.0.1'}):
            self.assertIn('max-age=', self.c.get('/health', headers={'X-Forwarded-Proto': 'https'}).headers['Strict-Transport-Security'])
            self.assertNotIn('Strict-Transport-Security', self.c.get('/health').headers)                                  # plain HTTP
            self.assertNotIn('Strict-Transport-Security', self.c.get('/health', headers={'X-Forwarded-Proto': 'http'}).headers)
        with mock.patch.dict(os.environ, {'SSAI_HSTS': '1', 'SSAI_TRUSTED_PROXIES': '10.9.9.9'}):          # a client claiming HTTPS
            self.assertNotIn('Strict-Transport-Security', self.c.get('/health', headers={'X-Forwarded-Proto': 'https'}).headers)
        with mock.patch.dict(os.environ, {'SSAI_HSTS': '1'}):
            self.assertNotIn('Strict-Transport-Security', self.c.get('/health', headers={'X-Forwarded-Proto': 'https'}).headers)


class Degraded(unittest.TestCase):
    def analyzer(self):
        import threading
        from agents import ai_swarm_agent as swarm
        a = object.__new__(swarm.AiSwarmAnalyzer)
        a._health, a._health_lock, a._degraded_logged = {}, threading.Lock(), {}
        return swarm, a

    def test_a_provider_that_stops_answering_is_logged_at_warning_once_per_window(self):
        swarm, a = self.analyzer()
        with self.assertLogs(swarm.log, level='WARNING') as cm:
            a._record_error('gemini', 'empty response')
            a._record_error('gemini', 'empty response')        # the same provider again: not repeated
            a._record_error('groq', 'HTTP 503')                # another provider: reported on its own
        lines = [r.getMessage() for r in cm.records]
        self.assertEqual(len(lines), 2, lines)
        self.assertTrue(lines[0].startswith('DEGRADED: AI provider gemini'), lines[0])
        self.assertIn('groq', lines[1])
        a._degraded_logged['gemini'] -= swarm.AiSwarmAnalyzer._DEGRADED_LOG_EVERY + 1       # the window passes
        with self.assertLogs(swarm.log, level='WARNING') as cm:
            a._record_error('gemini', 'empty response')
        self.assertEqual(len(cm.records), 1)

    def test_the_log_line_never_carries_a_key_and_the_health_page_still_gets_the_error(self):
        swarm, a = self.analyzer()
        with self.assertLogs(swarm.log, level='WARNING') as cm:
            a._record_error('gemini', 'request failed for https://x.example/v1?key=SUPERSECRETKEY123456&alt=json\nsecond line')
        line = cm.records[0].getMessage()
        self.assertNotIn('SUPERSECRETKEY123456', line)
        self.assertNotIn('\n', line)
        self.assertIn('last_error_msg', a.get_health()['gemini'])
        self.assertNotIn('_degraded_logged', a.get_health()['gemini'])

    def test_log_degraded_names_the_failure_type_and_stays_on_one_line(self):
        from agents import ai_swarm_agent as swarm
        with self.assertLogs(swarm.log, level='WARNING') as cm:
            swarm.log_degraded('AI provider x failed', ValueError('line one\nline two ' + 'y' * 500))
        line = cm.records[0].getMessage()
        self.assertTrue(line.startswith('DEGRADED: AI provider x failed: ValueError: line one line two'), line)
        self.assertLess(len(line), 300)
        self.assertNotIn('\n', line)


if __name__ == '__main__':
    logging.disable(logging.NOTSET)
    unittest.main(verbosity=2)
