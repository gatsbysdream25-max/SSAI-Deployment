#!/usr/bin/env python3
"""Phase 1 of the consensus plan: named provider errors, one bounded retry, no model names in code.
Run:  swarmsentinel-env/bin/python3 backend/tools/test_provider_errors.py"""
import json
import os
import re
import sys
import tempfile
import threading
import unittest
from unittest import mock

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
sys.path[:0] = [os.path.join(BACKEND, 'agents'), BACKEND]
import ai_swarm_agent as swarm  # noqa: E402
import provider_errors as pe  # noqa: E402
import sanitizer  # noqa: E402


def http_error(code, body=''):
    resp = requests.Response()
    resp.status_code, resp._content = code, body.encode()
    return requests.exceptions.HTTPError(f'{code} error', response=resp)


class Flaky:
    """A provider that fails with the given errors in order, then answers."""
    def __init__(self, name, errors, answer=None):
        self.name, self.errors, self.calls = name, list(errors), 0
        self.answer = json.dumps({'verdict': 'malicious', 'severity': 'HIGH', 'confidence': 80}) if answer is None else answer

    def analyze(self, prompt):
        self.calls += 1
        if self.errors:
            raise self.errors.pop(0)
        return self.answer


def analyzer():
    a = swarm.AiSwarmAnalyzer.__new__(swarm.AiSwarmAnalyzer)       # skip provider discovery (network)
    a._providers, a._health, a._health_lock = [], {}, threading.Lock()
    a._RETRY_PAUSE = 0.01
    return a


class Names(unittest.TestCase):
    def test_every_failure_gets_one_short_name(self):
        cases = [(http_error(402, 'Payment Required'), pe.NO_CREDITS), (http_error(401, 'bad key'), pe.BAD_KEY),
                 (http_error(404, 'no such model'), pe.BAD_MODEL), (http_error(429, 'slow down'), pe.RATE_LIMITED),
                 (http_error(502, 'bad gateway'), pe.PROVIDER_ERROR), (requests.exceptions.ReadTimeout('x'), pe.TIMEOUT),
                 (requests.exceptions.ConnectionError('refused'), pe.UNREACHABLE), (ValueError('odd'), pe.ERROR)]
        for exc, want in cases:
            self.assertEqual(pe.classify(exc)[0], want, repr(exc))

    def test_the_health_check_and_the_live_panel_share_one_classifier(self):
        import provider_check
        self.assertIs(provider_check.classify, pe.classify)
        self.assertEqual(provider_check.NO_CREDITS, pe.NO_CREDITS)

    def test_a_key_in_an_error_body_is_not_kept(self):
        key = 'sk-ant-' + 'A' * 30
        text = pe.classify(http_error(401, f'invalid key {key}'))[1]
        self.assertNotIn(key, text)


class LiveCalls(unittest.TestCase):
    def setUp(self):
        audit = os.path.join(tempfile.mkdtemp(), 'cloud_audit.jsonl')
        p = mock.patch.object(sanitizer, 'audit_path', return_value=audit)
        p.start()
        self.addCleanup(p.stop)

    def call(self, provider):
        a = analyzer()
        return a, a._safe_call(provider, '{}')

    def test_a_rate_limit_blip_is_retried_once_and_then_counts(self):
        p = Flaky('groq', [http_error(429, 'slow down')])
        a, verdict = self.call(p)
        self.assertEqual(p.calls, 2)
        self.assertEqual(verdict['verdict'], 'malicious')
        self.assertNotIn('last_error_kind', a._health.get('groq', {}))

    def test_a_server_error_that_keeps_happening_is_tried_twice_not_more(self):
        p = Flaky('groq', [http_error(503, 'down')] * 5)
        a, verdict = self.call(p)
        self.assertIsNone(verdict)
        self.assertEqual(p.calls, 2)
        self.assertEqual(a._health['groq']['last_error_kind'], pe.PROVIDER_ERROR)

    def test_errors_that_repeat_forever_are_never_retried(self):
        for exc, kind in ((http_error(401, 'bad'), pe.BAD_KEY), (http_error(402, 'pay'), pe.NO_CREDITS),
                          (http_error(404, 'gone'), pe.BAD_MODEL), (requests.exceptions.ReadTimeout('x'), pe.TIMEOUT)):
            p = Flaky('x', [exc] * 3)
            a, verdict = self.call(p)
            self.assertIsNone(verdict)
            self.assertEqual(p.calls, 1, kind)
            self.assertEqual(a._health['x']['last_error_kind'], kind)

    def test_no_retry_once_the_panel_has_closed(self):
        p = Flaky('groq', [http_error(429, 'slow')] * 3)
        closed = threading.Event()
        closed.set()
        self.assertIsNone(analyzer()._safe_call(p, '{}', closed))
        self.assertEqual(p.calls, 1)

    def test_an_unusable_answer_is_named_malformed(self):
        for answer in ('', 'no braces here', '{not json}', 'x' * 100000):
            p = Flaky('groq', [], answer)
            a, verdict = self.call(p)
            self.assertIsNone(verdict, answer[:20])
            self.assertEqual(a._health['groq']['last_error_kind'], pe.MALFORMED, answer[:20])


class NoModelNamesInCode(unittest.TestCase):
    def test_the_registry_takes_every_model_name_from_the_config_file(self):
        with open(os.path.join(BACKEND, 'agents', 'ai_swarm_agent.py'), encoding='utf-8') as f:
            src = f.read()
        literals = re.findall(r'^\s+"model":\s+"([^"]+)"', src, re.M)
        self.assertEqual(literals, [], f'model names found in code: {literals}')
        self.assertNotRegex(src, r'or \{"model":')                   # no invented fallback entries either
        for p in swarm.PROVIDER_REGISTRY:
            if p['id'] in ('groq', 'gemini', 'ollama'):
                self.assertTrue(p['model'], p['id'])                   # filled in from config/ai_models.json

    def test_a_missing_config_entry_is_a_clear_error_not_a_made_up_model(self):
        with mock.patch.object(swarm.model_config, 'get', return_value=None):
            with self.assertRaisesRegex(RuntimeError, 'not in config/ai_models.json'):
                swarm._GeminiProvider()

    def test_openrouter_is_off_and_its_slug_is_the_working_one(self):
        e = swarm.model_config.get('openrouter')
        self.assertFalse(e['default_on'])
        self.assertFalse(e['model'].endswith(':free'))
        self.assertFalse(swarm.provider_enabled('openrouter', overrides={}))


if __name__ == '__main__':
    unittest.main()
