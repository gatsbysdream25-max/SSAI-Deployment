#!/usr/bin/env python3
"""A provider that is out of credits or quota rests (stops voting), is rechecked on a schedule, and returns by itself.
Run:  swarmsentinel-env/bin/python3 backend/tools/test_provider_rest.py"""
import os
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
sys.path[:0] = [os.path.join(BACKEND, 'agents'), BACKEND]
_TMP = tempfile.mkdtemp()
os.environ['SSAI_PROVIDER_REST_FILE'] = os.path.join(_TMP, 'rest.json')
import ai_swarm_agent as swarm  # noqa: E402
import provider_errors as pe  # noqa: E402
import provider_rest as pr  # noqa: E402


def http_error(code, body=''):
    resp = requests.Response()
    resp.status_code, resp._content = code, body.encode()
    return requests.exceptions.HTTPError(f'{code} error', response=resp)


def analyzer():
    a = swarm.AiSwarmAnalyzer.__new__(swarm.AiSwarmAnalyzer)       # skip provider discovery (network)
    a._providers, a._health, a._health_lock = [], {}, threading.Lock()
    return a


def run_recheck(a, row):
    """Run the background recheck with a canned health-check answer and wait for it to finish."""
    import provider_check
    with mock.patch.object(provider_check, 'check_provider', return_value=row), \
            mock.patch.object(swarm.model_config, 'load', return_value={'groq': {}}):
        before = set(threading.enumerate())
        a.maybe_wake_resting()
        for t in set(threading.enumerate()) - before:
            t.join(5)


def make_due(pid):
    state = pr.all_resting()
    state[pid]['next_check'] = '2000-01-01T00:00:00+00:00'
    pr._save(state)


class Base(unittest.TestCase):
    def setUp(self):
        if os.path.exists(pr._path()):
            os.remove(pr._path())


class Naming(unittest.TestCase):
    def test_a_spent_daily_quota_is_told_apart_from_a_short_rate_limit(self):
        self.assertEqual(pe.classify(http_error(429, 'RESOURCE_EXHAUSTED: quota exceeded for this day'))[0], pe.QUOTA_USED)
        self.assertEqual(pe.classify(http_error(429, 'Rate limit reached: 30 requests per minute'))[0], pe.RATE_LIMITED)
        self.assertEqual(pe.classify(http_error(402, 'Payment Required'))[0], pe.NO_CREDITS)

    def test_quota_used_is_not_retried(self):
        self.assertNotIn(pe.QUOTA_USED, pe.RETRYABLE)


class Rest(Base):
    def test_resting_and_waking(self):
        self.assertTrue(pr.rest('gemini', pe.QUOTA_USED, 'quota'))
        self.assertFalse(pr.rest('gemini', pe.QUOTA_USED, 'quota'), 'resting twice is reported once')
        self.assertTrue(pr.is_resting('gemini'))
        self.assertTrue(pr.wake('gemini'))
        self.assertFalse(pr.is_resting('gemini'))
        self.assertFalse(pr.wake('gemini'))

    def test_not_due_at_first_then_due_later_and_backs_off(self):
        pr.rest('hf', pe.NO_CREDITS, 'x')
        self.assertEqual(pr.due(), [])
        make_due('hf')
        self.assertEqual(pr.due(), ['hf'])
        pr.still_out('hf', 'still no credits')
        self.assertEqual(pr.due(), [])
        self.assertEqual(pr.all_resting()['hf']['tries'], 1)

    def test_a_damaged_file_means_nobody_is_resting(self):
        with open(pr._path(), 'w') as f:
            f.write('{not json')
        self.assertEqual(pr.all_resting(), {})


class InThePanel(Base):
    def test_no_credits_error_rests_it_and_it_stops_voting(self):
        a = analyzer()
        prov = mock.Mock()
        prov.name = 'groq'
        self.assertTrue(swarm.panel_allowed(prov, overrides={'groq': True}, weights={}))
        a._record_error('groq', 'HTTP 402', pe.NO_CREDITS)
        self.assertTrue(pr.is_resting('groq'))
        self.assertFalse(swarm.panel_allowed(prov, overrides={'groq': True}, weights={}))

    def test_an_ordinary_failure_does_not_rest_it(self):
        analyzer()._record_error('groq', 'timed out', pe.TIMEOUT)
        self.assertFalse(pr.is_resting('groq'))

    def test_a_success_puts_it_back(self):
        a = analyzer()
        a._record_error('groq', 'HTTP 402', pe.NO_CREDITS)
        a._record_success('groq')
        self.assertFalse(pr.is_resting('groq'))

    def test_health_shows_the_rest(self):
        a = analyzer()
        a._record_error('groq', 'HTTP 402', pe.NO_CREDITS)
        self.assertEqual(a.get_health()['groq']['resting']['kind'], pe.NO_CREDITS)

    def test_the_operators_switch_is_not_touched(self):
        a = analyzer()
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'ai_providers.json')
            swarm.set_provider_enabled('groq', False, path)
            a._record_error('groq', 'HTTP 402', pe.NO_CREDITS)
            a._record_success('groq')
            self.assertFalse(swarm.load_provider_overrides(path)['groq'], 'a person switched it off: it stays off')

    def test_recheck_wakes_it_when_it_answers_again(self):
        a = analyzer()
        a._record_error('groq', 'HTTP 402', pe.NO_CREDITS)
        make_due('groq')
        run_recheck(a, {'working': True, 'status': 'ok', 'detail': ''})
        self.assertFalse(pr.is_resting('groq'))

    def test_recheck_keeps_it_resting_when_still_out(self):
        a = analyzer()
        a._record_error('groq', 'HTTP 402', pe.NO_CREDITS)
        make_due('groq')
        run_recheck(a, {'working': False, 'status': 'no_credits', 'detail': 'HTTP 402'})
        self.assertTrue(pr.is_resting('groq'))
        self.assertEqual(pr.all_resting()['groq']['tries'], 1)


if __name__ == '__main__':
    unittest.main()
