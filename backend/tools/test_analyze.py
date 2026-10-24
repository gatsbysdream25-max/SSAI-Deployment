#!/usr/bin/env python3
"""Tests for AiSwarmAnalyzer.analyze() panel handling (timeout bug found by the 2026-09-19 end-to-end test).
Run:  python3 backend/tools/test_analyze.py"""
import json
import os
import sys
import threading
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(os.path.dirname(HERE), 'agents'), os.path.dirname(HERE)]
import ai_swarm_agent as swarm  # noqa: E402
import sanitizer  # noqa: E402


class FakeProvider:
    def __init__(self, name, fn, delay=0.0):
        self.name, self.fn, self.delay = name, fn, delay

    def analyze(self, prompt):
        if self.delay:
            time.sleep(self.delay)
        return self.fn()


class Sev:
    name = 'MEDIUM'


class Event:
    title, category, severity, source, detail, agent = 't', 'url', Sev(), 'http://x/y', 'd', 'a'


def reply(v):
    return lambda: json.dumps({'verdict': v, 'severity': 'HIGH', 'confidence': 80})


def panel(*providers):
    a = swarm.AiSwarmAnalyzer.__new__(swarm.AiSwarmAnalyzer)      # skip provider discovery (network)
    a._providers, a._health, a._health_lock = list(providers), {}, threading.Lock()
    return a


class AnalyzePanel(unittest.TestCase):
    def setUp(self):
        self._t = swarm._ANALYSIS_TIMEOUT
        swarm._ANALYSIS_TIMEOUT = 0.4
        import tempfile                                                # fake providers count as cloud: keep the gate's
        audit = os.path.join(tempfile.mkdtemp(), 'cloud_audit.jsonl')  # audit lines out of the real log
        self._audit = mock.patch.object(sanitizer, 'audit_path', return_value=audit)
        self._audit.start()
        self.addCleanup(self._audit.stop)

    def tearDown(self):
        swarm._ANALYSIS_TIMEOUT = self._t

    def test_slow_provider_does_not_sink_the_panel(self):
        a = panel(FakeProvider('fast1', reply('malicious')), FakeProvider('fast2', reply('malicious')),
                  FakeProvider('slow', reply('benign'), delay=2.0))
        t0 = time.time()
        r = a.analyze(Event())
        self.assertLess(time.time() - t0, 1.5)                        # did not wait for the straggler
        self.assertIsNotNone(r)
        self.assertEqual(r['consensus_verdict'], 'malicious')
        self.assertEqual(sorted(r['ai_sources']), ['fast1', 'fast2'])
        self.assertIn('slow', a.get_health())                          # the timeout is surfaced, not silent
        self.assertIn('no answer within', a.get_health()["slow"]["last_error_msg"])

    def test_all_providers_too_slow_returns_none_without_raising(self):
        a = panel(FakeProvider('s1', reply('benign'), delay=1.5), FakeProvider('s2', reply('benign'), delay=1.5))
        self.assertIsNone(a.analyze(Event()))

    def test_failing_provider_is_ignored_and_recorded(self):
        def boom():
            raise RuntimeError('401')
        a = panel(FakeProvider('good', reply('benign')), FakeProvider('bad', boom))
        r = a.analyze(Event())
        self.assertEqual(r['ai_sources'], ['good'])
        self.assertIn('bad', a.get_health())

    def test_no_providers_returns_none(self):
        self.assertIsNone(panel().analyze(Event()))

    def test_zero_weight_providers_are_never_called(self):
        import tempfile
        calls = []

        def spy(name, verdict):
            def f():
                calls.append(name)
                return json.dumps({'verdict': verdict, 'severity': 'HIGH', 'confidence': 80})
            return f
        path = os.path.join(tempfile.mkdtemp(), 'w.json')
        with open(path, 'w') as f:
            json.dump({'provisional': False, 'weights': {'off': {'weight': 0}, 'off2': {'weight_firm': 0, 'weight_flag': 0},
                                                       'half': {'weight_firm': 0, 'weight_flag': 0.5}, 'on': {'weight': 1.0}}}, f)
        orig = swarm._WEIGHTS_PATH
        swarm._WEIGHTS_PATH = path
        swarm._weights_cache.update(mtime=None, weights={})
        try:
            a = panel(FakeProvider('off', spy('off', 'benign')), FakeProvider('off2', spy('off2', 'benign')),
                      FakeProvider('half', spy('half', 'malicious')), FakeProvider('on', spy('on', 'malicious')),
                      FakeProvider('unlisted', spy('unlisted', 'malicious')))
            r = a.analyze(Event())
            self.assertEqual(sorted(calls), ['half', 'on', 'unlisted'])          # off / off2 never consulted
            self.assertEqual(sorted(r['ai_sources']), ['half', 'on', 'unlisted'])
            calls.clear()
            b = panel(FakeProvider('off', spy('off', 'benign')))
            self.assertIsNone(b.analyze(Event()))                                 # everyone off -> no answer, no calls
            self.assertEqual(calls, [])
        finally:
            swarm._WEIGHTS_PATH = orig
            swarm._weights_cache.update(mtime=None, weights={})

    def test_default_timeout_covers_a_slow_local_model(self):
        self.assertGreaterEqual(self._t, 90)                           # local CPU inference can take 30-60s+



class GroqExtras(unittest.TestCase):
    def setUp(self):
        self._env = dict(os.environ)
        self._disc = swarm._OllamaProvider._discover
        swarm._OllamaProvider._discover = lambda self: None                       # no network in tests
        self._get = swarm.requests.get                                            # nor for the named local voices, and
        swarm.requests.get = mock.Mock(side_effect=swarm.requests.exceptions.ConnectionError('no network in tests'))
        self._ip = swarm.model_config.instance_path                               # not this machine's own instance/ai_models.json
        swarm.model_config.instance_path = lambda: os.devnull + '.none'
        for k in ('HF_TOKEN', 'GEMINI_API_KEY', 'ANTHROPIC_API_KEY', 'OPENROUTER_API_KEY', 'CEREBRAS_API_KEY', 'MISTRAL_API_KEY',
                  'TOGETHER_API_KEY', 'KIMI_API_KEY', 'GROK_API_KEY', 'GROQ_EXTRA_MODELS'):
            os.environ.pop(k, None)
        os.environ['GROQ_API_KEY'] = 'k'

    def tearDown(self):
        swarm._OllamaProvider._discover = self._disc
        swarm.requests.get = self._get
        swarm.model_config.instance_path = self._ip
        os.environ.clear()
        os.environ.update(self._env)

    def names(self):
        return [p.name for p in swarm.AiSwarmAnalyzer._init_providers(None)]

    def test_no_extras_by_default(self):
        self.assertEqual(self.names(), ['groq'])

    def test_extra_models_become_separate_panel_members_named_like_the_harness(self):
        os.environ['GROQ_EXTRA_MODELS'] = 'openai/gpt-oss-120b, openai/gpt-oss-safeguard-20b'
        provs = swarm.AiSwarmAnalyzer._init_providers(None)
        self.assertEqual([p.name for p in provs], ['groq', 'groq-gpt-oss-120b', 'groq-gpt-oss-safeguard-20b'])
        self.assertTrue(all(p.reasoning for p in provs[1:]))                       # gpt-oss variants get the reasoning-effort fix

    def test_extras_need_the_groq_key(self):
        os.environ.pop('GROQ_API_KEY')
        os.environ['GROQ_EXTRA_MODELS'] = 'openai/gpt-oss-120b'
        self.assertEqual(self.names(), [])


class FallbackPanel(unittest.TestCase):
    """The 2026-09-27 fallback: mistral/hermes3 stand in ONLY when the primary panel answers with nothing
    (this used to mean the threat was marked processed forever and silently dropped -- agent_runner.py)."""

    def setUp(self):
        self._t = swarm._ANALYSIS_TIMEOUT
        swarm._ANALYSIS_TIMEOUT = 0.4
        # Isolate from whatever real weights file happens to be adopted on this machine (production sets
        # ollama-mistral to weight 0, which would silently switch it off in these tests too).
        self._wp = swarm._WEIGHTS_PATH
        swarm._WEIGHTS_PATH = '/nonexistent-in-tests.json'
        swarm._weights_cache.update(mtime=None, weights={})

    def tearDown(self):
        swarm._ANALYSIS_TIMEOUT = self._t
        swarm._WEIGHTS_PATH = self._wp
        swarm._weights_cache.update(mtime=None, weights={})

    def test_fallback_used_when_primary_answers_nothing(self):
        def boom():
            raise RuntimeError('cloud outage')
        primary = FakeProvider('groq', boom)
        fb = FakeProvider('ollama-mistral', reply('malicious'))
        a = panel(primary, fb)
        r = a.analyze(Event())
        self.assertIsNotNone(r)
        self.assertEqual(r['ai_sources'], ['ollama-mistral'])
        self.assertEqual(r['panel_mode'], 'fallback')

    def test_fallback_not_used_when_primary_answers(self):
        calls = []

        def spy():
            calls.append('fallback-called')
            return json.dumps({'verdict': 'malicious', 'severity': 'HIGH', 'confidence': 80})
        primary = FakeProvider('groq', reply('benign'))
        fb = FakeProvider('ollama-mistral', spy)
        a = panel(primary, fb)
        r = a.analyze(Event())
        self.assertEqual(r['panel_mode'], 'primary')
        self.assertEqual(r['ai_sources'], ['groq'])
        self.assertEqual(calls, [])                                    # fallback never invoked -- no wasted latency

    def test_no_fallback_configured_still_returns_none(self):
        def boom():
            raise RuntimeError('cloud outage')
        a = panel(FakeProvider('groq', boom))                          # no ollama-mistral / ollama-hermes3 in this panel
        self.assertIsNone(a.analyze(Event()))

    def test_fallback_itself_failing_returns_none_not_raises(self):
        def boom():
            raise RuntimeError('cloud outage')

        def boom2():
            raise RuntimeError('local outage too')
        a = panel(FakeProvider('groq', boom), FakeProvider('ollama-hermes3', boom2))
        self.assertIsNone(a.analyze(Event()))


if __name__ == '__main__':
    unittest.main(verbosity=2)
