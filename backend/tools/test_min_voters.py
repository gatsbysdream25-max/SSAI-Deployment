#!/usr/bin/env python3
"""Phase 2 of the consensus plan: the minimum-voter rule (audit F-02, F-03; plan decision 3).
At least 3 models must answer, at least 2 of them local (where the panel has that many); otherwise the verdict is DEGRADED,
labelled so, and never proposed for blocking. The stand-in panel is always degraded.
Run:  swarmsentinel-env/bin/python3 backend/tools/test_min_voters.py"""
import json
import os
import sys
import tempfile
import threading
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
sys.path[:0] = [os.path.join(BACKEND, 'agents'), BACKEND]
import ai_swarm_agent as swarm  # noqa: E402
import sanitizer  # noqa: E402


class Sev:
    name = 'HIGH'


class Event:
    id, title, category, severity, source, detail, agent = 7, 't', 'url', Sev(), 'http://x/y', 'd', 'a'


class Voice:
    """A fake model. `local` makes swarm._is_local_provider treat it as an Ollama model on this network."""
    def __init__(self, name, local=False, verdict='malicious', fail=False):
        self.name, self.local, self.verdict, self.fail = name, local, verdict, fail
        self.model = name + '-model'

    def analyze(self, prompt):
        if self.fail:
            raise RuntimeError('down')
        return json.dumps({'verdict': self.verdict, 'severity': 'HIGH', 'confidence': 90})


def panel(*voices):
    a = swarm.AiSwarmAnalyzer.__new__(swarm.AiSwarmAnalyzer)
    a._providers, a._health, a._health_lock = list(voices), {}, threading.Lock()
    a._maybe_rediscover = lambda: None
    return a


class Rule(unittest.TestCase):
    def setUp(self):
        audit = os.path.join(tempfile.mkdtemp(), 'cloud_audit.jsonl')
        for p in (mock.patch.object(sanitizer, 'audit_path', return_value=audit),
                  mock.patch.object(swarm, '_is_local_provider', lambda p: getattr(p, 'local', False)),
                  mock.patch.object(swarm, 'panel_allowed', lambda p, *a, **k: True),
                  mock.patch.object(swarm, 'verifier_ids', lambda: []),
                  mock.patch.object(swarm, '_cloud_threat_json', lambda *a, **k: '{}', create=True)):
            p.start()
            self.addCleanup(p.stop)

    def run_panel(self, *voices):
        return panel(*voices).analyze(Event())['quorum']

    def test_three_answers_with_two_local_is_a_normal_verdict(self):
        q = self.run_panel(Voice('groq'), Voice('gemma', True), Voice('phi', True))
        self.assertFalse(q['degraded'])
        self.assertEqual((q['answered'], q['local'], q['min_voters'], q['min_local']), (3, 2, 3, 2))
        self.assertNotIn('DEGRADED', q['label'])

    def test_two_answers_is_degraded_even_if_they_agree_completely(self):
        q = self.run_panel(Voice('groq'), Voice('gemma', True), Voice('phi', True, fail=True))
        self.assertTrue(q['degraded'])
        self.assertIn('only 2 of the 3 models required', q['degraded_reason'])
        self.assertEqual(q['level'], 'Low')
        self.assertTrue(q['label'].startswith('DEGRADED, needs a person'))

    def test_three_cloud_answers_with_the_local_models_down_is_degraded(self):
        q = self.run_panel(Voice('a'), Voice('b'), Voice('c'), Voice('gemma', True, fail=True), Voice('phi', True, fail=True))
        self.assertTrue(q['degraded'])
        self.assertIn('0 of the 2 local models', q['degraded_reason'])

    def test_one_local_model_on_the_panel_does_not_make_every_verdict_degraded(self):
        q = self.run_panel(Voice('groq'), Voice('gemini'), Voice('gemma', True))
        self.assertFalse(q['degraded'])
        self.assertEqual((q['min_local'], q['roster_local']), (1, 1))      # the shortfall is stated, not hidden

    def test_that_one_local_model_going_silent_is_degraded(self):
        q = self.run_panel(Voice('groq'), Voice('gemini'), Voice('x'), Voice('gemma', True, fail=True))
        self.assertTrue(q['degraded'])

    def test_offline_all_local_is_marked_local_only_and_still_counts(self):
        q = self.run_panel(Voice('g', True), Voice('p', True), Voice('m', True))
        self.assertFalse(q['degraded'])
        self.assertTrue(q['local_only'])

    def test_the_stand_in_panel_is_always_degraded_and_says_so(self):
        a = panel(Voice('ollama-mistral', True), Voice('ollama-hermes3', True))
        with mock.patch.object(swarm, 'panel_allowed', lambda p, *x, **k: False):
            out = a.analyze(Event())
        self.assertEqual(out['panel_mode'], 'fallback')
        self.assertTrue(out['quorum']['degraded'])
        self.assertIn('stand-in panel', out['quorum']['degraded_reason'])
        self.assertEqual(out['quorum']['panel_mode'], 'fallback')


class Queue(unittest.TestCase):
    def test_a_degraded_or_stand_in_verdict_is_never_proposed(self):
        os.environ.setdefault('DATABASE_URL', 'sqlite://')
        try:
            import remediation_queue
        except ImportError as exc:                                       # needs the Flask models (run on the server)
            self.skipTest(str(exc))
        good = {'consensus_verdict': 'malicious', 'confidence': 95, 'ai_count': 3, 'consensus_severity': 'HIGH',
                'quorum': {'degraded': False}}
        self.assertTrue(remediation_queue.eligible(good))
        self.assertFalse(remediation_queue.eligible(dict(good, quorum={'degraded': True})))
        self.assertFalse(remediation_queue.eligible(dict(good, panel_mode='fallback')))
        self.assertTrue(remediation_queue.eligible({k: v for k, v in good.items() if k != 'quorum'}))   # old saved verdicts keep working


class Settings(unittest.TestCase):
    def test_a_blank_or_bad_setting_means_the_default(self):
        for raw in ('', 'three', '1.5'):
            with mock.patch.dict(os.environ, {'SSAI_MIN_VOTERS': raw}):
                self.assertEqual(swarm._whole_number_setting('SSAI_MIN_VOTERS', 3), 3)
        with mock.patch.dict(os.environ, {'SSAI_MIN_VOTERS': '0'}):
            self.assertEqual(swarm._whole_number_setting('SSAI_MIN_VOTERS', 3), 1)


if __name__ == '__main__':
    unittest.main()
