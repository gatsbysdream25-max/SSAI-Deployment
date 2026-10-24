#!/usr/bin/env python3
"""Tests for provider tiers and the operator on/off switches (2026-09-19).
Run:  python3 backend/tools/test_tiers.py"""
import json
import os
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(os.path.dirname(HERE), 'agents'), os.path.dirname(HERE)]
import ai_swarm_agent as swarm  # noqa: E402

TIERS = {'local', 'free', 'limited', 'credits', 'paid'}


class RegistryPolicy(unittest.TestCase):
    def test_every_provider_has_tier_verified_default_and_notes(self):
        for p in swarm.PROVIDER_REGISTRY:
            self.assertIn(p['tier'], TIERS, p['id'])
            for key in ('verified', 'default_on', 'notes'):
                self.assertIn(key, p, p['id'])
            self.assertIsInstance(p['default_on'], bool)

    def test_paid_limited_and_unmeasured_providers_are_never_on_by_default(self):
        for p in swarm.PROVIDER_REGISTRY:
            if p['tier'] in ('paid', 'limited', 'credits') or not p['verified']:
                self.assertFalse(p['default_on'], f"{p['id']} would join the panel automatically")

    def test_local_models_are_opt_in_until_a_good_one_is_measured(self):
        self.assertFalse(swarm._REGISTRY_BY_ID['ollama']['default_on'])

    def test_groq_is_the_verified_free_default(self):
        g = swarm._REGISTRY_BY_ID['groq']
        self.assertTrue(g['default_on'] and g['verified'])
        self.assertEqual(g['tier'], 'free')
        self.assertEqual([p['id'] for p in swarm.PROVIDER_REGISTRY if p['default_on']], ['groq'])

    def test_stale_free_claims_were_corrected(self):
        self.assertNotIn('1,500', swarm._REGISTRY_BY_ID['gemini']['rate_limit'])
        self.assertNotEqual(swarm._REGISTRY_BY_ID['huggingface']['cost'], 'Free')


class Overrides(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(tempfile.mkdtemp(), 'ai_providers.json')

    def test_missing_or_corrupt_file_gives_no_overrides(self):
        self.assertEqual(swarm.load_provider_overrides(self.path), {})
        for junk in ('{bad', '[1]', '{"enabled": 3}', '{"enabled": {"a": "yes", "b": 1, "c": true}}'):
            with open(self.path, 'w') as f:
                f.write(junk)
            data = swarm.load_provider_overrides(self.path)
            self.assertNotIn('a', data)                       # only real booleans count
            self.assertNotIn('b', data)

    def test_precedence_operator_choice_then_registry_default_then_on_for_extras(self):
        self.assertTrue(swarm.provider_enabled('groq', {}))
        self.assertFalse(swarm.provider_enabled('anthropic', {}))
        self.assertFalse(swarm.provider_enabled('ollama', {}))
        self.assertTrue(swarm.provider_enabled('groq-gpt-oss-120b', {}))              # configured on purpose, not in the registry
        self.assertTrue(swarm.provider_enabled('anthropic', {'anthropic': True}))      # operator opts in
        self.assertFalse(swarm.provider_enabled('groq', {'groq': False}))              # operator opts out

    def test_set_round_trips_and_keeps_other_choices(self):
        swarm.set_provider_enabled('anthropic', True, self.path)
        swarm.set_provider_enabled('groq', False, self.path)
        self.assertEqual(swarm.load_provider_overrides(self.path), {'anthropic': True, 'groq': False})
        swarm.set_provider_enabled('anthropic', False, self.path)
        self.assertEqual(swarm.load_provider_overrides(self.path), {'anthropic': False, 'groq': False})
        self.assertFalse(os.path.exists(self.path + '.tmp'))                            # atomic write left nothing behind

    def test_default_path_cache_picks_up_changes_without_restart(self):
        orig = swarm._PROVIDERS_PATH
        swarm._PROVIDERS_PATH = self.path
        swarm._overrides_cache.update(mtime=None, data={})
        try:
            self.assertFalse(swarm.provider_enabled('anthropic'))
            swarm.set_provider_enabled('anthropic', True)
            self.assertTrue(swarm.provider_enabled('anthropic'))
            swarm.set_provider_enabled('anthropic', False)
            self.assertFalse(swarm.provider_enabled('anthropic'))
        finally:
            swarm._PROVIDERS_PATH = orig
            swarm._overrides_cache.update(mtime=None, data={})

    def test_registry_reports_enabled_state(self):
        orig = swarm._PROVIDERS_PATH
        swarm._PROVIDERS_PATH = self.path
        swarm._overrides_cache.update(mtime=None, data={})
        try:
            swarm.set_provider_enabled('anthropic', True)
            reg = {p['id']: p for p in swarm.AiSwarmAnalyzer.get_provider_registry()}
            self.assertTrue(reg['anthropic']['enabled'])
            self.assertTrue(reg['groq']['enabled'])
            self.assertFalse(reg['gemini']['enabled'])
        finally:
            swarm._PROVIDERS_PATH = orig
            swarm._overrides_cache.update(mtime=None, data={})


class FakeProvider:
    def __init__(self, name, calls):
        self.name, self.calls = name, calls

    def analyze(self, prompt):
        self.calls.append(self.name)
        return json.dumps({'verdict': 'benign', 'severity': 'LOW', 'confidence': 80})


class Sev:
    name = 'MEDIUM'


class Event:
    title, category, severity, source, detail, agent = 't', 'url', Sev(), 'http://x/y', 'd', 'a'


class AnalyzeHonoursSwitches(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(tempfile.mkdtemp(), 'ai_providers.json')
        self._orig = swarm._PROVIDERS_PATH
        swarm._PROVIDERS_PATH = self.path
        swarm._overrides_cache.update(mtime=None, data={})

    def tearDown(self):
        swarm._PROVIDERS_PATH = self._orig
        swarm._overrides_cache.update(mtime=None, data={})

    def panel(self, calls, *names):
        a = swarm.AiSwarmAnalyzer.__new__(swarm.AiSwarmAnalyzer)
        a._providers = [FakeProvider(n, calls) for n in names]
        a._health, a._health_lock = {}, threading.Lock()
        return a

    def test_only_enabled_providers_are_consulted_and_toggling_is_live(self):
        calls = []
        a = self.panel(calls, 'groq', 'anthropic', 'gemini', 'ollama', 'groq-gpt-oss-120b')
        r = a.analyze(Event())
        self.assertEqual(sorted(calls), ['groq', 'groq-gpt-oss-120b'])               # paid / limited / local stay off by default
        self.assertEqual(sorted(r['ai_sources']), ['groq', 'groq-gpt-oss-120b'])
        calls.clear()
        swarm.set_provider_enabled('anthropic', True)                                 # operator opts in: no restart
        swarm.set_provider_enabled('groq', False)
        time.sleep(0.01)
        a.analyze(Event())
        self.assertEqual(sorted(calls), ['anthropic', 'groq-gpt-oss-120b'])

    def test_active_count_counts_only_providers_in_the_panel(self):
        a = self.panel([], 'groq', 'anthropic', 'gemini', 'ollama')
        self.assertEqual(a.active_count, 1)
        swarm.set_provider_enabled('anthropic', True)
        self.assertEqual(a.active_count, 2)

    def test_everything_off_returns_none_without_calling_anything(self):
        calls = []
        a = self.panel(calls, 'anthropic', 'gemini')
        self.assertIsNone(a.analyze(Event()))
        self.assertEqual(calls, [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
