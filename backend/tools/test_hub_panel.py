#!/usr/bin/env python3
"""The dashboard's AI SWARM card lists the real panel; node times are marked UTC (2026-09-26).
Run:  swarmsentinel-env/bin/python3 backend/tools/test_hub_panel.py"""
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

os.environ['SSAI_PROVIDER_CHECK'] = '0'
HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
sys.path[:0] = [os.path.join(BACKEND, 'agents'), BACKEND]
import ai_swarm_agent as swarm  # noqa: E402
import model_config  # noqa: E402

CONFIG = {'providers': {
    'groq':           {'kind': 'openai', 'model': 'openai/gpt-oss-20b', 'endpoint': 'https://api.groq.com/openai/v1', 'key_env': 'GROQ_API_KEY'},
    'gemini':         {'kind': 'gemini', 'model': 'gemini-3.6-flash', 'key_env': 'GEMINI_API_KEY'},
    'anthropic':      {'kind': 'anthropic', 'model': 'claude-haiku-4-5-20251001', 'key_env': 'ANTHROPIC_API_KEY'},
    'huggingface':    {'kind': 'huggingface', 'model': 'meta-llama/Llama-3.1-8B-Instruct', 'key_env': 'HF_TOKEN'},
    'ollama-hermes3': {'kind': 'ollama', 'model': 'hermes3', 'endpoint': 'http://192.168.1.20:11434'},
    'ollama-phi4':    {'kind': 'ollama', 'model': 'phi4:14b', 'endpoint': 'http://192.168.1.20:11434'},
    'ollama-nowhere': {'kind': 'ollama', 'model': 'x'},
}}


class PanelMembers(unittest.TestCase):
    def setUp(self):
        d = tempfile.mkdtemp()
        cfg = os.path.join(d, 'ai_models.json')
        with open(cfg, 'w') as f:
            json.dump(CONFIG, f)
        env = {k: v for k, v in os.environ.items() if not k.endswith(('_API_KEY', '_TOKEN'))}
        env.update(GROQ_API_KEY='k', GEMINI_API_KEY='k', HF_TOKEN='k')          # Anthropic: no key
        self.on = {'groq', 'gemini', 'anthropic', 'ollama-hermes3', 'ollama-nowhere'}   # huggingface + phi4 switched off
        for p in (mock.patch.object(model_config, 'DEFAULT_PATH', cfg),
                  mock.patch.object(model_config, 'instance_path', lambda: os.path.join(d, 'none.json')),
                  mock.patch.dict(model_config._cache, stamp=None, data=None),
                  mock.patch.dict(os.environ, env, clear=True),
                  mock.patch.object(swarm, 'provider_enabled', lambda pid, ov=None: pid in self.on),
                  mock.patch.object(swarm, 'load_provider_overrides', return_value={}),
                  mock.patch.object(swarm, 'load_weights', return_value={})):
            p.start()
            self.addCleanup(p.stop)

    def ids(self):
        return [m['provider'] for m in swarm.panel_members()]

    def test_only_switched_on_and_configured_providers_are_listed(self):
        self.assertEqual(self.ids(), ['groq', 'gemini', 'ollama-hermes3'])     # no key / off / no endpoint are left out

    def test_entries_carry_model_and_locality(self):
        by = {m['provider']: m for m in swarm.panel_members()}
        self.assertEqual(by['ollama-hermes3'], {'provider': 'ollama-hermes3', 'model': 'hermes3', 'local': True,
                                                'approval': 'local'})
        self.assertEqual(by['groq'], {'provider': 'groq', 'model': 'openai/gpt-oss-20b', 'local': False,
                                      'approval': 'pending'})

    def test_switching_a_provider_on_or_off_changes_the_list(self):
        self.on.discard('gemini')
        self.on.add('huggingface')
        self.assertEqual(self.ids(), ['groq', 'huggingface', 'ollama-hermes3'])

    def test_a_weighted_out_provider_is_not_listed(self):
        with mock.patch.object(swarm, 'load_weights', return_value={'groq': 0.0}):     # load_weights' parsed shape
            self.assertEqual(self.ids(), ['gemini', 'ollama-hermes3'])

    def test_model_env_override_is_what_is_shown(self):
        with mock.patch.dict(os.environ, {'GROQ_MODEL': 'openai/gpt-oss-120b'}):
            CONFIG['providers']['groq']['model_env'] = 'GROQ_MODEL'
            try:
                model_config._cache.update(stamp=None)
                with open(model_config.DEFAULT_PATH, 'w') as f:
                    json.dump(CONFIG, f)
                self.assertEqual(swarm.panel_members()[0]['model'], 'openai/gpt-oss-120b')
            finally:
                CONFIG['providers']['groq'].pop('model_env')


class UtcTimes(unittest.TestCase):
    def test_naive_times_are_marked_utc_and_aware_ones_kept(self):
        from models import _utc_iso
        self.assertIsNone(_utc_iso(None))
        self.assertEqual(_utc_iso(datetime(2026, 9, 26, 4, 0, 56)), '2026-09-26T04:00:56+00:00')
        eastern = timezone(timedelta(hours=-4))
        self.assertEqual(_utc_iso(datetime(2026, 9, 26, 0, 0, tzinfo=eastern)), '2026-09-26T00:00:00-04:00')


class UtcEverywhere(unittest.TestCase):
    """The API marks every time as UTC, so a page must not add its own 'Z' (that gives "...+00:00Z" = Invalid Date)."""
    def test_models_serialise_times_only_through_utc_iso(self):
        src = open(os.path.join(BACKEND, 'models', '__init__.py'), encoding='utf-8').read()
        self.assertEqual(src.count('.isoformat()'), 1)                  # the one inside _utc_iso

    def test_no_page_appends_z_to_an_api_time(self):
        import re
        tdir = os.path.join(BACKEND, 'templates')
        for name in os.listdir(tdir):
            if name.endswith('.html'):
                src = open(os.path.join(tdir, name), encoding='utf-8').read()
                self.assertIsNone(re.search(r"\+\s*['\"]Z['\"]", src), name)


if __name__ == '__main__':
    unittest.main(verbosity=2)
