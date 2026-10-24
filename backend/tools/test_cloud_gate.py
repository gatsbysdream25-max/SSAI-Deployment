#!/usr/bin/env python3
"""The AI panel's cloud boundary (2026-09-26): cloud providers only ever see the sanitized threat.
Run:  swarmsentinel-env/bin/python3 backend/tools/test_cloud_gate.py"""
import json
import os
import sys
import tempfile
import threading
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(os.path.dirname(HERE), 'agents'), os.path.dirname(HERE)]
import ai_swarm_agent as swarm  # noqa: E402
import sanitizer  # noqa: E402

VERDICT = json.dumps({'verdict': 'suspicious', 'severity': 'MEDIUM', 'confidence': 70})


class Cloud:
    """Any provider that is not an Ollama model on this network: Groq, Gemini, or something unrecognised."""
    def __init__(self, name='groq'):
        self.name, self.prompts = name, []

    def analyze(self, prompt):
        self.prompts.append(prompt)
        return VERDICT


def ollama(name, base_url):
    """A real _OllamaModelProvider without the network probe in its constructor."""
    p = swarm._OllamaModelProvider.__new__(swarm._OllamaModelProvider)
    p.name, p.base_url, p.model, p.available, p.problem = name, base_url, 'hermes3', True, ''
    p.prompts = []
    p.analyze = lambda prompt: (p.prompts.append(prompt), VERDICT)[1]
    return p


class Sev:
    name = 'HIGH'


class Event:
    """Shaped like agent_runner's _ThreatEventAdapter, with the kind of detail a real process alert carries."""
    title = detail = ('Suspicious process detected: srv01 17772 bash -c ssh jdoe@192.168.1.30 '
                      'cat /home/srv01/.env from 02:00:5e:00:53:01 (alice@example.com)')
    category, severity, source, agent = 'suspicious-process', Sev(), 'process://17772', 'ProcessMonitorAgent'


def panel(*providers):
    a = swarm.AiSwarmAnalyzer.__new__(swarm.AiSwarmAnalyzer)      # skip provider discovery (network)
    a._providers, a._health, a._health_lock = list(providers), {}, threading.Lock()
    return a


SECRETS = ['192.168.1.30', '/home/srv01', 'jdoe', '02:00:5e:00:53:01', 'alice@example.com']


class CloudGate(unittest.TestCase):
    def setUp(self):
        self.audit = os.path.join(tempfile.mkdtemp(), 'cloud_audit.jsonl')
        for p in (mock.patch.object(sanitizer, 'audit_path', return_value=self.audit),
                  mock.patch.dict(os.environ, {'SSAI_PRIVATE_NAMES': 'srv01,jdoe'}),
                  mock.patch.object(swarm, 'provider_enabled', return_value=True),
                  mock.patch.object(swarm, 'load_weights', return_value={}),
                  mock.patch.object(swarm, 'load_provider_overrides', return_value={})):
            p.start()
            self.addCleanup(p.stop)

    def test_cloud_provider_never_sees_internal_details_but_a_local_model_does(self):
        cloud, local = Cloud(), ollama('ollama-hermes3', 'http://192.168.1.20:11434')
        r = panel(cloud, local).analyze(Event())
        self.assertIsNotNone(r)
        self.assertEqual(len(cloud.prompts), 2)                        # the first round and the challenge round (a HIGH finding)
        for prompt in cloud.prompts:
            for s in SECRETS + ['srv01 ']:
                self.assertNotIn(s, prompt, s)
        self.assertIn('IP_', cloud.prompts[0])                         # still readable: tokens, not blanks
        self.assertIn('suspicious-process', cloud.prompts[0])
        self.assertIn('192.168.1.30', local.prompts[0])                # the local model keeps the full picture

    def test_what_crossed_is_in_the_audit_log_without_any_original_value(self):
        panel(Cloud()).analyze(Event())
        with open(self.audit, encoding='utf-8') as f:
            lines = f.read()
        self.assertIn('"ok": true', lines)
        for s in SECRETS:
            self.assertNotIn(s, lines)

    def test_gate_refusal_keeps_cloud_out_but_local_still_votes(self):
        cloud, local = Cloud(), ollama('ollama-hermes3', 'http://localhost:11434')
        with mock.patch.object(sanitizer, 'sanitize_for_cloud', return_value={}):
            r = panel(cloud, local).analyze(Event())
        self.assertEqual(cloud.prompts, [])
        self.assertEqual(len(local.prompts), 1)
        self.assertEqual(r['ai_sources'], ['ollama-hermes3'])

    def test_gate_crash_also_fails_closed(self):
        cloud = Cloud()
        with mock.patch.object(sanitizer, 'sanitize_for_cloud', side_effect=RuntimeError('boom')):
            self.assertIsNone(panel(cloud).analyze(Event()))           # nobody left to ask: no verdict, no crash
        self.assertEqual(cloud.prompts, [])

    def test_ollama_on_the_internet_counts_as_cloud(self):
        remote = ollama('ollama-remote', 'http://203.0.113.9:11434')
        panel(remote).analyze(Event())
        self.assertNotIn('192.168.1.30', remote.prompts[0])
        self.assertIn('IP_', remote.prompts[0])

    def test_unrecognised_provider_counts_as_cloud(self):
        odd = Cloud('something-new')
        panel(odd).analyze(Event())
        self.assertNotIn('192.168.1.30', odd.prompts[0])

    def test_which_endpoints_are_local(self):
        for url in ('http://localhost:11434', 'http://127.0.0.1:11434', 'http://192.168.1.20:11434',
                    'http://10.0.0.5:11434', 'http://watchtower:11434', 'http://box.lan:11434', 'http://[::1]:11434'):
            self.assertTrue(swarm._private_endpoint(url), url)
        for url in ('http://203.0.113.9:11434', 'https://ollama.example.com', 'https://api.groq.com/openai/v1', '', 'nonsense'):
            self.assertFalse(swarm._private_endpoint(url), url)


if __name__ == '__main__':
    unittest.main(verbosity=2)
