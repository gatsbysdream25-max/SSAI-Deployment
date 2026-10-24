#!/usr/bin/env python3
"""Independent verification of consensus (a model from a different maker checks the panel). Each test fails without the feature.
Run:  swarmsentinel-env/bin/python3 backend/tools/test_verifier.py"""
import json
import os
import sys
import tempfile
import threading
import unittest
from unittest import mock

_TMP = tempfile.mkdtemp()
os.environ['DATA_DIR'] = _TMP
os.environ['DATABASE_URL'] = f'sqlite:///{_TMP}/verifier-test.db'
os.environ['SSAI_PROVIDER_CHECK'] = '0'
os.environ['SSAI_STATE_DB'] = os.path.join(_TMP, 'state.db')
os.environ.pop('SSAI_VERIFIER_PROVIDER', None)

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
sys.path[:0] = [os.path.join(BACKEND, 'agents'), BACKEND]

from agents import ai_swarm_agent as swarm  # noqa: E402
from agents import recall, verifier  # noqa: E402
import remediation_queue  # noqa: E402


class Fake(swarm._OllamaModelProvider):
    """A local provider that answers from a script instead of the network."""
    base_url = 'http://127.0.0.1:11434'

    def __init__(self, name, model, reply):
        self.name, self.model, self.available = name, model, True
        self.reply = reply

    def analyze(self, _prompt):
        if isinstance(self.reply, Exception):
            raise self.reply
        return self.reply


def answer(verdict, **kw):
    return json.dumps(dict({'verdict': verdict, 'confidence': 80, 'severity': 'HIGH', 'reasoning': 'because'}, **kw))


class Event:
    title, category, source, detail, agent = 'odd login', 'ssh-login', 'host-a', 'x', 'AuthLogAgent'

    class severity:
        name = 'HIGH'


def analyzer(*providers):
    a = object.__new__(swarm.AiSwarmAnalyzer)
    a._providers = list(providers)
    a._health, a._health_lock = {}, threading.Lock()
    return a


def consensus(verdict='malicious', sources=('groq', 'gemini'), models=None):
    return {'consensus_verdict': verdict, 'consensus_severity': 'HIGH', 'confidence': 90, 'ai_count': len(sources),
            'ai_sources': list(sources), 'models': models or {'groq': 'openai/gpt-oss-20b', 'gemini': 'gemini-3.6-flash'},
            'quorum': {'agreed': 2, 'answered': 2, 'panel': 2, 'level': 'Medium', 'label': 'Medium, 2 of 2 agreed', 'complete': True}}


class Logic(unittest.TestCase):
    def test_the_maker_comes_from_the_model_not_the_host(self):
        self.assertEqual(verifier.family_of('groq', 'openai/gpt-oss-20b'), 'openai')
        self.assertEqual(verifier.family_of('groq', 'llama-3.3-70b'), 'meta')
        self.assertEqual(verifier.family_of('ollama-gemma4', 'gemma4:12b'), 'google')
        self.assertEqual(verifier.family_of('gemini', 'gemini-3.6-flash'), 'google')
        self.assertEqual(verifier.family_of('mystery'), 'mystery')

    def test_the_comparison(self):
        self.assertEqual(verifier.compare('malicious', {'verdict': 'Malicious'}), 'confirmed')
        self.assertEqual(verifier.compare('malicious', {'verdict': 'suspicious'}), 'partial')
        self.assertEqual(verifier.compare('malicious', {'verdict': 'benign'}), 'disputed')
        self.assertEqual(verifier.compare('benign', {'verdict': 'malicious'}), 'disputed')

    def test_a_disputed_consensus_can_never_read_as_high_confidence(self):
        c = consensus()
        c['quorum']['level'] = 'High'
        verifier.apply(c, verifier.record('disputed', Fake('hermes', 'hermes3', ''), {'verdict': 'benign'}))
        self.assertEqual(c['quorum']['level'], 'Low')
        self.assertIn('DISAGREES', c['quorum']['label'])
        self.assertEqual(c['verification']['family'], 'meta')

    def test_a_disputed_verdict_is_not_proposed_for_blocking_or_replayed(self):
        c = consensus()
        self.assertTrue(remediation_queue.eligible(c))
        verifier.apply(c, verifier.record('disputed', None, {'verdict': 'benign'}))
        self.assertFalse(remediation_queue.eligible(c))
        self.assertFalse(recall.reusable_consensus(dict(c, quorum=None)))
        ok = consensus()
        verifier.apply(ok, verifier.record('confirmed', None, {'verdict': 'malicious'}))
        self.assertTrue(remediation_queue.eligible(ok))
        self.assertIn('independent check: confirmed', remediation_queue._reason(ok))


class Verify(unittest.TestCase):
    def setUp(self):
        self.env = mock.patch.dict(os.environ, {'SSAI_VERIFIER_PROVIDER': 'ollama-hermes3'})
        self.env.start()

    def tearDown(self):
        self.env.stop()

    def test_a_reserved_model_from_another_maker_confirms(self):
        a = analyzer(Fake('ollama-hermes3', 'hermes3', answer('malicious')), Fake('ollama-gemma4', 'gemma4:12b', answer('benign')))
        c = a.verify(Event, consensus())
        self.assertEqual(c['verification']['status'], 'confirmed')
        self.assertEqual(c['verification']['verifier'], 'ollama-hermes3')
        self.assertTrue(c['verification']['independent_maker'])

    def test_it_disagrees_when_the_other_model_does(self):
        a = analyzer(Fake('ollama-hermes3', 'hermes3', answer('benign', reasoning='a known admin scan')))
        c = a.verify(Event, consensus())
        self.assertEqual(c['verification']['status'], 'disputed')
        self.assertIn('admin scan', c['verification']['reasoning'])

    def test_the_verifier_is_not_shown_the_panels_answer(self):
        seen = []
        p = Fake('ollama-hermes3', 'hermes3', answer('malicious'))
        p.analyze = lambda prompt: seen.append(prompt) or answer('malicious')
        analyzer(p).verify(Event, consensus())
        self.assertTrue(seen)
        self.assertNotIn('gpt-oss', seen[0])
        self.assertNotIn('consensus_verdict', seen[0])

    def test_a_voter_cannot_verify_its_own_panel(self):
        a = analyzer(Fake('ollama-hermes3', 'hermes3', answer('malicious')))
        c = a.verify(Event, consensus(sources=('ollama-hermes3', 'gemini'),
                                      models={'ollama-hermes3': 'hermes3', 'gemini': 'gemini-3.6-flash'}))
        self.assertEqual(c['verification']['status'], 'unavailable')
        self.assertIn('no independent model', c['verification']['reason'])

    def test_a_failing_or_garbled_verifier_is_unavailable_never_a_crash(self):
        for reply in (RuntimeError('boom'), 'not json at all', answer('maybe')):
            a = analyzer(Fake('ollama-hermes3', 'hermes3', reply))
            self.assertEqual(a.verify(Event, consensus())['verification']['status'], 'unavailable', repr(reply))

    def test_a_slow_verifier_times_out(self):
        gate = threading.Event()
        p = Fake('ollama-hermes3', 'hermes3', '')
        p.analyze = lambda _p: gate.wait(5) and answer('malicious')
        with mock.patch.object(swarm, '_ANALYSIS_TIMEOUT', 0.2):
            c = analyzer(p).verify(Event, consensus())
        gate.set()
        self.assertEqual(c['verification']['reason'], 'timed out')

    def test_it_can_be_switched_off(self):
        with mock.patch.dict(os.environ, {'SSAI_VERIFIER': '0'}):
            c = consensus()
            self.assertIsNone(analyzer(Fake('ollama-hermes3', 'hermes3', answer('malicious'))).verify(Event, c))
            self.assertNotIn('verification', c)

    def test_a_reserved_model_does_not_vote(self):
        self.assertEqual(swarm.verifier_ids(), ['ollama-hermes3'])
        a = analyzer(Fake('ollama-hermes3', 'hermes3', answer('malicious')), Fake('ollama-gemma4', 'gemma4:12b', answer('malicious')))
        with mock.patch.object(swarm, 'load_provider_overrides', return_value={'ollama-gemma4': True, 'ollama-hermes3': True}), \
                mock.patch.object(swarm, 'load_weights', return_value={}):
            out = a.analyze(Event)
            self.assertEqual(a.active_count, 1)
        self.assertEqual(out['ai_sources'], ['ollama-gemma4'])

    def test_a_cloud_verifier_only_ever_sees_the_sanitized_copy(self):
        class Cloud(Fake):
            base_url = 'https://api.example.com'

        sent = []
        p = Cloud('cloudy', 'qwen-72b', '')
        p.analyze = lambda prompt: sent.append(prompt) or answer('malicious')

        class Ev(Event):
            detail = 'login from 192.168.0.77 as bob@corp.example'

        with mock.patch.dict(os.environ, {'SSAI_VERIFIER_PROVIDER': 'cloudy'}), \
                mock.patch.object(swarm.provider_approval, 'cloud_allowed', return_value=True):
            self.assertFalse(swarm._is_local_provider(p))
            analyzer(p).verify(Ev, consensus())
        self.assertTrue(sent)
        self.assertNotIn('192.168.0.77', sent[0])
        self.assertNotIn('bob@corp.example', sent[0])


if __name__ == '__main__':
    unittest.main(verbosity=2)
