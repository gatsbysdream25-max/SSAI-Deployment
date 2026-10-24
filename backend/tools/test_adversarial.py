#!/usr/bin/env python3
"""Adversarial cases (pre-pilot hardening C2/D1, 2026-10-18): what a malformed or hostile AI provider, or a compromised node
holding a valid token, can and cannot do.
Run:  swarmsentinel-env/bin/python3 backend/tools/test_adversarial.py"""
import os
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timezone

_TMP = tempfile.mkdtemp()
os.environ['DATA_DIR'] = _TMP
os.environ['DATABASE_URL'] = f'sqlite:///{_TMP}/adversarial-test.db'
os.environ['SSAI_API_KEY'] = ADMIN = 'adversarial-admin-key'
os.environ['SSAI_PROVIDER_CHECK'] = '0'
os.environ['SSAI_STATE_DB'] = os.path.join(_TMP, 'state.db')
os.environ.pop('SSAI_TRUSTED_PROXIES', None)

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
sys.path[:0] = [os.path.join(BACKEND, 'agents'), BACKEND]

from agents import ai_swarm_agent as swarm  # noqa: E402

Analyzer = swarm.AiSwarmAnalyzer


class Fake:
    def __init__(self, name, text):
        self.name, self.text = name, text

    def analyze(self, prompt):
        return self.text


def analyzer():
    a = object.__new__(Analyzer)
    a._health, a._health_lock, a._degraded_logged = {}, threading.Lock(), {}
    return a


def vote(ai, verdict, confidence=90, severity='HIGH'):
    return {'ai': ai, 'verdict': verdict, 'confidence': confidence, 'severity': severity}


class MalformedProviderAnswers(unittest.TestCase):
    """A broken or hostile provider ABSTAINS: it is recorded as an error and never counted as a vote."""

    def ask(self, text):
        a = analyzer()
        return a, a._safe_call(Fake('p', text), '{}')

    def test_answers_without_a_valid_verdict_abstain(self):
        for text in ('{}', '{"verdict": "ALL YOUR BASE"}', '{"verdict": 1}', '{"verdict": null}', '{"verdict": ["malicious"]}',
                     '[1, 2, 3]', '"malicious"', 'no json here at all', '{"verdict": "malicious"'):
            a, got = self.ask(text)
            self.assertIsNone(got, text)
            self.assertIn('last_error', a.get_health()['p'], text)

    def test_a_valid_answer_is_still_counted_whatever_its_case(self):
        a, got = self.ask('Sure! {"verdict": " Malicious ", "confidence": 80}')
        self.assertEqual(got['verdict'], ' Malicious ')
        self.assertIsNone(a.get_health()['p'].get('last_error'))

    def test_a_huge_answer_is_refused_before_it_is_parsed(self):
        a, got = self.ask('{"verdict": "malicious", "pad": "' + 'a' * (swarm._MAX_ANSWER_CHARS + 10) + '"}')
        self.assertIsNone(got)
        self.assertIn('refused', a.get_health()['p']['last_error_msg'])

    def test_two_broken_providers_cannot_outvote_one_honest_benign(self):
        # Before: a missing verdict was read as "suspicious", so {} + {} + benign gave "suspicious".
        answers = [r for r in ({'ai': 'a'}, {'ai': 'b', 'verdict': 'nonsense'}, vote('c', 'benign')) if swarm.vote_problem(r) is None]
        c = Analyzer._consensus(answers, weights={})
        self.assertEqual(c['consensus_verdict'], 'benign')
        self.assertEqual(c['ai_count'], 1)

    def test_junk_entries_are_dropped_not_fatal(self):
        c = Analyzer._consensus([None, 'x', 3, vote('a', 'malicious'), vote('b', 'malicious'), vote('c', 'benign')], weights={})
        self.assertEqual((c['consensus_verdict'], c['ai_count']), ('malicious', 3))
        with self.assertRaises(ValueError):
            Analyzer._consensus([None, {}, 'x'], weights={})


class OneProviderCannotDecideAlone(unittest.TestCase):
    def test_a_lone_confident_alarmist_does_not_set_verdict_severity_or_confidence(self):
        results = [vote('rogue', 'malicious', 100, 'CRITICAL')] + [vote(n, 'benign', 90, 'LOW') for n in 'abc']
        c = Analyzer._consensus(results, weights={})
        self.assertEqual((c['consensus_verdict'], c['consensus_severity']), ('benign', 'LOW'))
        self.assertLessEqual(c['confidence'], 90)

    def test_a_lone_provider_cannot_whitewash_a_threat_the_rest_agree_is_malicious(self):
        results = [vote('rogue', 'benign', 100, 'LOW')] + [vote(n, 'malicious', 85, 'HIGH') for n in 'abc']
        c = Analyzer._consensus(results, weights={})
        self.assertEqual((c['consensus_verdict'], c['consensus_severity']), ('malicious', 'HIGH'))

    def test_a_provider_claiming_to_be_another_does_not_take_its_weight(self):
        # analyze() overwrites the provider's own "ai" field with the name it called, so a reply that says "ai": "groq" is
        # still weighed as the provider it really came from. Weights here: groq counts 5, the rogue 0.
        a = analyzer()
        got = a._safe_call(Fake('rogue', '{"verdict": "malicious", "ai": "groq", "confidence": 100}'), '{}')
        got['ai'] = 'rogue'                                  # what analyze() does with every answer
        c = Analyzer._consensus([got, vote('groq', 'benign'), vote('x', 'benign')], weights={'groq': 5.0, 'rogue': 0.0, 'x': 1.0})
        self.assertEqual(c['consensus_verdict'], 'benign')

    def test_absurd_confidence_and_severity_values_are_clamped(self):
        c = Analyzer._consensus([{'ai': 'a', 'verdict': 'malicious', 'confidence': 10 ** 9, 'severity': 'GOD MODE'},
                                 {'ai': 'b', 'verdict': 'malicious', 'confidence': 'lots', 'severity': None}], weights={})
        self.assertTrue(0 <= c['confidence'] <= 100)
        self.assertIn(c['consensus_severity'], ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'))


class CompromisedNode(unittest.TestCase):
    """A node holding a valid token can submit findings as itself. It cannot set what only the hub's AI or an admin sets."""

    @classmethod
    def setUpClass(cls):
        import app as appmod
        if _TMP not in appmod.app.config['SQLALCHEMY_DATABASE_URI']:
            raise RuntimeError('refusing to run against a non-test database')
        cls.appmod, cls.app, cls.db = appmod, appmod.app, appmod.db
        cls.app.config['TESTING'] = True
        appmod._AUDIT_PATH = os.path.join(_TMP, 'audit.jsonl')

    def setUp(self):
        import auth
        from models import Node, Threat
        self.auth, self.Node, self.Threat = auth, Node, Threat
        self.ctx = self.app.app_context()
        self.ctx.push()
        self.db.create_all()
        Threat.query.delete()
        Node.query.delete()
        self.token = auth.new_token()
        self.db.session.add(Node(node_id='box1', hostname='box1', status='active', token_hash=auth.hash_secret(self.token),
                                 registered=datetime.now(timezone.utc)))
        self.db.session.commit()
        auth.node_ingest = auth.SlidingWindow(10000, 60)
        self.c = self.app.test_client()

    def tearDown(self):
        self.db.session.remove()
        self.ctx.pop()

    def submit(self, **extra):
        body = {'url': '8.8.8.8:4444', 'type': 'c2-beacon', 'severity': 'high', 'description': 'd', 'detected_by': 'ProcessMonitorAgent'}
        body.update(extra)
        return self.c.post('/api/threats/', json=body, headers={'X-API-Key': self.token})

    def test_a_node_cannot_plant_an_ai_verdict_a_status_or_an_id(self):
        r = self.submit(ai_verdict='{"consensus": {"consensus_verdict": "malicious", "confidence": 100}}', ai_analyzed=True,
                        status='resolved', id=1, alert_count=9999, node_id='box2', first_seen='2001-01-01T00:00:00')
        self.assertEqual(r.status_code, 201, r.get_data(as_text=True))
        row = self.Threat.query.one()
        self.assertFalse(row.ai_analyzed)
        self.assertIsNone(row.ai_verdict)
        self.assertNotEqual(row.status, 'resolved')
        self.assertEqual(row.node_id, 'box1')
        self.assertLess(row.to_dict().get('alert_count') or 1, 100)

    def test_a_node_cannot_touch_what_decides_or_acts_on_a_finding(self):
        a = self.submit().get_json() or {}
        tid = a.get('id') or self.Threat.query.one().id
        h = {'X-API-Key': self.token}
        for method, path in (('put', f'/api/threats/{tid}'), ('post', f'/api/threats/{tid}/resolve'), ('post', f'/api/threats/{tid}/dismiss'),
                             ('post', f'/api/threats/{tid}/block'), ('post', '/api/allowlist'), ('delete', '/api/allowlist/1'),
                             ('post', '/api/remediation/1/approve'), ('post', '/api/remediation/sweep'), ('post', '/api/setup/enable'),
                             ('post', '/api/settings/agents'), ('post', '/api/nodes/box1/revoke'), ('post', '/api/nodes/enrollment-codes')):
            r = getattr(self.c, method)(path, headers=h, json={})
            self.assertIn(r.status_code, (401, 403), f'{method} {path} answered {r.status_code} to a node token')

    def test_a_flood_from_one_node_is_limited_and_does_not_starve_another(self):
        self.auth.node_ingest = self.auth.SlidingWindow(5, 60)
        other = self.auth.new_token()
        self.db.session.add(self.Node(node_id='box2', hostname='box2', status='active', token_hash=self.auth.hash_secret(other),
                                      registered=datetime.now(timezone.utc)))
        self.db.session.commit()
        codes = [self.submit(url=f'8.8.8.{i}:1').status_code for i in range(12)]
        self.assertIn(429, codes)
        ok = self.c.post('/api/threats/', json={'url': '1.1.1.1:2', 'type': 'c2-beacon', 'severity': 'low', 'description': 'd',
                                                'detected_by': 'x'}, headers={'X-API-Key': other})
        self.assertEqual(ok.status_code, 201)

    def test_a_revoked_node_loses_access_at_once(self):
        self.assertEqual(self.submit().status_code, 201)
        r = self.c.post('/api/nodes/box1/revoke', headers={'X-API-Key': ADMIN})
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        self.assertEqual(self.submit(url='8.8.4.4:9').status_code, 401)


if __name__ == '__main__':
    unittest.main(verbosity=2)
