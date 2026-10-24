#!/usr/bin/env python3
"""Recall wiring: the consensus agent reuses verdicts, and GET /api/threats/recall serves them (2026-09-19).
Run:  swarmsentinel-env/bin/python3 backend/tools/test_recall_integration.py"""
import json
import logging
import os
import sys
import tempfile
import time
import unittest
from datetime import datetime, timezone

# SAFETY: point every import of ssai_config/app at a throwaway database BEFORE anything imports them. These tests
# delete rows, so they must never see the real swarmsentinel.db.
_TMP = tempfile.mkdtemp()
os.environ['DATABASE_URL'] = f'sqlite:///{_TMP}/recall-test.db'
os.environ.setdefault('SSAI_API_KEY', 'k')

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
sys.path[:0] = [os.path.join(BACKEND, 'agents'), BACKEND]
import agent_runner as AR  # noqa: E402
import recall as R  # noqa: E402


def cons(verdict='malicious', **extra):
    return dict({'consensus_verdict': verdict, 'consensus_severity': 'HIGH', 'ai_count': 1}, **extra)


class FakeResp:
    def __init__(self, body, status=200):
        self._b, self.status_code = body, status

    def json(self):
        if isinstance(self._b, Exception):
            raise self._b
        return self._b


class FakeSession:
    def __init__(self, routes):
        self.routes, self.calls = routes, []

    def get(self, url, params=None, timeout=None, headers=None):
        self.calls.append((url, params))
        v = self.routes.get(url.rsplit('/', 1)[-1])
        if isinstance(v, Exception):
            raise v
        return v


def make_agent():
    agent = AR.SwarmConsensusAgent.__new__(AR.SwarmConsensusAgent)
    agent.log = logging.getLogger('test-swarm')
    agent.recall = R.RecallCache()
    return agent


class AgentReuse(unittest.TestCase):
    def setUp(self):
        self._session = AR.SESSION

    def tearDown(self):
        AR.SESSION = self._session

    def test_memory_hit_makes_no_api_call(self):
        AR.SESSION = FakeSession({})
        a = make_agent()
        a.recall.put('http://evil.example.com/x', 'malware-url', cons(), 3)
        got = a._recalled({'id': 9, 'url': 'http://evil.example.com/x', 'type': 'malware-url'})
        self.assertEqual((got['consensus_verdict'], got['recalled_from']), ('malicious', 3))
        self.assertEqual(AR.SESSION.calls, [])

    def test_database_hit_is_remembered_for_next_time(self):
        body = {'found': True, 'consensus': cons(), 'threat_id': 4, 'timestamp': datetime.now(timezone.utc).isoformat()}
        AR.SESSION = FakeSession({'recall': FakeResp(body)})
        a = make_agent()
        t = {'id': 9, 'url': 'http://evil.example.com/x', 'type': 'malware-url'}
        self.assertEqual(a._recalled(t)['recalled_from'], 4)
        self.assertEqual(a._recalled(t)['recalled_from'], 4)
        self.assertEqual(len(AR.SESSION.calls), 1)                       # second time came from memory

    def test_miss_and_failures_fall_through_to_the_panel(self):
        import requests
        t = {'id': 9, 'url': 'http://new.example.com/x', 'type': 'malware-url'}
        for routes in ({'recall': FakeResp({'found': False})}, {'recall': FakeResp({}, 500)},
                       {'recall': FakeResp(ValueError('bad json'))}, {'recall': requests.exceptions.ConnectionError('down')}):
            AR.SESSION = FakeSession(routes)
            self.assertIsNone(make_agent()._recalled(t), routes)

    def test_masked_indicator_never_touches_the_api(self):
        AR.SESSION = FakeSession({'recall': FakeResp({'found': True, 'consensus': cons(), 'threat_id': 1})})
        self.assertIsNone(make_agent()._recalled({'id': 1, 'url': '192.168.xxx.xxx:6667', 'type': 'suspicious-port'}))
        self.assertEqual(AR.SESSION.calls, [])

    def test_seed_warms_the_cache_and_survives_an_outage(self):
        rows = [{'id': 1, 'url': 'http://evil.example.com/x', 'type': 'u', 'timestamp': datetime.now(timezone.utc).isoformat(),
                 'ai_verdict': json.dumps({'consensus': cons()})}]
        AR.SESSION = FakeSession({'recall': FakeResp(rows)})
        a = make_agent()
        a._seed_recall()
        self.assertEqual(len(a.recall), 1)
        AR.SESSION = FakeSession({'recall': ValueError('x')})
        make_agent()._seed_recall()                                       # must not raise

    def test_a_recalled_copy_is_not_reusable_evidence(self):
        self.assertFalse(R.reusable_consensus(cons(recalled_from=3)))
        a = make_agent()
        self.assertFalse(a.recall.put('http://evil.example.com/x', 'u', cons(recalled_from=3), 5))


class Endpoint(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            import app as appmod
        except Exception as e:  # noqa: BLE001
            raise unittest.SkipTest(f'app not importable here: {e}')
        uri = appmod.app.config['SQLALCHEMY_DATABASE_URI']
        if _TMP not in uri:                                   # never delete rows from anything but the throwaway DB
            raise RuntimeError(f'refusing to run: app is using {uri}, not the test database')
        cls.app, cls.db = appmod.app, appmod.db
        from models import Threat
        cls.Threat = Threat
        cls.app.config['TESTING'] = True

    def setUp(self):
        self.ctx = self.app.app_context()
        self.ctx.push()
        self.db.create_all()
        self.Threat.query.delete()
        self.db.session.commit()

    def tearDown(self):
        self.db.session.remove()
        self.ctx.pop()

    def add(self, url, typ, verdict, age_s=60):
        ts = datetime.fromtimestamp(time.time() - age_s, timezone.utc).replace(tzinfo=None)
        t = self.Threat(url=url, type=typ, severity='high', description='d', detected_by='t', timestamp=ts,
                        ai_analyzed=True, ai_verdict=json.dumps({'consensus': verdict}) if verdict else None)
        self.db.session.add(t)
        self.db.session.commit()
        return t.id

    def get(self, **params):
        return self.app.test_client().get('/api/threats/recall', query_string=params, headers={'X-API-Key': os.environ['SSAI_API_KEY']}).get_json()

    def test_public_indicator_is_found_regardless_of_category(self):
        tid = self.add('http://evil.example.com/a.sh', 'malware-url', cons())
        body = self.get(url='http://evil.example.com/a.sh', category='something-else')
        self.assertTrue(body['found'])
        self.assertEqual(body['threat_id'], tid)
        self.assertEqual(body['consensus']['consensus_verdict'], 'malicious')

    def test_scoped_indicators_need_the_same_category(self):
        self.add('10.0.0.5:22', 'suspicious-port', cons('suspicious'))
        self.assertTrue(self.get(url='10.0.0.5:22', category='suspicious-port')['found'])
        self.assertFalse(self.get(url='10.0.0.5:22', category='dns-anomaly')['found'])

    def test_expired_recalled_masked_and_own_rows_are_not_returned(self):
        self.add('http://old.example.com/', 'u', cons('benign'), age_s=R.ttl_seconds('benign') + 60)
        self.add('http://copy.example.com/', 'u', cons(recalled_from=1))
        self.add('192.168.xxx.xxx', 'u', cons())
        own = self.add('http://own.example.com/', 'u', cons())
        for u in ('http://old.example.com/', 'http://copy.example.com/', '192.168.xxx.xxx'):
            self.assertFalse(self.get(url=u, category='u')['found'], u)
        self.assertFalse(self.get(url='http://own.example.com/', category='u', exclude_id=str(own))['found'])
        self.assertTrue(self.get(url='http://own.example.com/', category='u')['found'])

    def test_no_url_lists_recent_consensus_rows_only(self):
        self.add('http://a.example.com/', 'u', cons())
        self.add('http://b.example.com/', 'u', None)
        self.assertEqual([r['url'] for r in self.get()], ['http://a.example.com/'])
        self.assertEqual(self.get(limit='junk')[0]['url'], 'http://a.example.com/')

    def test_bad_input_is_handled(self):
        self.assertFalse(self.get(url='x' * 3000, category='u')['found'])
        self.assertFalse(self.get(url='http://a.example.com/', exclude_id='abc')['found'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
