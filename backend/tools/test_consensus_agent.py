#!/usr/bin/env python3
"""SwarmConsensusAgent.scan(): which threats get the AI panel (2026-09-26: it waited for tier-one analyzers that are
off by default, so nothing was judged for a week). Run:  swarmsentinel-env/bin/python3 backend/tools/test_consensus_agent.py"""
import json
import logging
import os
import sys
import unittest
from datetime import timedelta
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(os.path.dirname(HERE), 'agents'), os.path.dirname(HERE)]
import agent_runner as R  # noqa: E402

VERDICT = {'consensus_verdict': 'suspicious', 'ai_count': 2, 'ai_sources': ['groq', 'ollama-hermes3'], 'confidence': 70}


class Resp:
    def __init__(self, body, status=200):
        self._b, self.status_code = body, status

    def json(self):
        return self._b


class Swarm:
    def __init__(self):
        self.seen = []

    _raw_threat_json = staticmethod(lambda event: '{}')

    def analyze(self, event, deadline=None):
        self.seen.append(event.title)
        return dict(VERDICT)


def agent():
    a = R.SwarmConsensusAgent.__new__(R.SwarmConsensusAgent)       # no setup(): no network, no model discovery
    a.log = logging.getLogger('test-consensus')
    a._processed = R._BoundedSet(100)
    a._fail_counts = {}
    a.swarm = Swarm()
    a.recall = mock.Mock()
    a._recalled = lambda threat: None                              # nothing remembered: always ask the panel
    return a


def threat(tid, severity, when, **kw):
    t = {'id': tid, 'severity': severity, 'timestamp': when.isoformat(), 'type': 'suspicious-process',
         'url': f'process://{tid}', 'description': f'threat {tid}', 'detected_by': 'ProcessMonitorAgent',
         'ai_analyzed': False, 'ai_verdict': None}
    t.update(kw)
    return t


class Stale(unittest.TestCase):
    def test_a_panel_that_has_judged_nothing_for_an_hour_is_reported_loudly_but_not_every_cycle(self):
        import time
        a = agent()
        a._last_judged = time.time() - 7200
        with self.assertLogs('test-consensus', 'ERROR') as logs:
            a._check_stale(waiting=3)
        self.assertIn('AI PANEL STALE', logs.output[0])
        with self.assertNoLogs('test-consensus', 'ERROR'):
            a._check_stale(waiting=3)                            # logged once per half hour, not once per cycle
        b = agent()
        with self.assertNoLogs('test-consensus', 'ERROR'):
            b._check_stale(waiting=3)                            # a fresh agent starts its clock now
            b._last_judged = time.time() - 7200
            b._check_stale(waiting=0)                            # nothing waiting is a quiet network, not a stale panel


class Scan(unittest.TestCase):
    def run_scan(self, threats):
        a = agent()
        puts = []
        with mock.patch.object(R.SESSION, 'get', return_value=Resp(threats)), \
             mock.patch.object(R.SESSION, 'put', side_effect=lambda url, **kw: (puts.append((url, kw['json'])), Resp({}))[1]):
            a.scan()
        return a, puts

    def test_an_unanalysed_medium_plus_threat_gets_the_panel_and_is_saved(self):
        later = R.SwarmConsensusAgent.DEPLOY_CUTOFF + timedelta(minutes=1)
        a, puts = self.run_scan([threat(1, 'high', later)])            # no tier-one analysis: still judged
        self.assertEqual(a.swarm.seen, ['threat 1'])
        self.assertEqual(len(puts), 1)
        self.assertTrue(puts[0][0].endswith('/threats/1'))
        self.assertEqual(puts[0][1]['ai_verdict']['consensus']['consensus_verdict'], 'suspicious')

    def test_a_tier_one_verdict_is_kept_beside_the_consensus(self):
        later = R.SwarmConsensusAgent.DEPLOY_CUTOFF + timedelta(minutes=1)
        tier1 = {'analysis': 'looks like a scan', 'model': 'hermes3'}
        a, puts = self.run_scan([threat(2, 'medium', later, ai_analyzed=True, ai_verdict=json.dumps(tier1))])
        self.assertEqual(puts[0][1]['ai_verdict']['analysis'], 'looks like a scan')
        self.assertIn('consensus', puts[0][1]['ai_verdict'])

    def test_low_info_old_and_already_judged_threats_are_left_alone(self):
        later = R.SwarmConsensusAgent.DEPLOY_CUTOFF + timedelta(minutes=1)
        before = R.SwarmConsensusAgent.DEPLOY_CUTOFF - timedelta(minutes=1)
        judged = json.dumps({'consensus': VERDICT})
        a, puts = self.run_scan([threat(3, 'info', later), threat(4, 'low', later), threat(5, 'critical', before),
                                 threat(6, 'high', later, ai_analyzed=True, ai_verdict=judged)])
        self.assertEqual(a.swarm.seen, [])
        self.assertEqual(puts, [])

    def test_at_most_three_per_cycle(self):
        later = R.SwarmConsensusAgent.DEPLOY_CUTOFF + timedelta(minutes=1)
        a, puts = self.run_scan([threat(i, 'high', later) for i in range(10, 16)])
        self.assertEqual(len(a.swarm.seen), 3)


    def test_old_backlog_rows_do_not_raise_the_stale_alarm(self):
        before = R.SwarmConsensusAgent.DEPLOY_CUTOFF - timedelta(minutes=1)
        a = agent()
        a._last_judged = __import__('time').time() - 7200
        with mock.patch.object(R.SESSION, 'get', return_value=Resp([threat(7, 'high', before)])),              self.assertNoLogs('test-consensus', 'ERROR'):
            a.scan()                                             # skipped on purpose, so nothing is "waiting"


if __name__ == '__main__':
    unittest.main(verbosity=2)
