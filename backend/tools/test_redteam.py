#!/usr/bin/env python3
"""Tests for the built-in red team (2026-10-09): the probes pass on the real code, FAIL when a protection is broken
(so they are not decorative), and the agent alerts once per new failure.
Run:  swarmsentinel-env/bin/python3 backend/tools/test_redteam.py"""
import logging
import os
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(os.path.dirname(HERE), 'agents'), os.path.dirname(HERE)]
os.environ.setdefault('SSAI_PROVIDER_CHECK', '0')
import redteam as RT  # noqa: E402
import sanitizer  # noqa: E402
import state_store as S  # noqa: E402


def result(name):
    return RT.run_all(only=[name])[0]


class ProbesPassOnTheRealCode(unittest.TestCase):
    def test_every_probe_passes(self):
        logging.disable(logging.CRITICAL)
        try:
            res = RT.run_all()
        finally:
            logging.disable(logging.NOTSET)
        self.assertGreaterEqual(len(res), 13)
        self.assertEqual({r['category'] for r in res}, {'leakage', 'consensus', 'injection', 'agency'})
        bad = [f"{r['probe']}: {r['detail']}" for r in res if r['status'] != RT.PASS]
        self.assertEqual(bad, [])

    def test_probes_leave_the_real_cloud_audit_log_alone(self):
        d = tempfile.mkdtemp()
        real = os.path.join(d, 'cloud_audit.jsonl')
        with mock.patch.object(sanitizer, 'audit_path', return_value=real):
            logging.disable(logging.CRITICAL)
            try:
                RT.run_all()
            finally:
                logging.disable(logging.NOTSET)
        self.assertFalse(os.path.exists(real))


class ProbesCatchBreakage(unittest.TestCase):
    """Mutation checks: weaken one protection, the matching probe must fail."""

    def setUp(self):
        logging.disable(logging.CRITICAL)
        self.addCleanup(logging.disable, logging.NOTSET)

    def test_a_gate_that_stops_redacting_is_caught(self):
        with mock.patch.object(sanitizer.Redactor, 'redact', lambda self, t: str(t)), \
             mock.patch.object(sanitizer.Redactor, 'leftovers', staticmethod(lambda t: False)):
            self.assertEqual(result('cloud-gate-redacts-internal-data')['status'], RT.FAIL)
            self.assertEqual(result('panel-cloud-copy-is-sanitized')['status'], RT.FAIL)

    def test_widening_the_allow_list_is_caught(self):
        orig = sanitizer.sanitize_for_cloud

        def leaky(payload, **kw):
            out = orig(payload, **kw)
            if 'hostname' in payload:
                out['hostname'] = payload['hostname']
            return out
        with mock.patch.object(sanitizer, 'ALLOWED_FIELDS', sanitizer.ALLOWED_FIELDS + ('hostname',)), \
             mock.patch.object(sanitizer, 'sanitize_for_cloud', leaky):
            r = result('cloud-gate-drops-unlisted-fields')
        self.assertEqual(r['status'], RT.FAIL)

    def test_one_voice_deciding_is_caught(self):
        import ai_swarm_agent as asa
        with mock.patch.object(asa.AiSwarmAnalyzer, '_consensus',
                               staticmethod(lambda results, weights=None, panel=None: {
                                   'consensus_verdict': 'malicious', 'confidence': 100, 'votes': {},
                                   'recommended_action': results[0].get('recommended_action', '')})):
            self.assertEqual(result('one-spoofed-voice-cannot-decide')['status'], RT.FAIL)

    def test_single_ai_block_proposals_are_caught(self):
        import remediation_queue
        with mock.patch.object(remediation_queue, 'MIN_AI_COUNT', 1):
            self.assertEqual(result('single-voice-cannot-propose-a-block')['status'], RT.FAIL)

    def test_internal_targets_are_caught(self):
        import remediation_queue
        with mock.patch.object(remediation_queue, 'internal_address', lambda v: False):
            self.assertEqual(result('ai-cannot-target-internal-addresses')['status'], RT.FAIL)

    def test_an_agent_that_blocks_by_itself_is_caught(self):
        d = tempfile.mkdtemp()
        os.makedirs(os.path.join(d, 'agents'))
        with open(os.path.join(d, 'agents', 'agent_runner.py'), 'w') as f:
            f.write("import subprocess\nclass A:\n    def scan(self):\n        subprocess.run(['/usr/sbin/ufw', 'deny', 'from', 'x'])\n")
        with mock.patch.object(RT, '_BACKEND', d):
            self.assertEqual(result('agents-cannot-act-on-their-own')['status'], RT.FAIL)

    def test_a_crashing_probe_is_a_failure(self):
        with mock.patch.object(RT, 'PROBES', [('boom', 'agency', lambda: 1 / 0)]):
            r = RT.run_all()[0]
        self.assertEqual((r['status'], r['detail'][:13]), (RT.FAIL, 'probe crashed'))


class AuditLog(unittest.TestCase):
    def test_append_only_readable_newest_first(self):
        p = os.path.join(tempfile.mkdtemp(), 'rt.jsonl')
        RT.write_audit({'n': 1}, p)
        RT.write_audit({'n': 2}, p)
        self.assertEqual([r['n'] for r in RT.read_audit(10, p)], [2, 1])
        self.assertEqual(os.stat(p).st_mode & 0o777, 0o644)
        self.assertEqual(RT.read_audit(10, p + '.missing'), [])


class Agent(unittest.TestCase):
    def setUp(self):
        import agent_runner as AR
        self.AR = AR
        self.dir = tempfile.mkdtemp()
        self._store = S._STORE
        S._STORE = S.StateStore(os.path.join(self.dir, 'state.db'))
        self.addCleanup(setattr, S, '_STORE', self._store)
        self.submitted = []
        p = mock.patch.object(AR, 'submit_threat', lambda *a, **k: self.submitted.append(k))
        p.start()
        self.addCleanup(p.stop)
        p = mock.patch.object(RT, 'audit_path', return_value=os.path.join(self.dir, 'rt.jsonl'))
        p.start()
        self.addCleanup(p.stop)
        self.agent = AR.RedTeamAgent()

    def run_with(self, status):
        with mock.patch.object(RT, 'run_all', return_value=[
                {'probe': 'p1', 'category': 'leakage', 'status': status, 'detail': 'x', 'ts': '', 'ms': 0}]):
            self.agent.scan()

    def test_alerts_once_per_new_failure_and_again_after_a_fix_breaks(self):
        self.run_with(RT.FAIL)
        self.run_with(RT.FAIL)
        self.assertEqual(len(self.submitted), 1)
        self.assertEqual(self.submitted[0]['threat_type'], 'redteam-probe-failed')
        self.assertEqual(self.submitted[0]['severity'], 'high')
        self.run_with(RT.PASS)
        self.run_with(RT.FAIL)
        self.assertEqual(len(self.submitted), 2)
        self.assertEqual(len(RT.read_audit(10)), 4)

    def test_is_in_the_catalog_and_hub_only(self):
        import agent_catalog
        self.assertIn('RedTeamAgent', agent_catalog.CATALOG)
        self.assertIn('RedTeamAgent', agent_catalog.HUB_ONLY)
        self.assertTrue(agent_catalog.CATALOG['RedTeamAgent']['default_on'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
