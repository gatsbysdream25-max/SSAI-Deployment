#!/usr/bin/env python3
"""Sandbox tooling (2026-10-09): the drills refuse a non-sandbox install, recognise their own findings only, and the
interval scale is bounded; the release package builder leaves out what customers must not get.
Run:  swarmsentinel-env/bin/python3 backend/tools/test_sandbox.py"""
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

_TMP = tempfile.mkdtemp()
os.environ['DATA_DIR'] = _TMP
os.environ['SSAI_STATE_DB'] = os.path.join(_TMP, 'state.db')
HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
REPO = os.path.dirname(BACKEND)
sys.path[:0] = [os.path.join(BACKEND, 'agents'), BACKEND, HERE]
import sandbox_drills as SD  # noqa: E402


class Guard(unittest.TestCase):
    def test_refuses_without_the_sandbox_flag(self):
        with mock.patch.object(SD, 'env_file', return_value={}), mock.patch.dict(os.environ, {'SSAI_SANDBOX': ''}):
            self.assertEqual(SD.main([]), 2)

    def test_refuses_when_not_root(self):
        with mock.patch.object(SD, 'env_file', return_value={'SSAI_SANDBOX': '1'}), \
             mock.patch.object(SD.os, 'geteuid', return_value=1000):
            self.assertEqual(SD.main([]), 2)


class Matching(unittest.TestCase):
    def test_each_drill_recognises_only_its_own_finding(self):
        bf, br = SD.BruteForce(), SD.BreakIn()
        self.assertTrue(bf.match({'type': 'brute-force', 'url': bf.ip}))
        self.assertFalse(bf.match({'type': 'brute-force', 'url': '203.0.113.1' if bf.ip != '203.0.113.1' else '203.0.113.2'}))
        self.assertFalse(bf.match({'type': 'ssh-login', 'url': bf.ip}))
        self.assertTrue(br.match({'type': 'intrusion-attempt', 'url': br.ip}))
        slow = SD.SlowBruteForce()
        self.assertFalse(slow.expect)
        self.assertTrue(slow.match({'type': 'brute-force', 'url': slow.ips[3]}))
        self.assertTrue(slow.match({'type': 'distributed-brute-force', 'url': 'ssh://distributed', 'description': 'older run'}))
        self.assertTrue(SD.Backdoor().match({'type': 'unexpected-listener', 'url': 'localhost:4444'}))
        self.assertTrue(SD.FileTamper().match({'type': 'file-modification', 'url': '/etc/ssh/sshd_config'}))

    def test_addresses_are_documentation_ranges(self):
        for _ in range(20):
            self.assertTrue(SD.BruteForce().ip.startswith('203.0.113.'))
            self.assertTrue(all(ip.startswith('198.51.100.') for ip in SD.SlowBruteForce().ips))


class DistributedBruteForce(unittest.TestCase):
    """The gap the first sandbox run found: many addresses, each under the per-address threshold."""

    def agent(self):
        import agent_runner as AR
        a = AR.AuthLogAgent.__new__(AR.AuthLogAgent)
        a._recent_fails, a._last_spread_alert, a.sent = AR.deque(), float('-inf'), []
        a._submit = lambda **k: a.sent.append(k)
        return a

    def test_spread_attack_is_reported_once(self):
        a = self.agent()
        t = 1000.0
        for ip in [f'198.51.100.{i}' for i in range(6)]:
            for _ in range(4):
                t += 1
                a._note_spread(ip, now=t)
        self.assertEqual(len(a.sent), 1)
        self.assertEqual(a.sent[0]['threat_type'], 'distributed-brute-force')
        for _ in range(30):                                        # still going: no second alert within the cooldown
            t += 1
            a._note_spread('198.51.100.99', now=t)
        self.assertEqual(len(a.sent), 1)

    def test_one_noisy_address_or_slow_trickle_is_not_distributed(self):
        a = self.agent()
        for i in range(30):
            a._note_spread('203.0.113.5', now=1000.0 + i)               # one address: the per-address rule's job
        b = self.agent()
        for i in range(30):
            b._note_spread(f'198.51.100.{i % 6}', now=1000.0 + i * 60)  # 30 failures over 30 minutes: under the rate
        self.assertEqual((a.sent, b.sent), ([], []))


class IntervalScale(unittest.TestCase):
    def test_bounded(self):
        import agent_runner as AR
        for val, want in (('1', 60), ('0.2', 12), ('0', 5), ('-3', 5), ('junk', 60), ('100', 600)):
            with mock.patch.dict(os.environ, {'SSAI_INTERVAL_SCALE': val}):
                self.assertEqual(AR._scaled(60), want, val)


@unittest.skipUnless(os.path.exists(os.path.join(REPO, '.git')), 'needs a git checkout')
class ReleasePackage(unittest.TestCase):
    def test_package_leaves_out_internal_files(self):
        out = tempfile.mkdtemp()
        r = subprocess.run(['bash', os.path.join(REPO, 'deploy', 'make-release.sh'), '--out', out],
                           capture_output=True, text=True, cwd=REPO)
        self.assertEqual(r.returncode, 0, r.stderr)
        pkg = r.stdout.splitlines()[0]
        with tarfile.open(pkg) as t:
            names = t.getnames()
        self.assertIn('SwarmSentinel/deploy/install.sh', names)
        self.assertIn('SwarmSentinel/VERSION', names)
        for banned in ('Topography', 'threats/known_threats.json', 'docs/plans', 'windows_client_incomplete', '.env'):
            self.assertFalse(any(n.endswith(banned) or f'/{banned}/' in n + '/' for n in names if not n.endswith('.example')), banned)
        self.assertTrue(os.path.exists(pkg + '.sha256'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
