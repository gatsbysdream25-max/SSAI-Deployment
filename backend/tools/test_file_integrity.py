#!/usr/bin/env python3
"""HostHealthAgent file integrity: SHA-256 content hashes in the baseline (2026-11-15 sync).
Run:  swarmsentinel-env/bin/python3 backend/tools/test_file_integrity.py"""
import json
import logging
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(os.path.dirname(HERE), 'agents'), os.path.dirname(HERE)]
import agent_runner as R  # noqa: E402


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.f = os.path.join(self.dir, 'sshd_config')
        with open(self.f, 'w') as fh:
            fh.write('PermitRootLogin no\nPasswordAuthentication no\n')
        self.baseline = os.path.join(self.dir, 'baseline.json')

    def agent(self, paths=None):
        a = R.HostHealthAgent.__new__(R.HostHealthAgent)
        a.log = logging.getLogger('test-file-integrity')
        a.sent = []
        a._submit = lambda **k: a.sent.append(k)
        a.WATCH_PATHS = paths or [self.f]
        a.BASELINE_PATH = self.baseline
        a.EVIDENCE_LOGS = ()
        a.setup()
        return a

    def rewrite(self, text, keep_time=False):
        st = os.stat(self.f)
        with open(self.f, 'w') as fh:
            fh.write(text)
        if keep_time:
            os.utime(self.f, ns=(st.st_atime_ns, st.st_mtime_ns))

    def bump_time(self):
        st = os.stat(self.f)
        os.utime(self.f, ns=(st.st_atime_ns, st.st_mtime_ns + 5_000_000_000))


class ContentHashes(Base):
    def test_edit_with_size_and_timestamp_restored_is_a_high_alert(self):
        a = self.agent()
        self.rewrite('PermitRootLogin no\nPasswordAuthentication ok\n', keep_time=True)   # same length, time put back
        a._check_files()
        self.assertEqual(len(a.sent), 1)
        self.assertEqual(a.sent[0]['severity'], 'high')
        self.assertIn('Contents', a.sent[0]['description'])
        self.assertIn('restored', a.sent[0]['description'])

    def test_touch_is_silent(self):
        a = self.agent()
        self.bump_time()
        a._check_files()
        self.assertEqual(a.sent, [])

    def test_identical_rewrite_is_silent(self):
        a = self.agent()
        tmp = self.f + '.new'
        with open(self.f) as src, open(tmp, 'w') as dst:
            dst.write(src.read())
        os.replace(tmp, self.f)                                     # new inode, same bytes (what editors and installers do)
        self.bump_time()
        a._check_files()
        self.assertEqual(a.sent, [])

    def test_ordinary_edit_is_reported(self):
        a = self.agent()
        self.rewrite('PermitRootLogin yes\nPasswordAuthentication yes\nPort 2222\n')
        self.bump_time()
        a._check_files()
        self.assertEqual(len(a.sent), 1)
        self.assertEqual(a.sent[0]['severity'], 'medium')
        self.assertIn('Contents of', a.sent[0]['description'])

    def test_mode_change_always_alerts(self):
        a = self.agent()
        os.chmod(self.f, 0o666)
        a._check_files()
        self.assertEqual(len(a.sent), 1)
        self.assertEqual(a.sent[0]['severity'], 'high')
        self.assertIn('mode', a.sent[0]['description'])

    def test_baseline_saves_hashes_and_survives_a_restart(self):
        self.agent()
        with open(self.baseline) as fh:
            saved = json.load(fh)
        self.assertIn(self.f, saved['hashes'])
        self.rewrite('PermitRootLogin no\nPasswordAuthentication ok\n', keep_time=True)
        b = self.agent()                                           # a restart: the baseline comes from disk
        b._check_files()
        self.assertEqual(len(b.sent), 1)
        self.assertIn('while the agent was not running', b.sent[0]['description'])


class OldBaseline(Base):
    def test_baseline_from_before_hashes_still_alerts_on_metadata_change(self):
        st = os.stat(self.f)
        with open(self.baseline, 'w') as fh:                       # the 6-field format, no 'hashes' key
            json.dump({'sigs': {self.f: [st.st_mtime_ns, st.st_size, st.st_ino, st.st_mode, st.st_uid, st.st_gid]},
                       'gone': []}, fh)
        a = self.agent()
        self.bump_time()
        a._check_files()
        self.assertEqual(len(a.sent), 1)
        self.assertIn('mtime', a.sent[0]['description'])
        a.sent.clear()
        self.bump_time()                                            # the hash is stored now: a second touch is silent
        a._check_files()
        self.assertEqual(a.sent, [])


class AccountFiles(Base):
    def test_harmless_account_change_is_not_reported(self):
        a = self.agent()
        with mock.patch.object(R.change_evidence, 'ACCOUNT_FILES', (self.f,)), \
             mock.patch.object(R.change_evidence, 'assess', return_value={'harmless': True, 'reason': 'package run', 'changes': ['added svc']}):
            self.rewrite('PermitRootLogin no\nPasswordAuthentication no\nextra\n')
            self.bump_time()
            a._check_files()
        self.assertEqual(a.sent, [])

    def test_unexplained_account_change_is_reported_with_the_reason(self):
        a = self.agent()
        with mock.patch.object(R.change_evidence, 'ACCOUNT_FILES', (self.f,)), \
             mock.patch.object(R.change_evidence, 'assess', return_value={'harmless': False, 'reason': 'the password of alice was changed', 'changes': ['password-changed alice']}):
            self.rewrite('PermitRootLogin no\nPasswordAuthentication no\nextra\n')
            self.bump_time()
            a._check_files()
        self.assertEqual(len(a.sent), 1)
        self.assertIn('password of alice', a.sent[0]['description'])

    def test_mode_change_on_an_account_file_is_never_excused(self):
        a = self.agent()
        with mock.patch.object(R.change_evidence, 'ACCOUNT_FILES', (self.f,)), \
             mock.patch.object(R.change_evidence, 'assess', return_value={'harmless': True, 'reason': 'x', 'changes': []}):
            os.chmod(self.f, 0o666)
            a._check_files()
        self.assertEqual(len(a.sent), 1)
        self.assertEqual(a.sent[0]['severity'], 'high')


if __name__ == '__main__':
    unittest.main()
