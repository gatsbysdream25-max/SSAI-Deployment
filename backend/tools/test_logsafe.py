#!/usr/bin/env python3
"""C5: log files are not world-readable, audit files rotate by size, nothing is lost or rewritten.
Run:  swarmsentinel-env/bin/python3 backend/tools/test_logsafe.py"""
import json
import logging
import os
import stat
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
sys.path[:0] = [os.path.join(BACKEND, 'agents'), BACKEND]

import logsafe  # noqa: E402
import remediation  # noqa: E402

POSIX = os.name == 'posix'


class Logs(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()

    @unittest.skipUnless(POSIX, 'file modes are POSIX')
    def test_a_new_log_is_not_world_readable(self):
        path = os.path.join(self.d, 'a.log')
        old = os.umask(0)                      # worst case: a permissive umask
        try:
            h = logsafe.SecureRotatingFileHandler(path, maxBytes=1000, backupCount=2)
        finally:
            os.umask(old)
        lg = logging.getLogger('logsafe-test')
        lg.addHandler(h)
        lg.warning('hello')
        h.close()
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode) & 0o007, 0)

    @unittest.skipUnless(POSIX, 'file modes are POSIX')
    def test_an_old_world_readable_log_is_tightened_when_opened(self):
        path = os.path.join(self.d, 'old.log')
        open(path, 'w').write('x\n')
        os.chmod(path, 0o644)
        logsafe.SecureRotatingFileHandler(path).close()
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode) & 0o007, 0)


class Audit(unittest.TestCase):
    def setUp(self):
        self.p = os.path.join(tempfile.mkdtemp(), 'sub', 'audit.jsonl')

    def lines(self, path):
        with open(path, encoding='utf-8') as f:
            return [json.loads(x) for x in f]

    def test_small_files_are_appended_not_rotated(self):
        for i in range(3):
            logsafe.append_line(self.p, json.dumps({'i': i}))
        self.assertEqual([x['i'] for x in self.lines(self.p)], [0, 1, 2])
        self.assertFalse(os.path.exists(self.p + '.1'))

    def test_a_big_file_rotates_and_keeps_only_the_newest_copies(self):
        with mock.patch.dict(os.environ, {'SSAI_AUDIT_KEEP': '3'}):
            for i in range(30):
                logsafe.append_line(self.p, json.dumps({'i': i, 'pad': 'x' * 200}))
                logsafe.rotate_if_big(self.p, max_bytes=1500)
        names = sorted(os.listdir(os.path.dirname(self.p)))
        self.assertIn('audit.jsonl.1', names)
        self.assertNotIn('audit.jsonl.4', names)            # keep=3 -> .1 .2 .3 at most
        got = [x['i'] for n in names for x in self.lines(os.path.join(os.path.dirname(self.p), n))]
        self.assertEqual(max(got), 29)                       # the newest entries are never the ones dropped
        self.assertEqual(len(got), len(set(got)))            # and nothing is written twice

    def test_the_remediation_audit_rotates_and_never_raises(self):
        with mock.patch.dict(os.environ, {'SSAI_AUDIT_MAX_MB': '1'}):
            os.makedirs(os.path.dirname(self.p))
            with open(self.p, 'w') as f:
                f.write('y' * (1024 * 1024 + 10))
            remediation.audit(self.p, action='test', ok=True)
        self.assertTrue(os.path.exists(self.p + '.1'))
        self.assertEqual(self.lines(self.p)[0]['action'], 'test')
        remediation.audit(os.path.join(self.p, 'x', 'audit.jsonl'), action='x')       # a file where a folder should be: no exception

    def test_bad_settings_fall_back_to_defaults(self):
        with mock.patch.dict(os.environ, {'SSAI_AUDIT_MAX_MB': 'lots', 'SSAI_AUDIT_KEEP': ''}):
            self.assertFalse(logsafe.rotate_if_big(self.p))


if __name__ == '__main__':
    unittest.main(verbosity=2)
