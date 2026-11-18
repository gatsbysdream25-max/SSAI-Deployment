#!/usr/bin/env python3
"""live_checks: read-only direct checks before acting (2026-11-15 sync). Fake readers only: nothing here looks at the real machine.
Documentation addresses only (203.0.113.x, 198.51.100.x).
Run:  swarmsentinel-env/bin/python3 backend/tools/test_live_checks.py"""
import os
import socket
import sys
import unittest
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(os.path.dirname(HERE), 'agents'), os.path.dirname(HERE)]
import live_checks as L  # noqa: E402
import local_evidence  # noqa: E402

NOW = datetime(2026, 11, 15, 12, 0, 0, tzinfo=timezone.utc)
SS_LISTEN = "State Recv-Q Send-Q Local Address:Port Peer Address:Port\nLISTEN 0 1 0.0.0.0:4444 0.0.0.0:*\n"
SS_EST = ("Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"
          "0 0 192.0.2.10:51000 203.0.113.9:3333 users:((\"kworkerd\",pid=900,fd=4))\n")
AUTH = ("2026-11-15T10:00:00+00:00 hub sshd[1]: Failed password for root from 203.0.113.7 port 1 ssh2\n" * 6
        + "2026-11-15T10:05:00+00:00 hub sshd[1]: Accepted password for root from 203.0.113.7 port 1 ssh2\n"
        + "2026-11-10T10:00:00+00:00 hub sshd[1]: Failed password for root from 198.51.100.3 port 1 ssh2\n")


class FakeStore:
    def __init__(self, ips=(), domains=()):
        self.ips, self.domains = set(ips), set(domains)

    def stats(self):
        return {'entries': len(self.ips) + len(self.domains)}

    def match_ip(self, ip, port=None):
        return {'value': ip, 'source': 'feodo'} if ip in self.ips else None

    def match_domain(self, domain):
        return {'value': domain, 'source': 'threatfox'} if domain in self.domains else None


def run(threat, **kw):
    kw.setdefault('read_cmdline', lambda pid: None)
    kw.setdefault('ss', lambda args: '')
    kw.setdefault('read_tail', lambda path, size: AUTH)
    kw.setdefault('store', FakeStore())
    kw.setdefault('now', NOW)
    return L.check(dict({'detected_by': 'X'}, **threat), **kw)


PROC = {'type': 'suspicious-process', 'url': 'process://900',
        'description': 'Suspicious process detected (xmrig): www 900 /tmp/.x/xmrig --donate-level 1'}


class Process(unittest.TestCase):
    def test_still_running_same_command_line(self):
        self.assertEqual(run(PROC, read_cmdline=lambda pid: '/tmp/.x/xmrig --donate-level 1')['result'], L.CONFIRMED)

    def test_gone(self):
        r = run(PROC, read_cmdline=lambda pid: None)
        self.assertEqual(r['result'], L.NOT_CONFIRMED)
        self.assertIn('no longer running', r['detail'])

    def test_pid_reused_by_another_program(self):
        r = run(PROC, read_cmdline=lambda pid: '/usr/sbin/cron -f')
        self.assertEqual(r['result'], L.NOT_CONFIRMED)
        self.assertIn('different program', r['detail'])

    def test_no_pid_in_the_finding(self):
        self.assertEqual(run(dict(PROC, url='process://x'))['result'], L.INCONCLUSIVE)

    def test_command_line_missing_from_the_description(self):
        self.assertEqual(run(dict(PROC, description='odd'), read_cmdline=lambda pid: 'x')['result'], L.INCONCLUSIVE)

    def test_unreadable_proc_is_inconclusive(self):
        def deny(pid):
            raise PermissionError('no')
        self.assertEqual(run(PROC, read_cmdline=deny)['result'], L.INCONCLUSIVE)


class Ports(unittest.TestCase):
    def test_listening(self):
        self.assertEqual(run({'type': 'unexpected-listener', 'url': 'localhost:4444'}, ss=lambda a: SS_LISTEN)['result'], L.CONFIRMED)

    def test_closed(self):
        self.assertEqual(run({'type': 'unexpected-listener', 'url': 'localhost:5555'}, ss=lambda a: SS_LISTEN)['result'], L.NOT_CONFIRMED)

    def test_local_suspicious_port(self):
        self.assertEqual(run({'type': 'suspicious-port', 'url': 'localhost:4444'}, ss=lambda a: SS_LISTEN)['result'], L.CONFIRMED)

    def test_no_port_named(self):
        self.assertEqual(run({'type': 'unexpected-listener', 'url': 'localhost'})['result'], L.INCONCLUSIVE)

    def test_ss_failing_is_inconclusive(self):
        def broken(args):
            raise OSError('ss missing')
        self.assertEqual(run({'type': 'unexpected-listener', 'url': 'localhost:4444'}, ss=broken)['result'], L.INCONCLUSIVE)


class Connections(unittest.TestCase):
    def test_open(self):
        self.assertEqual(run({'type': 'c2-beacon', 'url': '203.0.113.9:3333'}, ss=lambda a: SS_EST)['result'], L.CONFIRMED)

    def test_closed(self):
        self.assertEqual(run({'type': 'c2-beacon', 'url': '203.0.113.9:4444'}, ss=lambda a: SS_EST)['result'], L.NOT_CONFIRMED)

    def test_intel_ip_not_in_feed_falls_back_to_connection(self):
        self.assertEqual(run({'type': 'intel-match', 'url': '203.0.113.9'}, ss=lambda a: SS_EST)['result'], L.CONFIRMED)

    def test_no_address(self):
        self.assertEqual(run({'type': 'c2-beacon', 'url': 'nothing'})['result'], L.INCONCLUSIVE)


class AuthLog(unittest.TestCase):
    def test_recent_failures_from_that_address(self):
        r = run({'type': 'brute-force', 'url': '203.0.113.7'})
        self.assertEqual(r['result'], L.CONFIRMED)
        self.assertIn('6 failed', r['detail'])

    def test_failures_older_than_48_hours_do_not_count(self):
        self.assertEqual(run({'type': 'brute-force', 'url': '198.51.100.3'})['result'], L.NOT_CONFIRMED)

    def test_distributed_uses_all_recent_failures(self):
        self.assertEqual(run({'type': 'distributed-brute-force', 'url': 'ssh://distributed'})['result'], L.CONFIRMED)

    def test_login_after_failures(self):
        self.assertEqual(run({'type': 'brute-force-success', 'url': '203.0.113.7'})['result'], L.CONFIRMED)

    def test_login_after_failures_not_seen(self):
        self.assertEqual(run({'type': 'brute-force-success', 'url': '198.51.100.3'})['result'], L.NOT_CONFIRMED)

    def test_unreadable_auth_log(self):
        self.assertEqual(run({'type': 'brute-force', 'url': '203.0.113.7'}, read_tail=lambda p, s: None)['result'], L.INCONCLUSIVE)

    def test_masked_url_uses_the_stored_real_address(self):
        r = run({'type': 'brute-force', 'url': '192.168.xxx.xxx', 'real_source': '203.0.113.7'})
        self.assertEqual(r['result'], L.CONFIRMED)


class Feeds(unittest.TestCase):
    def test_domain_listed(self):
        store = FakeStore(domains={'evil.example.com'})
        self.assertEqual(run({'type': 'malicious-domain', 'url': 'http://evil.example.com/x'}, store=store)['result'], L.CONFIRMED)

    def test_domain_no_longer_listed(self):
        store = FakeStore(domains={'other.example.com'})
        self.assertEqual(run({'type': 'malicious-domain', 'url': 'evil.example.com'}, store=store)['result'], L.NOT_CONFIRMED)

    def test_ip_listed(self):
        self.assertEqual(run({'type': 'intel-match', 'url': '203.0.113.9'}, store=FakeStore(ips={'203.0.113.9'}))['result'],
                         L.CONFIRMED)

    def test_no_feed_loaded(self):
        self.assertEqual(run({'type': 'malware-url', 'url': 'evil.example.com'}, store=FakeStore())['result'], L.INCONCLUSIVE)


class Scope(unittest.TestCase):
    def test_another_machines_finding_is_inconclusive(self):
        r = run(dict(PROC, detected_by='ProcessMonitorAgent@laptop'), read_cmdline=lambda pid: '/tmp/.x/xmrig --donate-level 1')
        self.assertEqual(r['result'], L.INCONCLUSIVE)
        r = run(dict(PROC, node_id='some-other-node'), read_cmdline=lambda pid: '/tmp/.x/xmrig --donate-level 1')
        self.assertEqual(r['result'], L.INCONCLUSIVE)
        r = run(dict(PROC, node_id=socket.gethostname()), read_cmdline=lambda pid: '/tmp/.x/xmrig --donate-level 1')
        self.assertEqual(r['result'], L.CONFIRMED)

    def test_unknown_kind_is_inconclusive(self):
        self.assertEqual(run({'type': 'disk-full', 'url': 'disk:///'})['result'], L.INCONCLUSIVE)

    def test_never_raises(self):
        for bad in (None, {}, {'type': None}, {'type': 'suspicious-process', 'url': None}, {'type': 'brute-force', 'url': 42}):
            r = L.check(bad, read_tail=lambda p, s: AUTH, ss=lambda a: '', read_cmdline=lambda pid: None, store=FakeStore(), now=NOW)
            self.assertIn(r['result'], (L.CONFIRMED, L.NOT_CONFIRMED, L.INCONCLUSIVE))


class Evidence(unittest.TestCase):
    T = {'id': 1, 'type': 'suspicious-process', 'detected_by': 'ProcessMonitorAgent'}

    def test_confirmed_counts_as_evidence(self):
        e = local_evidence.assess(self.T, [], None, direct={'result': 'confirmed', 'check': 'process', 'detail': 'running'})
        self.assertEqual(e['status'], 'partial')
        self.assertEqual(e['direct']['result'], 'confirmed')
        e2 = local_evidence.assess(self.T, [{'id': 2, 'detected_by': 'SocketWatchAgent'}], None,
                                   direct={'result': 'confirmed', 'check': 'process', 'detail': 'running'})
        self.assertEqual(e2['status'], 'verified')                           # second detector + direct check

    def test_not_confirmed_marks_the_verdict(self):
        e = local_evidence.assess(self.T, [], None, direct={'result': 'not-confirmed', 'check': 'process', 'detail': 'gone'})
        self.assertIn('not confirmed by a direct check', e['note'])
        c = local_evidence.apply({'consensus_verdict': 'malicious', 'quorum': {'label': '3 of 3'}}, e)
        self.assertEqual(c['direct_check'], 'not confirmed by a direct check')
        self.assertIn('not confirmed by a direct check', c['quorum']['label'])


if __name__ == '__main__':
    unittest.main()
