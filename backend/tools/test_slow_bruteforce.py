#!/usr/bin/env python3
"""AuthLogAgent: 48-hour per-address memory, slower distributed rules, and a login that follows failures (2026-11-15 sync).
Only documentation addresses (203.0.113.x, 198.51.100.x) appear here.
Run:  swarmsentinel-env/bin/python3 backend/tools/test_slow_bruteforce.py"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(os.path.dirname(HERE), 'agents'), os.path.dirname(HERE)]
import agent_runner as R  # noqa: E402

HOUR = 3600.0


def agent():
    a = R.AuthLogAgent.__new__(R.AuthLogAgent)
    a._seen, a._fail_times, a._bf_success = R._BoundedSet(1000), R._BoundedDict(1000), R._BoundedSet(1000)
    a._recent_fails, a._last_spread_alert, a.sent = R.deque(maxlen=a.SPREAD_KEEP), float('-inf'), []
    a._submit = lambda **k: a.sent.append(k)
    return a


def fail(a, ip, t, user='root'):
    a.handle_line(f'Nov 15 10:00:00 hub sshd[1]: Failed password for {user} from {ip} port 50000 ssh2', now=t)


def ok(a, ip, t, user='root'):
    a.handle_line(f'Nov 15 10:00:00 hub sshd[1]: Accepted password for {user} from {ip} port 50000 ssh2', now=t)


def kinds(a):
    return [s['threat_type'] for s in a.sent]


class PerAddressMemory(unittest.TestCase):
    def test_five_failures_alert(self):
        a = agent()
        for i in range(5):
            fail(a, '203.0.113.7', 1000 + i)
        self.assertEqual(kinds(a), ['brute-force'])

    def test_failures_older_than_48_hours_are_forgotten(self):
        a = agent()
        for i in range(4):
            fail(a, '203.0.113.7', 1000 + i)
        fail(a, '203.0.113.7', 1000 + 49 * HOUR)                   # one typo two days later: count is 1, not 5
        self.assertEqual(a.sent, [])
        self.assertEqual(a._recent_failures('203.0.113.7', 1000 + 49 * HOUR), 1)

    def test_at_most_60_timestamps_per_address(self):
        a = agent()
        for i in range(200):
            fail(a, '203.0.113.7', 1000 + i)
        self.assertEqual(len(a._fail_times['203.0.113.7']), 60)
        self.assertEqual([s['severity'] for s in a.sent if s['threat_type'] == 'brute-force'], ['medium', 'high', 'high'])


class LoginAfterFailures(unittest.TestCase):
    def test_success_after_five_failures_is_critical(self):
        a = agent()
        for i in range(5):
            fail(a, '203.0.113.9', 1000 + i)
        ok(a, '203.0.113.9', 1010)
        crit = [s for s in a.sent if s['threat_type'] == 'brute-force-success']
        self.assertEqual(len(crit), 1)
        self.assertEqual(crit[0]['severity'], 'critical')
        self.assertIn('root', crit[0]['description'])

    def test_reported_once_per_address_and_user(self):
        a = agent()
        for i in range(6):
            fail(a, '203.0.113.9', 1000 + i)
        ok(a, '203.0.113.9', 1010)
        ok(a, '203.0.113.9', 1020)
        ok(a, '203.0.113.9', 1030, user='backup')
        self.assertEqual(kinds(a).count('brute-force-success'), 2)

    def test_four_failures_then_success_is_just_a_login(self):
        a = agent()
        for i in range(4):
            fail(a, '203.0.113.9', 1000 + i)
        ok(a, '203.0.113.9', 1010)
        self.assertNotIn('brute-force-success', kinds(a))

    def test_never_for_loopback(self):
        a = agent()
        for i in range(10):
            fail(a, '127.0.0.1', 1000 + i)
        ok(a, '127.0.0.1', 1010)
        self.assertNotIn('brute-force-success', kinds(a))

    def test_old_failures_do_not_count(self):
        a = agent()
        for i in range(5):
            fail(a, '203.0.113.9', 1000 + i)
        ok(a, '203.0.113.9', 1000 + 50 * HOUR)
        self.assertNotIn('brute-force-success', kinds(a))


class DistributedRules(unittest.TestCase):
    def spread(self, a, n, ips, every, start=1000.0, user=None):
        for i in range(n):
            a._note_spread(f'198.51.100.{i % ips}', now=start + i * every, user=user)

    def test_fast_burst_is_caught_early(self):
        # 20 failures from 5 addresses in about 3 minutes. The 1-hour rule (12 failures, 4 addresses) is looser than the
        # 10-minute rule (20, 5), so it fires first, at the 12th failure; the burst is reported once.
        a = agent()
        self.spread(a, 20, 5, 10)
        self.assertEqual(len(a.sent), 1)
        self.assertIn('12 failed logins', a.sent[0]['description'])

    def test_ten_minute_rule_on_its_own(self):
        a = agent()
        a.SPREAD_RULES = ((600, 20, 5),)
        self.spread(a, 20, 5, 10)
        self.assertEqual(len(a.sent), 1)
        self.assertIn('10 min', a.sent[0]['description'])

    def test_one_hour_rule(self):
        a = agent()
        self.spread(a, 12, 4, 240)                                     # 12 failures over 44 minutes from 4 addresses
        self.assertEqual(len(a.sent), 1)
        self.assertIn('1 hour', a.sent[0]['description'])

    def test_one_day_rule(self):
        a = agent()
        self.spread(a, 30, 5, 2400)                                    # one every 40 minutes, 30 over ~19 hours
        self.assertEqual(len(a.sent), 1)
        self.assertIn('24 hours', a.sent[0]['description'])

    def test_one_account_from_three_addresses(self):
        a = agent()
        self.spread(a, 10, 3, 1500, user='finance')                   # 10 over ~4 hours, too slow for the host rules
        self.assertEqual(len(a.sent), 1)
        self.assertIn('finance', a.sent[0]['description'])

    def test_shared_cooldown(self):
        a = agent()
        self.spread(a, 20, 5, 10)
        self.spread(a, 40, 6, 20, start=1500.0, user='finance')        # still within the hour
        self.assertEqual(len(a.sent), 1)
        self.spread(a, 20, 5, 10, start=1000.0 + 2 * HOUR)
        self.assertEqual(len(a.sent), 2)

    def test_under_every_rule_is_quiet(self):
        a = agent()
        self.spread(a, 20, 6, 600)                                     # 20 failures, one every 10 minutes
        self.spread(a, 9, 3, 1500, start=1000.0 + 5 * HOUR, user='finance')
        self.assertEqual(a.sent, [])

    def test_user_is_read_from_the_log_line(self):
        a = agent()
        for i in range(10):
            a.handle_line(f'Nov 15 10:00:00 hub sshd[1]: Failed password for invalid user ops from 198.51.100.{i % 3} port 1 ssh2',
                          now=1000.0 + i * 1500)
        self.assertIn('distributed-brute-force', kinds(a))
        self.assertIn('ops', [s for s in a.sent if s['threat_type'] == 'distributed-brute-force'][0]['description'])


if __name__ == '__main__':
    unittest.main()
