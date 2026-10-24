#!/usr/bin/env python3
"""Tests for the block/unblock remediation logic (2026-09-19).
Run:  swarmsentinel-env/bin/python3 backend/tools/test_remediation.py"""
import json
import os
import sys
import tempfile
import types
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.dirname(HERE)]
import remediation as R  # noqa: E402


class FakeUfw:
    """Records commands; `fail_on` makes a matching command fail; `active` controls `ufw status`."""

    def __init__(self, active=True, fail_on=None, empty_rules=False):
        self.calls, self.active, self.fail_on, self.empty = [], active, fail_on, empty_rules

    def __call__(self, cmd, **kw):
        args = cmd[next(i for i, x in enumerate(cmd) if x.endswith('ufw')) + 1:]
        self.calls.append(args)
        ok = types.SimpleNamespace(returncode=0, stdout='', stderr='')
        if args == ['status']:
            return types.SimpleNamespace(returncode=0, stdout='Status: active\n' if self.active else 'Status: inactive\n', stderr='')
        if self.empty and args[0] == 'insert':
            return types.SimpleNamespace(returncode=1, stdout='', stderr="ERROR: Invalid position '1'")
        if self.fail_on and self.fail_on in args:
            return types.SimpleNamespace(returncode=1, stdout='', stderr='ERROR: boom')
        return ok


class Classify(unittest.TestCase):
    def kind(self, raw):
        return R.classify_target(raw)

    def test_ip_shapes(self):
        for raw in ('203.0.113.7', '203.0.113.7:8080', ' 203.0.113.7 ', 'http://203.0.113.8/bin.sh', 'https://203.0.113.8:8443/x?y=1'):
            t = self.kind(raw)
            self.assertEqual(t['kind'], 'ip', raw)
            self.assertTrue(t['value'].startswith('203.0.113.'))

    def test_domain_shapes(self):
        for raw, want in (('http://Evil-Test.example.com/a.sh', 'evil-test.example.com'), ('evil-test.example.com', 'evil-test.example.com'),
                          ('evil-test.example.com:8080/x', 'evil-test.example.com'), ('https://evil-test.example.com./', 'evil-test.example.com')):
            self.assertEqual(self.kind(raw), {'kind': 'domain', 'value': want}, raw)

    def test_masked_addresses_are_refused_with_a_reason(self):
        for raw in ('192.168.xxx.xxx', '192.168.xxx.xxx:6667', 'pihole://192.168.xxx.xxx:8081', '10.xxx.xxx.xxx'):
            with self.assertRaisesRegex(R.TargetError, 'masked'):
                self.kind(raw)

    def test_unblockable_things_are_refused(self):
        for raw in (None, '', '   ', 42, 'localhost', '127.0.0.1', '0.0.0.0', '224.0.0.1', '169.254.1.1', 'pihole://192.168.1.30',
                    'file:///etc/passwd', 'http://', 'not a host', 'nodots', 'a' * 300 + '.com'):
            with self.assertRaises(R.TargetError, msg=repr(raw)[:40]):
                self.kind(raw)

    def test_protected_domains_are_refused_including_subdomains(self):
        for raw in ('google.com', 'https://www.google.com/x', 'storage.googleapis.com', 'github.com'):
            with self.assertRaisesRegex(R.TargetError, 'protected'):
                self.kind(raw)
        os.environ['INTEL_ALLOWLIST'] = 'mycorp.example'
        try:
            with self.assertRaisesRegex(R.TargetError, 'protected'):
                self.kind('vpn.mycorp.example')
        finally:
            del os.environ['INTEL_ALLOWLIST']
        self.kind('vpn.mycorp.example')

    def test_private_lan_address_that_is_not_masked_can_be_blocked(self):
        self.assertEqual(self.kind('192.168.0.77'), {'kind': 'ip', 'value': '192.168.0.77'})


class Firewall(unittest.TestCase):
    def test_blocks_both_directions_above_existing_allow_rules(self):
        u = FakeUfw()
        msg = R.firewall_block('203.0.113.7', u)
        self.assertEqual(u.calls, [['status'], ['insert', '1', 'deny', 'from', '203.0.113.7'],
                                   ['insert', '1', 'deny', 'out', 'to', '203.0.113.7']])
        self.assertIn('this host only', msg)

    def test_refuses_when_the_firewall_is_off(self):
        u = FakeUfw(active=False)
        with self.assertRaisesRegex(R.RemediationError, 'switched off'):
            R.firewall_block('203.0.113.7', u)
        self.assertEqual(u.calls, [['status']])                          # no rule was added

    def test_a_missing_sudo_rule_and_a_missing_ufw_are_told_apart(self):
        import subprocess
        def failing(stderr):
            return lambda cmd, **kw: subprocess.CompletedProcess(cmd, 1, '', stderr)
        with self.assertRaisesRegex(R.RemediationError, 'not yet allowed to run ufw'):
            R.firewall_block('203.0.113.7', failing('sudo: a password is required'))
        with self.assertRaisesRegex(R.RemediationError, 'ufw is not installed'):
            R.firewall_block('203.0.113.7', failing('sudo: ufw: command not found'))

    def test_empty_ruleset_falls_back_to_append(self):
        u = FakeUfw(empty_rules=True)
        R.firewall_block('203.0.113.7', u)
        self.assertIn(['deny', 'from', '203.0.113.7'], u.calls)
        self.assertIn(['deny', 'out', 'to', '203.0.113.7'], u.calls)

    def test_half_a_block_is_rolled_back(self):
        u = FakeUfw(fail_on='out')
        with self.assertRaisesRegex(R.RemediationError, 'refused'):
            R.firewall_block('203.0.113.7', u)
        self.assertEqual(u.calls[-1], ['delete', 'deny', 'from', '203.0.113.7'])

    def test_unblock_removes_both_rules_and_reports_failure(self):
        u = FakeUfw()
        R.firewall_unblock('203.0.113.7', u)
        self.assertEqual(u.calls, [['delete', 'deny', 'from', '203.0.113.7'], ['delete', 'deny', 'out', 'to', '203.0.113.7']])
        with self.assertRaises(R.RemediationError):
            R.firewall_unblock('203.0.113.7', FakeUfw(fail_on='delete'))

    def test_missing_or_hung_ufw_is_a_clean_error(self):
        def boom(*a, **k):
            raise OSError('no sudo')
        with self.assertRaisesRegex(R.RemediationError, 'could not run ufw'):
            R.firewall_block('203.0.113.7', boom)


class FakeHttp:
    def __init__(self, login_ok=True, deny_status=201, deny_text='', delete_status=204, raise_on=None):
        self.calls, self.login_ok, self.deny_status, self.deny_text = [], login_ok, deny_status, deny_text
        self.delete_status, self.raise_on = delete_status, raise_on

    def _resp(self, status, body=None, text=''):
        return types.SimpleNamespace(status_code=status, text=text or json.dumps(body or {}), json=lambda: body or {})

    def post(self, url, **kw):
        self.calls.append(('POST', url, kw))
        if self.raise_on == 'login':
            import requests
            raise requests.exceptions.ConnectionError('down')
        if url.endswith('/api/auth'):
            return self._resp(200, {'session': {'valid': self.login_ok, 'sid': 'SID'}})
        return self.request('POST', url, **kw)

    def delete(self, url, **kw):
        self.calls.append(('DELETE', url, kw))
        return self._resp(204) if url.endswith('/api/auth') else self.request('DELETE', url, **kw)

    def request(self, method, url, **kw):
        if method == 'POST':
            self.calls.append(('POST-api', url, kw))
            return self._resp(self.deny_status, text=self.deny_text)
        self.calls.append(('DELETE-api', url, kw))
        return self._resp(self.delete_status)


class PiHoleTests(unittest.TestCase):
    def ph(self, **kw):
        http = FakeHttp(**kw)
        return R.PiHole('192.168.1.30:8081', 'pw', http), http

    def test_deny_adds_exact_domain_and_always_logs_out(self):
        ph, http = self.ph()
        R.block({'kind': 'domain', 'value': 'evil.example.com'}, 12, pihole=ph)
        api = [c for c in http.calls if c[0] == 'POST-api'][0]
        self.assertTrue(api[1].endswith('/api/domains/deny/exact'))
        self.assertEqual(api[2]['json']['domain'], 'evil.example.com')
        self.assertIn('#12', api[2]['json']['comment'])
        self.assertEqual(api[2]['params'], {'sid': 'SID'})
        self.assertEqual(http.calls[-1][0], 'DELETE')                    # session released

    def test_already_blocked_counts_as_success(self):
        ph, _ = self.ph(deny_status=400, deny_text='{"hint":"The item is already present"}')
        ph.deny('evil.example.com', 'x')

    def test_failures_are_reported_plainly(self):
        for kw, pattern in (({'login_ok': False}, 'rejected the login'), ({'deny_status': 500, 'deny_text': 'oops'}, 'HTTP 500'),
                            ({'raise_on': 'login'}, 'could not reach')):
            ph, _ = self.ph(**kw)
            with self.assertRaisesRegex(R.RemediationError, pattern):
                ph.deny('evil.example.com', 'x')

    def test_unconfigured_pihole_says_what_to_set(self):
        with self.assertRaisesRegex(R.RemediationError, 'PIHOLE_IP'):
            R.PiHole('', '', FakeHttp()).deny('evil.example.com', 'x')

    def test_unblock_and_already_gone(self):
        for status in (204, 404):
            ph, http = self.ph(delete_status=status)
            R.unblock({'kind': 'domain', 'value': 'evil.example.com'}, pihole=ph)
        ph, _ = self.ph(delete_status=500)
        with self.assertRaises(R.RemediationError):
            ph.undeny('evil.example.com')

    def test_block_dispatch_by_kind(self):
        u = FakeUfw()
        msg = R.block({'kind': 'ip', 'value': '203.0.113.7'}, 1, run=u)
        self.assertIn('203.0.113.7', msg)
        ph, _ = self.ph()
        self.assertIn('Pi-hole', R.block({'kind': 'domain', 'value': 'evil.example.com'}, 1, pihole=ph))


class Audit(unittest.TestCase):
    def test_appends_json_lines_and_never_raises(self):
        path = os.path.join(tempfile.mkdtemp(), 'sub', 'audit.jsonl')
        R.audit(path, action='block', target='203.0.113.7', ok=True)
        R.audit(path, action='unblock', target='203.0.113.7', ok=True)
        rows = [json.loads(line) for line in open(path)]
        self.assertEqual([r['action'] for r in rows], ['block', 'unblock'])
        self.assertIn('time', rows[0])
        R.audit('/proc/no-such/dir/audit.jsonl', action='block')          # unwritable: must not raise


if __name__ == '__main__':
    unittest.main(verbosity=2)
