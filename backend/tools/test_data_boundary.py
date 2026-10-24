#!/usr/bin/env python3
"""Phase 2 of the consensus plan: one set of redaction rules for everything that leaves this network.
F-08: user names written into log lines are masked. F-09: the public GitHub ledger uses the same rules as the cloud gate, and
publishes nothing if they cannot run.
Run:  swarmsentinel-env/bin/python3 backend/tools/test_data_boundary.py"""
import os
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
sys.path[:0] = [os.path.join(BACKEND, 'agents'), BACKEND]
import sanitizer  # noqa: E402


def gate(text):
    """What a cloud model would see for this summary."""
    audit = os.path.join(tempfile.mkdtemp(), 'a.jsonl')
    return sanitizer.sanitize_for_cloud({'severity': 'high', 'threat_type': 'auth', 'sanitized_summary': text},
                                        audit_file=audit, tokens=sanitizer._TokenMap()).get('sanitized_summary', '')


class UserNames(unittest.TestCase):
    def test_user_names_in_auth_log_phrasing_never_reach_the_cloud(self):
        for line, name in (('Failed password for bob from 203.0.113.9 port 22 ssh2', 'bob'),
                           ('Accepted publickey for alice from 203.0.113.9', 'alice'),
                           ('pam_unix(sshd:session): session opened for user carol by (uid=0)', 'carol'),
                           ('sudo: pam_unix(sudo:auth): authentication failure; logname=dave uid=1000 user=dave', 'dave'),
                           ('sudo:   erin : TTY=pts/0 ; PWD=/srv ; USER=root ; COMMAND=/bin/ls', 'erin'),
                           ('Failed password for frank_01 from 203.0.113.9', 'frank_01')):
            out = gate(line)
            self.assertNotIn(name, out, line)
            self.assertIn('USER_', out, line)

    def test_the_same_user_gets_the_same_token_and_different_users_differ(self):
        out = gate('Failed password for bob from 203.0.113.9; Failed password for bob again; Failed password for amy')
        self.assertEqual(out.count('USER_1'), 2)
        self.assertIn('USER_2', out)

    def test_system_accounts_and_attacker_typed_names_stay_because_they_identify_no_one(self):
        out = gate('Failed password for root from 203.0.113.9; Failed password for invalid user admin from 203.0.113.9')
        self.assertIn('for root', out)
        self.assertIn('invalid user admin', out)


class Ledger(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        data = tempfile.mkdtemp()
        os.environ['DATA_DIR'] = data
        os.makedirs(os.path.join(data, 'threat-intel-repo', 'logs'))      # the reporter opens its log at import
        import github_reporter
        cls.gr = github_reporter

    def test_what_the_old_masker_missed_is_masked_now(self):
        raw = ('seen on aa:bb:cc:dd:ee:ff at 100.101.102.103 and 169.254.7.7 and fe80::1ff:fe23:4567:890a, '
               'Failed password for bob from 203.0.113.9')
        out = self.gr._mask(raw)
        for leak in ('aa:bb:cc:dd:ee:ff', '100.101.102.103', '169.254.7.7', 'fe80::1ff', 'bob'):
            self.assertNotIn(leak, out)

    def test_attacker_addresses_on_the_public_internet_still_show(self):
        out = self.gr._mask('blocked 203.0.113.9 and 8.8.8.8 and 192.168.0.5')
        self.assertIn('203.0.113.9', out)
        self.assertIn('8.8.8.8', out)
        self.assertNotIn('192.168.0.5', out)

    def test_if_the_shared_rules_cannot_run_nothing_is_published(self):
        with mock.patch.object(sanitizer.Redactor, 'redact', side_effect=RuntimeError('boom')):
            self.assertEqual(self.gr._mask('anything at all'), self.gr._WITHHELD)

    def test_if_something_private_survives_the_rules_nothing_is_published(self):
        with mock.patch.object(sanitizer.Redactor, 'redact', side_effect=lambda t: t), \
                mock.patch.object(self.gr, '_HOME', self.gr._HOME):
            self.assertEqual(self.gr._shared_rules('mac 11:22:33:44:55:66'), self.gr._WITHHELD)

    def test_machine_names_the_hub_has_seen_are_masked_by_the_shared_rules_too(self):
        self.gr._known_names[:] = ['payroll-server']
        self.addCleanup(self.gr._known_names.clear)
        self.assertNotIn('payroll-server', self.gr._shared_rules('scan from payroll-server reached 203.0.113.9'))


if __name__ == '__main__':
    unittest.main()
