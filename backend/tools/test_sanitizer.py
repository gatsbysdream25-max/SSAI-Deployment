#!/usr/bin/env python3
"""The cloud sanitization gate (2026-09-23).
Run:  swarmsentinel-env/bin/python3 backend/tools/test_sanitizer.py"""
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.dirname(HERE)]
import sanitizer as S  # noqa: E402

KNOWN_IPS = ['192.168.1.30', '10.13.13.4', '172.16.4.9', '8.8.8.8', '192.168.xxx.xxx', '2001:db8::1', 'fe80::9ae7:f4ff:febc:ce53']
KNOWN_MACS = ['02:00:5e:00:53:01', 'AA-BB-CC-DD-EE-FF', 'aabb.ccdd.eeff']
KNOWN_HOSTS = ['jdoe', 'srv01.lan', 'fileserver.corp.internal', 'watchtower']


class Gate(unittest.TestCase):
    def setUp(self):
        self.audit = os.path.join(tempfile.mkdtemp(), 'audit.jsonl')
        self.env = mock.patch.dict(os.environ, {'SSAI_PRIVATE_NAMES': 'jdoe,watchtower'})
        self.env.start()
        self.addCleanup(self.env.stop)

    def run_gate(self, payload, **kw):
        return S.sanitize_for_cloud(payload, audit_file=self.audit, tokens=S._TokenMap(), **kw)

    def test_only_the_four_allowed_fields_can_pass(self):
        out = self.run_gate({'severity': 'HIGH', 'threat_type': 'ssh-login', 'timestamp': '2026-09-23T12:00:00Z',
                             'sanitized_summary': 'Repeated failed logins', 'url': '192.168.0.5', 'hostname': 'srv01',
                             'description': 'raw syslog line', 'payload': 'x', 'detected_by': 'AuthLogAgent',
                             'real_source': '192.168.0.5', 'ports': [22]})
        self.assertEqual(sorted(out), ['sanitized_summary', 'severity', 'threat_type', 'timestamp'])
        self.assertEqual(out['severity'], 'high')

    def test_a_disallowed_field_never_passes_even_when_it_looks_harmless(self):
        out = self.run_gate({'severity': 'low', 'notes': 'hello', 'source': 'x', 'title': 'y', 'anything': 1})
        self.assertEqual(out, {'severity': 'low'})

    def test_known_ips_hostnames_and_macs_never_appear_in_the_output(self):
        text = ' | '.join([f'from {i}' for i in KNOWN_IPS] + [f'device {m}' for m in KNOWN_MACS] + [f'host {h}' for h in KNOWN_HOSTS])
        out = self.run_gate({'severity': 'high', 'sanitized_summary': text})
        blob = json.dumps(out)
        for secret in KNOWN_IPS + KNOWN_MACS + KNOWN_HOSTS:
            self.assertNotIn(secret.lower(), blob.lower(), secret)
        self.assertNotIn('9a:e7', blob.lower())

    def test_same_value_same_token_and_different_values_different_tokens(self):
        tokens = S._TokenMap()
        a = S.sanitize_for_cloud({'sanitized_summary': 'scan from 192.168.0.5 then 192.168.0.5 and 192.168.0.6'}, audit_file=self.audit, tokens=tokens)
        b = S.sanitize_for_cloud({'sanitized_summary': 'again 192.168.0.5'}, audit_file=self.audit, tokens=tokens)
        self.assertEqual(a['sanitized_summary'], 'scan from IP_1 then IP_1 and IP_2')
        self.assertEqual(b['sanitized_summary'], 'again IP_1')                 # stable across calls

    def test_case_differences_do_not_create_new_tokens(self):
        out = self.run_gate({'sanitized_summary': 'Jdoe logged in; jdoe again; JDOE'})
        self.assertEqual(out['sanitized_summary'], 'HOST_1 logged in; HOST_1 again; HOST_1')

    def test_internal_domains_emails_and_home_paths_are_redacted(self):
        out = self.run_gate({'sanitized_summary': 'file /home/alice/x.txt and C:\\Users\\asmith\\a.doc mailed to boss@example.com via mail.corp.local'})
        s = out['sanitized_summary']
        for secret in ('alice', 'asmith', 'boss@example.com', 'mail.corp.local'):
            self.assertNotIn(secret, s)
        self.assertIn('USER_', s)
        self.assertIn('EMAIL_1', s)

    def test_ordinary_text_is_untouched(self):
        out = self.run_gate({'sanitized_summary': 'Outbound connection at 12:30:45 matched a known malware family (v3.11)'})
        self.assertEqual(out['sanitized_summary'], 'Outbound connection at 12:30:45 matched a known malware family (v3.11)')

    def test_bad_severity_type_and_timestamp_are_dropped_not_passed_through(self):
        out = self.run_gate({'severity': '192.168.0.5', 'threat_type': 'has spaces and 10.0.0.1', 'timestamp': 'yesterday-ish'})
        self.assertEqual(out, {})

    def test_timestamp_is_normalised_to_utc(self):
        out = self.run_gate({'timestamp': '2026-09-23T08:00:00-04:00'})
        self.assertEqual(out['timestamp'], '2026-09-23T12:00:00Z')

    def test_summary_is_length_limited(self):
        out = self.run_gate({'sanitized_summary': 'a' * 5000})
        self.assertLessEqual(len(out['sanitized_summary']), S.MAX_SUMMARY)

    def test_fails_closed_on_bad_input(self):
        for bad in (None, 'text', 42, ['severity']):
            self.assertEqual(self.run_gate(bad), {})

    def test_fails_closed_when_the_audit_log_cannot_be_written(self):
        blocker = os.path.join(tempfile.mkdtemp(), 'file')
        open(blocker, 'w').close()
        with self.assertLogs('ssai.sanitizer', level='ERROR') as logged:
            out = S.sanitize_for_cloud({'severity': 'high'}, audit_file=os.path.join(blocker, 'no', 'audit.jsonl'), tokens=S._TokenMap())
        self.assertEqual(out, {})                                              # cannot record it -> does not send it
        self.assertTrue(any('could not be written' in line for line in logged.output))   # and the missing record is not silent

    def test_fails_closed_when_redaction_breaks(self):
        with mock.patch.object(S.Redactor, 'redact', side_effect=RuntimeError('boom')):
            self.assertEqual(self.run_gate({'sanitized_summary': 'x'}), {})

    def test_an_address_that_survives_redaction_drops_the_payload(self):
        with mock.patch.object(S.Redactor, 'redact', side_effect=lambda self_, t: t, autospec=True):
            self.assertEqual(self.run_gate({'sanitized_summary': 'leak 10.1.2.3'}), {})

    def test_audit_log_records_what_crossed_but_never_an_original_value(self):
        self.run_gate({'severity': 'high', 'sanitized_summary': 'scan from 192.168.0.5 on jdoe', 'url': 'http://10.9.9.9/x'})
        lines = open(self.audit).read().splitlines()
        self.assertEqual(len(lines), 1)
        entry = json.loads(lines[0])
        self.assertTrue(entry['ok'])
        self.assertEqual(entry['dropped_fields'], ['url'])                     # names only
        self.assertEqual(entry['redactions'], {'HOST': 1, 'IP': 1})
        for secret in ('192.168.0.5', 'jdoe', '10.9.9.9'):
            self.assertNotIn(secret, lines[0])

    def test_audit_log_is_append_only_and_private(self):
        self.run_gate({'severity': 'low'})
        self.run_gate({'severity': 'high'})
        self.assertEqual(len(open(self.audit).read().splitlines()), 2)
        if os.name == 'posix':
            self.assertEqual(oct(os.stat(self.audit).st_mode & 0o777), '0o600')

    def test_a_dropped_payload_is_logged_without_its_content(self):
        with mock.patch.object(S.Redactor, 'redact', side_effect=RuntimeError('boom')):
            self.run_gate({'sanitized_summary': 'secret 10.0.0.1'})
        line = open(self.audit).read()
        self.assertIn('"ok": false', line)
        self.assertNotIn('10.0.0.1', line)

    def test_token_map_is_bounded(self):
        t = S._TokenMap()
        with mock.patch.object(S, 'MAX_TOKENS', 3):
            for i in range(10):
                t.token('IP', f'10.0.0.{i}')
        self.assertLessEqual(len(t._map), 3)

    # ── credentials (2026-09-26). Fake keys are built from pieces so secret scanners do not flag this file. ──
    FAKE = {
        'groq': 'gsk' + '_' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4',
        'openrouter': 'sk' + '-or-v1-' + '0123456789abcdef' * 4,
        'anthropic': 'sk' + '-ant-' + 'api03-' + 'Zz9Yy8Xx7Ww6Vv5Uu4Tt3',
        'google': 'AIza' + 'Sy' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6q',
        'huggingface': 'hf' + '_' + 'FakeFakeFakeFakeFakeFakeFake1234',
        'github': 'ghp' + '_' + 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8',
        'aws': 'AKIA' + 'IOSFODNN7EXAMPLE',
        'cloudflare': 'cfut' + '_' + 'FakeCloudflareTokenValue0123456789ab',
        'jwt': 'eyJ' + 'hbGciOiJIUzI1NiJ9' + '.eyJ' + 'zdWIiOiIxMjM0NTY3ODkwIn0' + '.' + 'dozjgNryP4J3jVmNHl0w5N',
    }

    def test_known_key_formats_never_cross(self):
        for kind, key in self.FAKE.items():
            out = self.run_gate({'sanitized_summary': f'process: python app.py --opt {key} started'})
            self.assertNotIn(key, json.dumps(out), kind)
            self.assertIn('SECRET_', out['sanitized_summary'], kind)

    def test_passwords_in_command_lines_urls_and_headers_never_cross(self):
        cases = [
            ("sshpass -p '654123' ssh -o StrictHostKeyChecking=no alice@example.org 'ls'", '654123'),
            ('sshpass -pHunter2x ssh box', 'Hunter2x'),
            ('bash -c echo S3cretPw9 | sudo -S systemctl restart swarmsentinel', 'S3cretPw9'),
            ('git clone https://alice:pAss12345@github.com/x/y.git', 'pAss12345'),
            ('curl -H "Authorization: Bearer abcDEF123456789xyz" https://api.example.com', 'abcDEF123456789xyz'),
            ('app --password hunter22 --verbose', 'hunter22'),
            ('app --api-key=ZXCV1234asdf', 'ZXCV1234asdf'),
            ('env MYSQL_PASSWORD=Tr0ub4dor ./run', 'Tr0ub4dor'),
            ('config {"client_secret": "q1w2e3r4t5"}', 'q1w2e3r4t5'),
        ]
        for text, secret in cases:
            out = self.run_gate({'sanitized_summary': text})
            self.assertNotIn(secret, json.dumps(out), text)
            self.assertIn('SECRET_', out['sanitized_summary'], text)

    def test_private_key_block_never_crosses_even_when_cut_off(self):
        body = 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASC'
        for text in (f'-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY----- tail',
                     f'cat key: -----BEGIN RSA PRIVATE KEY-----\n{body}'):
            out = self.run_gate({'sanitized_summary': text})
            self.assertNotIn(body, json.dumps(out))

    def test_hashes_and_ordinary_security_wording_are_kept(self):
        for text in ('sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 matched a sample',
                     'md5 d41d8cd98f00b204e9800998ecf8427e',
                     'Failed password for invalid user admin from port 22 ssh2',
                     'pam_unix(sshd:auth): authentication failure; logname= tty=ssh',
                     'Token bucket refilled; basic checks passed'):
            out = self.run_gate({'sanitized_summary': text})
            self.assertEqual(out['sanitized_summary'], text)

    def test_audit_counts_secrets_without_recording_them(self):
        key = self.FAKE['groq']
        self.run_gate({'sanitized_summary': f'GROQ_API_KEY={key} and sshpass -p 654123 ssh x'})
        line = open(self.audit).read()
        self.assertIn('"SECRET": 2', line)
        for secret in (key, '654123'):
            self.assertNotIn(secret, line)

    def test_a_key_that_survives_redaction_drops_the_payload(self):
        with mock.patch.object(S.Redactor, 'redact', side_effect=lambda self_, t: t, autospec=True):
            self.assertEqual(self.run_gate({'sanitized_summary': 'leak ' + self.FAKE['groq']}), {})


class RedTeamFindings(unittest.TestCase):
    """Gaps found by the built-in red team on 2026-10-09, and the audit log naming who data went to."""

    def setUp(self):
        self.audit = os.path.join(tempfile.mkdtemp(), 'audit.jsonl')

    def run_gate(self, payload, **kw):
        return S.sanitize_for_cloud(payload, audit_file=self.audit, tokens=S._TokenMap(), **kw)

    def test_defanged_addresses_and_names_are_redacted(self):
        for raw, secret in (('192[.]168[.]1[.]30', '168'), ('10(.)1(.)2(.)3', '10'), ('nas[.]corp[.]local', 'nas'),
                            ('192 [.] 168 [.] 4 [.] 24', '168')):
            out = self.run_gate({'sanitized_summary': f'beacon to {raw}'})
            self.assertTrue(out, raw)
            self.assertNotIn(secret, out['sanitized_summary'], raw)

    def test_public_defanged_indicator_stays_readable(self):
        out = self.run_gate({'sanitized_summary': 'payload from evil-example[.]com'})
        self.assertIn('evil-example.com', out['sanitized_summary'])

    def test_ps_aux_user_column_is_redacted_but_root_kept(self):
        line = ('Suspicious process detected: jdoe      4242  0.0  0.1  12345  6789 pts/0    S+   10:01   0:00 bash -i\n'
                'root         1  0.0  0.2 167000 11000 ?        Ss   Oct01   0:09 /sbin/init')
        out = self.run_gate({'sanitized_summary': line})['sanitized_summary']
        self.assertNotIn('jdoe', out)
        self.assertIn('USER_1', out)
        self.assertIn('root ', out)
        self.assertIn('bash -i', out)

    def test_audit_records_the_destination(self):
        self.run_gate({'severity': 'low'}, destination='microsoft-copilot')
        self.run_gate({'severity': 'low'}, destination=['groq', 'gemini', 'groq'])
        self.run_gate({'severity': 'low'})
        with open(self.audit) as f:
            rows = [json.loads(x) for x in f]
        self.assertEqual(rows[0]['to'], 'microsoft-copilot')
        self.assertEqual(rows[1]['to'], ['gemini', 'groq'])
        self.assertNotIn('to', rows[2])

    def test_refused_payload_still_records_the_destination(self):
        self.run_gate(['not a dict'], destination='groq')
        with open(self.audit) as f:
            row = json.loads(f.readline())
        self.assertEqual((row['ok'], row['to']), (False, 'groq'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
