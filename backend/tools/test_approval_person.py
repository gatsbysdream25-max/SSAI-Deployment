#!/usr/bin/env python3
"""Phase 5 of the consensus plan: a block is approved by a signed-in PERSON (audit F-04), and cannot happen unrecorded (F-14).
The admin API key is also held by the agents, so a key alone must not approve; the audit line is written before the firewall changes.
Run:  swarmsentinel-env/bin/python3 backend/tools/test_approval_person.py"""
import json
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

_TMP = tempfile.mkdtemp()
os.environ['DATA_DIR'] = _TMP
os.environ['DATABASE_URL'] = f'sqlite:///{_TMP}/approval-test.db'
os.environ['SSAI_API_KEY'] = ADMIN = 'approval-test-admin-key'
os.environ['SSAI_PROVIDER_CHECK'] = '0'
os.environ['SSAI_STATE_DB'] = os.path.join(_TMP, 'state.db')
os.environ.pop('SSAI_APPROVAL_REQUIRES_PERSON', None)

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
sys.path[:0] = [os.path.join(BACKEND, 'agents'), BACKEND]

import remediation  # noqa: E402
import remediation_queue  # noqa: E402
import sso  # noqa: E402

PERSON = 'dana@example.org'
CSRF = 'csrf-token-for-the-test'


class FakeRow:
    kind, target, expires_at, status, decided_by = 'ip', '203.0.113.9', None, 'approved', None

    def to_dict(self):
        return {'id': 1, 'kind': self.kind, 'target': self.target, 'status': self.status, 'decided_by': self.decided_by}


class Approve(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import app as appmod
        if _TMP not in appmod.app.config['SQLALCHEMY_DATABASE_URI']:
            raise RuntimeError('refusing to run against a non-test database')
        cls.appmod, cls.app = appmod, appmod.app
        cls.app.config['TESTING'] = True

    def setUp(self):
        self.audit = os.path.join(_TMP, f'audit-{time.time_ns()}.jsonl')
        self.appmod._AUDIT_PATH = self.audit
        self.c = self.app.test_client()
        self.calls = []

        def fake_approve(row_id, decided_by, ttl_hours=None, **kw):
            self.calls.append(decided_by)
            row = FakeRow()
            row.decided_by = decided_by
            return row, 'blocked'

        for p in (mock.patch.object(remediation_queue, 'approve_proposal', fake_approve),
                  mock.patch.object(remediation_queue, 'reject_proposal', lambda i, decided_by: self._reject(decided_by)),
                  mock.patch.object(sso, 'is_admin_subject', lambda subject, cfg=None: subject == PERSON),
                  mock.patch.object(sso, 'only', lambda: False)):
            p.start()
            self.addCleanup(p.stop)

    def _reject(self, decided_by):
        self.calls.append(decided_by)
        row = FakeRow()
        row.status, row.decided_by = 'rejected', decided_by
        return row

    def sign_in(self):
        with self.c.session_transaction() as s:
            s.update({'adm': True, 'iat': int(time.time()), 'sso': PERSON, 'csrf': CSRF})

    def audit_lines(self):
        try:
            with open(self.audit, encoding='utf-8') as f:
                return [json.loads(line) for line in f if line.strip()]
        except OSError:
            return []

    def approve(self, **headers):
        return self.c.post('/api/remediation/1/approve', json={}, headers=headers)

    def test_the_admin_key_alone_cannot_approve_and_the_refusal_is_recorded(self):
        r = self.approve(**{'X-API-Key': ADMIN})
        self.assertEqual(r.status_code, 403)
        self.assertIn('signed-in person', r.get_json()['error'])
        self.assertEqual(self.calls, [])                                    # nothing was blocked
        self.assertIn('refused', self.audit_lines()[-1]['error'])

    def test_a_signed_in_person_can_approve_and_is_named_in_the_record(self):
        self.sign_in()
        r = self.approve(**{'X-CSRF-Token': CSRF})
        self.assertEqual(r.status_code, 200)
        self.assertTrue(self.calls[0].startswith(PERSON + ' @ '))
        lines = self.audit_lines()
        self.assertEqual([x.get('stage') for x in lines if x['action'] == 'approve'], ['intent', None])   # intent first, result after
        self.assertTrue(lines[0]['by'].startswith(PERSON))

    def test_a_session_without_the_csrf_token_is_not_a_decision(self):
        self.sign_in()
        self.assertIn(self.approve().status_code, (401, 403))
        self.assertEqual(self.calls, [])

    def test_a_deployment_with_no_human_console_can_allow_the_key(self):
        with mock.patch.dict(os.environ, {'SSAI_APPROVAL_REQUIRES_PERSON': '0'}):
            r = self.approve(**{'X-API-Key': ADMIN})
        self.assertEqual(r.status_code, 200)
        self.assertTrue(self.calls[0].startswith('key @ '))                # and the record says it was a key, not a person

    def test_if_the_audit_line_cannot_be_written_nothing_is_blocked(self):
        broken = os.path.join(_TMP, 'a-file-not-a-folder')
        open(broken, 'w').close()
        self.appmod._AUDIT_PATH = os.path.join(broken, 'audit.jsonl')
        self.sign_in()
        r = self.approve(**{'X-CSRF-Token': CSRF})
        self.assertEqual(r.status_code, 502)
        self.assertIn('audit log could not be written', r.get_json()['error'])
        self.assertEqual(self.calls, [])

    def test_a_reject_by_key_is_allowed_and_recorded_as_a_key(self):
        r = self.c.post('/api/remediation/1/reject', json={}, headers={'X-API-Key': ADMIN})
        self.assertEqual(r.status_code, 200)
        self.assertTrue(self.calls[0].startswith('key @ '))

    def test_the_manual_block_button_needs_a_person_too(self):
        from models import Threat, db
        with self.app.app_context():
            t = Threat(url='http://203.0.113.9/x', type='malware-url', severity='high', status='active')
            db.session.add(t)
            db.session.commit()
            tid = t.id
        r = self.c.post(f'/api/threats/{tid}/block', json={}, headers={'X-API-Key': ADMIN})
        self.assertEqual(r.status_code, 403)
        self.assertIn('signed-in person', r.get_json()['error'])
        self.sign_in()
        broken = os.path.join(_TMP, 'file-not-folder-2')
        open(broken, 'w').close()
        self.appmod._AUDIT_PATH = os.path.join(broken, 'audit.jsonl')
        r = self.c.post(f'/api/threats/{tid}/block', json={}, headers={'X-CSRF-Token': CSRF})
        self.assertEqual(r.status_code, 502)                                        # no audit line, no block

    def test_addresses_wrapped_in_ipv6_are_still_internal(self):
        for wrapped in ('::ffff:192.168.1.5', '::ffff:10.0.0.1', '::ffff:c0a8:105'):
            target = remediation.classify_target(f'http://[{wrapped}]/')
            self.assertTrue(remediation_queue.internal_address(target['value']), wrapped)

    def test_unblocking_still_works_when_the_audit_log_is_broken(self):
        broken = os.path.join(_TMP, 'another-file')
        open(broken, 'w').close()
        event = remediation.audit(os.path.join(broken, 'audit.jsonl'), action='unblock', ok=True)   # must not raise
        self.assertEqual(event['action'], 'unblock')


if __name__ == '__main__':
    unittest.main()
