#!/usr/bin/env python3
"""Approve-first remediation queue: propose/approve/reject/sweep (2026-09-22).
Run:  swarmsentinel-env/bin/python3 backend/tools/test_remediation_queue.py"""
import os
import sys
import tempfile
import types
import unittest
from datetime import datetime, timedelta, timezone

_TMP = tempfile.mkdtemp()
os.environ['DATA_DIR'] = _TMP
os.environ['DATABASE_URL'] = 'sqlite:///' + os.path.join(_TMP, 'remq-test.db')

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
sys.path[:0] = [BACKEND]

import app as appmod  # noqa: E402
import remediation as R  # noqa: E402
import remediation_queue as RQ  # noqa: E402
from models import db, Threat, PendingRemediation  # noqa: E402


def malicious(confidence=90, ai_count=3, severity='CRITICAL', agreement=1.0, sources=None):
    return {
        'consensus_verdict': 'malicious', 'consensus_severity': severity, 'confidence': confidence,
        'ai_count': ai_count, 'ai_sources': sources or ['groq', 'gemini', 'anthropic'][:ai_count],
        'votes': {'malicious': ai_count, 'suspicious': 0, 'benign': 0}, 'agreement': agreement,
    }


class FakePiHole:
    def __init__(self):
        self.denied, self.undenied = [], []

    def deny(self, domain, comment):
        self.denied.append(domain)

    def undeny(self, domain):
        self.undenied.append(domain)


def fake_run_ok(cmd, **kw):
    args = cmd[next(i for i, x in enumerate(cmd) if x.endswith('ufw')) + 1:]
    if args == ['status']:
        return types.SimpleNamespace(returncode=0, stdout='Status: active\n', stderr='')
    return types.SimpleNamespace(returncode=0, stdout='', stderr='')


class Base(unittest.TestCase):
    def setUp(self):
        self.ctx = appmod.app.app_context()
        self.ctx.push()
        db.create_all()
        self.pihole = FakePiHole()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.ctx.pop()

    def threat(self, url='http://203.0.113.9/bin.sh', **kw):
        t = Threat(url=url, type=kw.pop('type', 'malware-url'), severity=kw.pop('severity', 'critical'), status='active')
        db.session.add(t)
        db.session.commit()
        return t


class Eligibility(Base):
    def test_weak_consensus_is_not_proposed(self):
        t = self.threat()
        for bad in (malicious(confidence=50), malicious(ai_count=1), malicious(severity='MEDIUM'),
                    {'consensus_verdict': 'suspicious', 'confidence': 99, 'ai_count': 5, 'consensus_severity': 'CRITICAL'},
                    None, 'not a dict'):
            self.assertIsNone(RQ.propose(t, bad), repr(bad)[:50])
        self.assertEqual(PendingRemediation.query.count(), 0)

    def test_strong_consensus_on_a_blockable_ip_is_proposed(self):
        t = self.threat()
        row = RQ.propose(t, malicious())
        self.assertIsNotNone(row)
        self.assertEqual(row.status, 'pending')
        self.assertEqual(row.kind, 'ip')
        self.assertEqual(row.target, '203.0.113.9')
        self.assertIn('malicious/CRITICAL', row.reason)

    def test_masked_lan_address_is_never_proposed(self):
        t = self.threat(url='192.168.xxx.xxx', type='suspicious-port')
        self.assertIsNone(RQ.propose(t, malicious()))
        self.assertEqual(PendingRemediation.query.count(), 0)

    def test_never_block_ip_is_refused_even_with_strong_consensus(self):
        t = self.threat(url='203.0.113.9')
        self.assertIsNone(RQ.propose(t, malicious(), never_block_ips={'203.0.113.9'}))

    def test_duplicate_target_does_not_queue_twice(self):
        t1 = self.threat(url='203.0.113.9')
        t2 = self.threat(url='http://203.0.113.9/other.sh')
        row1 = RQ.propose(t1, malicious())
        row2 = RQ.propose(t2, malicious())
        self.assertIsNotNone(row1)
        self.assertIsNone(row2)
        self.assertEqual(PendingRemediation.query.count(), 1)

    def test_domain_target_is_proposed(self):
        t = self.threat(url='http://evil-test.example.com/x', type='malicious-domain')
        row = RQ.propose(t, malicious())
        self.assertEqual(row.kind, 'domain')
        self.assertEqual(row.target, 'evil-test.example.com')


class ApproveReject(Base):
    def test_approve_blocks_for_real_and_sets_a_ttl(self):
        t = self.threat()
        row = RQ.propose(t, malicious())
        got, detail = RQ.approve_proposal(row.id, decided_by='1.2.3.4', ttl_hours=48, run=fake_run_ok)
        self.assertEqual(got.status, 'approved')
        self.assertEqual(got.decided_by, '1.2.3.4')
        self.assertIsNotNone(got.expires_at)
        self.assertIn('inbound and outbound', detail)
        self.assertEqual(Threat.query.get(t.id).status, 'blocked')

    def test_approve_domain_uses_pihole(self):
        t = self.threat(url='http://evil-test.example.com/x', type='malicious-domain')
        row = RQ.propose(t, malicious())
        RQ.approve_proposal(row.id, decided_by='1.2.3.4', pihole=self.pihole)
        self.assertEqual(self.pihole.denied, ['evil-test.example.com'])

    def test_approve_twice_is_refused(self):
        t = self.threat()
        row = RQ.propose(t, malicious())
        RQ.approve_proposal(row.id, decided_by='a', run=fake_run_ok)
        with self.assertRaises(ValueError):
            RQ.approve_proposal(row.id, decided_by='a', run=fake_run_ok)

    def test_reject_leaves_the_threat_untouched(self):
        t = self.threat()
        row = RQ.propose(t, malicious())
        got = RQ.reject_proposal(row.id, decided_by='1.2.3.4')
        self.assertEqual(got.status, 'rejected')
        self.assertEqual(Threat.query.get(t.id).status, 'active')

    def test_approve_failure_leaves_the_row_pending(self):
        t = self.threat()
        row = RQ.propose(t, malicious())

        def fail_run(cmd, **kw):
            return types.SimpleNamespace(returncode=1, stdout='', stderr='ufw refused')

        with self.assertRaises(R.RemediationError):
            RQ.approve_proposal(row.id, decided_by='a', run=fail_run)
        self.assertEqual(PendingRemediation.query.get(row.id).status, 'pending')


class Sweep(Base):
    def test_stale_pending_proposals_expire(self):
        t = self.threat()
        row = RQ.propose(t, malicious())
        row.proposed_at = datetime.now(timezone.utc) - timedelta(hours=RQ.PENDING_TTL_HOURS + 1)
        db.session.commit()
        result = RQ.sweep(run=fake_run_ok)
        self.assertEqual(result['expired'], 1)
        self.assertEqual(PendingRemediation.query.get(row.id).status, 'expired')

    def test_fresh_pending_proposal_is_not_swept(self):
        t = self.threat()
        row = RQ.propose(t, malicious())
        result = RQ.sweep(run=fake_run_ok)
        self.assertEqual(result['expired'], 0)
        self.assertEqual(PendingRemediation.query.get(row.id).status, 'pending')

    def test_expired_ttl_on_an_approved_block_auto_reverts(self):
        t = self.threat()
        row = RQ.propose(t, malicious())
        RQ.approve_proposal(row.id, decided_by='a', ttl_hours=1, run=fake_run_ok)
        got = PendingRemediation.query.get(row.id)
        got.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        db.session.commit()
        result = RQ.sweep(run=fake_run_ok)
        self.assertEqual(result['rolled_back'], 1)
        self.assertEqual(PendingRemediation.query.get(row.id).status, 'rolled_back')
        self.assertEqual(Threat.query.get(t.id).status, 'active')

    def test_approved_block_without_expiry_is_never_swept(self):
        t = self.threat()
        row = RQ.propose(t, malicious())
        RQ.approve_proposal(row.id, decided_by='a', ttl_hours=0, run=fake_run_ok)
        self.assertIsNone(PendingRemediation.query.get(row.id).expires_at)
        result = RQ.sweep(run=fake_run_ok)
        self.assertEqual(result['rolled_back'], 0)
        self.assertEqual(PendingRemediation.query.get(row.id).status, 'approved')

    def test_rollback_failure_is_reported_and_row_stays_approved(self):
        t = self.threat()
        row = RQ.propose(t, malicious())
        RQ.approve_proposal(row.id, decided_by='a', ttl_hours=1, run=fake_run_ok)
        got = PendingRemediation.query.get(row.id)
        got.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        db.session.commit()

        def fail_run(cmd, **kw):
            args = cmd[next(i for i, x in enumerate(cmd) if x.endswith('ufw')) + 1:]
            if args == ['status']:
                return types.SimpleNamespace(returncode=0, stdout='Status: active\n', stderr='')
            return types.SimpleNamespace(returncode=1, stdout='', stderr='ufw refused')

        result = RQ.sweep(run=fail_run)
        self.assertEqual(result['rolled_back'], 0)
        self.assertEqual(len(result['errors']), 1)
        self.assertEqual(PendingRemediation.query.get(row.id).status, 'approved')


if __name__ == '__main__':
    unittest.main(verbosity=2)
