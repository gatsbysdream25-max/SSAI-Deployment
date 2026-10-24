#!/usr/bin/env python3
"""Phase 7 of the consensus plan: bounded autonomy. A person grants one narrow permission; SSAI enforces its limits; everything
else waits in the approval queue. With no grant, behaviour is exactly as before.
Run:  swarmsentinel-env/bin/python3 backend/tools/test_autonomy.py"""
import json
import os
import sys
import tempfile
import time
import types
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

_TMP = tempfile.mkdtemp()
os.environ['DATA_DIR'] = _TMP
os.environ['DATABASE_URL'] = 'sqlite:///' + os.path.join(_TMP, 'autonomy-test.db')
os.environ['SSAI_API_KEY'] = ADMIN = 'autonomy-test-admin-key'
os.environ['SSAI_PROVIDER_CHECK'] = '0'
os.environ['SSAI_STATE_DB'] = os.path.join(_TMP, 'state.db')

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
sys.path[:0] = [BACKEND, os.path.join(BACKEND, 'agents')]

import app as appmod  # noqa: E402
import autonomy  # noqa: E402
import remediation  # noqa: E402
import remediation_queue as RQ  # noqa: E402
import sso  # noqa: E402
from models import AutonomyGrant, PendingRemediation, Threat, db  # noqa: E402

PERSON, CSRF = 'dana@example.org', 'csrf-for-the-test'
GOOD = {'category': 'malicious-domain', 'action': 'block-domain', 'severities': ['low', 'medium'], 'min_confidence': 90,
        'min_ai_count': 3, 'rate_limit_per_hour': 2, 'ttl_hours': 12, 'days': 30}


def fake_run_ok(cmd, **kw):
    return types.SimpleNamespace(returncode=0, stdout='Status: active\n', stderr='')


class FakePiHole:
    def __init__(self):
        self.denied = []

    def deny(self, domain, comment):
        self.denied.append(domain)

    def undeny(self, domain):
        pass


def verdict(**kw):
    base = {'consensus_verdict': 'malicious', 'consensus_severity': 'MEDIUM', 'confidence': 95, 'ai_count': 4,
            'ai_sources': ['a', 'b', 'c', 'd'], 'quorum': {'degraded': False}, 'panel_mode': 'primary',
            'evidence': {'status': 'verified', 'conflict': False}, 'verification': {'status': 'confirmed'}}
    base.update(kw)
    return base


class Base(unittest.TestCase):
    def setUp(self):
        self.ctx = appmod.app.app_context()
        self.ctx.push()
        db.create_all()
        self.audit = os.path.join(_TMP, f'audit-{time.time_ns()}.jsonl')
        self.pihole = FakePiHole()
        appmod._AUDIT_PATH = self.audit
        patch = mock.patch.object(remediation, 'block', lambda target, threat_id, **kw: self.pihole.deny(target['value'], 'x') or 'blocked')
        patch.start()
        self.addCleanup(patch.stop)

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.ctx.pop()

    def threat(self, url='http://evil-test.example.com/x', type_='malicious-domain', severity='medium'):
        t = Threat(url=url, type=type_, severity=severity, status='active')
        db.session.add(t)
        db.session.commit()
        return t

    def grant(self, **kw):
        kw.setdefault('allow_unverified', True)          # most tests are about other limits; proof has its own tests below
        fields, problem = autonomy.validate_new(dict(GOOD, **kw))
        self.assertEqual(problem, '')
        g = AutonomyGrant(granted_by='dana@example.org @ 127.0.0.1', **fields)
        db.session.add(g)
        db.session.commit()
        return g

    def audit_lines(self):
        try:
            with open(self.audit, encoding='utf-8') as f:
                return [json.loads(x) for x in f if x.strip()]
        except OSError:
            return []


class Acting(Base):
    def test_with_no_grant_a_medium_finding_is_not_even_proposed(self):
        self.assertIsNone(RQ.propose(self.threat(), verdict()))
        self.assertEqual(PendingRemediation.query.count(), 0)

    def test_a_covered_finding_is_blocked_by_itself_and_leaves_a_trail(self):
        g = self.grant()
        row = RQ.propose(self.threat(), verdict())
        self.assertEqual(row.status, 'approved')
        self.assertEqual(row.decided_by, f'auto:grant-{g.id}')
        self.assertEqual(self.pihole.denied, ['evil-test.example.com'])
        self.assertIsNotNone(row.expires_at)                                         # it will be undone
        stages = [(x['action'], x.get('stage'), x.get('grant')) for x in self.audit_lines()]
        self.assertEqual(stages, [('approve', 'intent', g.id), ('approve', None, g.id)])    # intent written first

    def test_each_limit_sends_the_finding_to_a_person_instead(self):
        self.grant()
        cases = {
            'degraded': verdict(quorum={'degraded': True}),
            'stand-in panel': verdict(panel_mode='fallback'),
            'injection': verdict(quorum={'degraded': False, 'injection': ['ignore-instructions']}),
            'disputed': verdict(verification={'status': 'disputed'}),
            'low confidence': verdict(confidence=85),
            'too few models': verdict(ai_count=2),
            'severity not covered': verdict(consensus_severity='HIGH'),
        }
        for name, c in cases.items():
            row = RQ.propose(self.threat(url=f'http://{name.replace(" ", "-")}.example.com/'), c)
            self.assertTrue(row is None or row.status == 'pending', name)       # never approved on its own
        self.assertEqual(self.pihole.denied, [])

    def test_a_different_category_or_action_is_not_covered(self):
        self.grant()
        row = RQ.propose(self.threat(type_='port-scan'), verdict())
        self.assertIsNone(row)                                                     # medium + no matching grant: not proposed at all
        ip = RQ.propose(self.threat(url='http://203.0.113.9/x'), verdict())       # an IP, but the grant is for domains
        self.assertIsNone(ip)

    def test_an_internal_address_is_never_blocked_even_under_a_grant(self):
        self.grant(category='port-scan', action='block-ip')
        t = self.threat(url='192.168.0.40', type_='port-scan')
        self.assertIsNone(RQ.propose(t, verdict()))
        self.assertEqual(self.pihole.denied, [])

    def test_the_rate_limit_stops_the_third_block_in_an_hour(self):
        self.grant(rate_limit_per_hour=2)
        done = [RQ.propose(self.threat(url=f'http://evil{i}.example.com/'), verdict()) for i in range(3)]
        self.assertEqual([r is not None and r.status == 'approved' for r in done], [True, True, False])

    def test_an_expired_or_revoked_grant_does_nothing(self):
        g = self.grant()
        g.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        db.session.commit()
        self.assertIsNone(RQ.propose(self.threat(), verdict()))
        g.expires_at = datetime.now(timezone.utc) + timedelta(days=1)
        g.revoked_at = datetime.now(timezone.utc)
        db.session.commit()
        self.assertIsNone(RQ.propose(self.threat(url='http://other.example.com/'), verdict()))

    def test_if_the_audit_cannot_be_written_nothing_is_blocked_and_the_proposal_waits(self):
        self.grant()
        broken = os.path.join(_TMP, 'file-not-folder')
        open(broken, 'w').close()
        appmod._AUDIT_PATH = os.path.join(broken, 'audit.jsonl')
        row = RQ.propose(self.threat(), verdict())
        self.assertEqual(row.status, 'pending')
        self.assertEqual(self.pihole.denied, [])

    def test_a_failed_block_leaves_the_proposal_for_a_person(self):
        self.grant()
        with mock.patch.object(remediation, 'block', side_effect=remediation.RemediationError('pihole down')):
            row = RQ.propose(self.threat(), verdict())
        self.assertEqual(row.status, 'pending')

    def test_a_forged_verdict_cannot_supply_its_own_local_proof(self):
        self.grant(allow_unverified=False)
        forged = verdict(evidence={'status': 'verified', 'conflict': False}, ai_count=5, confidence=100)
        row = RQ.propose(self.threat(), forged)                                      # no feed hit or second detector exists on the hub
        self.assertIsNone(row)
        self.assertEqual(self.pihole.denied, [])

    def test_real_local_proof_on_the_hub_does_allow_it(self):
        self.grant(allow_unverified=False)
        t = self.threat()
        db.session.add(Threat(url=t.url, type='malicious-domain', severity='low', status='active', detected_by='IntelFeedAgent'))
        db.session.commit()
        row = RQ.propose(t, verdict(evidence={'status': 'unverified'}))             # the verdict's own claim is ignored; the hub's data decides
        self.assertEqual(row.status, 'approved')

    def test_a_broken_autonomy_check_means_ask_a_person(self):
        with mock.patch('models.AutonomyGrant.query', side_effect=RuntimeError('db')):
            self.assertEqual(autonomy.matching_grant(self.threat(), verdict(), {'kind': 'domain', 'value': 'x.example.com'})[0], None)


class Creating(unittest.TestCase):
    def test_a_grant_must_be_narrow_and_must_end(self):
        bad = {'wildcard': dict(GOOD, category='*'), 'no category': dict(GOOD, category=''), 'odd action': dict(GOOD, action='format-disk'),
               'low confidence': dict(GOOD, min_confidence=60), 'two models': dict(GOOD, min_ai_count=2),
               'too fast': dict(GOOD, rate_limit_per_hour=500), 'forever': dict(GOOD, days=3650), 'never undone': dict(GOOD, ttl_hours=0),
               'not numbers': dict(GOOD, min_confidence='high'), 'severe without the sentence': dict(GOOD, severities=['high']),
               'severe half-confirmed': dict(GOOD, severities=['critical'], allow_severe=True)}
        for name, data in bad.items():
            fields, problem = autonomy.validate_new(data)
            self.assertIsNone(fields, name)
            self.assertTrue(problem, name)

    def test_severe_findings_need_the_typed_sentence_and_the_flag(self):
        fields, problem = autonomy.validate_new(dict(GOOD, severities=['high'], allow_severe=True, confirmation=autonomy.SEVERE_CONFIRMATION))
        self.assertEqual(problem, '')
        self.assertIn('high', fields['severities'])

    def test_an_infinite_number_is_a_clear_refusal_not_a_crash(self):
        fields, problem = autonomy.validate_new(dict(GOOD, days=float('inf'), min_confidence=float('inf')))
        self.assertIsNone(fields)
        self.assertTrue(problem)

    def test_proof_is_required_unless_the_person_says_otherwise(self):
        self.assertTrue(autonomy.validate_new(GOOD)[0]['require_verified'])
        self.assertFalse(autonomy.validate_new(dict(GOOD, allow_unverified=True))[0]['require_verified'])


class Api(Base):
    def setUp(self):
        super().setUp()
        self.c = appmod.app.test_client()
        for p in (mock.patch.object(sso, 'is_admin_subject', lambda subject, cfg=None: subject == PERSON), mock.patch.object(sso, 'only', lambda: False)):
            p.start()
            self.addCleanup(p.stop)

    def sign_in(self):
        with self.c.session_transaction() as s:
            s.update({'adm': True, 'iat': int(time.time()), 'sso': PERSON, 'csrf': CSRF})

    def test_an_api_key_cannot_grant_authority(self):
        r = self.c.post('/api/autonomy/grants', json=GOOD, headers={'X-API-Key': ADMIN})
        self.assertEqual(r.status_code, 403)
        self.assertEqual(AutonomyGrant.query.count(), 0)

    def test_a_signed_in_person_grants_it_by_name_and_it_is_recorded_first(self):
        self.sign_in()
        r = self.c.post('/api/autonomy/grants', json=GOOD, headers={'X-CSRF-Token': CSRF})
        self.assertEqual(r.status_code, 201)
        self.assertTrue(r.get_json()['grant']['granted_by'].startswith(PERSON))
        self.assertEqual(self.audit_lines()[0]['action'], 'grant-permission')

    def test_a_bad_request_is_explained_not_stored(self):
        self.sign_in()
        r = self.c.post('/api/autonomy/grants', json=dict(GOOD, category='*'), headers={'X-CSRF-Token': CSRF})
        self.assertEqual(r.status_code, 400)
        self.assertIn('wildcards', r.get_json()['error'])
        self.assertEqual(AutonomyGrant.query.count(), 0)

    def test_revoking_is_easy_and_stops_it_at_once(self):
        g = self.grant()
        r = self.c.post(f'/api/autonomy/grants/{g.id}/revoke', headers={'X-API-Key': ADMIN})
        self.assertEqual(r.status_code, 200)
        self.assertIsNotNone(r.get_json()['grant']['revoked_at'])
        self.assertIsNone(RQ.propose(self.threat(), verdict()))

    def test_listing_shows_the_grants_and_what_they_can_never_do(self):
        self.grant()
        body = self.c.get('/api/autonomy/grants', headers={'X-API-Key': ADMIN}).get_json()
        self.assertEqual(len(body['grants']), 1)
        self.assertTrue(any('no number of agreeing models' in x for x in body['what_a_grant_cannot_do']))
        self.assertEqual(self.c.get('/api/autonomy/grants').status_code, 401)


if __name__ == '__main__':
    unittest.main()
