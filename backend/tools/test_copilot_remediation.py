#!/usr/bin/env python3
"""Approving remediation from Teams (2026-09-30): only a named approver's genuine Entra token, together with the Copilot
lane key, may approve or reject; nothing private leaves in the list; every decision is audited.
Run:  swarmsentinel-env/bin/python3 backend/tools/test_copilot_remediation.py"""
import json
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

_TMP = tempfile.mkdtemp()
os.environ['DATA_DIR'] = _TMP
os.environ['DATABASE_URL'] = f'sqlite:///{_TMP}/teams-test.db'
os.environ['SSAI_API_KEY'] = ADMIN = 'teams-test-admin-key'
os.environ['SSAI_COPILOT_KEY'] = LANE = 'teams-test-lane-key-0123456789'
os.environ['SSAI_PROVIDER_CHECK'] = '0'
TENANT = '11111111-2222-3333-4444-555555555555'
APP = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
APPROVER = '99999999-8888-7777-6666-000000000001'
STRANGER = '99999999-8888-7777-6666-000000000002'
CONFIG = {'SSAI_COPILOT_TENANT_ID': TENANT, 'SSAI_COPILOT_AUDIENCE': f'{APP},api://ssai.example/{APP}',
          'SSAI_COPILOT_APPROVERS': f'{APPROVER}, 99999999-8888-7777-6666-00000000000f'}

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
sys.path[:0] = [os.path.join(BACKEND, 'agents'), BACKEND]

import jwt  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def hs256_with_public_key():
    """The classic algorithm-confusion forgery: HMAC-signed with the RSA public key as the secret (PyJWT refuses to
    build it, so it is assembled by hand)."""
    import base64
    import hashlib
    import hmac
    from cryptography.hazmat.primitives import serialization

    def b64(b):
        return base64.urlsafe_b64encode(b).rstrip(b'=').decode()
    now = int(time.time())
    head = b64(json.dumps({'alg': 'HS256', 'typ': 'JWT', 'kid': 'k1'}).encode())
    body = b64(json.dumps({'iss': f'https://login.microsoftonline.com/{TENANT}/v2.0', 'aud': APP, 'tid': TENANT,
                           'oid': APPROVER, 'iat': now, 'exp': now + 3600}).encode())
    pem = KEY.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    sig = b64(hmac.new(pem, f'{head}.{body}'.encode(), hashlib.sha256).digest())
    return f'{head}.{body}.{sig}'


def token(key=KEY, alg='RS256', **over):
    now = int(time.time())
    claims = {'iss': f'https://login.microsoftonline.com/{TENANT}/v2.0', 'aud': APP, 'tid': TENANT, 'oid': APPROVER,
              'name': 'Pat Approver', 'iat': now, 'nbf': now, 'exp': now + 3600}
    claims.update(over)
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, key, algorithm=alg, headers={'kid': 'k1'})


class Teams(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import app as appmod
        if _TMP not in appmod.app.config['SQLALCHEMY_DATABASE_URI']:
            raise RuntimeError('refusing to run against a non-test database')
        cls.app, cls.db = appmod.app, appmod.db
        cls.app.config['TESTING'] = True
        appmod._AUDIT_PATH = cls.audit = os.path.join(_TMP, 'audit.jsonl')

    def setUp(self):
        import entra
        import remediation_queue
        from models import PendingRemediation, Threat
        from routes import copilot
        self.ctx = self.app.app_context()
        self.ctx.push()
        self.db.create_all()
        PendingRemediation.query.delete()
        Threat.query.delete()
        rows = [('1.2.3.4', 'ip', 'malware-url', 'critical'), ('192.168.0.44', 'ip', 'c2-beacon', 'high'),
                ('evil-downloads.example.com', 'domain', 'malicious-domain', 'high')]
        self.ids = []
        for target, kind, typ, sev in rows:
            t = Threat(url=target, type=typ, severity=sev, description='x', status='active')
            self.db.session.add(t)
            self.db.session.flush()
            p = PendingRemediation(threat_id=t.id, kind=kind, target=target, status='pending', confidence=90,
                                   reason=f'malicious/CRITICAL at 90% confidence, seen talking to {target} from 192.168.0.9')
            self.db.session.add(p)
            self.db.session.flush()
            self.ids.append(p.id)
        self.db.session.commit()
        self.blocks = []
        for p in (mock.patch.dict(os.environ, CONFIG),
                  mock.patch.object(entra, '_signing_key', lambda tok, url: KEY.public_key()),
                  mock.patch.object(remediation_queue.remediation, 'block',
                                    lambda target, tid, **kw: self.blocks.append(target) or 'blocked'),
                  mock.patch.object(copilot, 'teams_failures', copilot.auth.SlidingWindow(10, 300))):
            p.start()
            self.addCleanup(p.stop)
        if os.path.exists(self.audit):
            os.remove(self.audit)

    def tearDown(self):
        self.db.session.remove()
        self.ctx.pop()

    def c(self):
        return self.app.test_client()

    def decide(self, i, action='approve', tok=None, lane=True, extra=None):
        headers = dict(extra or {})
        if lane:
            headers['X-Copilot-Key'] = LANE
        if tok is not None:
            headers['Authorization'] = f'Bearer {tok}'
        return self.c().post(f'/api/copilot/remediation/{self.ids[i]}/{action}', headers=headers)

    def audit_lines(self):
        with open(self.audit) as f:
            return [json.loads(line) for line in f]

    # ── the list ────────────────────────────────────────────────────────────
    def test_list_needs_the_lane_or_admin_key(self):
        self.assertEqual(self.c().get('/api/copilot/remediation').status_code, 401)
        self.assertEqual(self.c().get('/api/copilot/remediation', headers={'X-Copilot-Key': LANE}).status_code, 200)
        self.assertEqual(self.c().get('/api/copilot/remediation', headers={'X-API-Key': ADMIN}).status_code, 200)

    def test_list_shows_attacker_targets_but_never_a_lan_address(self):
        d = self.c().get('/api/copilot/remediation', headers={'X-Copilot-Key': LANE}).get_json()
        self.assertTrue(d['approvals_enabled'])
        targets = [(p['target'], p['target_shown']) for p in d['proposals']]
        self.assertEqual(targets, [('1.2.3.4', True), ('a device on your network', False),
                                   ('evil-downloads.example.com', True)])
        body = json.dumps(d)
        self.assertNotIn('192.168.0.44', body)
        self.assertNotIn('192.168.0.9', body)                  # the reason text goes through the privacy gate too

    def test_list_says_when_approvals_are_off(self):
        with mock.patch.dict(os.environ, {'SSAI_COPILOT_APPROVERS': ''}):
            d = self.c().get('/api/copilot/remediation', headers={'X-Copilot-Key': LANE}).get_json()
        self.assertFalse(d['approvals_enabled'])

    # ── deciding ────────────────────────────────────────────────────────────
    def test_an_approver_can_approve_and_it_is_audited_with_their_identity(self):
        r = self.decide(0, tok=token())
        self.assertEqual(r.status_code, 200, r.get_json())
        d = r.get_json()
        self.assertEqual((d['proposal']['status'], d['proposal']['decided_by']), ('approved', 'Pat Approver'))
        self.assertEqual(self.blocks, [{'kind': 'ip', 'value': '1.2.3.4'}])
        from models import PendingRemediation
        self.assertEqual(PendingRemediation.query.get(self.ids[0]).decided_by, 'teams:Pat Approver')
        line = self.audit_lines()[-1]
        self.assertEqual((line['action'], line['ok'], line['oid']), ('teams-approve', True, APPROVER))

    def test_reject_does_not_block(self):
        r = self.decide(2, 'reject', tok=token())
        self.assertEqual(r.get_json()['proposal']['status'], 'rejected')
        self.assertEqual(self.blocks, [])

    def test_a_v1_token_and_the_api_uri_audience_are_accepted(self):
        tok = token(iss=f'https://sts.windows.net/{TENANT}/', aud=f'api://ssai.example/{APP}')
        self.assertEqual(self.decide(0, tok=tok).status_code, 200)

    def test_every_bad_token_is_refused_and_nothing_is_blocked(self):
        now = int(time.time())
        bad = {
            'no token': None,
            'garbage': 'not.a.token',
            'signed by someone else': token(key=OTHER_KEY),
            'wrong audience': token(aud='some-other-app'),
            'wrong issuer': token(iss='https://login.microsoftonline.com/common/v2.0'),
            'other tenant (iss and tid)': token(iss='https://login.microsoftonline.com/0000/v2.0', tid='0000'),
            'tid differs from iss': token(tid='00000000-0000-0000-0000-000000000000'),
            'expired': token(iat=now - 7200, nbf=now - 7200, exp=now - 3600),
            'not yet valid': token(nbf=now + 3600),
            'not an approver': token(oid=STRANGER),
            'no oid': token(oid=None),
            'app-only token': token(idtyp='app'),
            'HS256 with the public key as secret': hs256_with_public_key(),
            'alg none': jwt.encode({'oid': APPROVER, 'tid': TENANT}, None, algorithm='none'),
        }
        for name, tok in bad.items():
            with self.subTest(name):
                r = self.decide(0, tok=tok)
                self.assertEqual(r.status_code, 403, f'{name}: {r.status_code} {r.get_json()}')
                from routes import copilot
                copilot.teams_failures = copilot.auth.SlidingWindow(10, 300)          # keep the lockout out of this test
        self.assertEqual(self.blocks, [])
        from models import PendingRemediation
        self.assertEqual(PendingRemediation.query.get(self.ids[0]).status, 'pending')
        self.assertTrue(all(not line['ok'] for line in self.audit_lines()))

    def test_the_lane_key_is_required_even_with_a_good_token_and_the_admin_key_is_not_a_substitute(self):
        self.assertEqual(self.decide(0, tok=token(), lane=False).status_code, 401)
        self.assertEqual(self.decide(0, tok=token(), lane=False, extra={'X-API-Key': ADMIN}).status_code, 401)
        self.assertEqual(self.decide(0, tok=None, extra={'X-API-Key': ADMIN}).status_code, 403)
        self.assertEqual(self.blocks, [])

    def test_off_until_configured(self):
        for var in CONFIG:
            with self.subTest(var), mock.patch.dict(os.environ, {var: ''}):
                self.assertEqual(self.decide(0, tok=token()).status_code, 503)
        self.assertEqual(self.blocks, [])

    def test_already_decided_is_a_conflict(self):
        self.assertEqual(self.decide(0, tok=token()).status_code, 200)
        self.assertEqual(self.decide(0, tok=token()).status_code, 409)
        self.assertEqual(self.decide(0, 'reject', tok=token()).status_code, 409)
        self.assertEqual(len(self.blocks), 1)

    def test_repeated_bad_tokens_lock_the_address_out(self):
        for _ in range(10):
            self.decide(0, tok=token(oid=STRANGER))
        self.assertEqual(self.decide(0, tok=token()).status_code, 429)             # even a good token must wait
        self.assertEqual(self.blocks, [])

    def test_a_failed_block_is_reported_and_audited(self):
        import remediation
        import remediation_queue

        def boom(*a, **k):
            raise remediation.RemediationError('ufw said no')
        with mock.patch.object(remediation_queue.remediation, 'block', boom):
            r = self.decide(0, tok=token())
        self.assertEqual(r.status_code, 502)
        self.assertNotIn('ufw', r.get_data(as_text=True))
        self.assertEqual(self.audit_lines()[-1]['error'], 'ufw said no')

    def test_unknown_proposal_is_404(self):
        r = self.c().post('/api/copilot/remediation/999999/approve',
                          headers={'X-Copilot-Key': LANE, 'Authorization': f'Bearer {token()}'})
        self.assertEqual(r.status_code, 404)


if __name__ == '__main__':
    unittest.main(verbosity=2)
