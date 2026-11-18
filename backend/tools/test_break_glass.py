#!/usr/bin/env python3
"""Break-glass and the never-pause list (Week 1, 2026-11-17).

  * no state file: not engaged; an unreadable or invalid file: ENGAGED (when in doubt, stop acting alone)
  * engaging and releasing are audited BEFORE the switch changes; a failed audit line changes nothing
  * while engaged: auto_response does nothing (not even dry-run rows) and autonomy grants approve nothing
  * a LIVE action hitting the hourly cap engages it by itself; a dry run never does
  * the admin key may engage; only a signed-in person may release
  * a program on the never-pause list is never paused automatically

SAFETY: no test may run a real firewall, Pi-hole call or signal (guards below). Documentation addresses only.
Run:  swarmsentinel-env/bin/python3 backend/tools/test_break_glass.py"""
import json
import os
import stat
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

_TMP = tempfile.mkdtemp()
os.environ['DATA_DIR'] = _TMP
os.environ['DATABASE_URL'] = 'sqlite:///' + os.path.join(_TMP, 'break-glass-test.db')
os.environ['SSAI_API_KEY'] = ADMIN = 'break-glass-test-admin-key'
os.environ['SSAI_PROVIDER_CHECK'] = '0'
os.environ['SSAI_STATE_DB'] = os.path.join(_TMP, 'state.db')

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
sys.path[:0] = [BACKEND, os.path.join(BACKEND, 'agents')]

import app as appmod  # noqa: E402
import auto_response as AR  # noqa: E402
import autonomy  # noqa: E402
import break_glass as BG  # noqa: E402
import remediation  # noqa: E402
import sso  # noqa: E402
from models import AutoAction, AutonomyGrant, Threat, db  # noqa: E402

PERSON, CSRF = 'dana@example.org', 'csrf-for-the-test'
NOW = datetime(2026, 11, 17, 12, 0, tzinfo=timezone.utc)
_GUARDS = []


def _forbidden(name):
    def boom(*a, **k):
        raise AssertionError(f'a test reached the REAL {name}')
    return boom


def setUpModule():
    for target, name in ((os, 'kill'), (remediation, 'block'), (remediation, 'unblock')):
        p = mock.patch.object(target, name, _forbidden(f'{target.__name__}.{name}'))
        p.start()
        _GUARDS.append(p)
    p = mock.patch('subprocess.run', _forbidden('subprocess.run'))
    p.start()
    _GUARDS.append(p)


def tearDownModule():
    for p in _GUARDS:
        p.stop()


def policy(dry_run=False):
    pol = AR.defaults()
    pol['enabled'], pol['dry_run'] = True, dry_run
    for a in AR.ACTIONS:
        pol['actions'][a] = {'enabled': True, 'hours': 24}
    return pol


class Fake:
    def __init__(self, cmdline='/tmp/x/xmrig --donate-level 1'):
        self.calls, self.cmd = [], cmdline

    def deps(self):
        return AR.Deps(block=lambda t, tid: self.calls.append(('block', t['value'])) or 'blocked (fake)',
                       unblock=lambda t: self.calls.append(('unblock', t['value'])),
                       kill=lambda pid, sig: self.calls.append(('kill', pid, sig)),
                       check=lambda facts: {'result': 'confirmed', 'check': 'fake', 'detail': 'fake check'},
                       read_cmdline=lambda pid: self.cmd, proc_uid=lambda pid: 1000, fail_count=lambda ip: 25,
                       never_block={'192.0.2.1'}, own_pids={'1'})


class Base(unittest.TestCase):
    def setUp(self):
        self.ctx = appmod.app.app_context()
        self.ctx.push()
        db.create_all()
        self.audit = os.path.join(_TMP, f'audit-{time.time_ns()}.jsonl')
        appmod._AUDIT_PATH = self.audit
        self.glass = os.path.join(_TMP, f'glass-{time.time_ns()}.json')
        for p in (mock.patch.object(BG, 'state_path', lambda: self.glass),
                  mock.patch.object(AR, 'policy_path', lambda: os.path.join(_TMP, 'no-policy.json'))):
            p.start()
            self.addCleanup(p.stop)

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.ctx.pop()

    def threat(self, type_='intel-match', url='203.0.113.9', description='listed by feodo'):
        # Week 2: only LOW findings are acted on when they arrive (action_risk.py); these tests are about break-glass.
        t = Threat(url=url, type=type_, severity='low', status='active', description=description,
                   detected_by='SocketWatchAgent')
        db.session.add(t)
        db.session.commit()
        return t

    def run_on(self, t, fake=None, pol=None):
        fake = fake or Fake()
        return AR.on_finding(t, 'admin', self.audit, deps=fake.deps(), policy=pol or policy(), now=NOW), fake

    def audit_lines(self):
        try:
            with open(self.audit, encoding='utf-8') as f:
                return [json.loads(x) for x in f if x.strip()]
        except OSError:
            return []

    def write_state(self, text):
        with open(self.glass, 'w', encoding='utf-8') as f:
            f.write(text)


class State(Base):
    def test_no_file_means_not_engaged(self):
        self.assertFalse(BG.engaged())

    def test_an_unreadable_or_invalid_file_means_engaged(self):
        for text in ('{not json', '[1, 2]', '"off"', 'null', '{}', '{"engaged": "false"}'):
            self.write_state(text)
            self.assertTrue(BG.engaged(), text)

    def test_only_a_literal_false_means_released(self):
        self.write_state('{"engaged": false, "by": "dana"}')
        self.assertFalse(BG.engaged())

    def test_engage_and_release_are_audited_first_and_the_file_is_owner_only(self):
        BG.engage('dana @ 198.51.100.7', 'testing', self.audit)
        self.assertTrue(BG.engaged())
        self.assertEqual(stat.S_IMODE(os.stat(self.glass).st_mode), 0o600)
        BG.release('dana @ 198.51.100.7', self.audit)
        self.assertFalse(BG.engaged())
        self.assertEqual([(a['action'], a['stage']) for a in self.audit_lines()],
                         [('break-glass', 'engage'), ('break-glass', 'release')])

    def test_a_failed_audit_line_changes_nothing(self):
        with mock.patch.object(remediation, 'audit_before_acting', side_effect=remediation.RemediationError('disk full')):
            with self.assertRaises(remediation.RemediationError):
                BG.engage('dana', 'testing', self.audit)
        self.assertFalse(os.path.exists(self.glass))


class Stops(Base):
    def test_engaged_means_no_automatic_response_not_even_dry_run(self):
        BG.engage('dana', 'testing', self.audit)
        for pol in (policy(), policy(dry_run=True)):
            row, fake = self.run_on(self.threat(), pol=pol)
            self.assertIsNone(row)
            self.assertEqual(fake.calls, [])
        self.assertEqual(AutoAction.query.count(), 0)

    def test_released_means_the_normal_rules_apply_again(self):
        BG.engage('dana', 'testing', self.audit)
        BG.release('dana', self.audit)
        row, fake = self.run_on(self.threat())
        self.assertEqual(row.status, 'done')
        self.assertEqual(fake.calls, [('block', '203.0.113.9')])

    def grant(self):
        g = AutonomyGrant(category='malicious-domain', action='block-domain', severities='low,medium', min_confidence=90,
                          min_ai_count=3, require_verified=False, ttl_hours=12, rate_limit_per_hour=5,
                          expires_at=datetime.now(timezone.utc) + timedelta(days=1), granted_by='dana')
        db.session.add(g)
        db.session.commit()
        return g

    def test_engaged_means_no_autonomy_grant_matches(self):
        self.grant()
        BG.engage('dana', 'testing', self.audit)
        t = self.threat('malicious-domain', 'evil.example.com')
        grant, why = autonomy.matching_grant(t, {'consensus_verdict': 'malicious'}, {'kind': 'domain', 'value': 'evil.example.com'})
        self.assertIsNone(grant)
        self.assertIn('break-glass', why)

    def test_engaged_at_the_moment_of_acting_stops_a_grant_too(self):
        g = self.grant()
        BG.engage('dana', 'testing', self.audit)
        approve = mock.Mock()
        self.assertIsNone(autonomy.act(mock.Mock(id=1, kind='domain', target='evil.example.com'), g, self.audit, approve=approve))
        approve.assert_not_called()


class Cap(Base):
    def fill_the_hour(self):
        for i in range(AR.HOURLY_CAP):
            db.session.add(AutoAction(action='block-bad-ip', kind='ip', target=f'198.51.100.{i}', status='done',
                                      created_at=NOW - timedelta(minutes=5)))
        db.session.commit()

    def test_a_live_action_at_the_cap_engages_break_glass(self):
        self.fill_the_hour()
        self.assertIsNone(self.run_on(self.threat())[0])
        self.assertTrue(BG.engaged())
        self.assertEqual(BG.status()['by'], 'auto: hourly cap')
        self.assertIn(('break-glass', 'engage'), [(a['action'], a.get('stage')) for a in self.audit_lines()])

    def test_a_dry_run_at_the_cap_does_not(self):
        self.fill_the_hour()
        self.assertIsNone(self.run_on(self.threat(), pol=policy(dry_run=True))[0])
        self.assertFalse(BG.engaged())

    def test_autonomy_at_the_cap_engages_it_too(self):
        Stops.grant(self)
        for i in range(AR.HOURLY_CAP):
            db.session.add(AutoAction(action='block-bad-ip', kind='ip', target=f'198.51.100.{i}', status='done'))
        db.session.commit()
        t = self.threat('malicious-domain', 'evil.example.com')
        grant, why = autonomy.matching_grant(t, {'consensus_verdict': 'malicious'}, {'kind': 'domain', 'value': 'evil.example.com'})
        self.assertIsNone(grant)
        self.assertIn('cap of 10', why)
        self.assertTrue(BG.engaged())


class NeverPause(Base):
    def proc(self, pid='4242'):
        return self.threat('suspicious-process', f'process://{pid}',
                           f'Suspicious process detected (xmrig): alice {pid} /tmp/x/xmrig --donate-level 1')

    def test_a_program_on_the_default_list_is_not_paused(self):
        for cmd in ('/usr/lib/postgresql/16/bin/postgres -D /var/lib/postgresql', '/usr/local/bin/ollama serve'):
            fake = Fake(cmdline=cmd)
            self.assertIsNone(self.run_on(self.proc(), fake)[0], cmd)
            self.assertEqual(fake.calls, [])

    def test_ssai_never_pause_adds_names(self):
        with mock.patch.dict(os.environ, {'SSAI_NEVER_PAUSE': 'LabTool, other'}):
            self.assertIn('labtool', AR.never_pause_names())
            fake = Fake(cmdline='/opt/labtool --run')
            row = AR.on_finding(self.proc(), 'admin', self.audit, deps=fake.deps(), policy=policy(), now=NOW)
        self.assertIsNone(row)
        self.assertEqual(fake.calls, [])

    def test_an_ordinary_miner_is_still_paused(self):
        row, fake = self.run_on(self.proc())
        self.assertEqual(row.status, 'done')
        self.assertEqual(len([c for c in fake.calls if c[0] == 'kill']), 1)


class Routes(Base):
    def setUp(self):
        super().setUp()
        self.c = appmod.app.test_client()
        for p in (mock.patch.object(sso, 'is_admin_subject', lambda subject, cfg=None: subject == PERSON),
                  mock.patch.object(sso, 'only', lambda: False)):
            p.start()
            self.addCleanup(p.stop)

    def sign_in(self):
        with self.c.session_transaction() as s:
            s.update({'adm': True, 'iat': int(time.time()), 'sso': PERSON, 'csrf': CSRF})

    def test_anonymous_callers_are_refused(self):
        self.assertEqual(self.c.get('/api/auto/break-glass').status_code, 401)
        self.assertEqual(self.c.post('/api/auto/break-glass/engage', json={}).status_code, 401)
        self.assertFalse(BG.engaged())

    def test_the_admin_key_may_engage_but_not_release(self):
        h = {'X-API-Key': ADMIN}
        r = self.c.post('/api/auto/break-glass/engage', json={'reason': 'something looks wrong'}, headers=h)
        self.assertEqual(r.status_code, 200)
        self.assertTrue(BG.engaged())
        self.assertEqual(BG.status()['reason'], 'something looks wrong')
        self.assertEqual(self.c.post('/api/auto/break-glass/release', json={}, headers=h).status_code, 403)
        self.assertTrue(BG.engaged())
        self.assertTrue(self.c.get('/api/auto/settings', headers=h).get_json()['break_glass']['engaged'])

    def test_a_signed_in_person_releases_it(self):
        BG.engage('admin key', 'testing', self.audit)
        self.sign_in()
        r = self.c.post('/api/auto/break-glass/release', json={}, headers={'X-CSRF-Token': CSRF})
        self.assertEqual(r.status_code, 200, r.get_json())
        self.assertFalse(BG.engaged())
        self.assertIn(PERSON, self.audit_lines()[-1]['by'])


if __name__ == '__main__':
    unittest.main()
