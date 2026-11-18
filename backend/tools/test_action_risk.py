#!/usr/bin/env python3
"""Week 2: the action-risk policy (action_risk.py), the verdict path, the consensus-gated pause, alerts, Keep paused, the pause
fix and the firewall preflight.

SAFETY: no test may run a real firewall, Pi-hole call or signal. setUpModule replaces os.kill, subprocess.run and
remediation.block/unblock with functions that FAIL the test if anything reaches them. Documentation addresses only.
Run:  swarmsentinel-env/bin/python3 backend/tools/test_action_risk.py"""
import json
import os
import signal
import sys
import tempfile
import time
import types
import unittest
from datetime import datetime, timezone
from unittest import mock

_TMP = tempfile.mkdtemp()
os.environ['DATA_DIR'] = _TMP
os.environ['DATABASE_URL'] = 'sqlite:///' + os.path.join(_TMP, 'action-risk-test.db')
os.environ['SSAI_API_KEY'] = ADMIN = 'action-risk-test-admin-key'
os.environ['SSAI_PROVIDER_CHECK'] = '0'
os.environ['SSAI_STATE_DB'] = os.path.join(_TMP, 'state.db')

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
sys.path[:0] = [BACKEND, os.path.join(BACKEND, 'agents')]

import action_risk as R  # noqa: E402
import alerts  # noqa: E402
import app as appmod  # noqa: E402
import auto_response as AR  # noqa: E402
import break_glass  # noqa: E402
import remediation  # noqa: E402
import sso  # noqa: E402
from models import AutoAction, Threat, db  # noqa: E402

PERSON, CSRF = 'dana@example.org', 'csrf-for-the-test'
NOW = datetime(2026, 11, 18, 12, 0, tzinfo=timezone.utc)
VOTERS = {'Llama': ('llama3', True), 'Hermes': ('hermes3', True), 'Mistral': ('mistral', True), 'Gemma': ('gemma4:12b', True),
          'Off': ('qwen/qwen3.8-27b', False), 'Mystery': ('some-new-model', True)}
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


def verdict(agree=('Llama', 'Mistral'), severity='MEDIUM', confidence=95, **kw):
    v = {'consensus_verdict': 'malicious', 'consensus_severity': severity, 'confidence': confidence, 'ai_count': 4,
         'quorum': {'degraded': False}, 'panel_mode': 'primary', 'verification': {'status': 'confirmed'},
         'positions': [{'ai': n, 'verdict': 'malicious'} for n in agree] + [{'ai': 'Gemma', 'verdict': 'benign'}]}
    v.update(kw)
    return v


# ── the table itself (pure) ──────────────────────────────────────────────────

class Table(unittest.TestCase):
    def test_on_arrival_only_low_findings_may_be_acted_on(self):
        self.assertEqual([R.at_arrival(s)[0] for s in ('informational', 'low', 'medium', 'high', 'critical')],
                         [False, True, False, False, False])

    def test_an_unknown_severity_counts_as_high(self):
        self.assertEqual(R.severity('weird'), 'high')
        self.assertEqual(R.severity(None), 'high')
        self.assertFalse(R.at_arrival('banana')[0])

    def test_the_stricter_severity_wins(self):
        self.assertEqual(R.stricter('low', 'HIGH'), 'high')
        self.assertEqual(R.stricter('critical', 'medium'), 'critical')

    def test_medium_after_the_verdict_needs_full_consensus(self):
        self.assertEqual(R.after_verdict('medium', 'block-bad-ip', verdict(), voters=VOTERS)[:1], (True,))
        ok, why, _ = R.after_verdict('medium', 'block-bad-ip', verdict(agree=('Llama',)), voters=VOTERS)
        self.assertFalse(ok)
        self.assertIn('1 independent model family', why)

    def test_high_and_critical_never_block_and_pause_only_through_the_gate(self):
        for sev in ('high', 'critical'):
            self.assertFalse(R.after_verdict(sev, 'block-bad-ip', verdict(), pause_enabled=True, channel_ok=True, voters=VOTERS)[0])
            self.assertFalse(R.after_verdict(sev, 'freeze-process', verdict(), pause_enabled=False, channel_ok=True, voters=VOTERS)[0])
            self.assertFalse(R.after_verdict(sev, 'freeze-process', verdict(), pause_enabled=True, channel_ok=False, voters=VOTERS)[0])
            self.assertEqual(R.after_verdict(sev, 'freeze-process', verdict(), pause_enabled=True, channel_ok=True, voters=VOTERS),
                             (True, '', 'consensus-pause'))

    def test_informational_is_only_logged(self):
        self.assertFalse(R.after_verdict('informational', 'block-bad-ip', verdict(), voters=VOTERS)[0])

    def test_grants_cover_low_and_medium_only(self):
        self.assertEqual([R.grant_may_cover(s) for s in ('low', 'medium', 'high', 'critical', 'nonsense')],
                         [True, True, False, False, False])


class Families(unittest.TestCase):
    def test_model_names_map_to_families(self):
        cases = {'llama3': 'meta-llama', 'hermes3': 'meta-llama', 'meta-llama/Llama-3.1-8B-Instruct': 'meta-llama',
                 'llama3.1-8b': 'meta-llama', 'mistral': 'mistral', 'mistral-small-latest': 'mistral', 'gemma4:12b': 'google',
                 'gemini-3.6-flash': 'google', 'phi4:14b': 'microsoft-phi', 'qwen/qwen3.8-27b': 'qwen',
                 'openai/gpt-oss-20b': 'openai', 'gpt-4.1-mini': 'openai', 'claude-haiku-4-5-20251001': 'anthropic',
                 'grok-beta': 'xai', 'kimi-k2.6': 'moonshot', 'something-else': None, '': None, None: None}
        for model, fam in cases.items():
            self.assertEqual(R.family_of(model), fam, model)

    def test_two_voters_on_the_same_family_count_once(self):
        self.assertEqual(R.agreeing_families(verdict(agree=('Llama', 'Hermes')), VOTERS), {'meta-llama'})
        self.assertFalse(R.full_consensus(verdict(agree=('Llama', 'Hermes')), voters=VOTERS)[0])

    def test_unknown_models_and_switched_off_providers_do_not_count(self):
        self.assertEqual(R.agreeing_families(verdict(agree=('Llama', 'Mystery', 'Off', 'NotOnThisHub')), VOTERS), {'meta-llama'})

    def test_model_names_inside_the_verdict_are_never_believed(self):
        forged = verdict(agree=('Llama', 'Hermes'), models={'Llama': 'claude-x', 'Hermes': 'gpt-5'})
        self.assertEqual(R.agreeing_families(forged, VOTERS), {'meta-llama'})

    def test_only_malicious_votes_count(self):
        v = verdict(agree=('Llama',))
        v['positions'].append({'ai': 'Mistral', 'verdict': 'suspicious'})
        self.assertEqual(R.agreeing_families(v, VOTERS), {'meta-llama'})

    def test_each_reason_to_refuse(self):
        cases = {'benign': verdict(consensus_verdict='benign'), 'degraded': verdict(quorum={'degraded': True}),
                 'fallback': verdict(panel_mode='fallback'), 'injection': verdict(quorum={'injection': ['x']}),
                 'disputed': verdict(verification={'status': 'disputed'}), 'confidence': verdict(confidence=85),
                 'not a dict': 'malicious'}
        for name, v in cases.items():
            self.assertFalse(R.full_consensus(v, voters=VOTERS)[0], name)

    def test_the_standard_has_floors_and_can_only_be_raised(self):
        self.assertEqual(R.standard({'min_families': 1, 'min_confidence': 50}), {'min_families': 2, 'min_confidence': 80})
        self.assertEqual(R.standard({'min_families': 3, 'min_confidence': 97}), {'min_families': 3, 'min_confidence': 97})
        self.assertEqual(R.standard({'min_families': True, 'min_confidence': 'x'}), R.DEFAULT_STANDARD)
        self.assertFalse(R.full_consensus(verdict(), {'min_families': 3}, VOTERS)[0])
        self.assertTrue(R.full_consensus(verdict(agree=('Llama', 'Mistral', 'Gemma')), {'min_families': 3}, VOTERS)[0])

    def test_the_real_registry_is_read_without_errors(self):
        voters = R._hub_voters()
        self.assertIsInstance(voters, dict)


# ── the engine: verdict path, consensus-gated pause, alerts ──────────────────

class Fake:
    def __init__(self, check='confirmed', uid=1000, cmdline='/tmp/x/xmrig --donate-level 1', kill_error=None, state='S'):
        self.calls, self.check_result, self.uid, self.cmd, self.kill_error, self.state = [], check, uid, cmdline, kill_error, state

    def deps(self):
        def kill(pid, sig):
            self.calls.append(('kill', pid, sig))
            if self.kill_error:
                raise self.kill_error
        return AR.Deps(block=lambda target, tid: self.calls.append(('block', target['value'])) or 'blocked (fake)',
                       unblock=lambda t: self.calls.append(('unblock', t['value'])), kill=kill,
                       check=lambda facts: {'result': self.check_result, 'detail': 'fake check'},
                       read_cmdline=lambda pid: self.cmd, proc_uid=lambda pid: self.uid, fail_count=lambda ip: 25,
                       never_block={'192.0.2.1'}, own_pids={'1', '2'}, never_pause=set(AR.DEFAULT_NEVER_PAUSE),
                       proc_state=lambda pid: self.state)


def policy(dry_run=False, pause=False, **std):
    pol = AR.defaults()
    pol['enabled'], pol['dry_run'], pol['consensus_pause'] = True, dry_run, pause
    for a in AR.ACTIONS:
        pol['actions'][a] = {'enabled': True, 'hours': 24}
    pol['consensus'] = R.standard(std or None)
    return pol


class Base(unittest.TestCase):
    def setUp(self):
        self.ctx = appmod.app.app_context()
        self.ctx.push()
        db.create_all()
        self.audit = os.path.join(_TMP, f'audit-{time.time_ns()}.jsonl')
        appmod._AUDIT_PATH = self.audit
        self.inst = os.path.join(_TMP, f'inst-{time.time_ns()}')
        for p in (mock.patch('ssai_config.INSTANCE_DIR', self.inst),
                  mock.patch.object(AR, 'policy_path', lambda: os.path.join(self.inst, 'auto_response.json')),
                  mock.patch.object(break_glass, 'state_path', lambda: os.path.join(self.inst, 'break_glass.json'))):
            p.start()
            self.addCleanup(p.stop)

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.ctx.pop()

    def threat(self, type_='intel-match', url='203.0.113.9', severity='medium', description='listed by feodo'):
        t = Threat(url=url, type=type_, severity=severity, status='active', description=description, detected_by='SocketWatchAgent')
        db.session.add(t)
        db.session.commit()
        return t

    def miner(self, severity='high', pid='4242'):
        return self.threat('suspicious-process', f'process://{pid}', severity,
                           f'Suspicious process detected (xmrig): alice {pid} /tmp/x/xmrig --donate-level 1')

    def channel_works(self):
        a = alerts.send_test('dana')
        alerts.acknowledge(a['id'], 'dana')

    def verdict_on(self, t, v, pol, fake=None):
        fake = fake or Fake()
        return AR.on_verdict(t, v, self.audit, deps=fake.deps(), policy=pol, now=NOW, voters=VOTERS), fake


class Arrival(Base):
    def test_medium_high_and_critical_findings_are_not_acted_on_when_they_arrive(self):
        for sev in ('medium', 'high', 'critical', 'informational'):
            fake = Fake()
            row = AR.on_finding(self.threat(url=f'203.0.113.{len(sev)}', severity=sev), 'admin', self.audit,
                                deps=fake.deps(), policy=policy(), now=NOW)
            self.assertIsNone(row, sev)
            self.assertEqual(fake.calls, [], sev)


class Verdict(Base):
    def test_a_medium_block_runs_after_the_verdict_with_two_families(self):
        row, fake = self.verdict_on(self.threat(), verdict(), policy())
        self.assertEqual((row.status, fake.calls), ('done', [('block', '203.0.113.9')]))
        self.assertIn('2 independent model families agreed', row.detail)
        self.assertEqual(len(alerts.open_alerts()), 1)                    # a live action raises an alert

    def test_one_family_means_a_person_decides(self):
        row, fake = self.verdict_on(self.threat(), verdict(agree=('Llama', 'Hermes')), policy())
        self.assertIsNone(row)
        self.assertEqual(fake.calls, [])

    def test_the_panels_severity_can_make_it_stricter_not_looser(self):
        row, fake = self.verdict_on(self.threat(severity='medium'), verdict(severity='HIGH'), policy())
        self.assertIsNone(row)                                             # high: a person (blocks are never consensus-gated)
        row, fake = self.verdict_on(self.threat(url='203.0.113.20', severity='high'), verdict(severity='LOW'), policy())
        self.assertIsNone(row)

    def test_the_direct_check_must_still_confirm(self):
        row, fake = self.verdict_on(self.threat(), verdict(), policy(), Fake(check='not-confirmed'))
        self.assertIsNone(row)
        self.assertEqual(fake.calls, [])

    def test_dry_run_records_would_have_and_touches_nothing(self):
        row, fake = self.verdict_on(self.threat(), verdict(), policy(dry_run=True))
        self.assertEqual((row.status, fake.calls), ('would-have', []))
        self.assertEqual(alerts.open_alerts(), [])                         # shadow mode: no alert for a "would have"

    def test_master_switch_and_break_glass_stop_it(self):
        pol = policy()
        pol['enabled'] = False
        self.assertIsNone(self.verdict_on(self.threat(), verdict(), pol)[0])
        break_glass.engage('dana', 'test', self.audit)
        self.assertIsNone(self.verdict_on(self.threat(url='203.0.113.30'), verdict(), policy())[0])

    def test_a_block_a_permission_already_approved_is_not_made_twice(self):
        from models import PendingRemediation
        t = self.threat()
        db.session.add(PendingRemediation(threat_id=t.id, kind='ip', target='203.0.113.9', status='approved',
                                          decided_by='auto:grant-1'))
        db.session.commit()
        row, fake = self.verdict_on(t, verdict(), policy())
        self.assertIsNone(row)
        self.assertEqual(fake.calls, [])

    def test_never_raises(self):
        self.assertIsNone(AR.on_verdict(None, verdict(), self.audit, policy=policy(), voters=VOTERS))
        self.assertIsNone(AR.on_verdict(self.threat(), 'not a dict', self.audit, policy=policy(), voters=VOTERS))


class ConsensusPause(Base):
    def test_off_by_default(self):
        self.assertFalse(AR.defaults()['consensus_pause'])
        self.channel_works()
        row, fake = self.verdict_on(self.miner(), verdict(severity='HIGH'), policy(pause=False))
        self.assertIsNone(row)
        self.assertEqual(fake.calls, [])

    def test_needs_a_tested_alert_channel(self):
        row, fake = self.verdict_on(self.miner(), verdict(severity='HIGH'), policy(pause=True))
        self.assertIsNone(row)
        self.assertEqual(fake.calls, [])

    def test_a_high_miner_is_paused_never_killed_stays_paused_and_alerts(self):
        self.channel_works()
        row, fake = self.verdict_on(self.miner(), verdict(severity='HIGH'), policy(pause=True))
        self.assertEqual(fake.calls, [('kill', 4242, signal.SIGSTOP)])
        self.assertEqual(row.status, 'done')
        self.assertIsNone(row.expires_at)                                  # no timer will resume it
        open_ = alerts.open_alerts()
        self.assertEqual(len(open_), 1)
        self.assertEqual(open_[0]['kind'], 'consensus-pause')
        self.assertIn("'xmrig'", open_[0]['title'])
        self.assertNotIn('--donate-level', json.dumps(open_))              # a program name, never the command line
        self.assertEqual(AR.sweep(self.audit, deps=fake.deps(), now=datetime(2027, 1, 1, tzinfo=timezone.utc))['expired'], 0)

    def test_critical_too_but_one_family_is_not_enough(self):
        self.channel_works()
        row, fake = self.verdict_on(self.miner(severity='critical'), verdict(severity='CRITICAL', agree=('Llama', 'Hermes')),
                                    policy(pause=True))
        self.assertIsNone(row)
        self.assertEqual(fake.calls, [])

    def test_a_raised_standard_is_respected(self):
        self.channel_works()
        row, _ = self.verdict_on(self.miner(), verdict(severity='HIGH'), policy(pause=True, min_families=3))
        self.assertIsNone(row)

    def test_it_works_without_the_freeze_switch_but_never_blocks(self):
        self.channel_works()
        pol = policy(pause=True)
        pol['actions']['freeze-process']['enabled'] = False
        row, fake = self.verdict_on(self.miner(), verdict(severity='HIGH'), pol)
        self.assertEqual(fake.calls, [('kill', 4242, signal.SIGSTOP)])
        row, fake = self.verdict_on(self.threat(url='203.0.113.40', severity='high'), verdict(severity='HIGH'), pol)
        self.assertIsNone(row)
        self.assertEqual(fake.calls, [])

    def test_protected_and_system_programs_are_still_never_paused(self):
        self.channel_works()
        row, fake = self.verdict_on(self.miner(pid='4300'), verdict(severity='HIGH'), policy(pause=True),
                                    Fake(cmdline='/usr/bin/postgres -D /x'))
        self.assertIsNone(row)
        row, fake = self.verdict_on(self.miner(pid='4301'), verdict(severity='HIGH'), policy(pause=True), Fake(uid=0))
        self.assertIsNone(row)

    def test_switching_it_on_needs_a_tested_channel(self):
        with self.assertRaises(AR.ActionError):
            AR.save_policy(dict(policy(pause=True)), 'dana', self.audit)
        self.channel_works()
        self.assertTrue(AR.save_policy(dict(policy(pause=True)), 'dana', self.audit)['consensus_pause'])

    def test_the_stored_standard_cannot_go_below_the_floors(self):
        pol = AR.normalise({'consensus': {'min_families': 1, 'min_confidence': 10}, 'consensus_pause': 'yes'})
        self.assertEqual(pol['consensus'], {'min_families': 2, 'min_confidence': 80})
        self.assertFalse(pol['consensus_pause'])


class PauseFix(Base):
    """Part C bug: a pause was logged 'failed' although the process had stopped, and a failed row has no Undo."""

    def test_a_pause_that_reported_an_error_but_stopped_the_process_is_recorded_as_paused(self):
        fake = Fake(kill_error=OSError('interrupted'), state='T')
        row = AR.on_finding(self.miner(severity='low'), 'admin', self.audit, deps=fake.deps(), policy=policy(), now=NOW)
        self.assertEqual(row.status, 'done')
        self.assertIn('recorded as paused', row.detail)
        fake.kill_error = None
        AR.undo(row.id, 'dana', self.audit, deps=fake.deps())                 # and Undo now works
        self.assertEqual(fake.calls[-1], ('kill', 4242, signal.SIGCONT))

    def test_a_pause_that_really_failed_stays_failed(self):
        row = AR.on_finding(self.miner(severity='low'), 'admin', self.audit,
                            deps=Fake(kill_error=PermissionError('no'), state='S').deps(), policy=policy(), now=NOW)
        self.assertEqual(row.status, 'failed')
        self.assertEqual(alerts.open_alerts(), [])

    def test_a_different_program_that_is_stopped_is_not_claimed(self):
        fake = Fake(kill_error=OSError('x'), state='T')
        deps = fake.deps()
        seq = iter(['/tmp/x/xmrig --donate-level 1', '/tmp/x/xmrig --donate-level 1', '/usr/sbin/cron -f'])
        deps.read_cmdline = lambda pid: next(seq)
        row = AR.on_finding(self.miner(severity='low'), 'admin', self.audit, deps=deps, policy=policy(), now=NOW)
        self.assertEqual(row.status, 'failed')


class KeepPaused(Base):
    def paused(self):
        row = AutoAction(action='freeze-process', kind='process', target='4242', dry_run=False, status='done', detail='x',
                         command_sha=AR._sha('/tmp/x/xmrig --donate-level 1'))
        db.session.add(row)
        db.session.commit()
        return row

    def test_keep_paused_is_recorded_and_signals_nothing(self):
        row = AR.keep_paused(self.paused().id, 'dana', self.audit, now=NOW)
        self.assertEqual(row.status, 'done')
        self.assertIn('kept paused by dana', row.detail)
        with open(self.audit, encoding='utf-8') as f:
            self.assertEqual(json.loads(f.readline())['action'], 'auto-keep-paused')

    def test_only_a_paused_program_can_be_kept(self):
        r = self.paused()
        r.status = 'undone'
        db.session.commit()
        with self.assertRaises(AR.ActionError):
            AR.keep_paused(r.id, 'dana', self.audit)


class Alerts(Base):
    def test_a_channel_works_only_after_a_person_acknowledges_a_test(self):
        self.assertFalse(alerts.a_channel_works())
        a = alerts.send_test('dana')
        self.assertFalse(alerts.a_channel_works())                          # sent is not enough
        alerts.acknowledge(a['id'], 'dana')
        self.assertTrue(alerts.a_channel_works())

    def test_acknowledging_an_ordinary_alert_does_not_confirm_a_channel(self):
        a = alerts.raise_alert('auto-action', 'x')
        alerts.acknowledge(a['id'], 'dana')
        self.assertFalse(alerts.a_channel_works())

    def test_files_are_owner_only(self):
        self.channel_works()
        for p in (alerts.alerts_path(), alerts.channels_path()):
            self.assertEqual(os.stat(p).st_mode & 0o777, 0o600, p)

    def test_an_unwritable_alert_never_raises(self):
        with mock.patch.object(alerts, '_append', side_effect=OSError('disk full')):
            self.assertIsNone(alerts.raise_alert('auto-action', 'x'))

    def test_unknown_alert(self):
        with self.assertRaises(KeyError):
            alerts.acknowledge('nope', 'dana')


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

    def test_the_admin_key_cannot_send_or_acknowledge_alerts(self):
        key = {'X-API-Key': ADMIN}
        self.assertEqual(self.c.post('/api/auto/alerts/test', headers=key).status_code, 403)
        a = alerts.send_test('dana')
        self.assertEqual(self.c.post(f'/api/auto/alerts/{a["id"]}/ack', headers=key).status_code, 403)
        self.assertEqual(self.c.get('/api/auto/alerts', headers=key).status_code, 200)       # reading is fine
        self.assertEqual(self.c.get('/api/auto/alerts').status_code, 401)

    def test_a_person_tests_and_acknowledges_then_may_switch_the_pause_on(self):
        self.sign_in()
        h = {'X-CSRF-Token': CSRF}
        pol = dict(policy(pause=True))
        r = self.c.post('/api/auto/settings', json=pol, headers=h)
        self.assertEqual(r.status_code, 400)
        self.assertIn('test alert', r.get_json()['error'])
        aid = self.c.post('/api/auto/alerts/test', headers=h).get_json()['alert']['id']
        r = self.c.post(f'/api/auto/alerts/{aid}/ack', headers=h)
        self.assertTrue(r.get_json()['channels']['dashboard']['working'])
        r = self.c.post('/api/auto/settings', json=pol, headers=h)
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json()['policy']['consensus_pause'])
        s = self.c.get('/api/auto/settings').get_json()
        self.assertEqual(s['floors'], {'min_families': 2, 'min_confidence': 80})
        self.assertEqual(len(s['risk_table']), 5)

    def test_keep_paused_route_is_person_only(self):
        row = AutoAction(action='freeze-process', kind='process', target='4242', dry_run=False, status='done', detail='x')
        db.session.add(row)
        db.session.commit()
        self.assertEqual(self.c.post(f'/api/auto/actions/{row.id}/keep', headers={'X-API-Key': ADMIN}).status_code, 403)
        self.sign_in()
        r = self.c.post(f'/api/auto/actions/{row.id}/keep', headers={'X-CSRF-Token': CSRF})
        self.assertEqual(r.status_code, 200)

    def test_saving_a_verdict_through_the_api_runs_the_verdict_path(self):
        # The hook in routes/threats.py itself (a NameError there was once caught only by the linter).
        AR.save_policy(dict(policy(dry_run=True)), 'dana', self.audit)
        t = self.threat()
        with mock.patch.object(R, '_hub_voters', lambda: dict(VOTERS)), \
                mock.patch('agents.live_checks.check', lambda facts, **kw: {'result': 'confirmed', 'detail': 'listed (test)'}):
            r = self.c.put(f'/api/threats/{t.id}', json={'ai_verdict': {'consensus': verdict()}}, headers={'X-API-Key': ADMIN})
        self.assertEqual(r.status_code, 200)
        rows = AutoAction.query.filter_by(threat_id=t.id).all()
        self.assertEqual([(x.status, x.action) for x in rows], [('would-have', 'block-bad-ip')])

    def test_preflight_reports_an_inactive_firewall_and_missing_pihole(self):
        from routes import auto_response as RT
        off = lambda cmd, **kw: types.SimpleNamespace(returncode=0, stdout='Status: inactive\n', stderr='')  # noqa: E731
        with mock.patch.dict(os.environ, {'PIHOLE_IP': '', 'PIHOLE_PASSWORD': ''}):
            out = RT._preflight(run=off)
        self.assertFalse(out['ufw']['ok'])
        self.assertIn('switched off', out['ufw']['detail'])
        self.assertFalse(out['pihole']['ok'])
        on = lambda cmd, **kw: types.SimpleNamespace(returncode=0, stdout='Status: active\n', stderr='')  # noqa: E731
        with mock.patch.dict(os.environ, {'PIHOLE_IP': '198.51.100.53', 'PIHOLE_PASSWORD': 'x'}):
            out = RT._preflight(run=on)
        self.assertTrue(out['ufw']['ok'] and out['pihole']['ok'])
        self.assertEqual(self.c.get('/api/auto/preflight').status_code, 401)


if __name__ == '__main__':
    unittest.main()
