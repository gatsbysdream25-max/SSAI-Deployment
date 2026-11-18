#!/usr/bin/env python3
"""Automatic response (auto_response.py, 2026-11-15 sync): opt-in, dry run by default, a person controls it, audit first, never
inside the organisation, never another machine's finding, never a non-person process, at most 10 an hour.

SAFETY: no test may run a real firewall, Pi-hole call or signal. setUpModule replaces os.kill, subprocess.run and
remediation.block/unblock with functions that FAIL the test if anything reaches them; each test passes its own fakes.
Documentation addresses only (203.0.113.x, 198.51.100.x).
Run:  swarmsentinel-env/bin/python3 backend/tools/test_auto_response.py"""
import json
import os
import signal
import stat
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

_TMP = tempfile.mkdtemp()
os.environ['DATA_DIR'] = _TMP
os.environ['DATABASE_URL'] = 'sqlite:///' + os.path.join(_TMP, 'auto-response-test.db')
os.environ['SSAI_API_KEY'] = ADMIN = 'auto-response-test-admin-key'
os.environ['SSAI_PROVIDER_CHECK'] = '0'
os.environ['SSAI_STATE_DB'] = os.path.join(_TMP, 'state.db')

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
sys.path[:0] = [BACKEND, os.path.join(BACKEND, 'agents')]

import app as appmod  # noqa: E402
import auto_response as AR  # noqa: E402
import autonomy  # noqa: E402
import break_glass  # noqa: E402
import remediation  # noqa: E402
import sso  # noqa: E402
from models import AutoAction, AutonomyGrant, PendingRemediation, Threat, db  # noqa: E402

PERSON, CSRF = 'dana@example.org', 'csrf-for-the-test'
REAL_DEPS = AR.Deps                     # Fake.deps() builds the real class even while a test patches AR.Deps
NOW = datetime(2026, 11, 15, 12, 0, tzinfo=timezone.utc)
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


def policy(on=True, dry_run=False, hours=24, **actions):
    pol = AR.defaults()
    pol['enabled'], pol['dry_run'] = on, dry_run
    for a in AR.ACTIONS:
        pol['actions'][a] = {'enabled': actions.get(a.replace('-', '_'), True), 'hours': hours}
    return pol


class Fake:
    """Stands in for everything that touches the machine. Records every call."""

    def __init__(self, check='confirmed', fails=25, uid=1000, cmdline='/tmp/x/xmrig --donate-level 1', block_error=None,
                 kill_error=None, state='S'):
        self.calls, self.check_result, self.fails, self.uid, self.cmd = [], check, fails, uid, cmdline
        self.block_error, self.kill_error, self.state = block_error, kill_error, state
        self.audit_at_block = None

    def deps(self, audit_path=None):
        def block(target, threat_id):
            if audit_path:
                with open(audit_path, encoding='utf-8') as f:
                    self.audit_at_block = [json.loads(x) for x in f if x.strip()]
            self.calls.append(('block', target['value']))
            if self.block_error:
                raise remediation.RemediationError(self.block_error)
            return 'blocked (fake)'

        def kill(pid, sig):
            self.calls.append(('kill', pid, sig))
            if self.kill_error:
                raise self.kill_error

        return REAL_DEPS(block=block, unblock=lambda t: self.calls.append(('unblock', t['value'])), kill=kill,
                       check=lambda facts: {'result': self.check_result, 'check': 'fake', 'detail': 'fake check'},
                       read_cmdline=lambda pid: self.cmd, proc_uid=lambda pid: self.uid,
                       fail_count=lambda ip: self.fails, never_block={'192.0.2.1', '203.0.113.250'}, own_pids={'1', '2'},
                       proc_state=lambda pid: self.state)


class Base(unittest.TestCase):
    def setUp(self):
        self.ctx = appmod.app.app_context()
        self.ctx.push()
        db.create_all()
        self.audit = os.path.join(_TMP, f'audit-{time.time_ns()}.jsonl')
        appmod._AUDIT_PATH = self.audit
        self.policy_file = os.path.join(_TMP, f'policy-{time.time_ns()}.json')
        p = mock.patch.object(AR, 'policy_path', lambda: self.policy_file)
        p.start()
        self.addCleanup(p.stop)
        self.glass_file = os.path.join(_TMP, f'glass-{time.time_ns()}.json')     # break-glass state, one per test
        p = mock.patch('ssai_config.INSTANCE_DIR', os.path.join(_TMP, f'inst-{time.time_ns()}'))   # alerts, one folder per test
        p.start()
        self.addCleanup(p.stop)
        p = mock.patch.object(break_glass, 'state_path', lambda: self.glass_file)
        p.start()
        self.addCleanup(p.stop)

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.ctx.pop()

    def threat(self, type_='intel-match', url='203.0.113.9', description='listed by feodo', status='active', **kw):
        # Week 2: only LOW findings are acted on when they arrive (action_risk.py); these tests are about the other rules.
        t = Threat(url=url, type=type_, severity=kw.pop('severity', 'low'), status=status, description=description,
                   detected_by=kw.pop('detected_by', 'SocketWatchAgent'), **kw)
        db.session.add(t)
        db.session.commit()
        return t

    def proc(self, pattern='xmrig', pid='4242'):
        return self.threat('suspicious-process', f'process://{pid}',
                           f'Suspicious process detected ({pattern}): alice {pid} /tmp/x/xmrig --donate-level 1')

    def run_on(self, t, fake=None, pol=None, who='admin', **kw):
        fake = fake or Fake()
        return AR.on_finding(t, who, self.audit, deps=fake.deps(self.audit), policy=pol or policy(), now=NOW, **kw), fake

    def audit_lines(self):
        try:
            with open(self.audit, encoding='utf-8') as f:
                return [json.loads(x) for x in f if x.strip()]
        except OSError:
            return []


# ── the GLOBAL RULES, one test each ──────────────────────────────────────────

class Invariants(Base):
    def test_1_master_switch_and_all_four_actions_are_off_by_default(self):
        d = AR.load_policy()
        self.assertFalse(d['enabled'])
        self.assertEqual({a: v['enabled'] for a, v in d['actions'].items()}, {a: False for a in AR.ACTIONS})

    def test_2_dry_run_is_on_by_default_and_only_false_turns_it_off(self):
        self.assertTrue(AR.load_policy()['dry_run'])
        for v in ('false', 0, None, 'no', [], {}):
            self.assertTrue(AR.normalise({'dry_run': v})['dry_run'], repr(v))
        self.assertTrue(AR.normalise({})['dry_run'])
        self.assertFalse(AR.normalise({'dry_run': False})['dry_run'])

    def test_3_only_a_signed_in_person_changes_settings_or_presses_undo_or_terminate(self):
        c = appmod.app.test_client()
        for path in ('/api/auto/settings', '/api/auto/actions/1/undo', '/api/auto/actions/1/terminate'):
            r = c.post(path, json={'enabled': True}, headers={'X-API-Key': ADMIN})
            self.assertEqual(r.status_code, 403, path)
        self.assertFalse(os.path.exists(self.policy_file))

    def test_4_every_automatic_action_writes_its_audit_line_before_acting(self):
        fake = Fake()
        row, _ = self.run_on(self.threat(), fake)
        self.assertEqual(row.status, 'done')
        self.assertEqual([(a['action'], a['stage']) for a in fake.audit_at_block], [('block-bad-ip', 'intent')])

    def test_5_never_inside_the_organisation_never_other_machines_never_non_person_processes(self):
        for url in ('10.1.2.3', '192.168.4.5', '172.16.0.9', '100.64.1.1', '203.0.113.250'):
            self.assertIsNone(self.run_on(self.threat(url=url))[0], url)
        self.assertIsNone(self.run_on(self.threat(url='203.0.113.9'), who='node')[0])
        self.assertIsNone(self.run_on(self.threat(url='203.0.113.10', detected_by='SocketWatchAgent@laptop'))[0])
        for uid in (0, 33, 999, 65534):
            fake = Fake(uid=uid)
            self.assertIsNone(self.run_on(self.proc(pid=str(5000 + uid)), fake)[0], uid)
            self.assertEqual(fake.calls, [])

    def test_6_never_more_than_ten_automatic_actions_an_hour(self):
        fake = Fake()
        rows = [self.run_on(self.threat(url=f'203.0.113.{i}'), fake)[0] for i in range(20, 32)]
        self.assertEqual(sum(1 for r in rows if r is not None), 10)
        self.assertEqual(len([c for c in fake.calls if c[0] == 'block']), 10)


# ── policy ───────────────────────────────────────────────────────────────────

class Policy(Base):
    def write(self, text):
        with open(self.policy_file, 'w', encoding='utf-8') as f:
            f.write(text)

    def test_missing_file_means_off(self):
        self.assertEqual(AR.load_policy(), AR.defaults())

    def test_corrupt_file_means_off(self):
        self.write('{not json')
        self.assertEqual(AR.load_policy(), AR.defaults())

    def test_a_list_or_text_means_off(self):
        for text in ('[1,2]', '"on"', 'null', '42'):
            self.write(text)
            self.assertEqual(AR.load_policy(), AR.defaults(), text)

    def test_switches_need_a_real_true(self):
        p = AR.normalise({'enabled': 'true', 'actions': {'freeze-process': {'enabled': 1}, 'block-bad-ip': {'enabled': True}}})
        self.assertFalse(p['enabled'])
        self.assertFalse(p['actions']['freeze-process']['enabled'])
        self.assertTrue(p['actions']['block-bad-ip']['enabled'])

    def test_time_limits_default_to_24_hours_and_are_bounded(self):
        for given, want in ((48, 48), (0, 24), (10_000, 24), (True, 24), ('12', 24), (None, 24), (168, 168)):
            self.assertEqual(AR.normalise({'actions': {'block-bad-ip': {'hours': given}}})['actions']['block-bad-ip']['hours'],
                             want, repr(given))

    def test_unknown_actions_are_ignored(self):
        p = AR.normalise({'actions': {'wipe-disk': {'enabled': True}}})
        self.assertNotIn('wipe-disk', p['actions'])

    def test_save_is_owner_only_and_audited_first(self):
        AR.save_policy({'enabled': True}, 'dana', self.audit)
        self.assertEqual(stat.S_IMODE(os.stat(self.policy_file).st_mode), 0o600)
        self.assertEqual(self.audit_lines()[0]['action'], 'auto-response-policy')
        self.assertTrue(AR.load_policy()['enabled'])

    def test_save_refused_when_the_audit_cannot_be_written(self):
        with mock.patch.object(remediation, 'audit_before_acting', side_effect=remediation.RemediationError('disk')):
            with self.assertRaises(remediation.RemediationError):
                AR.save_policy({'enabled': True}, 'dana', self.audit)
        self.assertFalse(os.path.exists(self.policy_file))


# ── which action a finding asks for ──────────────────────────────────────────

class Wanted(unittest.TestCase):
    def test_mapping(self):
        W = AR.wanted_action
        self.assertEqual(W('brute-force', '203.0.113.7', ''), 'block-attacker-ip')
        self.assertEqual(W('intel-match', '203.0.113.9:443', ''), 'block-bad-ip')
        self.assertEqual(W('malicious-domain', 'evil.example.com', ''), 'block-bad-domain')
        self.assertEqual(W('malware-url', 'http://evil.example.com/x', ''), 'block-bad-domain')

    def test_processes(self):
        W = AR.wanted_action
        for p in ('xmrig', 'miner-args', 'netcat-exec', 'fifo-shell', 'busybox-netcat-exec', 'interpreter-revshell'):
            self.assertEqual(W('suspicious-process', 'process://1', f'Suspicious process detected ({p}): x 1 y'), 'freeze-process', p)
        for p in ('hidden-temp-program', 'cpu-hog-from-temp', 'fake-kernel-thread', 'ip-dropper'):
            self.assertIsNone(W('suspicious-process', 'process://1', f'Suspicious process detected ({p}): x 1 y'), p)

    def test_everything_else_is_left_alone(self):
        for t in ('distributed-brute-force', 'brute-force-success', 'unexpected-listener', 'file-modification', 'c2-beacon', 'disk-full'):
            self.assertIsNone(AR.wanted_action(t, '203.0.113.9', ''), t)
        self.assertIsNone(AR.wanted_action('intel-match', '192.168.xxx.xxx', ''))      # masked: nothing to block


# ── deciding and acting ──────────────────────────────────────────────────────

class Deciding(Base):
    def test_master_switch_off_does_nothing_at_all(self):
        fake = Fake()
        self.assertIsNone(self.run_on(self.threat(), fake, policy(on=False))[0])
        self.assertEqual((fake.calls, self.audit_lines()), ([], []))

    def test_action_switch_off_does_nothing(self):
        self.assertIsNone(self.run_on(self.threat(), pol=policy(block_bad_ip=False))[0])

    def test_dry_run_records_would_have_and_touches_nothing(self):
        fake = Fake()
        row, _ = self.run_on(self.threat(), fake, policy(dry_run=True))
        self.assertEqual((row.status, row.dry_run), ('would-have', True))
        self.assertIn('would have blocked', row.detail)
        self.assertEqual(fake.calls, [])
        self.assertEqual(self.audit_lines()[0]['stage'], 'would-have')

    def test_dry_run_writes_one_row_per_target_an_hour(self):
        t = self.threat()
        self.run_on(t, pol=policy(dry_run=True))
        self.assertIsNone(self.run_on(t, pol=policy(dry_run=True))[0])

    def test_bad_ip_is_blocked_with_a_time_limit(self):
        row, fake = self.run_on(self.threat(), pol=policy(hours=6))
        self.assertEqual(fake.calls, [('block', '203.0.113.9')])
        self.assertEqual(row.expires_at.replace(tzinfo=timezone.utc), NOW + timedelta(hours=6))

    def test_bad_domain_is_blocked(self):
        row, fake = self.run_on(self.threat('malicious-domain', 'http://evil.example.com/x'))
        self.assertEqual((row.action, fake.calls), ('block-bad-domain', [('block', 'evil.example.com')]))

    def test_attacker_needs_twenty_failed_logins_counted_in_the_log(self):
        t = self.threat('brute-force', '203.0.113.7', 'SSH brute force from 203.0.113.7 — 50 failed attempts')
        self.assertIsNone(self.run_on(t, Fake(fails=19))[0])                    # the text says 50; the log says 19
        self.assertIsNone(self.run_on(t, Fake(fails=None))[0])                  # the log cannot be read
        row, fake = self.run_on(t, Fake(fails=20))
        self.assertEqual((row.action, fake.calls), ('block-attacker-ip', [('block', '203.0.113.7')]))

    def test_a_masked_lan_address_is_judged_by_its_real_address_and_never_blocked(self):
        # Only private addresses are masked, so the real address behind 192.168.xxx.xxx is inside the organisation.
        fake = Fake()
        self.assertIsNone(self.run_on(self.threat(url='192.168.xxx.xxx', real_source='10.20.0.44'), fake)[0])
        self.assertEqual(fake.calls, [])

    def test_the_hub_itself_and_the_never_block_list_are_never_blocked(self):
        self.assertIsNone(self.run_on(self.threat(url='192.0.2.1'))[0])
        self.assertIsNone(self.run_on(self.threat(url='203.0.113.250'))[0])

    def test_findings_from_other_machines_are_never_acted_on(self):
        self.assertIsNone(self.run_on(self.threat(node_id='laptop'))[0])
        self.assertIsNone(self.run_on(self.threat(), who='node')[0])

    def test_a_dismissed_finding_is_left_alone(self):
        self.assertIsNone(self.run_on(self.threat(status='dismissed'))[0])

    def test_the_direct_check_must_confirm(self):
        for result in ('not-confirmed', 'inconclusive', ''):
            fake = Fake(check=result)
            self.assertIsNone(self.run_on(self.threat(url='203.0.113.60'), fake)[0], result)
            self.assertEqual(fake.calls, [])

    def test_a_second_finding_does_not_block_twice(self):
        t = self.threat()
        self.run_on(t)
        row, fake = self.run_on(t)
        self.assertIsNone(row)
        self.assertEqual(fake.calls, [])

    def test_a_failed_block_is_recorded_not_raised(self):
        row, _ = self.run_on(self.threat(), Fake(block_error='ufw is switched off'))
        self.assertEqual(row.status, 'failed')
        self.assertIn('ufw is switched off', row.detail)
        self.assertIsNone(row.expires_at)
        self.assertFalse(self.audit_lines()[-1]['ok'])

    def test_no_audit_line_means_no_action_and_no_row(self):
        fake = Fake()
        with mock.patch.object(remediation, 'audit_before_acting', side_effect=remediation.RemediationError('disk full')):
            self.assertIsNone(self.run_on(self.threat(), fake)[0])
        self.assertEqual((fake.calls, AutoAction.query.count()), ([], 0))

    def test_the_cap_counts_the_autonomy_grants_too(self):
        for i in range(10):
            db.session.add(PendingRemediation(threat_id=1, kind='domain', target=f'x{i}.example.com', status='approved',
                                              decided_by='auto:grant-1', decided_at=NOW - timedelta(minutes=5)))
        db.session.commit()
        self.assertIsNone(self.run_on(self.threat())[0])

    def test_actions_older_than_an_hour_do_not_count(self):
        for i in range(10):
            db.session.add(AutoAction(action='block-bad-ip', kind='ip', target=f'198.51.100.{i}', status='expired',
                                      created_at=NOW - timedelta(hours=2)))
        db.session.commit()
        self.assertIsNotNone(self.run_on(self.threat())[0])

    def test_never_raises(self):
        broken = AR.Deps(check=lambda f: 1 / 0, block=None, never_block=set(), own_pids=set())
        t = self.threat()
        self.assertIsNone(AR.on_finding(t, 'admin', self.audit, deps=broken, policy=policy(), now=NOW))
        self.assertIsNone(AR.on_finding(None, 'admin', self.audit, deps=broken, policy=policy(), now=NOW))


class Freezing(Base):
    def test_a_persons_miner_is_paused(self):
        row, fake = self.run_on(self.proc())
        self.assertEqual(fake.calls, [('kill', 4242, signal.SIGSTOP)])
        self.assertEqual((row.status, row.kind, row.target), ('done', 'process', '4242'))
        self.assertEqual(row.command_sha, AR._sha('/tmp/x/xmrig --donate-level 1'))

    def test_a_reverse_shell_is_paused(self):
        t = self.threat('suspicious-process', 'process://4300', 'Suspicious process detected (fifo-shell): alice 4300 sh -c mkfifo')
        self.assertEqual(self.run_on(t)[1].calls, [('kill', 4300, signal.SIGSTOP)])

    def test_system_and_root_processes_are_never_paused(self):
        for uid in (0, 1, 999, 65534, None):
            fake = Fake(uid=uid)
            self.assertIsNone(self.run_on(self.proc(pid=f'7{uid or 0}'), fake)[0], uid)
            self.assertEqual(fake.calls, [])

    def test_ssai_itself_is_never_paused(self):
        fake = Fake()
        self.assertIsNone(self.run_on(self.proc(pid='2'), fake)[0])
        self.assertEqual(fake.calls, [])

    def test_a_process_that_changed_just_before_is_not_paused(self):
        fake = Fake()
        seq = iter(['/tmp/x/xmrig --donate-level 1', '/usr/sbin/cron -f'])
        deps = fake.deps(self.audit)
        deps.read_cmdline = lambda pid: next(seq)
        row = AR.on_finding(self.proc(), 'admin', self.audit, deps=deps, policy=policy(), now=NOW)
        self.assertEqual(row.status, 'failed')
        self.assertEqual(fake.calls, [])

    def test_no_permission_to_pause_is_recorded(self):
        row, _ = self.run_on(self.proc(), Fake(kill_error=PermissionError('not allowed')))
        self.assertEqual(row.status, 'failed')
        self.assertIn('PermissionError', row.detail)

    def test_the_newest_report_wording_is_used_for_a_merged_repeat(self):
        t = self.threat('suspicious-process', 'process://4242', 'Suspicious process detected (hidden-temp-program): alice 4242 x')
        row, fake = self.run_on(t, description='Suspicious process detected (xmrig): alice 4242 /tmp/x/xmrig --donate-level 1')
        self.assertEqual(fake.calls, [('kill', 4242, signal.SIGSTOP)])


class Ending(Base):
    def done(self, kind='ip', target='203.0.113.9', expires=NOW + timedelta(hours=1), sha=None):
        row = AutoAction(action='freeze-process' if kind == 'process' else 'block-bad-ip', kind=kind, target=target,
                         dry_run=False, status='done', expires_at=expires, command_sha=sha, detail='x')
        db.session.add(row)
        db.session.commit()
        return row

    def test_undo_lifts_a_block_and_is_audited_first(self):
        fake = Fake()
        row = AR.undo(self.done().id, 'dana', self.audit, deps=fake.deps())
        self.assertEqual((row.status, fake.calls), ('undone', [('unblock', '203.0.113.9')]))
        self.assertEqual([a['action'] for a in self.audit_lines()], ['auto-undo', 'auto-undo'])

    def test_undo_resumes_the_same_paused_process(self):
        fake = Fake()
        r = self.done('process', '4242', sha=AR._sha(fake.cmd))
        AR.undo(r.id, 'dana', self.audit, deps=fake.deps())
        self.assertEqual(fake.calls, [('kill', 4242, signal.SIGCONT)])

    def test_undo_never_signals_a_different_program(self):
        fake = Fake(cmdline='/usr/sbin/cron -f')
        r = self.done('process', '4242', sha=AR._sha('/tmp/x/xmrig --donate-level 1'))
        row = AR.undo(r.id, 'dana', self.audit, deps=fake.deps())
        self.assertEqual((row.status, fake.calls), ('undone', []))
        self.assertIn('nothing resumed', row.detail)

    def test_undo_of_something_not_active_is_refused(self):
        r = self.done()
        r.status = 'expired'
        db.session.commit()
        with self.assertRaises(AR.ActionError):
            AR.undo(r.id, 'dana', self.audit, deps=Fake().deps())
        with self.assertRaises(AR.ActionError):
            AR.undo(99999, 'dana', self.audit, deps=Fake().deps())

    def test_terminate_kills_the_same_paused_program(self):
        fake = Fake()
        r = self.done('process', '4242', sha=AR._sha(fake.cmd))
        row = AR.terminate(r.id, 'dana', self.audit, deps=fake.deps())
        self.assertEqual((row.status, fake.calls), ('terminated', [('kill', 4242, signal.SIGKILL)]))

    def test_terminate_refuses_a_changed_process_and_blocks(self):
        r = self.done('process', '4242', sha=AR._sha('/tmp/x/xmrig --donate-level 1'))
        fake = Fake(cmdline='/usr/sbin/cron -f')
        with self.assertRaises(AR.ActionError):
            AR.terminate(r.id, 'dana', self.audit, deps=fake.deps())
        with self.assertRaises(AR.ActionError):
            AR.terminate(self.done().id, 'dana', self.audit, deps=fake.deps())
        self.assertEqual(fake.calls, [])

    def test_sweep_ends_only_what_is_due_and_never_resumes_a_pause(self):
        # Week 2: "paused stays paused" -- even a pause stored with a time limit (before Week 2) is left for a person.
        fake = Fake()
        due = self.done(expires=NOW - timedelta(minutes=1))
        later = self.done(target='203.0.113.10', expires=NOW + timedelta(hours=3))
        paused = self.done('process', '4242', expires=NOW - timedelta(minutes=1), sha=AR._sha(fake.cmd))
        out = AR.sweep(self.audit, deps=fake.deps(), now=NOW)
        self.assertEqual(out, {'expired': 1, 'errors': []})
        self.assertEqual(fake.calls, [('unblock', '203.0.113.9')])
        self.assertEqual([AutoAction.query.get(i).status for i in (due.id, later.id, paused.id)], ['expired', 'done', 'done'])

    def test_a_failed_expiry_is_tried_again(self):
        self.done(expires=NOW - timedelta(minutes=1))
        deps = Fake().deps()

        def refuse(target):
            raise remediation.RemediationError('pihole down')
        deps.unblock = refuse
        out = AR.sweep(self.audit, deps=deps, now=NOW)
        self.assertEqual(out['expired'], 0)
        self.assertEqual(len(out['errors']), 1)
        self.assertEqual(AutoAction.query.first().status, 'done')

    def test_sweep_with_nothing_due_builds_nothing(self):
        with mock.patch.object(AR, 'Deps', side_effect=AssertionError('should not be built')):
            self.assertEqual(AR.sweep(self.audit, now=NOW), {'expired': 0, 'errors': []})


# ── the web routes ───────────────────────────────────────────────────────────

class Api(Base):
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

    def test_reading_needs_admin(self):
        self.assertEqual(self.c.get('/api/auto/settings').status_code, 401)
        r = self.c.get('/api/auto/settings', headers={'X-API-Key': ADMIN})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()['policy'], AR.defaults())
        self.assertEqual(r.get_json()['hourly_cap'], 10)

    def test_a_person_changes_the_policy_and_it_is_recorded_with_their_name(self):
        self.sign_in()
        r = self.c.post('/api/auto/settings', json={'enabled': True, 'dry_run': 'false'}, headers={'X-CSRF-Token': CSRF})
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json()['policy']['enabled'])
        self.assertTrue(r.get_json()['policy']['dry_run'])                      # the text "false" does not turn dry run off
        self.assertTrue(self.audit_lines()[0]['by'].startswith(PERSON))

    def test_a_bad_body_is_refused(self):
        self.sign_in()
        r = self.c.post('/api/auto/settings', data='[1]', content_type='application/json', headers={'X-CSRF-Token': CSRF})
        self.assertEqual(r.status_code, 400)

    def test_a_person_presses_undo(self):
        row = AutoAction(action='block-bad-ip', kind='ip', target='203.0.113.9', dry_run=False, status='done')
        db.session.add(row)
        db.session.commit()
        self.sign_in()
        with mock.patch.object(AR, 'Deps', lambda: Fake().deps()):
            r = self.c.post(f'/api/auto/actions/{row.id}/undo', headers={'X-CSRF-Token': CSRF})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()['action']['status'], 'undone')

    def test_terminate_on_a_block_is_a_clear_refusal(self):
        row = AutoAction(action='block-bad-ip', kind='ip', target='203.0.113.9', dry_run=False, status='done')
        db.session.add(row)
        db.session.commit()
        self.sign_in()
        with mock.patch.object(AR, 'Deps', lambda: Fake().deps()):
            r = self.c.post(f'/api/auto/actions/{row.id}/terminate', headers={'X-CSRF-Token': CSRF})
        self.assertEqual(r.status_code, 400)

    def test_the_log_can_be_filtered(self):
        for st in ('done', 'would-have', 'would-have'):
            db.session.add(AutoAction(action='block-bad-ip', kind='ip', target='203.0.113.9', status=st))
        db.session.commit()
        r = self.c.get('/api/auto/actions?status=would-have', headers={'X-API-Key': ADMIN})
        self.assertEqual([a['status'] for a in r.get_json()], ['would-have', 'would-have'])


class Hooks(Base):
    def setUp(self):
        super().setUp()
        self.c = appmod.app.test_client()

    def test_submitting_a_finding_with_automatic_response_off_changes_nothing(self):
        r = self.c.post('/api/threats/', json={'url': '203.0.113.9', 'type': 'intel-match', 'severity': 'high'},
                        headers={'X-API-Key': ADMIN})
        self.assertEqual(r.status_code, 201)
        self.assertEqual(AutoAction.query.count(), 0)

    def test_a_crash_in_the_response_never_breaks_ingest(self):
        with mock.patch.object(AR, 'on_finding', side_effect=RuntimeError('boom')):
            r = self.c.post('/api/threats/', json={'url': '203.0.113.9', 'type': 'intel-match', 'severity': 'high'},
                            headers={'X-API-Key': ADMIN})
        self.assertEqual(r.status_code, 201)

    def test_the_hook_sees_the_finding_and_who_sent_it(self):
        with mock.patch.object(AR, 'on_finding', return_value=None) as hook:
            self.c.post('/api/threats/', json={'url': '203.0.113.9', 'type': 'intel-match', 'severity': 'high'},
                        headers={'X-API-Key': ADMIN})
        self.assertEqual(hook.call_args[0][1], 'admin')
        self.assertEqual(hook.call_args[0][0].url, '203.0.113.9')

    def test_the_sweep_route_ends_automatic_actions_too(self):
        with mock.patch.object(AR, 'sweep', return_value={'expired': 3, 'errors': []}) as sw, \
             mock.patch('remediation_queue.sweep', return_value={'expired': 0, 'rolled_back': 0, 'errors': []}):
            r = self.c.post('/api/remediation/sweep', headers={'X-API-Key': ADMIN})
        self.assertEqual(r.get_json()['auto_expired'], 3)
        sw.assert_called_once()

    def test_autonomy_grants_stop_at_the_shared_cap(self):
        g = AutonomyGrant(category='malicious-domain', action='block-domain', severities='low,medium', min_confidence=90,
                          min_ai_count=3, require_verified=False, ttl_hours=12, rate_limit_per_hour=5,
                          expires_at=datetime.now(timezone.utc) + timedelta(days=1), granted_by='dana')
        db.session.add(g)
        for i in range(10):
            db.session.add(AutoAction(action='block-bad-ip', kind='ip', target=f'198.51.100.{i}', status='done'))
        db.session.commit()
        t = self.threat('malicious-domain', 'evil.example.com')
        grant, why = autonomy.matching_grant(t, {'consensus_verdict': 'malicious'}, {'kind': 'domain', 'value': 'evil.example.com'})
        self.assertIsNone(grant)
        self.assertIn('cap of 10', why)


if __name__ == '__main__':
    unittest.main()
