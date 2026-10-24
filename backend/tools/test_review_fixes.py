#!/usr/bin/env python3
"""Fixes for the 2026-09-30 code review (findings 1-10 and the minor ones), one test class per finding.
Run:  swarmsentinel-env/bin/python3 backend/tools/test_review_fixes.py"""
import json
import os
import stat
import sys
import tempfile
import threading
import types
import unittest
from unittest import mock

_TMP = tempfile.mkdtemp()
os.environ['DATA_DIR'] = _TMP
os.environ['DATABASE_URL'] = 'sqlite:///' + os.path.join(_TMP, 'review-test.db')
os.environ['SSAI_API_KEY'] = ADMIN = 'review-fixes-admin-key'
os.environ['SSAI_PROVIDER_CHECK'] = '0'
os.environ['SSAI_STATE_DB'] = os.path.join(_TMP, 'state.db')
os.makedirs(os.path.join(_TMP, 'threat-intel-repo', 'logs'), exist_ok=True)   # github_reporter logs there

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
REPO = os.path.dirname(BACKEND)
sys.path[:0] = [os.path.join(BACKEND, 'agents'), BACKEND]

import app as appmod  # noqa: E402
import envfile  # noqa: E402
import quarantine_dropbox as QD  # noqa: E402
import remediation_queue as RQ  # noqa: E402
from agents import redact  # noqa: E402
from models import db, Threat, PendingRemediation  # noqa: E402

if _TMP not in appmod.app.config['SQLALCHEMY_DATABASE_URI']:
    raise RuntimeError('refusing to run against a non-test database')
appmod.app.config['TESTING'] = True


class F1LedgerCredentials(unittest.TestCase):
    def test_redact_catches_command_line_credentials(self):
        for text, secret in (('sshpass -p Hunter2pass ssh root@x', 'Hunter2pass'),
                             ('echo S3cretPw | sudo -S ufw status', 'S3cretPw'),
                             ('mysql --password CorrectHorse9 -u app', 'CorrectHorse9'),
                             ('git clone https://bob:Tok3nValue@git.example.com/r.git', 'Tok3nValue'),
                             ('curl -H "Authorization: Bearer abcdef123456789"', 'abcdef123456789')):
            out = redact.redact(text)
            self.assertNotIn(secret, out, text)
            self.assertIn('[redacted]', out)

    def test_ledger_publishes_no_process_command_line(self):
        import github_reporter as G
        rec = {'type': 'suspicious-process', 'url': 'process://4242', 'detected_by': 'ProcessMonitorAgent',
               'description': 'Suspicious process detected: jdoe 4242 0.0 python -c import os; sshpass -p pw ssh x'}
        out = G._sanitize(rec)
        self.assertEqual(out['description'], G._PROCESS_PUBLIC)
        self.assertEqual(G.threat_id(out), G.threat_id(G._sanitize(out)))          # stable id after a re-scrub

    def test_ledger_masks_credentials_and_home_folders_everywhere(self):
        import github_reporter as G
        out = G._sanitize({'type': 'syslog', 'url': 'https://u:Pw12345@evil.example.com/x',
                           'description': 'cron: cat /home/alice/.env token=abcdefgh123'})
        blob = json.dumps(out)
        for leak in ('Pw12345', 'alice', 'abcdefgh123'):
            self.assertNotIn(leak, blob)
        self.assertIn('evil.example.com', blob)                                       # the indicator stays


class F2QuarantineRace(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(tempfile.mkdtemp(), 'quarantine_dropbox.json')

    def test_import_during_a_scan_is_not_lost(self):
        QD.update(self.path, lambda e: e.append({'id': 'a', 'processed': False}))
        snapshot = QD.read(self.path)                                                   # the agent's view
        QD.update(self.path, lambda e: e.append({'id': 'b', 'processed': False}))      # an import lands meanwhile
        QD.mark_processed(self.path, [x['id'] for x in snapshot])                       # agent finishes
        entries = {e['id']: e['processed'] for e in QD.read(self.path)}
        self.assertEqual(entries, {'a': True, 'b': False})

    def test_concurrent_writers_never_lose_an_entry(self):
        def add(i):
            QD.update(self.path, lambda e: e.append({'id': str(i), 'processed': False}))
        ts = [threading.Thread(target=add, args=(i,)) for i in range(40)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        self.assertEqual(len(QD.read(self.path)), 40)

    def test_agent_marks_by_id(self):
        import agent_runner as AR
        with open(self.path, 'w') as f:
            json.dump([{'id': 'x1', 'sender': 's@example.com', 'policy_type': 'Phish', 'processed': False}], f)
        a = AR.EmailQuarantineAgent()
        sent = []
        with mock.patch.object(AR.ssai_config, 'QUARANTINE_DROPBOX_PATH', self.path), \
             mock.patch.object(AR, 'submit_threat', lambda *a_, **k: sent.append(a_)):
            a.scan()
            a.scan()                                                                    # nothing twice
        self.assertEqual(len(sent), 1)
        self.assertTrue(QD.read(self.path)[0]['processed'])

    def test_import_route_uses_the_locked_update(self):
        with mock.patch.object(appmod, '_QUARANTINE_DROPBOX_PATH', self.path):
            r = appmod.app.test_client().post('/api/quarantine/import', headers={'X-API-Key': ADMIN},
                                              json={'items': [{'sender': 'a@example.com', 'subject': 'hi'}]})
        self.assertEqual(r.status_code, 201)
        self.assertEqual((r.get_json()['added'], len(QD.read(self.path))), (1, 1))


class F3ReloadButton(unittest.TestCase):
    def test_reload_sends_the_csrf_token(self):
        with open(os.path.join(BACKEND, 'templates', 'setup.html'), encoding='utf-8') as f:
            src = f.read()
        call = src[src.index("fetch('/api/setup/reload'"):][:200]
        self.assertIn('X-CSRF-Token', call)


class F4DashboardTitle(unittest.TestCase):
    def test_dashboard_reads_fields_the_api_sends(self):
        with open(os.path.join(BACKEND, 'templates', 'dashboard.html'), encoding='utf-8') as f:
            src = f.read()
        self.assertNotIn('t.title', src)


class F5EnvFile(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(tempfile.mkdtemp(), '.env')
        with open(self.path, 'w') as f:
            f.write('# keys\nGROQ_API_KEY=old\nOTHER=keep me\n')
        os.chmod(self.path, 0o600)

    def test_update_keeps_other_lines_and_permissions(self):
        envfile.set_values(self.path, {'GROQ_API_KEY': 'new', 'NEW_ONE': 'x'})
        with open(self.path) as f:
            self.assertEqual(f.read(), '# keys\nGROQ_API_KEY=new\nOTHER=keep me\nNEW_ONE=x\n')
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)

    def test_injection_and_bad_names_are_refused_before_writing(self):
        for k, v in (('GROQ_API_KEY', 'x\nSSAI_API_KEY=pwned'), ('lower', 'x'), ('A B', 'x'), ('K', 'a\rb'), ('K', 1)):
            with self.assertRaises(envfile.EnvError):
                envfile.set_values(self.path, {k: v})
        with open(self.path) as f:
            self.assertNotIn('pwned', f.read())

    def test_backslashes_are_kept_literally(self):
        envfile.set_values(self.path, {'GROQ_API_KEY': r'ab\1cd\gef'})
        with open(self.path) as f:
            self.assertIn('GROQ_API_KEY=ab\\1cd\\gef\n', f.read())

    def test_a_failed_write_leaves_the_old_file(self):
        with mock.patch.object(envfile.os, 'replace', side_effect=OSError('disk full')):
            with self.assertRaises(OSError):
                envfile.set_values(self.path, {'GROQ_API_KEY': 'new'})
        with open(self.path) as f:
            self.assertIn('GROQ_API_KEY=old', f.read())
        self.assertEqual([n for n in os.listdir(os.path.dirname(self.path)) if n.endswith('.tmp')], [])

    def test_save_env_key_goes_through_it(self):
        import ai_swarm_agent as asa
        with mock.patch.object(asa, '_find_env_path', return_value=__import__('pathlib').Path(self.path)), \
             mock.patch.dict(os.environ, {}, clear=False):
            self.assertTrue(asa.save_env_key('GROQ_API_KEY', r'k\1'))
            self.assertFalse(asa.save_env_key('GROQ_API_KEY', 'a\nB=c'))
        with open(self.path) as f:
            self.assertIn('GROQ_API_KEY=k\\1\n', f.read())

    def test_ai_routing_route_validates(self):
        c = appmod.app.test_client()
        h = {'X-API-Key': ADMIN}
        with mock.patch.object(appmod, '_ENV_PATH', self.path), \
             mock.patch('subprocess.run', return_value=types.SimpleNamespace(returncode=0)):
            for bad in ([1, 2], {'ollama': 'x'}, {'ollama': {'url': 'http://h:1\nSSAI_API_KEY=x'}},
                        {'ollama': {'url': 'file:///etc/passwd'}}, {'ollama': {'model': 'a b'}}, {}):
                self.assertEqual(c.post('/api/settings/ai_routing', headers=h, json=bad).status_code, 400, bad)
            ok = c.post('/api/settings/ai_routing', headers=h,
                        json={'ollama': {'url': 'http://192.168.1.20:11434', 'model': 'llama3:8b'}})
        self.assertEqual(ok.status_code, 200)
        with open(self.path) as f:
            text = f.read()
        self.assertIn('OLLAMA_URL=http://192.168.1.20:11434\n', text)
        self.assertIn('OTHER=keep me\n', text)


class DbCase(unittest.TestCase):
    def setUp(self):
        self.ctx = appmod.app.app_context()
        self.ctx.push()
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.ctx.pop()

    def proposal(self):
        t = Threat(url='203.0.113.9', type='malware-url', severity='critical', status='active')
        db.session.add(t)
        db.session.commit()
        p = PendingRemediation(threat_id=t.id, kind='ip', target='203.0.113.9', status='pending', confidence=90)
        db.session.add(p)
        db.session.commit()
        return p.id


class F6ApproveOnce(DbCase):
    def test_second_decision_is_refused_and_blocks_once(self):
        pid = self.proposal()
        calls = []
        with mock.patch.object(RQ.remediation, 'block', lambda *a, **k: calls.append(a) or 'blocked'):
            RQ.approve_proposal(pid, 'dashboard')
            with self.assertRaises(ValueError):
                RQ.approve_proposal(pid, 'teams')
            with self.assertRaises(ValueError):
                RQ.reject_proposal(pid, 'teams')
        self.assertEqual(len(calls), 1)

    def test_bad_ttl_is_refused_before_anything_is_blocked(self):
        pid = self.proposal()
        calls = []
        with mock.patch.object(RQ.remediation, 'block', lambda *a, **k: calls.append(a) or 'blocked'):
            for bad in ('abc', -1, 10 ** 9, True, [1]):
                with self.assertRaises(ValueError):
                    RQ.approve_proposal(pid, 'x', ttl_hours=bad)
        self.assertEqual(calls, [])
        self.assertEqual(PendingRemediation.query.get(pid).status, 'pending')

    def test_failed_block_goes_back_to_pending(self):
        pid = self.proposal()
        with mock.patch.object(RQ.remediation, 'block', side_effect=RQ.remediation.RemediationError('ufw down')):
            with self.assertRaises(RQ.remediation.RemediationError):
                RQ.approve_proposal(pid, 'x')
        self.assertEqual(PendingRemediation.query.get(pid).status, 'pending')

    def test_sweep_releases_a_stuck_claim(self):
        from datetime import datetime, timedelta, timezone
        pid = self.proposal()
        row = PendingRemediation.query.get(pid)
        row.status, row.decided_at = 'approving', datetime.now(timezone.utc) - timedelta(hours=1)
        db.session.commit()
        RQ.sweep()
        self.assertEqual(PendingRemediation.query.get(pid).status, 'pending')


class F7SetupActivate(unittest.TestCase):
    def test_activate_rebuilds_the_panel_card(self):
        import inspect
        src = inspect.getsource(appmod.setup_activate)
        self.assertIn('_sync_hub_ai()', src)
        self.assertNotIn('n.ai_capabilities', src)                                  # no hand-edited card


class F9NeedsConsensus(DbCase):
    def test_tier_one_verdicts_still_reach_the_panel(self):
        rows = [Threat(url='a', type='t', severity='medium', status='active', ai_analyzed=False),
                Threat(url='b', type='t', severity='medium', status='active', ai_analyzed=True,
                       ai_verdict=json.dumps({'analysis': 'tier one', 'model': 'hermes3'})),
                Threat(url='c', type='t', severity='medium', status='active', ai_analyzed=True,
                       ai_verdict=json.dumps({'consensus': {'consensus_verdict': 'benign'}}))]
        db.session.add_all(rows)
        db.session.commit()
        got = appmod.app.test_client().get('/api/threats/?needs_consensus=true&severity=medium', headers={'X-API-Key': ADMIN}).get_json()
        self.assertEqual(sorted(t['url'] for t in got), ['a', 'b'])

    def test_the_panel_asks_for_it(self):
        with open(os.path.join(BACKEND, 'agents', 'agent_runner.py'), encoding='utf-8') as f:
            src = f.read()
        self.assertIn('needs_consensus=true&severity={sev_q}', src)


class F10Sudoers(unittest.TestCase):
    def test_ufw_rule_is_scoped(self):
        with open(os.path.join(REPO, 'deploy', 'install.sh'), encoding='utf-8') as f:
            src = f.read()
        line = next(x for x in src.splitlines() if 'rules="$UFW' in x)
        for allowed in ('status', 'insert 1 deny from *', 'delete deny out to *'):
            self.assertIn(allowed, line)
        self.assertNotIn('rules="$UFW"', src)
        self.assertNotIn('allow', line)
        self.assertNotIn('disable', line)


class Minor(unittest.TestCase):
    def test_ollama_env_restores_unset_variables(self):
        import agent_runner as AR
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop('OLLAMA_URL', None)
            os.environ['OLLAMA_MODEL'] = 'llama3'
            with AR._ollama_env('http://wt:11434', 'mistral'):
                self.assertEqual(os.environ['OLLAMA_URL'], 'http://wt:11434')
            self.assertNotIn('OLLAMA_URL', os.environ)
            self.assertEqual(os.environ['OLLAMA_MODEL'], 'llama3')

    def test_resolve_and_dismiss_are_audited(self):
        with appmod.app.app_context():
            db.create_all()
            t = Threat(url='x', type='t', severity='high', status='active')
            db.session.add(t)
            db.session.commit()
            tid = t.id
        audit = os.path.join(tempfile.mkdtemp(), 'audit.jsonl')
        with mock.patch.object(appmod, '_AUDIT_PATH', audit):
            c = appmod.app.test_client()
            self.assertEqual(c.post(f'/api/threats/{tid}/dismiss', headers={'X-API-Key': ADMIN}).status_code, 200)
            self.assertEqual(c.post(f'/api/threats/{tid}/resolve', headers={'X-API-Key': ADMIN}).status_code, 200)
        with open(audit) as f:
            rows = [json.loads(x) for x in f]
        self.assertEqual([(r['action'], r['previous_status']) for r in rows], [('dismiss', 'active'), ('resolve', 'dismissed')])

    def test_rate_limit_memory_is_bounded(self):
        appmod._rl_hits.clear()
        old = appmod._time.monotonic
        try:
            now = [1000.0]
            appmod._time.monotonic = lambda: now[0]
            with appmod.app.test_request_context(environ_base={'REMOTE_ADDR': '1.1.1.1'}):
                for i in range(10001):
                    appmod._rl_hits[f'b:{i}'] = [now[0]]
                now[0] += 120
                appmod._rate_limited('b')
            self.assertLess(len(appmod._rl_hits), 10)
        finally:
            appmod._time.monotonic = old
            appmod._rl_hits.clear()


if __name__ == '__main__':
    unittest.main(verbosity=2)
