#!/usr/bin/env python3
"""The ledger pipeline end to end (2026-09-29): state file, DB reads, run_cycle, backfill, --scrub and the git step.
test_ledger_privacy.py covers what is *sanitized*; this covers what is *published*, and that the bot only ever commits the ledger.
Run:  swarmsentinel-env/bin/python3 backend/tools/test_ledger_pipeline.py"""
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

_TMP = tempfile.mkdtemp()
os.environ['DATA_DIR'] = _TMP
os.environ['SSAI_PRIVATE_NAMES'] = 'jdoe,asmith'
os.environ.pop('THREAT_INTEL_REPO_DIR', None)

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
sys.path[:0] = [BACKEND, os.path.join(BACKEND, 'agents')]

import ssai_config  # noqa: E402
os.makedirs(ssai_config.INSTANCE_DIR)
os.makedirs(os.path.join(ssai_config.THREAT_INTEL_REPO, 'logs'))
import github_reporter as G  # noqa: E402

REPO = G.REPO
_GIT_ENV = dict(os.environ, GIT_AUTHOR_NAME='t', GIT_AUTHOR_EMAIL='t@t', GIT_COMMITTER_NAME='t', GIT_COMMITTER_EMAIL='t@t')


def git(*args, cwd=None):
    return subprocess.run(['git', *args], cwd=cwd or REPO, capture_output=True, text=True, env=_GIT_ENV, check=True).stdout


def commit_count():
    r = subprocess.run(['git', 'rev-list', '--count', 'HEAD'], cwd=REPO, capture_output=True, text=True)
    return int(r.stdout.strip()) if r.returncode == 0 else 0


def make_db(rows):
    if os.path.exists(G.DB_PATH):
        os.remove(G.DB_PATH)
    c = sqlite3.connect(G.DB_PATH)
    c.execute('CREATE TABLE threat (id INTEGER PRIMARY KEY, url TEXT, type TEXT, severity TEXT, description TEXT, detected_by TEXT, '
              'node_id TEXT, status TEXT, timestamp TEXT)')
    c.executemany('INSERT INTO threat VALUES (?,?,?,?,?,?,?,?,?)', rows)
    c.commit()
    c.close()


def row(i, url='203.0.113.9', ttype='firewall-block', sev='low', desc='blocked', by='SyslogAgent', node='n1'):
    return (i, url, ttype, sev, desc, by, node, 'open', f'2026-09-29 00:00:{i:02d}')


def fresh_repo():
    """An empty git repo at the reporter's REPO (keeps logs/, which the reporter's own log handler holds open)."""
    for name in os.listdir(REPO):
        if name in ('logs',):
            continue
        p = os.path.join(REPO, name)
        if os.path.isdir(p):
            subprocess.run(['rm', '-rf', p])
        else:
            os.remove(p)
    subprocess.run(['rm', '-rf', os.path.join(REPO, '.git')])
    git('init', '-q', '-b', 'main')
    with open(os.path.join(REPO, 'README'), 'w') as f:
        f.write('x')
    git('add', 'README')
    git('commit', '-q', '-m', 'init')
    if os.path.exists(G.STATE_FILE):
        os.remove(G.STATE_FILE)


class RealGitExceptPush:
    """subprocess.run that runs real git for everything except `git push`, which is recorded and answered."""
    def __init__(self, push_rc=0):
        self.pushes, self.push_rc, self.real = [], push_rc, subprocess.run

    def __call__(self, cmd, *a, **k):
        if cmd[:2] == ['git', 'push']:
            self.pushes.append(cmd)
            return subprocess.CompletedProcess(cmd, self.push_rc, '', 'rejected' if self.push_rc else '')
        return self.real(cmd, *a, **k)


class StateAndReads(unittest.TestCase):
    def setUp(self):
        fresh_repo()

    def test_state_defaults_and_round_trips(self):
        self.assertEqual(G.load_state(), {'last_id': 0, 'last_push': None})
        G.save_state({'last_id': 7, 'last_push': 'x'})
        self.assertEqual(G.load_state(), {'last_id': 7, 'last_push': 'x'})

    def test_reads_are_ordered_and_respect_last_id(self):
        make_db([row(3), row(1), row(2)])
        self.assertEqual([t['id'] for t in G.fetch_all_threats()], [1, 2, 3])
        self.assertEqual([t['id'] for t in G.fetch_new_threats(1)], [2, 3])
        self.assertEqual(G.fetch_new_threats(3), [])


class Ledger(unittest.TestCase):
    def setUp(self):
        fresh_repo()
        G.load_private_names(os.path.join(_TMP, 'none.db'))

    def test_repeats_fold_into_one_entry_and_severity_only_escalates(self):
        ledger = {}
        new, rep = G.update_ledger(ledger, [dict(zip(('id', 'url', 'type', 'severity', 'description', 'detected_by', 'node_id', 'status',
                                                       'timestamp'), row(1, sev='high'))),
                                            dict(zip(('id', 'url', 'type', 'severity', 'description', 'detected_by', 'node_id', 'status',
                                                      'timestamp'), row(2, sev='low')))])
        self.assertEqual((new, rep, len(ledger)), (1, 1, 1))
        entry = next(iter(ledger.values()))
        self.assertEqual((entry['times_seen'], entry['severity']), (2, 'high'))      # a later low never downgrades it

    def test_firewall_block_identity_ignores_the_destination_port(self):
        a = G.threat_id({'type': 'firewall-block', 'url': '203.0.113.9:443'})
        b = G.threat_id({'type': 'firewall-block', 'url': '203.0.113.9:22'})
        c = G.threat_id({'type': 'firewall-block', 'url': '203.0.113.10:443'})
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)

    def test_save_orders_by_times_seen_and_round_trips(self):
        G.save_ledger({'a': {'id': 'a', 'times_seen': 1}, 'b': {'id': 'b', 'times_seen': 5}})
        self.assertEqual([e['id'] for e in json.load(open(G.LEDGER_PATH))], ['b', 'a'])
        self.assertEqual(set(G.load_ledger()), {'a', 'b'})


class GitStep(unittest.TestCase):
    def setUp(self):
        fresh_repo()
        os.makedirs(G.EXPORT_DIR, exist_ok=True)

    def write_ledger(self, n=1):
        G.save_ledger({'a': {'id': 'a', 'times_seen': n}})

    def test_no_ledger_change_means_no_commit_and_no_push(self):
        before = commit_count()
        push = RealGitExceptPush()
        with mock.patch.object(G.subprocess, 'run', push):
            self.assertFalse(G.git_commit_push('m'))
        self.assertEqual((commit_count(), push.pushes), (before, []))

    def test_unrelated_dirty_files_do_not_count_as_a_ledger_change(self):
        """The live repo always has other uncommitted work; that must not trigger an empty commit + push every cycle."""
        with open(os.path.join(REPO, 'README'), 'w') as f:
            f.write('changed')
        with open(os.path.join(REPO, 'untracked.txt'), 'w') as f:
            f.write('x')
        git('remote', 'add', 'origin', 'https://github.com/example/ledger.git')
        push = RealGitExceptPush()
        before = commit_count()
        with mock.patch.object(G.subprocess, 'run', push):
            self.assertFalse(G.git_commit_push('m'))
        self.assertEqual((commit_count(), push.pushes), (before, []))

    def test_only_the_ledger_is_committed_even_if_other_files_are_staged(self):
        """Someone staging a file (say, in-progress dashboard work) must never ride along into the bot's public commit."""
        with open(os.path.join(REPO, 'README'), 'w') as f:
            f.write('secret work in progress')
        git('add', 'README')
        self.write_ledger()
        with mock.patch.object(G.subprocess, 'run', RealGitExceptPush()):
            G.git_commit_push('ledger update')
        files = git('show', '--name-only', '--format=', 'HEAD').split()
        self.assertEqual(files, ['threats/known_threats.json'])
        self.assertIn('README', git('diff', '--cached', '--name-only'))              # still staged for its owner

    def test_no_remote_commits_locally_and_reports_not_pushed(self):
        self.write_ledger()
        before = commit_count()
        push = RealGitExceptPush()
        with mock.patch.object(G.subprocess, 'run', push):
            self.assertFalse(G.git_commit_push('m'))
        self.assertEqual((commit_count(), push.pushes), (before + 1, []))

    def test_only_github_remotes_are_pushed_to(self):
        git('remote', 'add', 'origin', 'https://example.org/somewhere/else.git')
        self.write_ledger()
        push = RealGitExceptPush()
        with mock.patch.object(G.subprocess, 'run', push):
            self.assertFalse(G.git_commit_push('m'))
        self.assertEqual(push.pushes, [])

    def test_github_push_success_and_failure(self):
        git('remote', 'add', 'origin', 'https://github.com/example/ledger.git')
        self.write_ledger(1)
        ok = RealGitExceptPush(0)
        with mock.patch.object(G.subprocess, 'run', ok):
            self.assertTrue(G.git_commit_push('m'))
        self.assertEqual(ok.pushes, [['git', 'push', 'origin', 'main']])
        self.write_ledger(2)
        before = commit_count()
        bad = RealGitExceptPush(1)
        with mock.patch.object(G.subprocess, 'run', bad):
            self.assertFalse(G.git_commit_push('m2'))
        self.assertEqual(commit_count(), before + 1)                                # the commit is kept locally for the next cycle


class Cycle(unittest.TestCase):
    def setUp(self):
        fresh_repo()
        os.makedirs(G.EXPORT_DIR, exist_ok=True)
        if os.path.exists(G.LEDGER_PATH):
            os.remove(G.LEDGER_PATH)

    def test_cycle_publishes_a_sanitized_ledger_advances_state_and_then_goes_quiet(self):
        make_db([row(1, url='203.0.113.9', desc='2026-09-29T00:00:01+00:00 jdoe kernel: BLOCK SRC=192.168.1.41 DST=203.0.113.9'),
                 row(2, url='203.0.113.9', sev='high', desc='again from asmith at 10.1.2.3')])
        with mock.patch.object(G.subprocess, 'run', RealGitExceptPush()):
            G.run_cycle()
        published = open(G.LEDGER_PATH).read()
        for private in ('jdoe', 'asmith', '192.168.1.41', '10.1.2.3'):
            self.assertNotIn(private, published)
        self.assertIn('203.0.113.9', published)                                      # the attacker address is the point
        entries = json.loads(published)
        self.assertEqual((len(entries), entries[0]['times_seen'], entries[0]['severity']), (1, 2, 'high'))
        self.assertEqual(G.load_state()['last_id'], 2)
        self.assertIn('1 new, 1 repeat', git('log', '-1', '--format=%s'))
        before = commit_count()
        with mock.patch.object(G, 'git_commit_push') as gp:
            G.run_cycle()                                                            # nothing new: no ledger write, no git at all
        gp.assert_not_called()
        self.assertEqual(commit_count(), before)

    def test_new_rows_only_are_folded_in_on_the_next_cycle(self):
        make_db([row(1)])
        with mock.patch.object(G.subprocess, 'run', RealGitExceptPush()):
            G.run_cycle()
            c = sqlite3.connect(G.DB_PATH)
            c.execute('INSERT INTO threat VALUES (?,?,?,?,?,?,?,?,?)', row(2, url='198.51.100.4'))
            c.commit()
            c.close()
            G.run_cycle()
        self.assertEqual(sorted(e['url'] for e in json.load(open(G.LEDGER_PATH))), ['198.51.100.4', '203.0.113.9'])
        self.assertEqual(G.load_state()['last_id'], 2)


class BackfillAndScrub(unittest.TestCase):
    def setUp(self):
        fresh_repo()
        os.makedirs(G.EXPORT_DIR, exist_ok=True)

    def test_backfill_rebuilds_from_history_removes_legacy_dumps_and_resets_state(self):
        for legacy in ('2026-01-02.json', 'latest.json'):
            with open(os.path.join(G.EXPORT_DIR, legacy), 'w') as f:
                f.write('[]')
        with open(os.path.join(G.EXPORT_DIR, 'notes.txt'), 'w') as f:
            f.write('keep me')
        make_db([row(1), row(5, url='198.51.100.4'), row(9, url='203.0.113.9')])
        with mock.patch.object(G.subprocess, 'run', RealGitExceptPush()):
            G.backfill()
        self.assertEqual(sorted(os.listdir(G.EXPORT_DIR)), ['known_threats.json', 'notes.txt'])
        self.assertEqual(len(json.load(open(G.LEDGER_PATH))), 2)
        self.assertEqual(G.load_state()['last_id'], 9)
        self.assertIn('consolidate', git('log', '-1', '--format=%s'))

    def test_backfill_of_an_empty_history_does_not_crash(self):
        make_db([])
        with mock.patch.object(G.subprocess, 'run', RealGitExceptPush()):
            G.backfill()
        self.assertEqual(G.load_state()['last_id'], 0)

    def test_scrub_rewrites_a_leaky_ledger_and_commits_only_when_it_changed(self):
        leaky = {'x': {'id': 'x', 'type': 'firewall-block', 'severity': 'low', 'times_seen': 3, 'url': '203.0.113.9',
                       'description': 'seen by jdoe on 192.168.1.5', 'detected_by': 'asmith-pc',
                       'first_seen': '2026-01-01', 'last_seen': '2026-01-02'}}
        G.save_ledger(leaky)
        git('add', 'threats/')
        git('commit', '-q', '-m', 'leaky')
        with mock.patch.object(sys, 'argv', ['github_reporter.py', '--scrub']), mock.patch.object(G.subprocess, 'run', RealGitExceptPush()):
            G.main()
        text = open(G.LEDGER_PATH).read()
        for private in ('jdoe', 'asmith', '192.168.1.5'):
            self.assertNotIn(private, text)
        self.assertIn('remove private names', git('log', '-1', '--format=%s'))
        before = commit_count()
        with mock.patch.object(sys, 'argv', ['github_reporter.py', '--scrub']), mock.patch.object(G.subprocess, 'run', RealGitExceptPush()):
            G.main()                                                                # already clean: nothing to rewrite, no commit
        self.assertEqual(commit_count(), before)


if __name__ == '__main__':
    unittest.main(verbosity=1)
