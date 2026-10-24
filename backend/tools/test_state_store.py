#!/usr/bin/env python3
"""Tests for the per-machine agent state store and the agents' resume points (2026-10-09).
Run:  swarmsentinel-env/bin/python3 backend/tools/test_state_store.py"""
import logging
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(os.path.dirname(HERE), 'agents'), os.path.dirname(HERE)]
os.environ.setdefault('SSAI_PROVIDER_CHECK', '0')
import state_store as S  # noqa: E402
import agent_runner as AR  # noqa: E402


class Store(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.st = S.StateStore(os.path.join(self.dir, 'state.db'))

    def test_values_round_trip_as_json(self):
        self.assertIsNone(self.st.get('A', 'k'))
        self.assertEqual(self.st.get('A', 'k', 7), 7)
        self.assertTrue(self.st.put('A', 'k', {'pos': 10, 'ino': 3}))
        self.assertEqual(self.st.get('A', 'k'), {'pos': 10, 'ino': 3})
        self.st.put('A', 'k', [1, 2])
        self.assertEqual(self.st.get('A', 'k'), [1, 2])
        self.assertEqual(self.st.get('B', 'k'), None)                    # per agent

    def test_survives_a_new_process(self):
        self.st.put('A', 'k', 'v')
        self.st.close()
        again = S.StateStore(self.st.path)
        self.assertEqual(again.get('A', 'k'), 'v')
        self.assertIn('A', again.agent_states())

    def test_another_user_can_read_it(self):
        self.st.put('A', 'k', 'v')
        self.assertEqual(os.stat(self.st.path).st_mode & 0o777, 0o644)       # web app reads what root's agents wrote
        self.assertFalse(os.path.exists(self.st.path + '-wal'))              # no WAL: a reader needs no write access
        ro = S.StateStore(self.st.path, readonly=True)
        self.assertEqual(ro.get('A', 'k'), 'v')
        logging.disable(logging.CRITICAL)
        try:
            self.assertFalse(ro.put('A', 'k', 'x'))                          # read-only really is read-only
        finally:
            logging.disable(logging.NOTSET)
        self.assertEqual(self.st.get('A', 'k'), 'v')

    def test_readonly_store_before_anything_was_written(self):
        ro = S.StateStore(os.path.join(self.dir, 'none.db'), readonly=True)
        logging.disable(logging.CRITICAL)
        try:
            self.assertEqual(ro.lineage_events(), [])
            self.assertIsNone(ro.current_manifest_id())
        finally:
            logging.disable(logging.NOTSET)
        self.assertFalse(os.path.exists(os.path.join(self.dir, 'none.db')))

    def test_unusable_path_never_raises(self):
        blocker = os.path.join(self.dir, 'file')
        open(blocker, 'w').close()
        bad = S.StateStore(os.path.join(blocker, 'x', 'state.db'))
        logging.disable(logging.CRITICAL)
        try:
            self.assertFalse(bad.put('A', 'k', 1))
            self.assertEqual(bad.get('A', 'k', 'dflt'), 'dflt')
            self.assertIsNone(bad.sync_start('feed'))
            bad.sync_finish(None, True)
            self.assertTrue(bad.due('feed', 60))
            self.assertEqual(bad.recent_syncs(), [])
        finally:
            logging.disable(logging.NOTSET)

    def test_sync_log_and_due(self):
        self.assertTrue(self.st.due('feodo', 600))
        sid = self.st.sync_start('feodo')
        self.st.sync_finish(sid, True, 200, 42)
        self.assertFalse(self.st.due('feodo', 600))
        later = datetime.now(timezone.utc) + timedelta(seconds=601)
        self.assertTrue(self.st.due('feodo', 600, now=later))
        row = self.st.recent_syncs(source='feodo')[0]
        self.assertEqual((row['ok'], row['http_status'], row['records']), (True, 200, 42))

    def test_failed_pull_does_not_count_as_a_refresh(self):
        sid = self.st.sync_start('threatfox')
        self.st.sync_finish(sid, False, 503, note='down')
        self.assertTrue(self.st.due('threatfox', 600))
        self.assertIsNone(self.st.last_good_sync('threatfox'))

    def test_sync_log_is_pruned_per_source(self):
        old = S.SYNC_LOG_KEEP
        S.SYNC_LOG_KEEP = 3
        try:
            for _ in range(6):
                self.st.sync_finish(self.st.sync_start('a'), True)
            self.st.sync_finish(self.st.sync_start('b'), True)
            self.assertEqual(len(self.st.recent_syncs(source='a')), 3)
            self.assertEqual(len(self.st.recent_syncs(source='b')), 1)
        finally:
            S.SYNC_LOG_KEEP = old


class FakeAgent:
    name_id = 'AuthLogAgent'
    log = logging.getLogger('test')


class TailResume(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self._store = S._STORE
        S._STORE = S.StateStore(os.path.join(self.dir, 'state.db'))
        self.log = os.path.join(self.dir, 'auth.log')
        with open(self.log, 'w') as f:
            f.write('line one\n')

    def tearDown(self):
        S._STORE = self._store

    def append(self, text):
        with open(self.log, 'a') as f:
            f.write(text)

    def test_first_start_reads_from_the_end(self):
        a = FakeAgent()
        self.assertEqual(AR._resume_offset(a, self.log), os.path.getsize(self.log))

    def test_restart_resumes_and_reads_what_was_written_while_down(self):
        a = FakeAgent()
        AR._resume_offset(a, self.log)
        AR._save_offset(a, self.log)
        self.append('Failed password for root from 203.0.113.5\n')            # written while "down"
        b = FakeAgent()
        pos = AR._resume_offset(b, self.log)
        with open(self.log) as f:
            f.seek(pos)
            self.assertIn('Failed password', f.read())

    def test_rotated_file_starts_at_the_end_of_the_new_one(self):
        a = FakeAgent()
        AR._resume_offset(a, self.log)
        AR._save_offset(a, self.log)
        os.rename(self.log, self.log + '.1')
        with open(self.log, 'w') as f:
            f.write('new file\n')
        b = FakeAgent()
        self.assertEqual(AR._resume_offset(b, self.log), os.path.getsize(self.log))

    def test_huge_backlog_is_skipped(self):
        a = FakeAgent()
        AR._resume_offset(a, self.log)
        AR._save_offset(a, self.log)
        old = AR._CATCHUP_MAX
        AR._CATCHUP_MAX = 10
        try:
            self.append('x' * 100 + '\n')
            b = FakeAgent()
            self.assertEqual(AR._resume_offset(b, self.log), os.path.getsize(self.log))
        finally:
            AR._CATCHUP_MAX = old

    def test_unchanged_offset_is_not_rewritten(self):
        a = FakeAgent()
        AR._resume_offset(a, self.log)
        AR._save_offset(a, self.log)
        before = S.store().get('AuthLogAgent', 'tail:' + self.log)
        S.store().put('AuthLogAgent', 'tail:' + self.log, {'pos': -1, 'ino': 0})     # would be overwritten if saved
        AR._save_offset(a, self.log)
        self.assertNotEqual(S.store().get('AuthLogAgent', 'tail:' + self.log), before)


class ConsensusCutoff(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self._store = S._STORE
        S._STORE = S.StateStore(os.path.join(self.dir, 'state.db'))
        self.a = AR.SwarmConsensusAgent.__new__(AR.SwarmConsensusAgent)
        self.a.log = logging.getLogger('test')

    def tearDown(self):
        S._STORE = self._store

    def test_fresh_install_starts_now(self):
        self.assertEqual(self.a._resume_cutoff(), AR.SwarmConsensusAgent.DEPLOY_CUTOFF)

    def test_restart_covers_the_downtime(self):
        last = datetime.now(timezone.utc) - timedelta(hours=2)
        S.store().put('SwarmConsensusAgent', 'last_cycle', last.isoformat())
        cut = self.a._resume_cutoff()
        self.assertLessEqual(cut, last)
        self.assertGreater(cut, last - timedelta(minutes=11))

    def test_long_outage_is_capped(self):
        S.store().put('SwarmConsensusAgent', 'last_cycle', (datetime.now(timezone.utc) - timedelta(days=9)).isoformat())
        cut = self.a._resume_cutoff()
        self.assertGreater(cut, datetime.now(timezone.utc) - timedelta(hours=24, minutes=1))

    def test_garbage_state_is_ignored(self):
        S.store().put('SwarmConsensusAgent', 'last_cycle', 'not a date')
        self.assertEqual(self.a._resume_cutoff(), AR.SwarmConsensusAgent.DEPLOY_CUTOFF)


if __name__ == '__main__':
    unittest.main(verbosity=2)
