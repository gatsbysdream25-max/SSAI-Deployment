#!/usr/bin/env python3
"""The GitHub ledger must publish REPEAT sightings (the detectors merge repeats into the existing row), at most once per
REPEAT_INTERVAL, and record when it last checked. No real git or network: git_commit_push is replaced.
Run:  swarmsentinel-env/bin/python3 backend/tools/test_github_repeats.py"""
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
import github_reporter as G  # noqa: E402

COLS = 'id INTEGER PRIMARY KEY, url TEXT, type TEXT, severity TEXT, description TEXT, detected_by TEXT, node_id TEXT, ' \
       'status TEXT, timestamp TEXT, last_seen TEXT'


class Repeats(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.db = os.path.join(self.dir, 't.db')
        c = sqlite3.connect(self.db)
        c.execute(f'CREATE TABLE threat ({COLS})')
        c.executemany('INSERT INTO threat VALUES (?,?,?,?,?,?,?,?,?,?)', [
            (1, '203.0.113.9:22', 'brute-force', 'medium', 'x', 'SSHLogAgent', None, 'active', '2026-11-01 00:00:00', '2026-11-17 10:00:00'),
            (2, '198.51.100.7:443', 'suspicious-port', 'medium', 'y', 'PortAgent', None, 'active', '2026-11-02 00:00:00', '2026-11-02 00:00:00')])
        c.commit()
        c.close()
        self.ledger_dir = os.path.join(self.dir, 'threats')
        self.patches = [mock.patch.object(G, 'DB_PATH', self.db), mock.patch.object(G, 'STATE_FILE', os.path.join(self.dir, 's.json')),
                        mock.patch.object(G, 'EXPORT_DIR', self.ledger_dir),
                        mock.patch.object(G, 'LEDGER_PATH', os.path.join(self.ledger_dir, 'known_threats.json')),
                        mock.patch.object(G, 'load_private_names', lambda *a, **k: None),
                        mock.patch.object(G, 'push_waiting_commits', lambda *a, **k: False)]
        for p in self.patches:
            p.start()
        self.commits = []
        self.gp = mock.patch.object(G, 'git_commit_push', lambda msg: self.commits.append(msg) or True)
        self.gp.start()
        G.save_state({'last_id': 2, 'last_push': '2026-11-04T00:29:44+00:00'})
        ledger = {}                                         # both rows were published before the last push
        G.update_ledger(ledger, G.fetch_new_threats(0))
        G.save_ledger(ledger)

    def tearDown(self):
        self.gp.stop()
        for p in self.patches:
            p.stop()

    def test_a_repeat_sighting_is_published_and_the_dashboard_state_moves_on(self):
        G.run_cycle()
        self.assertEqual(len(self.commits), 1)
        self.assertIn('0 new, 1 repeat sightings', self.commits[0])
        state = G.load_state()
        self.assertEqual(state['last_id'], 2)                              # the cursor for NEW rows is unchanged
        self.assertGreater(state['repeats_since'], '2026-11-17T10:00:00')    # the next window starts at this publish
        self.assertEqual(state['ledger_size'], 2)
        entry = next(e for e in G.load_ledger().values() if e['type'] == 'brute-force')
        self.assertEqual((entry['times_seen'], entry['last_seen'][:10]), (2, '2026-11-17'))
        self.assertIn('last_check', state)
        G.run_cycle()                                                      # nothing new: no second commit
        self.assertEqual(len(self.commits), 1)

    def test_repeats_wait_for_the_interval(self):
        now = datetime.now(timezone.utc)
        G.save_state({'last_id': 2, 'last_push': (now - timedelta(minutes=5)).isoformat(),
                      'repeats_since': '2026-11-04T00:29:44'})
        G.run_cycle()
        self.assertEqual(self.commits, [])
        self.assertIn('last_check', G.load_state())                        # but the check itself is recorded

    def test_no_push_time_means_no_repeats(self):
        self.assertEqual(G.fetch_repeat_sightings(2, None), [])

    def test_a_new_row_is_never_published_again_as_a_repeat(self):
        G.run_cycle()                                                      # publishes the waiting repeat of row 1
        seen = (datetime.now(timezone.utc) - timedelta(seconds=1)).strftime('%Y-%m-%d %H:%M:%S.%f')
        c = sqlite3.connect(self.db)
        c.execute('INSERT INTO threat VALUES (3, "malware.example.com", "intel-match", "medium", "z", "FeedAgent", NULL, '
                  '"active", ?, ?)', (seen, seen))
        c.commit()
        c.close()
        G.run_cycle()                                                      # row 3 is new: published once
        self.assertIn('1 new', self.commits[-1])
        st = G.load_state()
        st['last_push'] = '2026-01-01T00:00:00+00:00'                      # make repeats due again
        G.save_state(st)
        n = len(self.commits)
        G.run_cycle()
        self.assertEqual(len(self.commits), n)                             # not sent again as a "repeat"


if __name__ == '__main__':
    unittest.main()
