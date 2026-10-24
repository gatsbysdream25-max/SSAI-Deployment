"""The ledger pusher must not wait forever when its cursor is ahead of the table (retention reuses ids)."""
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
import github_reporter as G


class Cursor(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.db = os.path.join(self.dir, 't.db')
        c = sqlite3.connect(self.db)
        c.execute('CREATE TABLE threat (id INTEGER PRIMARY KEY, timestamp TEXT)')
        c.executemany('INSERT INTO threat VALUES (?, ?)', [(1, '2026-09-29 10:00:00'), (2, '2026-09-30 03:00:00'), (3, '2026-10-05 10:00:00')])
        c.commit()
        c.close()
        self.old, G.DB_PATH = G.DB_PATH, self.db

    def tearDown(self):
        G.DB_PATH = self.old

    def test_a_cursor_inside_the_table_is_left_alone(self):
        self.assertEqual(G.resync_cursor(2, '2026-09-30T04:15:52+00:00'), 2)

    def test_a_cursor_ahead_of_the_table_goes_back_to_the_last_push(self):
        self.assertEqual(G.resync_cursor(900, '2026-09-30T04:15:52.700793+00:00'), 2)   # row 3 is newer than the push: it will be sent

    def test_with_no_push_time_it_starts_from_the_beginning(self):
        self.assertEqual(G.resync_cursor(900, None), 0)


class WaitingPush(unittest.TestCase):
    """A ledger commit whose push was refused must be retried even when no new finding arrives."""

    def git(self, cwd, *args):
        return subprocess.run(['git', '-c', 'user.name=t', '-c', 'user.email=t@t', *args], cwd=cwd, capture_output=True, text=True, check=True).stdout

    def setUp(self):
        root = tempfile.mkdtemp()
        self.origin, self.clone, self.other = (os.path.join(root, n) for n in ('origin.git', 'clone', 'other'))
        subprocess.run(['git', 'init', '-q', '--bare', '-b', 'main', self.origin], check=True)
        for path in (self.clone, self.other):
            subprocess.run(['git', 'clone', '-q', self.origin, path], check=True, capture_output=True)
        for path in (self.clone, self.other):
            self.git(path, 'checkout', '-q', '-B', 'main')
        with open(os.path.join(self.clone, 'a.txt'), 'w') as f:
            f.write('1')
        self.git(self.clone, 'add', '.')
        self.git(self.clone, 'commit', '-q', '-m', 'first')
        self.git(self.clone, 'push', '-q', 'origin', 'main')
        self.git(self.other, 'pull', '-q', 'origin', 'main')

    def waiting_commit(self):
        os.makedirs(os.path.join(self.clone, 'threats'), exist_ok=True)
        with open(os.path.join(self.clone, 'threats', 'x.json'), 'w') as f:
            f.write('{}')
        self.git(self.clone, 'add', '.')
        self.git(self.clone, 'commit', '-q', '-m', 'ledger')

    def test_nothing_is_done_when_nothing_is_waiting(self):
        self.assertFalse(G.push_waiting_commits(self.clone, require_github=False))

    def test_a_waiting_commit_is_pushed(self):
        self.waiting_commit()
        self.assertTrue(G.push_waiting_commits(self.clone, require_github=False))
        self.assertIn('ledger', self.git(self.other, 'pull', '-q', 'origin', 'main') + self.git(self.other, 'log', '--oneline'))

    def test_a_refused_push_is_not_forced(self):
        self.waiting_commit()
        with open(os.path.join(self.other, 'b.txt'), 'w') as f:        # someone else pushes first
            f.write('2')
        self.git(self.other, 'add', '.')
        self.git(self.other, 'commit', '-q', '-m', 'someone else')
        self.git(self.other, 'push', '-q', 'origin', 'main')
        self.assertFalse(G.push_waiting_commits(self.clone, require_github=False))
        self.assertIn('someone else', self.git(self.origin, 'log', '--oneline', 'main'))          # their work is still there
        self.assertNotIn('ledger', self.git(self.origin, 'log', '--oneline', 'main'))

    def test_a_remote_that_is_not_github_is_left_alone(self):
        self.waiting_commit()
        self.assertFalse(G.push_waiting_commits(self.clone))


if __name__ == '__main__':
    unittest.main()
