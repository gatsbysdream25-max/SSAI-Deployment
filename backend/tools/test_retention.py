#!/usr/bin/env python3
"""Retention deletes only what it should, backs up first, and a dry run changes nothing (2026-09-20).
Run:  swarmsentinel-env/bin/python3 backend/tools/test_retention.py"""
import contextlib
import io
import os
import sqlite3
import stat
import sys
import tempfile
import unittest

_TMP = tempfile.mkdtemp()
os.environ['DATA_DIR'] = _TMP
HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
sys.path[:0] = [BACKEND]
import retention as R  # noqa: E402

SCHEMA = ('CREATE TABLE threat (id INTEGER PRIMARY KEY, url TEXT, type TEXT, severity TEXT, status TEXT, timestamp DATETIME, last_seen DATETIME);'
          'CREATE TABLE github_sync (id INTEGER PRIMARY KEY, threat_id INTEGER, committed_at DATETIME);')


def build(rows):
    path = os.path.join(tempfile.mkdtemp(), 'x.db')
    c = sqlite3.connect(path)
    c.executescript(SCHEMA)
    for i, (sev, status, age) in enumerate(rows, 1):
        c.execute("INSERT INTO threat (id, url, type, severity, status, timestamp) VALUES (?,?,?,?,?, datetime('now', ?))",
                  (i, f'u{i}', 't', sev, status, f'-{age} days'))
        c.execute('INSERT INTO github_sync (threat_id) VALUES (?)', (i,))
    c.commit()
    c.close()
    return path


ROWS = [
    ('info', 'active', 20), ('info', 'active', 5),                       # 1 old info (removed), 1 recent (kept)
    ('low', 'active', 40), ('low', 'resolved', 40), ('low', 'active', 10),   # 2 old low (removed), 1 recent
    ('medium', 'active', 900), ('high', 'active', 400), ('critical', 'active', 999),   # ACTIVE medium+: never removed
    ('medium', 'resolved', 400), ('high', 'dismissed', 366), ('medium', 'resolved', 100),   # 2 removed, 1 too new
    ('low', 'active', 31), ('info', 'active', 15),                        # boundary rows (older than the window): removed
]
EXPECT_REMOVED = {1, 3, 4, 9, 10, 12, 13}


def run(*args):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        rc = R.main(list(args))
    return rc, out.getvalue()


class LastSeen(unittest.TestCase):
    """Code review 2026-09-30, finding 8: age counts from the last sighting, so a dismissed finding that is still
    happening keeps its row (and its dismissal) instead of being deleted and coming back as a new alert."""

    def test_a_still_sighted_dismissed_threat_is_kept(self):
        db = build([('medium', 'dismissed', 400), ('medium', 'dismissed', 400), ('low', 'active', 40)])
        c = sqlite3.connect(db)
        c.execute("UPDATE threat SET last_seen = datetime('now', '-1 days') WHERE id IN (1, 3)")   # still happening
        c.commit()
        c.close()
        rc, _ = run('--db', db, '--apply')
        self.assertEqual(rc, 0)
        c = sqlite3.connect(db)
        try:
            self.assertEqual({r[0] for r in c.execute('SELECT id FROM threat')}, {1, 3})
        finally:
            c.close()


class Retention(unittest.TestCase):
    def ids(self, path):
        c = sqlite3.connect(path)
        try:
            return {r[0] for r in c.execute('SELECT id FROM threat')}, c.execute('SELECT COUNT(*) FROM github_sync').fetchone()[0]
        finally:
            c.close()

    def test_a_dry_run_reports_and_changes_nothing(self):
        db = build(ROWS)
        before = self.ids(db)
        rc, out = run('--db', db)
        self.assertEqual(rc, 0)
        self.assertIn('Dry run', out)
        self.assertIn(f'{len(EXPECT_REMOVED)} would be removed', out)
        self.assertEqual(self.ids(db), before)
        self.assertEqual([f for f in os.listdir(os.path.dirname(db)) if 'pre-retention' in f], [])       # not even a backup

    def test_apply_removes_exactly_the_eligible_rows_after_writing_a_private_backup(self):
        db = build(ROWS)
        rc, out = run('--db', db, '--apply', '--batch', '2')                                          # tiny batches: exercises the loop
        self.assertEqual(rc, 0, out)
        kept, syncs = self.ids(db)
        self.assertEqual(kept, {i for i in range(1, len(ROWS) + 1)} - EXPECT_REMOVED)
        self.assertEqual(syncs, len(kept))                                                            # bookkeeping removed with them
        backups = [f for f in os.listdir(os.path.dirname(db)) if 'pre-retention' in f]
        self.assertEqual(len(backups), 1)
        bpath = os.path.join(os.path.dirname(db), backups[0])
        self.assertEqual(stat.S_IMODE(os.stat(bpath).st_mode), 0o600)
        self.assertEqual(self.ids(bpath)[0], set(range(1, len(ROWS) + 1)))                            # the backup holds everything

    def test_active_medium_and_above_are_never_removed_however_old(self):
        db = build([('medium', 'active', 5000), ('high', 'active', 5000), ('critical', 'active', 5000), ('low', 'active', 5000)])
        run('--db', db, '--apply', '--low-days', '1', '--other-days', '1', '--info-days', '1')
        self.assertEqual(self.ids(db)[0], {1, 2, 3})

    def test_windows_are_tunable(self):
        db = build(ROWS)
        rc, out = run('--db', db, '--low-days', '5', '--info-days', '1', '--other-days', '50')
        self.assertIn('would be removed', out)
        self.assertNotIn(f'{len(EXPECT_REMOVED)} would be removed', out)

    def test_applying_twice_is_harmless_and_an_empty_plan_writes_no_backup(self):
        db = build(ROWS)
        run('--db', db, '--apply')
        n = len([f for f in os.listdir(os.path.dirname(db)) if 'pre-retention' in f])
        rc, out = run('--db', db, '--apply')
        self.assertEqual(rc, 0)
        self.assertIn('Nothing to remove', out)
        self.assertEqual(len([f for f in os.listdir(os.path.dirname(db)) if 'pre-retention' in f]), n)

    def test_it_refuses_to_delete_when_it_cannot_back_up(self):
        db = build(ROWS)
        before = self.ids(db)
        real = R.backup
        R.backup = lambda p: (_ for _ in ()).throw(OSError('disk full'))
        try:
            rc, out = run('--db', db, '--apply')
        finally:
            R.backup = real
        self.assertEqual(rc, 1)
        self.assertIn('Refusing to delete', out)
        self.assertEqual(self.ids(db), before)

    def test_a_missing_database_is_a_clean_error(self):
        rc, out = run('--db', '/no/such/file.db')
        self.assertEqual(rc, 2)

    def test_keep_backups_prunes_only_the_oldest_of_this_databases_backups(self):
        path = build(ROWS)
        folder = os.path.dirname(path)
        for stamp in ('20260901-000000', '20260902-000000', '20260903-000000'):
            open(f'{path}.pre-retention-{stamp}', 'w').close()
        open(os.path.join(folder, 'other.db.pre-retention-20260101-000000'), 'w').close()      # another database's
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(R.main(['--db', path, '--apply', '--keep-backups', '2']), 0)
        left = sorted(f for f in os.listdir(folder) if 'pre-retention' in f)
        self.assertEqual(len([f for f in left if f.startswith('x.db.')]), 2)
        self.assertIn('x.db.pre-retention-20260903-000000', left)                               # newest old one kept
        self.assertNotIn('x.db.pre-retention-20260901-000000', left)
        self.assertIn('other.db.pre-retention-20260101-000000', left)

    def test_keep_backups_never_removes_the_one_just_written(self):
        path = build(ROWS)
        with contextlib.redirect_stdout(io.StringIO()):
            R.main(['--db', path, '--apply', '--keep-backups', '0'])
        self.assertEqual(len([f for f in os.listdir(os.path.dirname(path)) if 'pre-retention' in f]), 1)

    def test_works_without_a_github_sync_table(self):
        db = build(ROWS)
        c = sqlite3.connect(db)
        c.execute('DROP TABLE github_sync')
        c.commit()
        c.close()
        rc, _ = run('--db', db, '--apply')
        self.assertEqual(rc, 0)
        c = sqlite3.connect(db)
        try:
            self.assertEqual(c.execute('SELECT COUNT(*) FROM threat').fetchone()[0], len(ROWS) - len(EXPECT_REMOVED))
        finally:
            c.close()


if __name__ == '__main__':
    unittest.main(verbosity=2)
