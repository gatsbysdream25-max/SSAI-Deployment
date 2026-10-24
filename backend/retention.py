#!/usr/bin/env python3
"""Threat-table retention: report what is old enough to remove, and remove it only when asked.

  retention.py                       dry run: count what each rule would delete, change nothing
  retention.py --apply               back the database up, then delete in small batches
  retention.py --low-days 60 ...     tune the windows
  retention.py --apply --vacuum --keep-backups 7   what the daily timer runs (deploy/systemd/ssai-retention.*)

Rules (a threat is removed when it matches one):
  info      not seen for --info-days   (default 14)   feed listings and other reference rows
  low       not seen for --low-days    (default 30)   e.g. months of firewall-block log noise
  medium and above, only once RESOLVED or DISMISSED and not seen for --other-days (default 365)

Never removed: an ACTIVE medium/high/critical threat, however old (someone has not dealt with it), and anything newer
than its window. Deleting is irreversible, so --apply first writes a consistent backup next to the database and refuses
to continue if it cannot. Threats already exported to the ledger stay in the ledger. Run it as the account that owns the
database, and stop nothing: deletes run in small batches so the dashboard and agents keep working.
"""
import argparse
import os
import sqlite3
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [HERE]

# Age = time since the threat was last SEEN, not since it was first recorded (code review 2026-09-30, finding 8). A
# dismissed finding that is still sighted every day keeps its row, and with it the operator's "dismissed" decision;
# deleting it by first-seen date made it come straight back as a brand-new alert. Rows from before sightings were
# tracked have no last_seen and fall back to their timestamp.
_AGE = "COALESCE(last_seen, timestamp)"
RULES = (
    ('info', f"severity = 'info' AND {_AGE} < datetime('now', ?)", 'info_days'),
    ('low', f"severity = 'low' AND {_AGE} < datetime('now', ?)", 'low_days'),
    ('resolved/dismissed medium+', "severity IN ('medium','high','critical') AND status IN ('resolved','dismissed') "
                                   f"AND {_AGE} < datetime('now', ?)", 'other_days'),
)


def _predicate(days):
    """One WHERE clause and its parameters covering every rule."""
    clauses, params = [], []
    for _name, sql, key in RULES:
        clauses.append(f'({sql})')
        params.append(f'-{int(days[key])} days')
    return ' OR '.join(clauses), params


def plan(conn, days):
    """[(rule name, rows it would remove)] and the total (a row matching two rules is counted once)."""
    out = []
    for name, sql, key in RULES:
        n = conn.execute(f'SELECT COUNT(*) FROM threat WHERE {sql}', (f'-{int(days[key])} days',)).fetchone()[0]
        out.append((name, n))
    where, params = _predicate(days)
    total = conn.execute(f'SELECT COUNT(*) FROM threat WHERE {where}', params).fetchone()[0]
    return out, total


def apply(conn, days, batch=5000, log=print):
    """Delete matching rows in batches (plus their ledger-sync bookkeeping). Returns the number of threats removed."""
    where, params = _predicate(days)
    removed = 0
    has_sync = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='github_sync'").fetchone() is not None
    while True:
        ids = [r[0] for r in conn.execute(f'SELECT id FROM threat WHERE {where} LIMIT ?', params + [batch])]
        if not ids:
            return removed
        marks = ','.join('?' * len(ids))
        if has_sync:
            conn.execute(f'DELETE FROM github_sync WHERE threat_id IN ({marks})', ids)
        conn.execute(f'DELETE FROM threat WHERE id IN ({marks})', ids)
        conn.commit()
        removed += len(ids)
        log(f'  removed {removed}')
        time.sleep(0.05)                                    # let the web app and agents take their turn


def prune_backups(db_path, keep):
    """Delete all but the `keep` newest pre-retention backups of this database. Returns the paths removed."""
    folder, base = os.path.split(os.path.abspath(db_path))
    prefix = base + '.pre-retention-'
    mine = sorted(f for f in os.listdir(folder) if f.startswith(prefix) and not f.endswith(('-wal', '-shm', '-journal')))
    gone = []
    for f in mine[:max(0, len(mine) - keep)]:        # names end in %Y%m%d-%H%M%S, so name order is age order
        p = os.path.join(folder, f)
        os.remove(p)
        gone.append(p)
    return gone


def backup(db_path):
    """Copy the database to a timestamped '.pre-retention-' file (readable only by its owner) so deleted rows can be
    recovered; returns the new path."""
    dst = f'{db_path}.pre-retention-{time.strftime("%Y%m%d-%H%M%S")}'
    src = sqlite3.connect(db_path)
    out = sqlite3.connect(dst)
    src.backup(out)                                         # consistent even while the app is writing
    out.close()
    src.close()
    os.chmod(dst, 0o600)
    return dst


def main(argv=None):
    """Command-line entry point: show how many old threats would be removed and, only with --apply, back up the database and delete them.
    Returns the exit code (0 ok, 1 backup failed, 2 database not found).
    """
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--db')
    ap.add_argument('--apply', action='store_true', help='actually delete (after a backup)')
    ap.add_argument('--info-days', type=int, default=14)
    ap.add_argument('--low-days', type=int, default=30)
    ap.add_argument('--other-days', type=int, default=365)
    ap.add_argument('--vacuum', action='store_true', help='shrink the file afterwards (locks the database briefly)')
    ap.add_argument('--batch', type=int, default=5000)
    ap.add_argument('--keep-backups', type=int, default=None, metavar='N',
                    help='after a successful run keep only the N newest pre-retention backups (for scheduled runs)')
    args = ap.parse_args(argv)

    import ssai_config
    db_path = args.db or ssai_config.DB_PATH
    if not os.path.exists(db_path):
        print(f'No database at {db_path}', file=sys.stderr)
        return 2
    days = {'info_days': args.info_days, 'low_days': args.low_days, 'other_days': args.other_days}
    conn = sqlite3.connect(db_path, timeout=30)
    total_rows = conn.execute('SELECT COUNT(*) FROM threat').fetchone()[0]
    per_rule, total = plan(conn, days)
    print(f'{db_path}: {total_rows} threats, {os.path.getsize(db_path) / 1e6:.1f} MB')
    for name, n in per_rule:
        print(f'  {name:28} {n:>8} eligible')
    print(f'  {"TOTAL (each row once)":28} {total:>8} would be removed, {total_rows - total} kept')
    if not args.apply:
        print('Dry run: nothing changed. Add --apply to delete (a backup is written first).')
        return 0
    if not total:
        print('Nothing to remove.')
        return 0
    try:
        saved = backup(db_path)
    except (OSError, sqlite3.Error) as e:
        print(f'Refusing to delete: could not write a backup ({e})', file=sys.stderr)
        return 1
    print(f'Backup written: {saved}')
    removed = apply(conn, days, batch=args.batch)
    conn.execute('PRAGMA wal_checkpoint(TRUNCATE)')
    if args.vacuum:
        conn.execute('VACUUM')
    print(f'Removed {removed} threats. Remaining: {conn.execute("SELECT COUNT(*) FROM threat").fetchone()[0]}.')
    conn.close()
    if args.keep_backups is not None:
        for p in prune_backups(db_path, max(1, args.keep_backups)):     # never the backup just written
            print(f'Old backup removed: {p}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
