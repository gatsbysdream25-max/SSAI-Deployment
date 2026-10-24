"""The email-quarantine drop box: one JSON list shared by the web app (POST /api/quarantine/import adds entries) and
EmailQuarantineAgent (marks them processed). Code review 2026-09-30, finding 2: both did an unlocked read-modify-write,
so an import that landed while the agent was working was silently dropped by the agent's write-back.

Every change now runs under an exclusive lock on <path>.lock, re-reads the file inside the lock, and writes it back in
place (keeping its owner and mode: the app and the agents may run as different users). The agent no longer writes its
stale copy back: it marks entries processed BY ID in a second locked step, so nothing added in between is lost.
"""
import contextlib
import fcntl
import json
import os


@contextlib.contextmanager
def _locked(path):
    """Hold an exclusive lock for the duration of a `with` block so the web app and the agent cannot change the drop box
    file at the same time."""
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    fd = os.open(path + '.lock', os.O_RDONLY | os.O_CREAT, 0o644)   # read-only is enough for flock (other users too)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _read_unlocked(path):
    try:
        with open(path) as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def read(path):
    """A consistent snapshot of the entries ([] when missing or unreadable)."""
    with _locked(path):
        return _read_unlocked(path)


def update(path, change):
    """Run change(entries) on the current entries under the lock and write them back. Returns change's result."""
    with _locked(path):
        entries = _read_unlocked(path)
        result = change(entries)
        with open(path, 'a+') as f:                 # in place: keeps owner and mode
            f.seek(0)
            f.truncate()
            json.dump(entries, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        return result


def mark_processed(path, ids):
    """Mark the entries with these ids processed; returns how many were marked."""
    ids = set(ids)

    def change(entries):
        n = 0
        for e in entries:
            if isinstance(e, dict) and e.get('id') in ids and not e.get('processed'):
                e['processed'] = True
                n += 1
        return n
    return update(path, change) if ids else 0
