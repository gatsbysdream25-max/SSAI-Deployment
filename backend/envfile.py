"""Safe updates of the install's .env file (code review 2026-09-30, finding 5).

The .env holds every secret (API keys, the admin key, the session key). It used to be rewritten with a plain
open(..., 'w'): a crash or full disk mid-write left it truncated, and two writers at once could interleave. Values
were not checked either, so a newline in a value injected a new KEY=... line, and re.sub() treated backslashes in an
API key as escape sequences.

set_values() validates every key and value, takes an exclusive lock, rewrites the file into a temporary file next to
it with the same permissions, fsyncs, and atomically renames it over the original. Unrelated lines and comments are
kept as they are.
"""
import contextlib
import fcntl
import os
import re
import tempfile

KEY_RE = re.compile(r'^[A-Z][A-Z0-9_]{0,63}$')
MAX_VALUE = 4096


class EnvError(ValueError):
    """A key or value that must not be written."""


def check(key, value):
    """Raise EnvError unless `key` is a safe setting name and `value` is a single-line piece of text of reasonable length.
    This stops a value from sneaking in a new KEY=... line.
    """
    if not isinstance(key, str) or not KEY_RE.match(key):
        raise EnvError(f'invalid setting name: {key!r}')
    if not isinstance(value, str):
        raise EnvError(f'{key}: value must be text')
    if any(c in value for c in '\n\r\x00'):
        raise EnvError(f'{key}: value must be a single line')
    if len(value) > MAX_VALUE:
        raise EnvError(f'{key}: value too long')


@contextlib.contextmanager
def _locked(path):
    """Hold an exclusive lock for the duration of a `with` block so two writers cannot change the .env file at once.
    The lock lives on a separate '.lock' file because the .env itself gets replaced during a write.
    """
    fd = os.open(path + '.lock', os.O_RDONLY | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _write_atomic(path, text):
    """Replace the file at `path` with `text` all-or-nothing: write a temporary file, then swap it in.
    This way a crash or full disk can never leave a half-written .env, and the original permissions and owner are kept.
    """
    d = os.path.dirname(os.path.abspath(path))
    try:
        st = os.stat(path)
        mode = st.st_mode & 0o777
    except FileNotFoundError:
        st, mode = None, 0o600
    fd, tmp = tempfile.mkstemp(prefix='.env.', suffix='.tmp', dir=d)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        if st is not None and hasattr(os, 'chown'):
            try:
                os.chown(tmp, st.st_uid, st.st_gid)       # only works as root; otherwise the owner is already us
            except PermissionError:
                pass
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def set_values(path, updates):
    """Set KEY=value for every item of `updates` (dict). Raises EnvError before touching the file if any is invalid."""
    for k, v in updates.items():
        check(k, v)
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with _locked(path):
        try:
            with open(path, encoding='utf-8') as f:
                lines = f.readlines()
        except FileNotFoundError:
            lines = []
        out, seen = [], set()
        for line in lines:
            stripped = line.strip()
            if stripped and not stripped.startswith('#') and '=' in stripped:
                k = stripped.split('=', 1)[0].strip()
                if k in updates:
                    if k not in seen:                    # a duplicate KEY= line collapses into the one value
                        out.append(f'{k}={updates[k]}\n')
                        seen.add(k)
                    continue
            out.append(line if line.endswith('\n') else line + '\n')
        for k, v in updates.items():
            if k not in seen:
                out.append(f'{k}={v}\n')
        _write_atomic(path, ''.join(out))
