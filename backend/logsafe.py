"""Log and audit-file protection (pilot hardening C5).

* Log files are created owner+group readable only (0640), never world-readable: a log can hold hostnames, addresses and
  finding titles from a customer's network. An older world-readable file is tightened the next time it is opened.
* Append-only audit files (JSON lines) are rotated by size instead of growing for ever: at SSAI_AUDIT_MAX_MB (default 20)
  the file becomes <name>.1, older copies shift up, and SSAI_AUDIT_KEEP (default 5) are kept. Nothing is ever rewritten.
"""
import logging
import os
from logging.handlers import RotatingFileHandler

LOG_MODE = 0o640


def _int_env(name, default, low, high):
    try:
        return max(low, min(high, int(os.environ.get(name, default))))
    except (TypeError, ValueError):
        return default


def _tighten(path, mode):
    try:
        if os.stat(path).st_mode & 0o777 & ~mode:       # has permission bits beyond the wanted ones
            os.chmod(path, mode)
    except OSError:                                    # owned by another account (e.g. root): theirs to set
        pass


class SecureRotatingFileHandler(RotatingFileHandler):
    """RotatingFileHandler whose files are created 0640 (the default is 0666 minus the umask, usually 0644)."""

    def _open(self):
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
        fd = os.open(self.baseFilename, flags, LOG_MODE)
        _tighten(self.baseFilename, LOG_MODE)
        return os.fdopen(fd, self.mode, encoding=self.encoding)


def rotate_if_big(path, max_bytes=None, keep=None):
    """Shift path -> path.1 -> path.2 ... once it passes max_bytes. Safe if two processes race: a lost rename is skipped."""
    if max_bytes is None:
        max_bytes = _int_env('SSAI_AUDIT_MAX_MB', 20, 1, 1024) * 1024 * 1024
    if keep is None:
        keep = _int_env('SSAI_AUDIT_KEEP', 5, 1, 50)
    try:
        if os.path.getsize(path) < max_bytes:
            return False
    except OSError:
        return False
    try:
        for i in range(keep - 1, 0, -1):
            src = f'{path}.{i}'
            if os.path.exists(src):
                os.replace(src, f'{path}.{i + 1}')
        os.replace(path, f'{path}.1')
        return True
    except OSError as exc:
        logging.getLogger('logsafe').warning('could not rotate %s: %s', path, exc)
        return False


def append_line(path, line, mode=0o600):
    """Append one line to an audit file (created with `mode`), rotating it first when it is big."""
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    rotate_if_big(path)
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, mode)
    with os.fdopen(fd, 'a', encoding='utf-8') as f:
        f.write(line if line.endswith('\n') else line + '\n')
