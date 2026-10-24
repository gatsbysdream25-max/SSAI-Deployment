"""Keep secrets out of logs and out of stored error messages.

HTTP client exceptions embed the full request URL, and some providers take their key as a query parameter, so an
ordinary "request failed" log line can contain a working API key. Anything that reaches a log record, or that is stored
for display (provider health), goes through `redact` first. The log hook wraps the record factory, so it covers every
logger in the process (the agents, Flask, gunicorn) without touching call sites.

Redaction is pattern-based (key=..., Bearer ..., known key formats, "api_key": "...") plus the exact values of any
secret-looking environment variable on this host, so a key in an unexpected format is still caught.
"""
import logging
import os
import re

_MARK = '[redacted]'
_PATTERNS = (
    # ?key=... &token=... in URLs and query strings
    (re.compile(r'(?i)([?&](?:key|api[_-]?key|apikey|token|access[_-]?token|auth|password|secret|sid|code)=)[^&\s"\'<>)]+'), r'\1' + _MARK),
    # Authorization: Bearer xxx / Basic xxx
    (re.compile(r'(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}'), r'\1 ' + _MARK),
    # x-api-key: xxx, "api_key": "xxx", password=xxx, token: xxx
    (re.compile(r'(?i)(\b(?:x-api-key|x-goog-api-key|x-csrf-token|authorization|api[_-]?key|password|passwd|secret|token|sid|session[_-]?id)["\']?\s*[:=]\s*["\']?)'
                r'(?!\[redacted\])[^\s,"\'})&]{6,}'), r'\1' + _MARK),
    # credentials typed on a command line (process lists, shell history in log lines): sshpass -p X,
    # echo X | sudo -S, --password X, scheme://user:X@host (code review 2026-09-30, finding 1)
    (re.compile(r'(\bsshpass\s+-p\s*)(?!\[redacted\])\S+'), r'\1' + _MARK),
    (re.compile(r'(\becho\s+)(?!\[redacted\])\S+(\s*\|\s*sudo\b[^|\n]*?\s-S\b)'), r'\1' + _MARK + r'\2'),
    (re.compile(r'(?i)((?<![\w-])--?(?:password|passwd|pass|token|secret|api-?key)\s+)(?!-)(?!\[redacted\])\S+'), r'\1' + _MARK),
    (re.compile(r'(?i)(\b[a-z][a-z0-9+.-]*://[^\s:/@]+:)(?!\[redacted\])[^\s@/]+(@)'), r'\1' + _MARK + r'\2'),
    # well-known key formats, wherever they appear
    (re.compile(r'\bgsk_[A-Za-z0-9]{16,}|\bAIza[0-9A-Za-z_-]{20,}|\bsk-ant-[A-Za-z0-9_-]{16,}|\bsk-[A-Za-z0-9]{20,}'
                r'|\bhf_[A-Za-z0-9]{20,}|\bghp_[A-Za-z0-9]{20,}|\bssn_[A-Za-z0-9_-]{20,}'), _MARK),
)
_SECRET_NAME = re.compile(r'(KEY|TOKEN|SECRET|PASSWORD|PASSWD)', re.I)
_SAFE_NAMES = {'SSH_AUTH_SOCK', 'GPG_AGENT_INFO', 'XDG_SESSION_TOKEN'}


def _env_values():
    return [v for k, v in os.environ.items() if _SECRET_NAME.search(k) and k not in _SAFE_NAMES and len(v) >= 8]


def redact(text):
    """`text` with secrets replaced by [redacted]. Non-strings are returned unchanged."""
    if not isinstance(text, str) or not text:
        return text
    for pattern, repl in _PATTERNS:
        text = pattern.sub(repl, text)
    for value in _env_values():
        if value in text:
            text = text.replace(value, _MARK)
    return text


def install_log_redaction():
    """Redact every log record created in this process. Safe to call more than once."""
    if getattr(logging, '_ssai_redaction_installed', False):
        return
    previous = logging.getLogRecordFactory()

    def factory(*args, **kwargs):
        """Make a log record as usual, then redact secrets from its message and arguments before anything is written."""
        record = previous(*args, **kwargs)
        try:
            if isinstance(record.msg, str):
                record.msg = redact(record.msg)
            if isinstance(record.args, tuple):
                record.args = tuple(redact(str(a)) if isinstance(a, BaseException) else redact(a) if isinstance(a, str) else a
                                    for a in record.args)
        except Exception:                      # logging must never fail because of the redactor
            pass
        return record
    logging.setLogRecordFactory(factory)
    logging._ssai_redaction_installed = True
