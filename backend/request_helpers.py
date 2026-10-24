"""Small helpers that clean what a client sent and read the clock (request_helpers.py).

Everything a client sends is untrusted: these cut it to a known length and keep only expected values, so no route stores a
megabyte string or an invented severity. No dependency on the web app, so any route file may import them.
"""
from datetime import datetime, timezone

_ALLOWED_SEVERITIES = {'critical', 'high', 'medium', 'low', 'info'}
_ALLOWED_TIERS = {'free', 'paid', 'enterprise'}
_MAX_STR = 256         # longest text field accepted, in characters
_MAX_LIST = 25         # most items accepted in a list field


def _clean_str(v, maxlen=_MAX_STR):
    """The text, trimmed and cut to maxlen; anything that is not text becomes ''."""
    if not isinstance(v, str):
        return ''
    return v.strip()[:maxlen]


def _clean_severity(v):
    """One of the known severities; anything else counts as 'low' (a client cannot invent a level)."""
    s = _clean_str(v, 16).lower()
    return s if s in _ALLOWED_SEVERITIES else 'low'


def _clean_tier(v):
    """One of the known machine tiers; anything else counts as 'free'."""
    s = _clean_str(v, 16).lower()
    return s if s in _ALLOWED_TIERS else 'free'


def _clean_list_of_str(v, maxlen=_MAX_LIST, item_maxlen=64):
    """A short list of short strings; anything else is dropped."""
    if not isinstance(v, list):
        return []
    return [_clean_str(x, item_maxlen) for x in v[:maxlen] if isinstance(x, str)]


def _utcnow():
    """Now in UTC without a time-zone marker, the form the database stores."""
    return datetime.now(timezone.utc).replace(tzinfo=None)
