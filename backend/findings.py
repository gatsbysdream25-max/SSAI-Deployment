"""Finding memory and re-alert rules (2026-09-23).

Agents look at the same thing again and again. Before this, a repeated event became a new row every time (one
firewall source filled 56,000 rows) and a repeated condition just had its timestamp nudged, so an operator could not
tell "new" from "still going".

Every finding gets a FINGERPRINT: a hash of threat type + machine + indicator. The first sighting is reported and
remembered. A repeat inside the quiet period only updates last-seen and the count. But plain de-duplication would
also silence an attack that is still under way, so each finding remembers when it was last REPORTED and is
reported again once its severity's interval has passed:

    critical  every 5 minutes       high  hourly       medium  every 6 hours       low / info  daily

A re-alert (a) moves the finding back to the top of the list and (b) says so: "Still active: first seen 3 hours ago,
alerted 12 times". A finding that gets MORE severe is reported at once. What an operator dismissed or resolved
stays quiet (Reopen brings it back). Intervals can be changed with SSAI_REALERT_MINUTES='{"critical": 10}'.
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from typing import Optional

DEFAULT_MINUTES = {'critical': 5, 'high': 60, 'medium': 360, 'low': 1440, 'info': 1440}
_RANK = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}


def every_occurrence_types() -> set:
    """Types where each occurrence is a distinct item (one row per quarantined e-mail), never merged."""
    raw = os.environ.get('SSAI_FINGERPRINT_EXEMPT', 'email-quarantine')
    return {t.strip() for t in raw.split(',') if t.strip()}


def fingerprint(type_, node_id, real_source, url) -> str:
    """Same finding = same type, same machine, same indicator. The indicator is the real device address when one is
    stored (LAN devices all share one masked URL), otherwise the URL."""
    parts = [str(type_ or '').strip().lower(), str(node_id or '').strip().lower(),
             str(real_source or url or '').strip().lower()]
    return hashlib.sha256('|'.join(parts).encode('utf-8', 'replace')).hexdigest()[:32]


def interval(severity) -> timedelta:
    """How long to wait before alerting again about a finding of this severity (from built-in defaults, optionally overridden by SSAI_REALERT_MINUTES).
    Bad override values are ignored rather than raising an error.
    """
    minutes = dict(DEFAULT_MINUTES)
    try:
        for k, v in (json.loads(os.environ.get('SSAI_REALERT_MINUTES') or '{}') or {}).items():
            if str(k).lower() in minutes and float(v) > 0:
                minutes[str(k).lower()] = float(v)
    except (ValueError, TypeError, AttributeError):
        pass
    return timedelta(minutes=minutes.get(str(severity or 'low').lower(), minutes['low']))


def utc(dt: Optional[datetime]) -> Optional[datetime]:
    """SQLite hands datetimes back without a zone; everything stored here is UTC."""
    if dt is None:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def start(threat, now: datetime) -> None:
    """First sighting: remember it."""
    threat.first_seen = threat.last_seen = threat.last_reported = now
    threat.times_seen = threat.times_reported = 1


def sighted(threat, now: datetime) -> None:
    """Note a repeat sighting without reporting it."""
    if threat.first_seen is None:
        threat.first_seen = threat.timestamp
    threat.last_seen = now
    threat.times_seen = (threat.times_seen or 1) + 1


def observe(threat, new_severity, now: datetime) -> dict:
    """A repeat sighting of an ACTIVE finding. Updates the memory and says whether to report it again.
    Returns {'realert': bool, 'reason': 'escalated'|'interval'|'quiet'}."""
    sighted(threat, now)
    escalated = _RANK.get(str(new_severity or '').lower(), 0) > _RANK.get(str(threat.severity or '').lower(), 0)
    if escalated:
        threat.severity = str(new_severity).lower()
    last = utc(threat.last_reported) or utc(threat.timestamp) or now
    due = now - last >= interval(threat.severity)
    if not (escalated or due):
        return {'realert': False, 'reason': 'quiet'}
    threat.timestamp = now                       # back to the top of the list
    threat.last_reported = now
    threat.times_reported = (threat.times_reported or 1) + 1
    return {'realert': True, 'reason': 'escalated' if escalated else 'interval'}


def _ago(delta: timedelta) -> str:
    s = max(0, int(delta.total_seconds()))
    for unit, size in (('day', 86400), ('hour', 3600), ('minute', 60)):
        if s >= size:
            n = s // size
            return f'{n} {unit}{"s" if n != 1 else ""}'
    return 'moments'


def still_active(threat, now: Optional[datetime] = None) -> Optional[str]:
    """'Still active: first seen 3 hours ago, alerted 12 times' (None for a finding seen once)."""
    reported, seen = (threat.times_reported or 1), (threat.times_seen or 1)
    if reported <= 1 and seen <= 1:
        return None
    now = now or datetime.now(timezone.utc)
    first = utc(threat.first_seen) or utc(threat.timestamp) or now
    text = f'Still active: first seen {_ago(now - first)} ago, alerted {reported} time{"s" if reported != 1 else ""}'
    if seen > reported:
        text += f', seen {seen} times'
    return text
