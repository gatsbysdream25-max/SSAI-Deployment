"""Providers that are out of credits rest instead of voting badly (provider_rest.py).

When an AI provider says its credits or free quota are used up, asking it again on every finding only produces degraded
verdicts and wastes time. So it is put to REST: it stops voting, SSAI checks it now and then with one tiny request, and
the moment it answers again it goes back on the panel by itself.

This is separate from the operator's on/off switch (ai_providers.json) on purpose: a person's choice is never changed by
the system, and a rested provider that the person switched off stays off when the credits return.

State lives in instance/provider_rest.json so the agent runner (which finds out) and the web app (which shows it) agree.
"""
from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional

try:
    import provider_errors
except ImportError:                       # imported as agents.provider_rest by the web app
    from agents import provider_errors

# Failures that mean "it will keep failing until the account is topped up or the quota resets".
REST_KINDS = frozenset({provider_errors.NO_CREDITS, provider_errors.QUOTA_USED})

# Minutes to wait before the next check, growing while it stays out, then steady. Free quotas usually reset daily and
# credit top-ups are rare, so checking more often than this would only spend requests for nothing.
_BACKOFF_MINUTES = (15, 30, 60, 120, 360)

_lock = threading.Lock()


def _path() -> str:
    """Where the 'resting providers' state file lives: a test override, a throwaway temp file under the test harness, or
    the instance folder."""
    override = os.environ.get("SSAI_PROVIDER_REST_FILE")      # tests point this at a throwaway file
    if override:
        return override
    if os.environ.get("NOCLOUD_GUARD"):                       # running under the test harness: never touch the real state
        import tempfile
        return os.path.join(tempfile.gettempdir(), "ssai-rest-tests-%d.json" % os.getpid())
    try:
        import ssai_config
        return os.path.join(ssai_config.INSTANCE_DIR, "provider_rest.json")
    except ImportError:
        return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "instance", "provider_rest.json")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _load(path: Optional[str] = None) -> Dict[str, dict]:
    try:
        with open(path or _path(), encoding="utf-8") as f:
            data = json.load(f).get("resting", {})
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError, AttributeError):
        return {}


def _save(resting: Dict[str, dict], path: Optional[str] = None) -> None:
    path = path or _path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"resting": resting}, f, indent=1)
    os.replace(tmp, path)


def _next_check(tries: int) -> str:
    minutes = _BACKOFF_MINUTES[min(tries, len(_BACKOFF_MINUTES) - 1)]
    return (_now() + timedelta(minutes=minutes)).isoformat()


def all_resting(path: Optional[str] = None) -> Dict[str, dict]:
    """{provider id: {since, kind, detail, tries, next_check}} for every provider currently resting."""
    return _load(path)


def is_resting(pid: str, path: Optional[str] = None) -> bool:
    return pid in _load(path)


def rest(pid: str, kind: str, detail: str, path: Optional[str] = None) -> bool:
    """Put a provider to rest. Returns True only when it was not already resting (so the caller logs it once)."""
    with _lock:
        resting = _load(path)
        if pid in resting:
            return False
        resting[pid] = {"since": _now().isoformat(), "kind": kind, "detail": detail[:200], "tries": 0,
                        "next_check": _next_check(0)}
        _save(resting, path)
        return True


def wake(pid: str, path: Optional[str] = None) -> bool:
    """Take a provider off rest (it answered again). Returns True when it had been resting."""
    with _lock:
        resting = _load(path)
        if resting.pop(pid, None) is None:
            return False
        _save(resting, path)
        return True


def due(path: Optional[str] = None) -> list:
    """Ids of resting providers whose next check time has passed."""
    now = _now().isoformat()
    return [pid for pid, r in _load(path).items() if str(r.get("next_check", "")) <= now]


def still_out(pid: str, detail: str = "", path: Optional[str] = None) -> None:
    """A check found it still out: wait longer before the next one."""
    with _lock:
        resting = _load(path)
        r = resting.get(pid)
        if r is None:
            return
        r["tries"] = int(r.get("tries", 0)) + 1
        r["next_check"] = _next_check(r["tries"])
        if detail:
            r["detail"] = detail[:200]
        _save(resting, path)
