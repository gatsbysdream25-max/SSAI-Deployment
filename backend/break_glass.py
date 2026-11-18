"""Break-glass: one switch that stops everything SSAI does on its own (Week 1, 2026-11-17).

Two code paths can act without a person asking (Week 1 automation map, docs/audit/week1-automation-map.md):
  * auto_response.py   the four opt-in automatic responses (block IPs and domains, pause a process)
  * autonomy.py        the person-granted permissions that approve blocks automatically
Both check this switch first. While it is engaged neither acts, and auto_response does not even write "would have" rows.
Monitoring, findings, the AI panel and everything a person does by hand keep working.

Rules (each has a test in tools/test_break_glass.py):
  * no state file means NOT engaged (the normal case). A file that cannot be read or parsed means ENGAGED: when in doubt,
    SSAI stops acting on its own rather than carrying on.
  * engaging is always allowed to an admin (a signed-in person OR the admin key: stopping is the safe direction, and a script
    or a panicking operator must be able to do it). Releasing needs a signed-in PERSON (routes/auto_response.py).
  * every engage and release writes its audit line BEFORE the switch changes.
  * the shared cap of automatic actions an hour trips the switch by itself (trip_on_cap) when a live action hits it, and
    says so in the audit file and the log. A dry run never trips it.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Optional

log = logging.getLogger("break_glass")


def state_path() -> str:
    import ssai_config
    return os.path.join(ssai_config.INSTANCE_DIR, "break_glass.json")


def status(path: Optional[str] = None) -> dict:
    """{'engaged': bool, 'by', 'at', 'reason'}. Never raises."""
    p = path or state_path()
    try:
        with open(p, encoding="utf-8") as f:
            raw = json.load(f)
    except FileNotFoundError:
        return {"engaged": False, "by": None, "at": None, "reason": None}
    except (OSError, ValueError) as exc:
        return {"engaged": True, "by": "break-glass", "at": None,
                "reason": f"the break-glass state file could not be read ({type(exc).__name__}); automatic actions stay stopped "
                          "until a person releases the switch"}
    if not isinstance(raw, dict) or raw.get("engaged") is False:
        if isinstance(raw, dict):
            return {"engaged": False, "by": raw.get("by"), "at": raw.get("at"), "reason": raw.get("reason")}
        return {"engaged": True, "by": "break-glass", "at": None, "reason": "the break-glass state file is not valid"}
    return {"engaged": True, "by": raw.get("by"), "at": raw.get("at"), "reason": raw.get("reason")}


def engaged(path: Optional[str] = None) -> bool:
    return status(path)["engaged"]


def _write(state: dict, path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def engage(who: str, reason: str, audit_path: str, path: Optional[str] = None) -> dict:
    """Stop all automatic actions. Audited before the switch changes; raises if the audit line cannot be written."""
    import remediation
    reason = (reason or "no reason given").strip()[:300]
    remediation.audit_before_acting(audit_path, action="break-glass", stage="engage", by=who, reason=reason)
    state = {"engaged": True, "by": who, "at": datetime.now(timezone.utc).isoformat(), "reason": reason}
    _write(state, path or state_path())
    log.warning(f"BREAK-GLASS ENGAGED by {who}: {reason}. SSAI takes no automatic actions until a person releases it.")
    return state


def release(who: str, audit_path: str, path: Optional[str] = None) -> dict:
    """Let automatic actions run again (their own switches still apply). A signed-in person only (enforced by the route)."""
    import remediation
    before = status(path)
    remediation.audit_before_acting(audit_path, action="break-glass", stage="release", by=who,
                                    was_engaged_by=before.get("by"), was_reason=before.get("reason"))
    state = {"engaged": False, "by": who, "at": datetime.now(timezone.utc).isoformat(), "reason": "released"}
    _write(state, path or state_path())
    log.warning(f"break-glass released by {who}: automatic actions may run again under their own switches")
    return state


def trip_on_cap(audit_path: str, cap: int, path: Optional[str] = None) -> bool:
    """Engage the switch because the hourly cap was hit. Returns True when it is engaged afterwards. Never raises."""
    try:
        if engaged(path):
            return True
        engage("auto: hourly cap", f"the cap of {cap} automatic actions an hour was reached; a person should check what "
                                   "SSAI was doing before releasing the switch", audit_path, path)
        return True
    except Exception as exc:                               # noqa: BLE001 -- the cap itself still stops the action
        log.warning(f"break-glass could not be engaged at the hourly cap: {type(exc).__name__}: {exc}")
        return False
