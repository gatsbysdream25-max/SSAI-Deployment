"""Alerts to the administrators (Week 2, 2026-11-18). First channel: the dashboard itself.

Every automatic action that really happens (not a dry run) raises an alert, and so does every consensus-gated pause. An alert
stays OPEN until a signed-in person acknowledges it; the dashboard shows a banner while any is open.

A channel counts as WORKING only after a test alert was sent through it AND a signed-in person acknowledged that test alert
(not merely "the request returned 200"). The consensus-gated pause cannot be switched on until one channel works.

Alerts carry a finding id, the action and a program NAME, never a full command line, an address book or a link with an action
token in it: links go to the dashboard, where the person signs in. Later channels (Teams or Slack webhook, email) reuse
`raise_alert`; their secrets will live in an owner-only file and are never logged.

Storage: alerts.jsonl (append-only, one JSON object per line) and alert_channels.json, both owner-only, in the instance folder.
Rules each have a test in tools/test_action_risk.py (class Alerts).
"""
from __future__ import annotations

import json
import logging
import os
import threading
import uuid
from datetime import datetime, timezone
from typing import Optional

log = logging.getLogger("alerts")
CHANNELS = ("dashboard",)
_LOCK = threading.Lock()
MAX_RETURNED = 200


def _dir() -> str:
    import ssai_config
    return ssai_config.INSTANCE_DIR


def alerts_path() -> str:
    return os.path.join(_dir(), "alerts.jsonl")


def channels_path() -> str:
    return os.path.join(_dir(), "alert_channels.json")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _append(event: dict) -> None:
    path = alerts_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, default=str) + "\n")


def _events() -> list:
    try:
        with open(alerts_path(), encoding="utf-8") as f:
            out = []
            for line in f:
                try:
                    out.append(json.loads(line))
                except ValueError:
                    continue
            return out
    except OSError:
        return []


def all_alerts() -> list:
    """Alerts newest first, each with `acknowledged_by` / `acknowledged_at` folded in from the acknowledgement lines."""
    raised, acks = {}, {}
    for e in _events():
        if e.get("event") == "alert" and e.get("id"):
            raised[e["id"]] = e
        elif e.get("event") == "ack" and e.get("id"):
            acks[e["id"]] = e
    out = []
    for aid, a in raised.items():
        row = {k: v for k, v in a.items() if k != "event"}
        ack = acks.get(aid)
        row["acknowledged_by"] = ack.get("by") if ack else None
        row["acknowledged_at"] = ack.get("at") if ack else None
        out.append(row)
    out.sort(key=lambda r: r.get("at") or "", reverse=True)
    return out


def open_alerts() -> list:
    return [a for a in all_alerts() if not a["acknowledged_by"]]


def raise_alert(kind: str, title: str, detail: str = "", finding: Optional[int] = None, action: Optional[str] = None,
                auto_action: Optional[int] = None, level: str = "high") -> Optional[dict]:
    """Record an alert on every channel. Never raises: a failed alert is logged and the caller carries on (a pause still stands,
    because it is reversible)."""
    alert = {"event": "alert", "id": uuid.uuid4().hex[:12], "at": _now(), "kind": str(kind)[:40], "level": str(level)[:12],
             "title": str(title)[:160], "detail": str(detail)[:400], "finding": finding, "action": action,
             "auto_action": auto_action, "channels": list(CHANNELS)}
    try:
        with _LOCK:
            _append(alert)
    except OSError as exc:
        log.warning(f"ALERT NOT RECORDED ({kind}: {title}): {type(exc).__name__}: {exc}")
        return None
    log.warning(f"alert: {title}")
    return {k: v for k, v in alert.items() if k != "event"}


def acknowledge(alert_id: str, who: str) -> dict:
    """A signed-in person acknowledges one alert (enforced by the route). Acknowledging a TEST alert marks its channel working."""
    alert_id = str(alert_id or "")[:20]
    with _LOCK:
        match = next((a for a in all_alerts() if a["id"] == alert_id), None)
        if match is None:
            raise KeyError("no such alert")
        if match["acknowledged_by"]:
            return match
        _append({"event": "ack", "id": alert_id, "at": _now(), "by": str(who)[:100]})
        if match.get("kind") == "test":
            for ch in match.get("channels") or []:
                _mark_channel(ch, who)
    match["acknowledged_by"], match["acknowledged_at"] = str(who)[:100], _now()
    return match


def send_test(who: str) -> dict:
    return raise_alert("test", "Test alert", f"Sent by {who}. Acknowledge it on the dashboard to confirm this channel works.",
                       level="info")


def _read_channels() -> dict:
    try:
        with open(channels_path(), encoding="utf-8") as f:
            raw = json.load(f)
        return raw if isinstance(raw, dict) else {}
    except (OSError, ValueError):
        return {}


def _mark_channel(channel: str, who: str) -> None:
    state = _read_channels()
    state[channel] = {"confirmed_by": str(who)[:100], "confirmed_at": _now()}
    path = channels_path()
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def channels() -> dict:
    state = _read_channels()
    return {ch: {"working": bool((state.get(ch) or {}).get("confirmed_by")), **(state.get(ch) or {})} for ch in CHANNELS}


def a_channel_works() -> bool:
    return any(c["working"] for c in channels().values())
