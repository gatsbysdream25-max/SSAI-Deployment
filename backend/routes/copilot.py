"""The Copilot lane's only door into SwarmSentinel (2026-09-26).

    GET /api/copilot/brief?hours=24&limit=5   ->  a short status report for the Microsoft 365 agent in copilot/
    GET /api/copilot/brief?since=<next_since>&min_severity=high   ->  what was reported after the cursor, oldest first,
        plus the next cursor. The agent's alert poller uses this; a finding that is re-alerted (finding memory) gets a new
        report time, so it comes round again on the hub's own schedule.

The agent runs in Microsoft's cloud, so everything in the answer is either a count or has passed
sanitizer.sanitize_for_cloud(): internal addresses, host names, user names, command lines and credentials never
leave. Threat URLs and real_source are not read at all.

Access: the admin key, or SSAI_COPILOT_KEY sent as X-Copilot-Key. With SSAI_COPILOT_KEY unset the lane is off and
only an admin can call this (to preview what the agent would see). The Copilot key opens these routes and nothing else.

2026-09-30, approve-first remediation from Teams:
    GET  /api/copilot/remediation                  pending block proposals, sanitized (lane key or admin key)
    POST /api/copilot/remediation/<id>/approve     the lane key AND the signed-in person's own Entra token
    POST /api/copilot/remediation/<id>/reject      (Authorization: Bearer ...), verified by entra.py against the
                                                   hub's approver list. The lane key alone, or the admin key, is
                                                   not enough: a named approver decides, and is audited.
"""
import hmac
import ipaddress
import json
import os
from datetime import datetime, timedelta, timezone

from flask import Blueprint, jsonify, request
from sqlalchemy import func

import auth
import entra
import remediation
import remediation_queue
import sanitizer
from auth import is_admin
from models import PendingRemediation, Threat

copilot_bp = Blueprint("copilot", __name__)
_DESTINATION = "microsoft-copilot"      # provider id in config/provider_approvals.json; recorded in the cloud audit log

SEVERITIES = ("critical", "high", "medium", "low", "info")
REPORTED = ("critical", "high", "medium")          # what the brief itemises; low / info only appear in the counts
MAX_ITEMS = 20
MIN_KEY_LEN = 16
MAX_SINCE = timedelta(days=7)                      # a cursor older than this is clamped: alerts are not a history dump


def _authorized() -> bool:
    if is_admin():
        return True
    key = os.environ.get("SSAI_COPILOT_KEY", "")
    given = request.headers.get("X-Copilot-Key", "")
    return len(key) >= MIN_KEY_LEN and hmac.compare_digest(given.encode(), key.encode())


def _lane_key_given() -> bool:
    """The Copilot lane key itself (the admin key does not count here)."""
    key = os.environ.get("SSAI_COPILOT_KEY", "")
    given = request.headers.get("X-Copilot-Key", "")
    return len(key) >= MIN_KEY_LEN and hmac.compare_digest(given.encode(), key.encode())


def _bounded(value, default: int, lo: int, hi: int) -> int:
    try:
        return max(lo, min(hi, int(value)))
    except (TypeError, ValueError):
        return default


def _verdict_text(raw) -> str:
    """'AI verdict: suspicious, 2 of 3 AIs agreed.' from a stored consensus, or '' if there is none."""
    try:
        v = json.loads(raw) if isinstance(raw, str) else raw
    except ValueError:
        return ""
    c = v.get("consensus") if isinstance(v, dict) else None
    if not isinstance(c, dict) or not c.get("consensus_verdict"):
        return ""
    q = c.get("quorum") if isinstance(c.get("quorum"), dict) else {}
    agreed = f", {q['agreed']} of {q['answered']} AIs agreed" if q.get("answered") else ""
    return f"AI verdict: {c['consensus_verdict']}{agreed}."


def _parse_since(raw):
    """An ISO-8601 cursor -> naive UTC datetime (how timestamps are stored). Raises ValueError on garbage."""
    dt = datetime.fromisoformat(raw.strip().replace('Z', '+00:00'))
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _iso(dt) -> str:
    return dt.replace(tzinfo=timezone.utc).isoformat(timespec='microseconds')


def _counts(query) -> dict:
    out = {s: 0 for s in SEVERITIES}
    for sev, n in query.with_entities(Threat.severity, func.count(Threat.id)).group_by(Threat.severity):
        if sev in out:
            out[sev] = n
    return out


@copilot_bp.route("/brief", methods=["GET"])
def brief():
    """The Copilot report. Without ?since it gives counts plus the newest findings. With ?since=<cursor> it gives
    findings reported after that cursor, oldest first, plus a new cursor. Every item passes the cloud sanitizer; ones
    it refuses are only counted in 'withheld'."""
    if not _authorized():
        return jsonify({"error": "Unauthorized"}), 401
    hours = _bounded(request.args.get("hours"), 24, 1, 168)
    limit = _bounded(request.args.get("limit"), 5, 0, MAX_ITEMS)
    now = datetime.now(timezone.utc).replace(tzinfo=None)                                     # stored as naive UTC
    since = now - timedelta(hours=hours)
    min_sev = request.args.get("min_severity", "medium")
    if min_sev not in REPORTED:
        return jsonify({"error": f"min_severity must be one of {', '.join(REPORTED)}"}), 400
    wanted = REPORTED[:REPORTED.index(min_sev) + 1]
    cursor = None
    if request.args.get("since"):
        try:
            cursor = max(_parse_since(request.args["since"]), now - MAX_SINCE)
        except ValueError:
            return jsonify({"error": "since must be an ISO-8601 time (use next_since from the last answer)"}), 400

    recent = Threat.query.filter(Threat.timestamp >= since)
    open_now = Threat.query.filter(Threat.status == "active", Threat.severity.in_(REPORTED))

    items, withheld = [], 0
    if cursor is None:                              # the status view: newest first
        rows = (recent.filter(Threat.severity.in_(wanted)).order_by(Threat.timestamp.desc()).limit(limit * 3)
                if limit else [])                   # a few spare rows, in case the gate withholds some
    else:                                           # the alert feed: oldest first after the cursor, so none is skipped
        rows = (Threat.query.filter(Threat.timestamp > cursor, Threat.severity.in_(wanted))
                .order_by(Threat.timestamp.asc(), Threat.id.asc()).limit(limit * 3) if limit else [])
    next_cursor = cursor
    for t in rows:
        if len(items) >= limit:
            break
        next_cursor = t.timestamp                   # sent or withheld, it is behind us now
        status = t.status if t.status in ("active", "resolved", "dismissed") else "other"
        summary = " ".join(x for x in (f"[{status}]", t.description or t.type or "", _verdict_text(t.ai_verdict)) if x)
        out = sanitizer.sanitize_for_cloud({"severity": t.severity, "threat_type": t.type or "",
                                            "timestamp": t.timestamp, "sanitized_summary": summary},
                                           destination=_DESTINATION)
        if out.get("sanitized_summary"):
            items.append(out)
        else:
            withheld += 1                           # the gate refused it: not sent, only counted

    return jsonify({
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "window_hours": hours,
        "counts": _counts(recent),
        "open": {s: n for s, n in _counts(open_now).items() if s in REPORTED},
        "threats": items,
        "withheld": withheld,
        **({"next_since": _iso(next_cursor)} if cursor is not None else {}),
        "note": "Counts and sanitized summaries only. Internal addresses, host names, user names and credentials "
                "are replaced by tokens (IP_1, HOST_1, SECRET_1 ...).",
    })


# ── Approve-first remediation from Teams (2026-09-30) ────────────────────────
teams_failures = auth.SlidingWindow(auth._env_int("SSAI_TEAMS_MAX_FAILURES", 10), 300)   # bad tokens per address


def _target_shown(row):
    """What the approver sees as the target. A public address or domain is the attacker's, fine to show; a LAN
    address is never sent to the cloud (the approver is told it is a device here and can look in the dashboard)."""
    if row.kind == "ip":
        try:
            ip = ipaddress.ip_address(row.target or "")
        except ValueError:
            return None
        return str(ip) if ip.is_global else None
    out = sanitizer.sanitize_for_cloud({"sanitized_summary": row.target or ""}, destination=_DESTINATION).get("sanitized_summary")
    return out if out == row.target else None


def _proposal_view(row):
    """One block proposal as the Teams approver sees it. LAN addresses and anything the privacy filter alters are
    replaced by a generic description, because this goes to Microsoft's cloud."""
    threat = Threat.query.get(row.threat_id)
    shown = _target_shown(row)
    reason = sanitizer.sanitize_for_cloud({"sanitized_summary": row.reason or ""}, destination=_DESTINATION).get("sanitized_summary") or ""
    return {
        "id": row.id, "kind": row.kind, "status": row.status,
        "target": shown or ("a device on your network" if row.kind == "ip" else "a name withheld by the privacy filter"),
        "target_shown": shown is not None,
        "reason": reason, "confidence": row.confidence,
        "proposed_at": _iso(row.proposed_at) if row.proposed_at else None,
        "severity": threat.severity if threat else None, "threat_type": threat.type if threat else None,
        "ttl_hours": remediation_queue.DEFAULT_TTL_HOURS,
    }


@copilot_bp.route("/remediation", methods=["GET"])
def teams_pending():
    if not _authorized():
        return jsonify({"error": "Unauthorized"}), 401
    rows = (PendingRemediation.query.filter_by(status="pending")
            .order_by(PendingRemediation.proposed_at.asc()).limit(MAX_ITEMS).all())
    return jsonify({"approvals_enabled": entra.settings() is not None,
                    "proposals": [_proposal_view(r) for r in rows]})


def _decide(id, action):
    """Shared body of the Teams approve and reject routes. Needs the Copilot lane key AND a valid Entra token from a
    named approver; repeated bad tokens from one address are blocked for a while; every attempt is audited. 409 means
    already decided, 502 means the block could not be applied."""
    from app import _AUDIT_PATH
    ip = auth.client_ip()
    if not _lane_key_given():
        return jsonify({"error": "Unauthorized"}), 401
    if entra.settings() is None:
        return jsonify({"ok": False, "error": "Approving from Teams is not set up on this hub. Use the dashboard."}), 503
    if teams_failures.count(ip) >= teams_failures.limit:
        return jsonify({"ok": False, "error": "Too many failed attempts. Wait a few minutes."}), 429
    header = request.headers.get("Authorization", "")
    token = header[7:].strip() if header.lower().startswith("bearer ") else ""
    try:
        who = entra.verify(token)
    except entra.TokenError as exc:
        teams_failures.hit(ip)
        remediation.audit(_AUDIT_PATH, action=f"teams-{action}", proposal_id=id, ok=False, error=str(exc), by=ip)
        return jsonify({"ok": False, "error": "Not allowed: only people on this hub's approver list can decide."}), 403
    decided_by = f"teams:{who['name']}"[:100]
    audit_who = {"by": decided_by, "oid": who["oid"], "via": ip}
    try:
        if action == "approve":
            remediation.audit_before_acting(_AUDIT_PATH, action="teams-approve", stage="intent", proposal_id=id, **audit_who)
            row, _detail = remediation_queue.approve_proposal(id, decided_by=decided_by)
        else:
            row = remediation_queue.reject_proposal(id, decided_by=decided_by)
    except ValueError as exc:                       # already decided / expired
        return jsonify({"ok": False, "error": str(exc)}), 409
    except remediation.RemediationError as exc:
        remediation.audit(_AUDIT_PATH, action=f"teams-{action}", proposal_id=id, ok=False, error=str(exc), **audit_who)
        return jsonify({"ok": False, "error": "The block could not be applied; see the dashboard."}), 502
    remediation.audit(_AUDIT_PATH, action=f"teams-{action}", proposal_id=id, kind=row.kind, target=row.target, ok=True,
                      expires_at=row.expires_at.isoformat() if row.expires_at else None, **audit_who)
    view = _proposal_view(row)
    view.update(decided_by=who["name"], expires_at=_iso(row.expires_at) if row.expires_at else None)
    return jsonify({"ok": True, "proposal": view})


@copilot_bp.route("/remediation/<int:id>/approve", methods=["POST"])
def teams_approve(id):
    return _decide(id, "approve")


@copilot_bp.route("/remediation/<int:id>/reject", methods=["POST"])
def teams_reject(id):
    return _decide(id, "reject")
