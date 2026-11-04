"""Actions a signed-in person approves for ONE enrolled Windows PC, carried out by that PC's own agent.

The agent never listens for commands. It asks the hub for work (a pull), so nothing has to be opened on the PC and it
works on any network. The hub sends an action NAME plus arguments checked here, never a script or a command line, and the
agent only runs names on its own fixed list. Every action is reversible except killing a process, and each one that changes
the PC's network carries a time limit after which the agent undoes it by itself, even if the hub is gone.

There is no automatic path: only a signed-in person creates an action (routes/node_actions.py), and a PC whose agent is set
to response "off" (its own agent.json, the default) never asks for work at all.
"""
import ipaddress
import json
import re
from datetime import datetime, timedelta, timezone

import remediation
import remediation_queue
from models import Node, NodeAction, db

QUEUE_MINUTES = 60              # an approved action nobody fetched within this time is dropped, never run a day later
SENT_MINUTES = 60               # an action fetched but never reported on is closed as failed
MAX_QUEUED_PER_NODE = 20
BATCH = 5
DEFAULT_TTL = {"block-ip": 24, "block-domain": 24, "isolate-host": 1}
MAX_TTL = {"block-ip": 24 * 7, "block-domain": 24 * 7, "isolate-host": 24}
_IMAGE = re.compile(r"^[\w .()\-]{1,100}\.exe$", re.I)
# Same list the agent keeps. The agent is the last line of defence; this one gives the operator the reason early.
PROTECTED_IMAGES = frozenset((
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "lsaiso.exe",
    "svchost.exe", "dwm.exe", "fontdrvhost.exe", "msmpeng.exe", "nissrv.exe", "securityhealthservice.exe", "ssai-agent.exe"))
ACTIONS = ("block-ip", "block-domain", "defender-scan", "defender-remove", "kill-process", "isolate-host", "undo")


class ActionError(ValueError):
    """The action cannot be queued; the message is shown to the operator."""


def _utc(dt):
    return dt.replace(tzinfo=timezone.utc) if dt is not None and dt.tzinfo is None else dt


def _ttl(action, raw):
    if action not in DEFAULT_TTL:
        return None
    if raw is None:
        return DEFAULT_TTL[action]
    if isinstance(raw, bool):
        raise ActionError("ttl_hours must be a number of hours")
    try:
        ttl = float(raw)
    except (TypeError, ValueError):
        raise ActionError("ttl_hours must be a number of hours") from None
    if not 0 < ttl <= MAX_TTL[action]:
        raise ActionError("ttl_hours must be more than 0 and at most %d for %s (the agent undoes it after that)" % (MAX_TTL[action], action))
    return ttl


def validate(action, args, ttl_hours=None, never_block_ips=frozenset(), node_id=None):
    """Check one request. Returns (clean args, ttl hours or None) or raises ActionError."""
    if action not in ACTIONS:
        raise ActionError("action must be one of: " + ", ".join(ACTIONS))
    if not isinstance(args, dict):
        raise ActionError("args must be an object")
    ttl = _ttl(action, ttl_hours)
    if action == "block-ip":
        try:
            ip = ipaddress.ip_address(str(args.get("ip", "")).strip())
            remediation.classify_target(str(ip))                 # refuses loopback, multicast, reserved and the like
        except ValueError as e:                                  # ValueError covers TargetError too
            raise ActionError(str(e) if isinstance(e, remediation.TargetError) else "block-ip needs a valid IP address in args.ip") from None
        if remediation_queue.internal_address(str(ip)) or str(ip) in never_block_ips:
            raise ActionError("%s is inside the organisation or on the never-block list, so it will not be blocked" % ip)
        return {"ip": str(ip)}, ttl
    if action == "block-domain":
        try:
            target = remediation.classify_target(str(args.get("domain", "")))
        except remediation.TargetError as e:
            raise ActionError(str(e)) from None
        if target["kind"] != "domain":
            raise ActionError("block-domain needs a domain name in args.domain")
        return {"domain": target["value"]}, ttl
    if action == "kill-process":
        try:
            pid = int(args.get("pid"))
        except (TypeError, ValueError):
            raise ActionError("kill-process needs the process id in args.pid") from None
        image = str(args.get("image", "")).strip()
        if pid <= 4 or pid > 4194304 or isinstance(args.get("pid"), bool):
            raise ActionError("that process id cannot be stopped")
        if not _IMAGE.match(image):
            raise ActionError("kill-process needs the program's file name (for example evil.exe) in args.image")
        if image.lower() in PROTECTED_IMAGES:
            raise ActionError("%s is part of Windows or of SwarmSentinel's protection and will not be stopped" % image)
        return {"pid": pid, "image": image}, None
    if action == "undo":
        try:
            of = int(args.get("of"))
        except (TypeError, ValueError):
            raise ActionError("undo needs the action id in args.of") from None
        target = NodeAction.query.filter_by(id=of, node_id=node_id).first()
        if target is None or target.action not in DEFAULT_TTL:
            raise ActionError("action %s is not an undoable action on this machine" % of)
        if target.status != "done":
            raise ActionError("action %s is %s, so there is nothing to undo" % (of, target.status))
        return {"of": of}, None
    return {}, ttl                               # defender-scan, defender-remove, isolate-host take no arguments


def create(node_id, action, args, created_by, reason="", threat_id=None, ttl_hours=None, never_block_ips=frozenset()):
    """Queue an action for a Windows PC. Raises ActionError."""
    node = Node.query.filter_by(node_id=node_id).first()
    if node is None or node.status != "active":
        raise ActionError("no active machine named '%s'" % node_id)
    if "windows" not in (node.platform or "").lower():
        raise ActionError("'%s' is not a Windows PC; these actions are carried out by the Windows agent" % node_id)
    clean, ttl = validate(action, args, ttl_hours, never_block_ips, node_id)
    if NodeAction.query.filter_by(node_id=node_id, status="queued").count() >= MAX_QUEUED_PER_NODE:
        raise ActionError("too many actions are already waiting for '%s'" % node_id)
    row = NodeAction(node_id=node_id, action=action, args=json.dumps(clean), ttl_hours=ttl, reason=(reason or "")[:300],
                     threat_id=threat_id if isinstance(threat_id, int) and not isinstance(threat_id, bool) else None,
                     status="queued", created_by=(created_by or "")[:100])
    db.session.add(row)
    db.session.commit()
    return row


def _close_stale(node_id, now):
    for row in NodeAction.query.filter_by(node_id=node_id, status="queued").all():
        if _utc(row.created_at) < now - timedelta(minutes=QUEUE_MINUTES):
            row.status, row.finished_at, row.result = "expired", now, "not fetched in time; never ran"
    for row in NodeAction.query.filter_by(node_id=node_id, status="sent").all():
        if _utc(row.sent_at) < now - timedelta(minutes=SENT_MINUTES):
            row.status, row.finished_at, row.result = "failed", now, "the agent never reported a result"
    db.session.commit()


def fetch(node):
    """The queued actions for this PC, oldest first. Each is handed out once: it becomes 'sent' before it is returned."""
    now = datetime.now(timezone.utc)
    _close_stale(node.node_id, now)
    out = []
    for row in NodeAction.query.filter_by(node_id=node.node_id, status="queued").order_by(NodeAction.id).limit(BATCH).all():
        claimed = (NodeAction.query.filter_by(id=row.id, status="queued")
                   .update({"status": "sent", "sent_at": now}, synchronize_session=False))
        db.session.commit()
        if claimed != 1:
            continue
        out.append({"id": row.id, "action": row.action, "args": json.loads(row.args or "{}"), "ttl_hours": row.ttl_hours,
                    "valid_until": (_utc(row.created_at) + timedelta(minutes=QUEUE_MINUTES)).isoformat()})
    return out


def record_result(node, action_id, ok, detail, undone=False):
    """The agent reports. Returns the row, or None when this PC has no such action in a state that can take the report."""
    row = NodeAction.query.filter_by(id=action_id, node_id=node.node_id).first()
    if row is None:
        return None
    now = datetime.now(timezone.utc)
    if undone and row.status == "done":
        row.status = "undone"
    elif not undone and row.status == "sent":
        row.status = "done" if ok else "failed"
    else:
        return None
    row.finished_at = now
    row.result = str(detail or "")[:500]
    db.session.commit()
    return row
