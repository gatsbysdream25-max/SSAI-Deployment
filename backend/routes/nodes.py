"""Machines that report to this hub: enrolment, heartbeats, the list, revoking, and the shared signal feed.

A machine trades a single-use enrolment code for its OWN credential (see auth.py); the old open registration handed a token to
anyone. The admin key never leaves the hub. Every enrolment, revocation and removal is written to the audit file.
"""
import secrets
import socket

from flask import Blueprint, jsonify, request

import auth as _auth
from models import Agent, EnrollmentCode, Node, Threat, db
from request_helpers import _clean_list_of_str, _clean_severity, _clean_str, _clean_tier, _utcnow

nodes_bp = Blueprint("nodes", __name__)


def _audit_path():
    """The audit file, looked up when needed: app.py owns it and tests point it somewhere else after start-up."""
    from app import _AUDIT_PATH
    return _AUDIT_PATH


def _rate_limited(bucket):
    """app.py keeps the rate-limit counters (tests and the dashboard read them), so ask it."""
    from app import _rate_limited as limited
    return limited(bucket)


@nodes_bp.route("/api/node/register", methods=["POST"])
def node_register():
    """Enrol a machine: a valid, unused, unexpired enrolment code -> that machine's own token, shown once."""
    import remediation
    ip = _auth.client_ip()
    if _auth.enroll_failures.count(ip) >= _auth.enroll_failures.limit:
        return jsonify({"error": "too many failed attempts; try again later"}), 429
    data = request.get_json(silent=True) or {}
    code = _auth.normalize_code(data.get("enrollCode") or data.get("code"))
    now = _utcnow()
    row = EnrollmentCode.query.filter_by(code_hash=_auth.hash_secret(code)).first() if code else None

    def refuse():
        _auth.enroll_failures.hit(ip)
        remediation.audit(_audit_path(), action="enroll", ok=False, error="invalid, used or expired code", by=ip)
        return jsonify({"error": "invalid or expired enrollment code"}), 401     # one answer for every reason: no oracle
    if row is None or row.used_at is not None or row.expires_at <= now:
        return refuse()

    hostname = _clean_str(data.get("hostname") or "unknown", 128)
    platform = _clean_str(data.get("platform", ""), 64)
    nid = (row.node_id or _auth.clean_node_id(data.get("nodeId") or data.get("nodeName"))
           or _auth.clean_node_id(hostname, "node-" + secrets.token_hex(3)))
    node = Node.query.filter_by(node_id=nid).first()
    if nid == socket.gethostname() and not row.node_id:
        return jsonify({"error": f"'{nid}' is this hub's own name; pick another name (--node-id)"}), 409
    if node is not None and node.status == "active" and node.token_hash and not row.node_id:
        return jsonify({"error": f"a machine named '{nid}' is already enrolled; pick another name (--node-id), or ask the "
                                 "admin for a code made for that machine to replace its credential"}), 409
    # Claim the code atomically: two workers must not both redeem it.
    if EnrollmentCode.query.filter_by(id=row.id, used_at=None).update({"used_at": now, "used_by": nid}) != 1:
        db.session.rollback()
        return refuse()
    db.session.commit()

    token = _auth.new_token()
    if node is None:
        node = Node(node_id=nid, registered=now)
        db.session.add(node)
    node.hostname, node.platform = hostname, platform
    node.tier = _clean_tier(data.get("tier", "free"))
    node.eula_ver = _clean_str(data.get("eulaVersion", ""), 32)
    node.status, node.last_seen, node.enrolled_at, node.revoked_at = "active", now, now, None
    node.token, node.token_hash, node.token_hint = None, _auth.hash_secret(token), token[:8]
    db.session.commit()
    remediation.audit(_audit_path(), action="enroll", ok=True, node=nid, by=ip)
    return jsonify({"nodeId": nid, "token": token, "apiBase": request.host_url.rstrip("/") + "/api"}), 200


@nodes_bp.route("/api/node/heartbeat", methods=["POST"])
def node_heartbeat():
    who = _auth.identity()
    if who is None or who.kind != "node":
        return jsonify({"ok": False, "error": "a node credential is required"}), 401
    if _auth.node_rate_limited(who.node):
        return jsonify({"error": "rate limited"}), 429
    return jsonify({"ok": True})                     # identity() has already refreshed last_seen


@nodes_bp.route("/api/nodes", methods=["GET"])
def get_nodes():
    """Admin only: list the machines, with agent_count recalculated from the agents whose names end in @<node id>."""
    if not _auth.is_admin():
        return jsonify({'error': 'Unauthorized'}), 401
    from collections import Counter
    per_node = Counter(a.name.rsplit("@", 1)[1] for a in Agent.query.filter(Agent.name.like("%@%")).all())
    out = []
    for n in Node.query.order_by(Node.last_seen.desc()).all():
        d = n.to_dict()
        d["agent_count"] = per_node.get(n.node_id, d["agent_count"])
        out.append(d)
    return jsonify(out)


@nodes_bp.route("/api/nodes/enrollment-codes", methods=["POST"])
def create_enrollment_code():
    """Admin: a single-use code for one new machine (or, with node_id, to replace one machine's credential)."""
    import remediation
    from datetime import timedelta
    if not _auth.is_admin():
        return jsonify({"error": "Unauthorized"}), 401
    body = request.get_json(silent=True) or {}
    nid = _auth.clean_node_id(body.get("node_id")) or None
    try:
        ttl = min(max(int(body.get("ttl_minutes", 60)), 5), 1440)
    except (TypeError, ValueError):
        ttl = 60
    now = _utcnow()
    EnrollmentCode.query.filter(EnrollmentCode.expires_at < now - timedelta(days=7)).delete()
    code = _auth.new_code()
    db.session.add(EnrollmentCode(code_hash=_auth.hash_secret(_auth.normalize_code(code)), node_id=nid, created_at=now,
                                  expires_at=now + timedelta(minutes=ttl), created_by=_auth.client_ip()))
    db.session.commit()
    remediation.audit(_audit_path(), action="enrollment-code", ok=True, node=nid, ttl_minutes=ttl, by=_auth.client_ip())
    return jsonify({"code": code, "node_id": nid, "ttl_minutes": ttl,
                    "expires_at": (now + timedelta(minutes=ttl)).isoformat() + "Z", "hub_url": request.host_url.rstrip("/")})


@nodes_bp.route("/api/nodes/<node_id>/revoke", methods=["POST"])
def revoke_node(node_id):
    """Admin: the machine's token stops working immediately. Its history stays."""
    import remediation
    if not _auth.is_admin():
        return jsonify({"error": "Unauthorized"}), 401
    node = Node.query.filter_by(node_id=node_id).first_or_404()
    node.status, node.token_hash, node.token_hint, node.revoked_at = "revoked", None, None, _utcnow()
    db.session.commit()
    remediation.audit(_audit_path(), action="revoke-node", ok=True, node=node_id, by=_auth.client_ip())
    return jsonify({"ok": True, "node_id": node_id, "credential": "revoked"})


@nodes_bp.route("/api/nodes/<node_id>", methods=["DELETE"])
def delete_node(node_id):
    """Admin only: delete a machine's record entirely (revoking instead keeps its history)."""
    import remediation
    if not _auth.is_admin():
        return jsonify({"error": "Unauthorized"}), 401
    node = Node.query.filter_by(node_id=node_id).first_or_404()
    db.session.delete(node)
    db.session.commit()
    remediation.audit(_audit_path(), action="delete-node", ok=True, node=node_id, by=_auth.client_ip())
    return jsonify({"ok": True})


# ─── Signal endpoints (v2.1.0 protocol) ─────────────────────────────────────
@nodes_bp.route("/api/signal", methods=["POST"])
def submit_signal():
    """A node reports a threat signal. Needs that node's own token; the node id comes from the token, never from the
    request body. Saved as a new threat."""
    if _rate_limited('signal'):
        return jsonify({"error": "rate limited"}), 429
    data = request.get_json(silent=True) or {}
    # A signal must come with an enrolled node's own token; the node id is that token's, never taken from the body
    # (node ids are listed publicly, so trusting one was an open door for forged threats).
    who = _auth.identity()
    if who is None or who.kind != "node":
        return jsonify({"error": "a node credential is required"}), 401
    if _auth.node_rate_limited(who.node):
        return jsonify({"error": "rate limited"}), 429
    node_id = who.node.node_id
    ttps = _clean_list_of_str(data.get('ttps', []))
    threat = Threat(
        url         = _clean_str(data.get("source") or data.get("url") or data.get("iocHash", "")),
        type        = _clean_str(data.get("type", "unknown"), 64) or "unknown",
        severity    = _clean_severity(data.get("severity", "medium")),
        description = f"TTPs: {','.join(ttps)}  platform: {_clean_str(data.get('platform',''), 64)}",
        detected_by = node_id,
        node_id     = node_id,
    )
    db.session.add(threat)
    db.session.commit()
    return jsonify({"success": True, "id": threat.id}), 201


@nodes_bp.route("/api/signal/feed", methods=["GET"])
def signal_feed():
    """The newest threats (default 100, at most 1000) plus the total count, as the shared signal feed."""
    try:
        limit = max(1, min(int(request.args.get("limit", 100)), 1000))
    except (TypeError, ValueError):
        limit = 100
    signals = Threat.query.order_by(Threat.timestamp.desc()).limit(limit).all()
    return jsonify({
        "signals": [t.to_dict() for t in signals],
        "total":   Threat.query.count(),
    })
