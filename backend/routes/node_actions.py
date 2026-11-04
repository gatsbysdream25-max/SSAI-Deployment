"""Actions for enrolled Windows PCs: a person approves one here, the PC's agent fetches and carries it out.

  POST /api/nodes/<node_id>/actions            a signed-in person queues an action (never an API key)
  GET  /api/nodes/<node_id>/actions            the newest 100 for that PC (admin)
  POST /api/nodes/<node_id>/actions/<id>/undo  a signed-in person asks the agent to undo an action early
  POST /api/node/actions/poll                  the PC's agent asks for work (its own token)
  POST /api/node/actions/<id>/result           the PC's agent reports the outcome (its own token)
See node_actions.py for what an action may be. The intent is written to the audit file BEFORE it is queued.
"""
from flask import Blueprint, jsonify, request

import auth as _auth
import node_actions
import remediation
from models import NodeAction

node_actions_bp = Blueprint("node_actions", __name__)


def _audit_path():
    from app import _AUDIT_PATH
    return _AUDIT_PATH


def _never_block():
    from app import _never_block_ips
    return _never_block_ips()


def _person_or_refusal():
    """(who, None) for a signed-in person, or (None, response) when the caller is only a key."""
    # Unlike approving a block, this never falls back to the admin key, whatever SSAI_APPROVAL_REQUIRES_PERSON says: these
    # actions can cut a PC off the network or stop its programs, so a program holding the key must not be able to start them.
    person = _auth.approving_person()
    if person is None:
        return None, (jsonify({"ok": False, "error": "queueing an action for a PC needs a signed-in person: sign in to the "
                                                     "dashboard and do it there (an API key is held by programs and cannot)"}), 403)
    return f"{person} @ {_auth.client_ip()}"[:100], None


def _queue(node_id, action, args, ttl_hours, reason, threat_id):
    who, refusal = _person_or_refusal()
    if refusal:
        return refusal
    try:
        # Validate first, then record the intent, then queue: nothing is queued if it cannot be recorded.
        node_actions.validate(action, args, ttl_hours, _never_block(), node_id)
        remediation.audit_before_acting(_audit_path(), action="node-action", stage="intent", node=node_id, node_action=action,
                                        args=args, by=who)
        row = node_actions.create(node_id, action, args, who, reason, threat_id, ttl_hours, _never_block())
    except node_actions.ActionError as e:
        remediation.audit(_audit_path(), action="node-action", ok=False, node=node_id, node_action=action, error=str(e), by=who)
        return jsonify({"ok": False, "error": str(e)}), 400
    remediation.audit(_audit_path(), action="node-action", ok=True, node=node_id, node_action=action, action_id=row.id,
                      args=row.to_dict()["args"], ttl_hours=row.ttl_hours, by=who)
    return jsonify({"ok": True, "action": row.to_dict()}), 201


@node_actions_bp.route("/api/nodes/<node_id>/actions", methods=["POST"])
def queue_action(node_id):
    if not _auth.is_admin():
        return jsonify({"error": "Unauthorized"}), 401
    body = request.get_json(silent=True) or {}
    return _queue(node_id, str(body.get("action", "")), body.get("args") if "args" in body else {}, body.get("ttl_hours"),
                  str(body.get("reason", "")), body.get("threat_id"))


@node_actions_bp.route("/api/nodes/<node_id>/actions", methods=["GET"])
def list_actions(node_id):
    if not _auth.is_admin():
        return jsonify({"error": "Unauthorized"}), 401
    rows = NodeAction.query.filter_by(node_id=node_id).order_by(NodeAction.id.desc()).limit(100).all()
    return jsonify([r.to_dict() for r in rows])


@node_actions_bp.route("/api/nodes/<node_id>/actions/<int:id>/undo", methods=["POST"])
def undo_action(node_id, id):
    if not _auth.is_admin():
        return jsonify({"error": "Unauthorized"}), 401
    return _queue(node_id, "undo", {"of": id}, None, "undo action %d" % id, None)


@node_actions_bp.route("/api/node/actions/poll", methods=["POST"])
def poll():
    who = _auth.identity()
    if who is None or who.kind != "node":
        return jsonify({"ok": False, "error": "a node credential is required"}), 401
    if _auth.node_rate_limited(who.node):
        return jsonify({"error": "rate limited"}), 429
    return jsonify({"ok": True, "actions": node_actions.fetch(who.node)})


@node_actions_bp.route("/api/node/actions/<int:id>/result", methods=["POST"])
def result(id):
    who = _auth.identity()
    if who is None or who.kind != "node":
        return jsonify({"ok": False, "error": "a node credential is required"}), 401
    if _auth.node_rate_limited(who.node):
        return jsonify({"error": "rate limited"}), 429
    body = request.get_json(silent=True) or {}
    row = node_actions.record_result(who.node, id, body.get("ok") is True, body.get("detail"), body.get("undone") is True)
    if row is None:
        return jsonify({"ok": False, "error": "no such action in a state that takes a result"}), 404
    remediation.audit(_audit_path(), action="node-action-result", ok=row.status in ("done", "undone"), node=row.node_id,
                      node_action=row.action, action_id=row.id, status=row.status, detail=row.result, by=row.node_id)
    return jsonify({"ok": True, "status": row.status})
