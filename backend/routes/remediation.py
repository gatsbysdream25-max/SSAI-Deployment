"""Approve-first remediation queue endpoints. See remediation_queue.py for the actual logic;
this blueprint is just auth + HTTP plumbing, same pattern as routes/threats.py."""
from flask import Blueprint, jsonify, request

from auth import approving_person, client_ip, is_admin, person_required_for_approval
from models import PendingRemediation
import remediation
import remediation_queue

remediation_bp = Blueprint("remediation", __name__)


def _check_auth():
    return is_admin()


def _decider(person):
    """Who is recorded as having decided: the signed-in person and the address they came from (the column holds 100 characters),
    or just the address when a program called (only possible where SSAI_APPROVAL_REQUIRES_PERSON=0, or for a reject)."""
    return (f"{person} @ {client_ip()}" if person else f"key @ {client_ip()}")[:100]


@remediation_bp.route("/", methods=["GET"])
def list_pending():
    """Admin only: list block proposals (newest first, at most 200); ?status=pending is the default, ?status=all shows
    every one."""
    if not _check_auth():
        return jsonify({"error": "Unauthorized"}), 401
    status = request.args.get("status", "pending")
    q = PendingRemediation.query
    if status != "all":
        q = q.filter_by(status=status)
    rows = q.order_by(PendingRemediation.proposed_at.desc()).limit(200).all()
    return jsonify([r.to_dict() for r in rows])


@remediation_bp.route("/<int:id>/approve", methods=["POST"])
def approve(id):
    """Approve a proposed block. By default this needs a signed-in person, not an API key. The intent is written to the
    audit file before the firewall changes; 409 means the proposal was already decided, 502 means applying the block
    failed."""
    if not _check_auth():
        return jsonify({"error": "Unauthorized"}), 401
    from app import _AUDIT_PATH
    data = request.get_json(silent=True) or {}
    ttl_hours = data.get("ttl_hours")
    person = approving_person()
    if person is None and person_required_for_approval():
        # The agents hold the same admin key, so a key alone is not a person's decision (audit F-04).
        remediation.audit(_AUDIT_PATH, action="approve", proposal_id=id, ok=False, by=client_ip(),
                          error="refused: approving needs a signed-in person, not an API key")
        return jsonify({"ok": False, "error": "approving a block needs a signed-in person: sign in to the dashboard and approve there "
                                              "(an API key is held by programs and cannot approve)"}), 403
    who = _decider(person)
    try:
        # The intent is on disk before the firewall changes: if it cannot be recorded, nothing is blocked (audit F-14).
        remediation.audit_before_acting(_AUDIT_PATH, action="approve", stage="intent", proposal_id=id, by=who, ip=client_ip())
        row, detail = remediation_queue.approve_proposal(id, decided_by=who, ttl_hours=ttl_hours)
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 409
    except remediation.RemediationError as e:
        remediation.audit(_AUDIT_PATH, action="approve", proposal_id=id, ok=False, error=str(e), by=who)
        return jsonify({"ok": False, "error": str(e)}), 502
    remediation.audit(_AUDIT_PATH, action="approve", proposal_id=id, kind=row.kind, target=row.target,
                      ok=True, detail=detail, expires_at=row.expires_at.isoformat() if row.expires_at else None, by=who, ip=client_ip())
    return jsonify({"ok": True, "detail": detail, "proposal": row.to_dict()})


@remediation_bp.route("/<int:id>/reject", methods=["POST"])
def reject(id):
    """Reject a proposed block (nothing is blocked); 409 when it was already decided."""
    if not _check_auth():
        return jsonify({"error": "Unauthorized"}), 401
    from app import _AUDIT_PATH
    who = _decider(approving_person())
    try:
        row = remediation_queue.reject_proposal(id, decided_by=who)
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 409
    remediation.audit(_AUDIT_PATH, action="reject", proposal_id=id, kind=row.kind, target=row.target,
                      ok=True, by=who)
    return jsonify({"ok": True, "proposal": row.to_dict()})


@remediation_bp.route("/sweep", methods=["POST"])
def sweep():
    """Called periodically by RemediationSweepAgent (admin API key, same as every other agent->API call):
    expire stale pending proposals and auto-unblock any approved block whose TTL has passed."""
    if not _check_auth():
        return jsonify({"error": "Unauthorized"}), 401
    from app import _AUDIT_PATH
    result = remediation_queue.sweep(audit_path=_AUDIT_PATH)
    return jsonify(result)
