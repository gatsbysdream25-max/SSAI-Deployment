"""Permissions for acting without asking (autonomy.py): list, grant, revoke.

Granting authority is a person's act: it needs a signed-in session, never an API key, because the agents hold the key. Revoking is
easy on purpose: a signed-in person or the admin key can switch a permission off at once.
"""
from datetime import datetime, timezone

from flask import Blueprint, jsonify, request

import autonomy
import remediation
from auth import approving_person, client_ip, is_admin
from models import AutonomyGrant, db

autonomy_bp = Blueprint("autonomy", __name__)


@autonomy_bp.route("/grants", methods=["GET"])
def list_grants():
    if not is_admin():
        return jsonify({"error": "Unauthorized"}), 401
    rows = AutonomyGrant.query.order_by(AutonomyGrant.id.desc()).limit(200).all()
    return jsonify({"grants": [r.to_dict() for r in rows], "what_a_grant_cannot_do": list(autonomy.LIMITS)})


@autonomy_bp.route("/grants", methods=["POST"])
def create_grant():
    """Create a permission to act without asking. Needs a signed-in person, not an API key. The terms are written to the
    audit file BEFORE the grant is saved, so if the audit cannot be written no permission is created."""
    if not is_admin():
        return jsonify({"error": "Unauthorized"}), 401
    from app import _AUDIT_PATH
    person = approving_person()
    if person is None:
        return jsonify({"ok": False, "error": "granting a permission needs a signed-in person, not an API key"}), 403
    fields, problem = autonomy.validate_new(request.get_json(silent=True) or {})
    if fields is None:
        return jsonify({"ok": False, "error": problem}), 400
    who = f"{person} @ {client_ip()}"[:100]
    try:
        remediation.audit_before_acting(_AUDIT_PATH, action="grant-permission", by=who, terms={k: str(v) for k, v in fields.items()})
    except remediation.RemediationError as e:
        return jsonify({"ok": False, "error": str(e)}), 502
    grant = AutonomyGrant(granted_by=who, **fields)
    db.session.add(grant)
    db.session.commit()
    return jsonify({"ok": True, "grant": grant.to_dict()}), 201


@autonomy_bp.route("/grants/<int:id>/revoke", methods=["POST"])
def revoke_grant(id):
    """Switch a permission off now. Safe to repeat: a grant that is already revoked is returned unchanged."""
    if not is_admin():
        return jsonify({"error": "Unauthorized"}), 401
    from app import _AUDIT_PATH
    grant = db.session.get(AutonomyGrant, id)
    if grant is None:
        return jsonify({"ok": False, "error": "no such permission"}), 404
    if grant.revoked_at is None:
        grant.revoked_at = datetime.now(timezone.utc)
        grant.revoked_by = f"{approving_person() or 'key'} @ {client_ip()}"[:100]
        db.session.commit()
        remediation.audit(_AUDIT_PATH, action="revoke-permission", grant=id, by=grant.revoked_by, ok=True)
    return jsonify({"ok": True, "grant": grant.to_dict()})
