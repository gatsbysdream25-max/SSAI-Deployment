"""Automatic response settings and log (auto_response.py).

  GET  /api/auto/settings                  the policy (admin)
  POST /api/auto/settings                  change it (a signed-in PERSON only, never an API key)
  GET  /api/auto/actions                   the newest automatic actions, ?status= filter (admin)
  POST /api/auto/actions/<id>/undo         end a block or pause early (person only)
  POST /api/auto/actions/<id>/terminate    end a paused program for good (person only)
  POST /api/auto/actions/<id>/keep         leave a paused program paused, recorded (person only)
  GET  /api/auto/alerts                    alerts, ?open=1 for the unacknowledged ones (admin)
  POST /api/auto/alerts/test               send a test alert (person only)
  POST /api/auto/alerts/<id>/ack           acknowledge an alert (person only)
  GET  /api/auto/preflight                 is the firewall (ufw) on and Pi-hole configured (admin)
  GET  /api/auto/break-glass               is break-glass engaged (admin)
  POST /api/auto/break-glass/engage        stop every automatic action (admin: a person OR the admin key; stopping is safe)
  POST /api/auto/break-glass/release       let them run again (person only)
"""
from flask import Blueprint, jsonify, request

import action_risk
import alerts
import auth as _auth
import auto_response
import break_glass
import remediation

auto_bp = Blueprint("auto_response", __name__)


def _audit_path():
    from app import _AUDIT_PATH
    return _AUDIT_PATH


def _person_or_refusal(what):
    """(who, None) for a signed-in person, or (None, 403 response). The agents hold the admin key, so a key never counts."""
    person = _auth.approving_person()
    if person is None:
        return None, (jsonify({"ok": False, "error": f"{what} needs a signed-in person: sign in to the dashboard and do it there "
                                                     "(an API key is held by programs and cannot)"}), 403)
    return f"{person} @ {_auth.client_ip()}"[:100], None


@auto_bp.route("/settings", methods=["GET"])
def get_settings():
    if not _auth.is_admin():
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({"policy": auto_response.load_policy(), "defaults": auto_response.defaults(),
                    "hourly_cap": auto_response.HOURLY_CAP, "actions_last_hour": auto_response.actions_last_hour(),
                    "attacker_min_fails": auto_response.ATTACKER_MIN_FAILS, "max_hours": auto_response.MAX_HOURS,
                    "break_glass": break_glass.status(), "never_pause": sorted(auto_response.never_pause_names()),
                    "risk_table": action_risk.describe(), "floors": {"min_families": action_risk.MIN_FAMILIES_FLOOR,
                                                                     "min_confidence": action_risk.MIN_CONFIDENCE_FLOOR},
                    "alert_channels": alerts.channels()})


@auto_bp.route("/settings", methods=["POST"])
def set_settings():
    if not _auth.is_admin():
        return jsonify({"error": "Unauthorized"}), 401
    who, refusal = _person_or_refusal("changing automatic response")
    if refusal:
        return refusal
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"ok": False, "error": "send the policy as a JSON object"}), 400
    try:
        pol = auto_response.save_policy(data, who, _audit_path())
    except auto_response.ActionError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    except (remediation.RemediationError, OSError) as e:
        return jsonify({"ok": False, "error": f"not saved: {e}"}), 500
    return jsonify({"ok": True, "policy": pol})


@auto_bp.route("/actions", methods=["GET"])
def list_actions():
    if not _auth.is_admin():
        return jsonify({"error": "Unauthorized"}), 401
    from models import AutoAction
    q = AutoAction.query
    status = (request.args.get("status") or "").strip()
    if status:
        q = q.filter(AutoAction.status == status)
    try:
        limit = max(1, min(int(request.args.get("limit", 200)), 1000))
    except ValueError:
        limit = 200
    return jsonify([r.to_dict() for r in q.order_by(AutoAction.id.desc()).limit(limit).all()])


def _end(id, fn, what):
    if not _auth.is_admin():
        return jsonify({"error": "Unauthorized"}), 401
    who, refusal = _person_or_refusal(what)
    if refusal:
        return refusal
    try:
        row = fn(id, who, _audit_path())
    except auto_response.ActionError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    except Exception as e:                                 # noqa: BLE001 -- the firewall, Pi-hole or a signal refused
        remediation.audit(_audit_path(), action=f"auto-{what}", auto_action=id, ok=False, error=str(e)[:200], by=who)
        return jsonify({"ok": False, "error": f"could not finish: {e}"}), 500
    return jsonify({"ok": True, "action": row.to_dict()})


@auto_bp.route("/actions/<int:id>/undo", methods=["POST"])
def undo_action(id):
    return _end(id, auto_response.undo, "undo")


@auto_bp.route("/actions/<int:id>/terminate", methods=["POST"])
def terminate_action(id):
    return _end(id, auto_response.terminate, "terminate")


@auto_bp.route("/actions/<int:id>/keep", methods=["POST"])
def keep_paused_action(id):
    return _end(id, auto_response.keep_paused, "keep-paused")


# ── alerts ───────────────────────────────────────────────────────────────────

@auto_bp.route("/alerts", methods=["GET"])
def list_alerts():
    if not _auth.is_admin():
        return jsonify({"error": "Unauthorized"}), 401
    rows = alerts.open_alerts() if request.args.get("open") in ("1", "true") else alerts.all_alerts()
    return jsonify({"alerts": rows[:alerts.MAX_RETURNED], "open": len(alerts.open_alerts()), "channels": alerts.channels()})


@auto_bp.route("/alerts/test", methods=["POST"])
def test_alert():
    if not _auth.is_admin():
        return jsonify({"error": "Unauthorized"}), 401
    who, refusal = _person_or_refusal("sending a test alert")
    if refusal:
        return refusal
    a = alerts.send_test(who)
    if a is None:
        return jsonify({"ok": False, "error": "the alert could not be recorded (see the server log)"}), 500
    remediation.audit(_audit_path(), action="alert-test", alert=a["id"], by=who, ok=True)
    return jsonify({"ok": True, "alert": a})


@auto_bp.route("/alerts/<alert_id>/ack", methods=["POST"])
def ack_alert(alert_id):
    if not _auth.is_admin():
        return jsonify({"error": "Unauthorized"}), 401
    who, refusal = _person_or_refusal("acknowledging an alert")
    if refusal:
        return refusal
    try:
        a = alerts.acknowledge(alert_id, who)
    except KeyError:
        return jsonify({"ok": False, "error": "no such alert"}), 404
    remediation.audit(_audit_path(), action="alert-ack", alert=a["id"], kind=a.get("kind"), by=who, ok=True)
    return jsonify({"ok": True, "alert": a, "channels": alerts.channels()})


# ── preflight: would a block actually be enforced? ───────────────────────────

def _preflight(run=None):
    import os
    import subprocess
    run = run or subprocess.run
    out = {"ufw": {"ok": False, "detail": ""}, "pihole": {"ok": False, "detail": ""}}
    try:
        r = remediation._ufw(["status"], run)
        text = ((r.stdout or "") + (r.stderr or "")).strip()
        if r.returncode == 0 and "status: active" in (r.stdout or "").lower():
            out["ufw"] = {"ok": True, "detail": "the firewall (ufw) is on"}
        elif r.returncode == 0:
            out["ufw"]["detail"] = "the firewall (ufw) is switched off, so an IP block would not be enforced"
        elif "password is required" in text or "a terminal is required" in text:
            out["ufw"]["detail"] = "this account may not run ufw yet (re-run deploy/install.sh as root)"
        else:
            out["ufw"]["detail"] = f"ufw is not usable: {text[:160]}"
    except remediation.RemediationError as e:
        out["ufw"]["detail"] = str(e)[:200]
    if os.environ.get("PIHOLE_IP") and os.environ.get("PIHOLE_PASSWORD"):
        out["pihole"] = {"ok": True, "detail": "Pi-hole is configured (PIHOLE_IP and PIHOLE_PASSWORD are set)"}
    else:
        out["pihole"]["detail"] = "Pi-hole is not configured (PIHOLE_IP / PIHOLE_PASSWORD in .env), so a domain block would fail"
    return out


@auto_bp.route("/preflight", methods=["GET"])
def preflight():
    if not _auth.is_admin():
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(_preflight())


# ── break-glass ──────────────────────────────────────────────────────────────

@auto_bp.route("/break-glass", methods=["GET"])
def break_glass_status():
    if not _auth.is_admin():
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(break_glass.status())


@auto_bp.route("/break-glass/engage", methods=["POST"])
def break_glass_engage():
    """Stopping is the safe direction, so the admin key may do it too (a script, or an operator without a browser)."""
    if not _auth.is_admin():
        return jsonify({"error": "Unauthorized"}), 401
    person = _auth.approving_person()
    who = f"{person or 'admin key'} @ {_auth.client_ip()}"[:100]
    data = request.get_json(silent=True)
    reason = data.get("reason") if isinstance(data, dict) and isinstance(data.get("reason"), str) else ""
    try:
        state = break_glass.engage(who, reason or "engaged from the dashboard or API", _audit_path())
    except (remediation.RemediationError, OSError) as e:
        return jsonify({"ok": False, "error": f"not engaged: {e}"}), 500
    return jsonify({"ok": True, "state": state})


@auto_bp.route("/break-glass/release", methods=["POST"])
def break_glass_release():
    if not _auth.is_admin():
        return jsonify({"error": "Unauthorized"}), 401
    who, refusal = _person_or_refusal("releasing break-glass")
    if refusal:
        return refusal
    try:
        state = break_glass.release(who, _audit_path())
    except (remediation.RemediationError, OSError) as e:
        return jsonify({"ok": False, "error": f"not released: {e}"}), 500
    return jsonify({"ok": True, "state": state})
