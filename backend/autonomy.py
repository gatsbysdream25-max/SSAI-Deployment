"""Bounded autonomy: what SSAI may do WITHOUT asking, one narrow permission at a time (consensus plan phase 7).

By default SSAI proposes and a person decides. A person can grant ONE permission at a time, such as "block a known-bad domain on low
and medium findings of type malicious-domain, for 30 days, at most 5 an hour". A grant is data in a table, not code: the software
enforces it on every automatic action, and anything outside every grant waits in the approval queue exactly as before.

What a grant can NOT do, whatever it says and however many models agree (a vote never overrides these):
  * act on a degraded verdict, a stand-in panel, possible prompt injection, or an independent check that disagrees;
  * act without local proof (a threat-feed hit, or two independent detectors) unless the grant explicitly allows unverified;
  * block anything inside the organisation (private, Tailscale, link-local) or on the operator's never-block list;
  * run after it expires, after it is revoked, or faster than its rate limit;
  * act on severe or critical findings, unless the grant says allow_severe AND the person typed the confirmation sentence;
  * be created by an API key: only a signed-in person grants authority.
Every automatic action writes its audit line BEFORE it acts (no record, no action), is named "auto:grant-N" in the queue, and is
undone by the same TTL rollback as a person's approval. Revoking a grant stops it at once; already-applied blocks run out their TTL.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

log = logging.getLogger("autonomy")

ACTIONS = ("block-ip", "block-domain")
NORMAL_SEVERITIES = ("low", "medium")
SEVERE_CONFIRMATION = "I understand severe findings will be acted on without a person"
MIN_CONFIDENCE_FLOOR = 80          # a grant cannot ask for less than the proposal queue already requires
MIN_AI_COUNT_FLOOR = 3
MAX_DAYS = 90                      # a permission always ends: renew it on purpose
MAX_RATE = 20
MAX_TTL_HOURS = 24 * 7
LIMITS = (
    "never on a degraded verdict, a stand-in panel, possible prompt injection, or an independent check that disagrees",
    "never without local proof (threat-feed hit or two independent detectors) unless the grant allows unverified",
    "never on an internal, private, Tailscale or never-block address",
    "never after it expires or is revoked, nor faster than its rate limit",
    "never on high or critical findings unless allow_severe is true with the typed confirmation",
    "no number of agreeing models can override any of the above",
)


def _aware(dt):
    return dt if dt is None or dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def validate_new(data: dict, now: Optional[datetime] = None) -> Tuple[Optional[dict], str]:
    """Check a request to create a grant. Returns (clean fields, '') or (None, what is wrong), in plain words."""
    now = now or datetime.now(timezone.utc)
    if not isinstance(data, dict):
        return None, "send a JSON object"
    category = str(data.get("category") or "").strip().lower()
    if not category or category in ("*", "any", "all"):
        return None, "name ONE threat category (for example malicious-domain); wildcards are not allowed"
    action = str(data.get("action") or "").strip().lower()
    if action not in ACTIONS:
        return None, f"action must be one of: {', '.join(ACTIONS)}"
    severities = data.get("severities", list(NORMAL_SEVERITIES))
    if not isinstance(severities, list) or not severities or not all(isinstance(s, str) for s in severities):
        return None, "severities must be a list such as [\"low\", \"medium\"]"
    severities = sorted({s.strip().lower() for s in severities})
    severe = [s for s in severities if s not in NORMAL_SEVERITIES]
    if any(s not in ("low", "medium", "high", "critical") for s in severe):
        return None, "unknown severity in the list"
    if severe and not (data.get("allow_severe") is True and data.get("confirmation") == SEVERE_CONFIRMATION):
        return None, f"high and critical findings keep needing a person unless allow_severe is true and confirmation is exactly: \"{SEVERE_CONFIRMATION}\""
    try:
        confidence = int(data.get("min_confidence", 90))
        ai_count = int(data.get("min_ai_count", 3))
        rate = int(data.get("rate_limit_per_hour", 5))
        ttl = int(data.get("ttl_hours", 24))
        days = float(data.get("days", 30))
    except (TypeError, ValueError, OverflowError):
        return None, "min_confidence, min_ai_count, rate_limit_per_hour, ttl_hours and days must be numbers"
    if not MIN_CONFIDENCE_FLOOR <= confidence <= 100:
        return None, f"min_confidence must be {MIN_CONFIDENCE_FLOOR} to 100"
    if not MIN_AI_COUNT_FLOOR <= ai_count <= 20:
        return None, f"min_ai_count must be at least {MIN_AI_COUNT_FLOOR}"
    if not 1 <= rate <= MAX_RATE:
        return None, f"rate_limit_per_hour must be 1 to {MAX_RATE}"
    if not 1 <= ttl <= MAX_TTL_HOURS:
        return None, f"ttl_hours must be 1 to {MAX_TTL_HOURS} (every automatic block is undone after this)"
    if not 0 < days <= MAX_DAYS:
        return None, f"a permission lasts at most {MAX_DAYS} days"
    return {"category": category[:100], "action": action, "severities": ",".join(severities), "min_confidence": confidence,
            "min_ai_count": ai_count, "require_verified": data.get("allow_unverified") is not True,
            "ttl_hours": ttl, "rate_limit_per_hour": rate, "expires_at": now + timedelta(days=days)}, ""


def _target_action(kind: str) -> str:
    return {"ip": "block-ip", "domain": "block-domain"}.get(kind, "")


def check(grant, threat, consensus: dict, target: dict, now: Optional[datetime] = None, recent_auto: int = 0) -> Tuple[bool, str]:
    """May this grant cover this finding right now? (True, '') or (False, the first reason it does not)."""
    now = now or datetime.now(timezone.utc)
    if grant.revoked_at is not None:
        return False, "revoked"
    if _aware(grant.expires_at) is None or _aware(grant.expires_at) <= now:
        return False, "expired"
    if (threat.type or "").strip().lower() != grant.category:
        return False, "different threat category"
    if _target_action(target.get("kind", "")) != grant.action:
        return False, "different action"
    q = consensus.get("quorum") if isinstance(consensus.get("quorum"), dict) else {}
    ev = consensus.get("evidence") if isinstance(consensus.get("evidence"), dict) else {}
    vf = consensus.get("verification") if isinstance(consensus.get("verification"), dict) else {}
    if consensus.get("consensus_verdict") != "malicious":
        return False, "the panel did not say malicious"
    if q.get("degraded") or consensus.get("panel_mode") == "fallback" or q.get("injection"):
        return False, "degraded verdict, stand-in panel or possible prompt injection"
    if vf.get("status") == "disputed" or ev.get("conflict"):
        return False, "an independent check or a threat feed disagrees"
    if grant.require_verified and ev.get("status") != "verified":
        return False, "no local proof (needs a threat-feed hit or two independent detectors)"
    if int(consensus.get("confidence") or 0) < grant.min_confidence or int(consensus.get("ai_count") or 0) < grant.min_ai_count:
        return False, "below the grant's confidence or model-count minimum"
    sev = str(consensus.get("consensus_severity") or "").lower()
    if sev not in {s for s in grant.severities.split(",") if s}:
        return False, f"severity {sev or 'unknown'} is not covered"
    if recent_auto >= grant.rate_limit_per_hour:
        return False, "rate limit reached for this hour"
    return True, ""


def _with_hub_evidence(threat, consensus: dict) -> dict:
    """A copy of the verdict whose local proof is recomputed HERE from the hub's own records. The verdict arrives in a request body
    that any holder of the admin key can write, so its own `evidence` is never believed: a forged "verified" must not start a block."""
    from datetime import timedelta
    from agents import local_evidence, recall
    from models import Threat
    rows = []
    cands = recall.candidate_urls(threat.url or "")
    if cands:
        since = datetime.now(timezone.utc) - timedelta(days=local_evidence.WINDOW_DAYS)
        for t in Threat.query.filter(Threat.url.in_(cands), Threat.id != threat.id, Threat.timestamp >= since).limit(25).all():
            rows.append({"id": t.id, "type": t.type, "detected_by": t.detected_by, "status": t.status})
    checked = dict(consensus)
    checked["evidence"] = local_evidence.assess({"id": threat.id, "type": threat.type, "detected_by": threat.detected_by,
                                                 "times_seen": threat.times_seen}, rows, consensus)
    return checked


def matching_grant(threat, consensus: dict, target: dict):
    """The first live grant that covers this finding, as (grant, ''), or (None, why not) for the best-matching reason. Never raises."""
    try:
        from models import AutonomyGrant, PendingRemediation
        now = datetime.now(timezone.utc)
        why = "no permission has been granted"
        for grant in AutonomyGrant.query.filter(AutonomyGrant.revoked_at.is_(None)).order_by(AutonomyGrant.id).all():
            recent = PendingRemediation.query.filter(
                PendingRemediation.decided_by == f"auto:grant-{grant.id}",
                PendingRemediation.decided_at >= now - timedelta(hours=1)).count()
            ok, reason = check(grant, threat, _with_hub_evidence(threat, consensus), target, now, recent)
            if ok:
                return grant, ""
            why = f"grant {grant.id}: {reason}"
        return None, why
    except Exception as exc:                                    # noqa: BLE001 -- autonomy failing must mean "ask a person"
        log.warning(f"autonomy check failed, the proposal waits for a person: {type(exc).__name__}: {exc}")
        return None, "autonomy check failed"


def act(row, grant, audit_path: str, approve=None):
    """Carry out one automatic approval. The audit line is written first; any failure leaves the proposal pending for a person.
    Returns the approved row, or None."""
    import remediation
    import remediation_queue
    approve = approve or remediation_queue.approve_proposal
    who = f"auto:grant-{grant.id}"
    try:
        remediation.audit_before_acting(audit_path, action="approve", stage="intent", proposal_id=row.id, by=who,
                                        grant=grant.id, kind=row.kind, target=row.target)
        approved, detail = approve(row.id, decided_by=who, ttl_hours=grant.ttl_hours)
    except Exception as exc:                                    # noqa: BLE001 -- stays in the queue for a person
        log.warning(f"automatic approval of proposal {row.id} under grant {grant.id} did not happen: {type(exc).__name__}: {exc}")
        remediation.audit(audit_path, action="approve", proposal_id=row.id, ok=False, by=who, grant=grant.id, error=str(exc)[:200])
        return None
    remediation.audit(audit_path, action="approve", proposal_id=row.id, kind=row.kind, target=row.target, ok=True, by=who,
                      grant=grant.id, detail=detail,
                      expires_at=approved.expires_at.isoformat() if approved.expires_at else None)
    return approved
