"""Approve-first remediation queue: turn a high-confidence AI consensus into a PROPOSAL, never an action.

An operator approves or rejects every proposal by hand. Approving runs the same code path as the manual Block
button (see remediation.py) and stamps a TTL; RemediationSweepAgent auto-reverts an approved block once that
TTL passes, so approving something is never a silent forever-block. Nothing here ever calls remediation.block()
or remediation.PiHole().deny() except approve_proposal() -- proposing only classifies the target (no side effect).
"""
import ipaddress
import os
from datetime import datetime, timedelta, timezone

from models import db, PendingRemediation, Threat
import remediation

MIN_CONFIDENCE = int(os.environ.get("SSAI_AUTO_PROPOSE_MIN_CONFIDENCE", "80"))
MIN_AI_COUNT   = int(os.environ.get("SSAI_AUTO_PROPOSE_MIN_AI_COUNT", "2"))
MIN_SEVERITIES = {s.strip().upper() for s in os.environ.get("SSAI_AUTO_PROPOSE_SEVERITIES", "CRITICAL,HIGH").split(",") if s.strip()}
DEFAULT_TTL_HOURS = int(os.environ.get("SSAI_REMEDIATION_TTL_HOURS", str(7 * 24)))
PENDING_TTL_HOURS = int(os.environ.get("SSAI_REMEDIATION_PENDING_TTL_HOURS", "72"))


def eligible(consensus, any_severity=False):
    """May this verdict become a block PROPOSAL? `any_severity` is True only when a live autonomy grant covers lower severities too
    (autonomy.py); every other test still applies."""
    if not isinstance(consensus, dict):
        return False
    if consensus.get("consensus_verdict") != "malicious":
        return False
    if int(consensus.get("confidence") or 0) < MIN_CONFIDENCE:
        return False
    if int(consensus.get("ai_count") or 0) < MIN_AI_COUNT:
        return False
    if not any_severity and str(consensus.get("consensus_severity") or "").upper() not in MIN_SEVERITIES:
        return False
    quorum = consensus.get("quorum")
    if consensus.get("panel_mode") == "fallback" or (isinstance(quorum, dict) and quorum.get("degraded")):
        return False                       # too few voters, or the stand-in panel: a person looks, SSAI does not propose (audit F-02, F-03)
    verification = consensus.get("verification")
    if isinstance(verification, dict) and verification.get("status") == "disputed":
        return False                       # an independent model from another maker disagrees: no proposal, a person looks instead
    return True


def _reason(consensus):
    """Write the one-line explanation stored with a proposal: the verdict, confidence, how many AIs agreed, the votes and
    the independent check."""
    votes = consensus.get("votes") or {}
    check = consensus.get("verification") if isinstance(consensus.get("verification"), dict) else {}
    tail = " | independent check: {}{}".format(check.get("status", "none"),
                                              " by " + str(check["verifier"]) if check.get("verifier") else "")
    return ("{}/{} at {}% confidence, agreement {}, {} AI(s) ({}), "
            "votes malicious={} suspicious={} benign={}").format(
        consensus.get("consensus_verdict"), consensus.get("consensus_severity"),
        consensus.get("confidence"), consensus.get("agreement"), consensus.get("ai_count"),
        ", ".join(consensus.get("ai_sources") or []),
        votes.get("malicious", 0), votes.get("suspicious", 0), votes.get("benign", 0)) + tail


# AI-proposed blocks never target an address inside the organisation (2026-10-09, red-team finding): RFC 1918,
# carrier-grade NAT / Tailscale (100.64.0.0/10), IPv6 unique-local and link-local. Otherwise crafted log lines could
# steer the panel into proposing to cut off a colleague's laptop or a VPN peer (denial of service through the
# defensive tool itself). An operator can still block such an address by hand from the dashboard.
_INTERNAL_NETS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7", "fe80::/10"))


def internal_address(value):
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    if getattr(ip, 'ipv4_mapped', None) is not None:
        ip = ip.ipv4_mapped
    return any(ip.version == n.version and ip in n for n in _INTERNAL_NETS) or ip.is_link_local


def _never_block(target, never_block_ips):
    return target["kind"] == "ip" and (target["value"] in never_block_ips or internal_address(target["value"]))


def propose(threat, consensus, never_block_ips=frozenset(), audit_path=None):
    """Queue a block proposal for a finding if the verdict is strong enough and the target is safe to block; returns the
    new row, or None if nothing was queued."""
    try:
        target = remediation.classify_target(threat.url)
    except remediation.TargetError:
        return None
    if _never_block(target, never_block_ips):
        return None
    import autonomy
    grant, _ = autonomy.matching_grant(threat, consensus, target) if isinstance(consensus, dict) else (None, "")
    if not eligible(consensus, any_severity=grant is not None):
        return None
    existing = (PendingRemediation.query
                .filter_by(kind=target["kind"], target=target["value"], status="pending")
                .first())
    if existing is not None:
        return None
    row = PendingRemediation(
        threat_id=threat.id, kind=target["kind"], target=target["value"],
        reason=_reason(consensus), confidence=int(consensus.get("confidence") or 0),
        status="pending",
    )
    db.session.add(row)
    db.session.commit()
    if grant is not None:                      # a person granted this exact kind of action; otherwise it waits for a person
        autonomy.act(row, grant, audit_path or _audit_path())
        db.session.refresh(row)
    return row


def _audit_path():
    from app import _AUDIT_PATH
    return _AUDIT_PATH


MAX_TTL_HOURS = 24 * 365
CLAIM_TIMEOUT_MINUTES = 10


def _ttl(ttl_hours):
    """The block's lifetime in hours, validated BEFORE anything is blocked. 0 = until removed by hand."""
    if ttl_hours is None:
        return DEFAULT_TTL_HOURS
    if isinstance(ttl_hours, bool):
        raise ValueError("ttl_hours must be a number of hours")
    try:
        ttl = float(ttl_hours)
    except (TypeError, ValueError):
        raise ValueError("ttl_hours must be a number of hours") from None
    if not 0 <= ttl <= MAX_TTL_HOURS:
        raise ValueError("ttl_hours must be between 0 and {}".format(MAX_TTL_HOURS))
    return ttl


def _claim(row_id, new_status):
    """Atomically move a proposal out of 'pending' (code review 2026-09-30, finding 6). The dashboard and Teams can
    decide the same proposal at the same moment; only the one whose UPDATE matches a still-pending row proceeds, the
    other gets 'already ...'. Without this both approvals inserted the same firewall rules."""
    row = PendingRemediation.query.get_or_404(row_id)
    claimed = (PendingRemediation.query
               .filter(PendingRemediation.id == row_id, PendingRemediation.status == "pending")
               .update({"status": new_status, "decided_at": datetime.now(timezone.utc)}, synchronize_session=False))
    db.session.commit()
    if claimed != 1:
        db.session.refresh(row)
        raise ValueError("this proposal is already {}".format(row.status))
    db.session.refresh(row)
    return row


def approve_proposal(row_id, decided_by, ttl_hours=None, pihole=None, run=None):
    """A person approves a proposal: carry out the block, then mark it approved with an expiry time. If the block fails
    the proposal goes back to pending."""
    ttl = _ttl(ttl_hours)                                  # a bad TTL is refused before the block, not after it
    row = _claim(row_id, "approving")
    target = {"kind": row.kind, "value": row.target}
    kwargs = {}
    if pihole is not None:
        kwargs["pihole"] = pihole
    if run is not None:
        kwargs["run"] = run
    try:
        detail = remediation.block(target, row.threat_id, **kwargs)
    except BaseException:
        row.status, row.decided_at = "pending", None       # the block failed: back to the queue, nothing half-done
        db.session.commit()
        raise
    row.status = "approved"
    row.decided_at = datetime.now(timezone.utc)
    row.decided_by = decided_by
    row.expires_at = datetime.now(timezone.utc) + timedelta(hours=ttl) if ttl > 0 else None
    threat = Threat.query.get(row.threat_id)
    if threat is not None:
        threat.status = "blocked"
    db.session.commit()
    return row, detail


def reject_proposal(row_id, decided_by):
    row = _claim(row_id, "rejected")
    row.decided_by = decided_by
    db.session.commit()
    return row


def sweep(pihole=None, run=None, audit_path=None):
    """Housekeeping: free proposals stuck mid-approval, expire old unanswered ones, and undo approved blocks whose time
    is up. Returns counts and any errors."""
    now = datetime.now(timezone.utc)
    expired = 0
    rolled_back = 0
    errors = []

    # A process that died between claiming a proposal and recording the block leaves it "approving": hand it back.
    claim_cutoff = now - timedelta(minutes=CLAIM_TIMEOUT_MINUTES)
    for row in PendingRemediation.query.filter_by(status="approving").all():
        claimed = row.decided_at.replace(tzinfo=timezone.utc) if row.decided_at and row.decided_at.tzinfo is None else row.decided_at
        if claimed is None or claimed < claim_cutoff:
            row.status, row.decided_at = "pending", None
            db.session.commit()

    stale_cutoff = now - timedelta(hours=PENDING_TTL_HOURS)
    for row in PendingRemediation.query.filter_by(status="pending").all():
        proposed = row.proposed_at
        if proposed is not None and proposed.tzinfo is None:
            proposed = proposed.replace(tzinfo=timezone.utc)
        if proposed is not None and proposed < stale_cutoff:
            row.status = "expired"
            row.decided_at = now
            expired += 1
    if expired:
        db.session.commit()

    kwargs = {}
    if pihole is not None:
        kwargs["pihole"] = pihole
    if run is not None:
        kwargs["run"] = run
    due = (PendingRemediation.query
           .filter(PendingRemediation.status == "approved", PendingRemediation.expires_at.isnot(None),
                   PendingRemediation.expires_at < now)
           .all())
    for row in due:
        target = {"kind": row.kind, "value": row.target}
        try:
            detail = remediation.unblock(target, **kwargs)
        except remediation.RemediationError as e:
            errors.append("{}:{} (proposal {}): {}".format(row.kind, row.target, row.id, e))
            if audit_path:
                remediation.audit(audit_path, action="auto-rollback", proposal_id=row.id, kind=row.kind,
                                  target=row.target, ok=False, error=str(e), by="RemediationSweepAgent")
            continue
        row.status = "rolled_back"
        row.rolled_back_at = now
        threat = Threat.query.get(row.threat_id)
        if threat is not None and threat.status == "blocked":
            threat.status = "active"
        rolled_back += 1
        if audit_path:
            remediation.audit(audit_path, action="auto-rollback", proposal_id=row.id, kind=row.kind,
                              target=row.target, ok=True, detail=detail, by="RemediationSweepAgent")
    if rolled_back:
        db.session.commit()

    return {"expired": expired, "rolled_back": rolled_back, "errors": errors}
