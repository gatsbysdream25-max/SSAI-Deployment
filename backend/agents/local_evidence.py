"""Does anything on THIS network back up what the AI panel said? (consensus plan phase 4, design rule 11)

AI agreement is not verification. Four models can agree on a guess. A verdict is "verified" only by facts the hub already holds
from sources that are not language models: a threat-feed hit, or a second independent detector that saw the same indicator.

    verified     a feed hit, or two or more independent detectors saw it
    partial      one independent detector, or the same detector keeps seeing it (3+ sightings)
    unverified   nothing local supports it; the models are the only evidence

`assess()` is pure: it is handed the finding and the related findings the hub returned, and decides. It never changes a verdict. It
adds the proof to the saved record so a person can see WHY a block is being proposed, and flags the one case where local proof and
the panel disagree (a feed says it is bad, the models say benign), which always goes to a person.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional

FEED_MARKERS = ("intelfeed", "threatfox", "threatfeed", "urlhaus", "feodo")       # detected_by values that are threat-feed lookups, not AI
WINDOW_DAYS = 30                                                   # how far back related sightings count
VERIFIED, PARTIAL, UNVERIFIED = "verified", "partial", "unverified"


def _is_feed(detector: str) -> bool:
    """A threat-feed lookup made by THIS hub's own agent. A node's submissions carry '@<node>' (added by the hub, see the submit route),
    so a node cannot pass for a feed by choosing a name."""
    low = (detector or "").lower()
    return "@" not in low and any(m in low for m in FEED_MARKERS)


def _origin(detector: str) -> str:
    """Who really reported: a node's submissions end in '@<node>', and one node counts once however many names it uses."""
    return detector.rsplit("@", 1)[-1] if "@" in detector else detector


def _is_ai(detector: str) -> bool:
    """A reading by an AI model is not independent proof of anything (it is the thing being checked)."""
    low = (detector or "").lower()
    return ("analyzer" in low or "swarm" in low or "consensus" in low or low.startswith("screenshot-upload")
            or "redteam" in low or "ledger-import" in low)       # synthetic probes and other installs' public ledger are not local proof


def assess(threat: dict, related: List[dict], consensus: Optional[dict] = None) -> dict:
    """Look for proof from this network (not from the AI models) that a finding is real, and rate it verified, partial or
    unverified."""
    own = str(threat.get("detected_by") or "")
    proofs: List[dict] = []
    seen_detectors = set()
    for row in related or []:
        who = str(row.get("detected_by") or "")
        if not who or row.get("id") == threat.get("id") or _is_ai(who) or str(row.get("status") or "").lower() in ("dismissed", "resolved"):
            continue
        if _is_feed(who):
            proofs.append({"kind": "feed-hit", "source": who, "finding": row.get("id"), "type": row.get("type")})
        elif _origin(who) != _origin(own) and _origin(who) not in seen_detectors:
            seen_detectors.add(_origin(who))
            proofs.append({"kind": "second-detector", "source": who, "finding": row.get("id"), "type": row.get("type")})
    try:
        repeats = int(threat.get("times_seen") or 0)
    except (TypeError, ValueError):
        repeats = 0
    # Three sightings is no longer a one-off; one or two are normal background noise and prove nothing.
    if repeats >= 3 and not _is_feed(own):
        proofs.append({"kind": "repeat-sightings", "source": own or "unknown", "count": repeats})

    feed = any(p["kind"] == "feed-hit" for p in proofs) or _is_feed(own)
    if _is_feed(own) and not any(p["kind"] == "feed-hit" for p in proofs):
        proofs.insert(0, {"kind": "feed-hit", "source": own, "finding": threat.get("id"), "type": threat.get("type")})
    independent = sum(1 for p in proofs if p["kind"] == "second-detector")
    if feed or independent >= 2:
        status = VERIFIED
    elif independent == 1 or any(p["kind"] == "repeat-sightings" for p in proofs):
        status = PARTIAL
    else:
        status = UNVERIFIED
    verdict = str((consensus or {}).get("consensus_verdict") or "").lower()
    conflict = bool(feed and verdict == "benign")
    note = {VERIFIED: "confirmed by data from this network", PARTIAL: "some local support",
            UNVERIFIED: "the AI models are the only evidence; nothing local confirms it"}[status]
    if conflict:
        note = "a threat feed lists this indicator but the panel said benign: a person must decide"
    # At most 10 proofs are saved, so one very noisy indicator cannot make the stored verdict huge.
    return {"status": status, "proofs": proofs[:10], "conflict": conflict, "note": note,
            "checked": datetime.now(timezone.utc).isoformat(timespec="seconds")}


def apply(consensus: dict, evidence: dict) -> dict:
    """Attach the evidence to the verdict. An 'unverified' malicious verdict has its quorum label say so."""
    consensus["evidence"] = evidence
    quorum = consensus.get("quorum")
    if isinstance(quorum, dict) and evidence["status"] == UNVERIFIED and consensus.get("consensus_verdict") in ("malicious", "suspicious"):
        if "unverified" not in str(quorum.get("label", "")):
            quorum["label"] = f"{quorum.get('label', '')} | unverified: no local proof".strip(" |")
    return consensus
