"""The steps one finding goes through on its way to a person, each recorded with its time (consensus plan phase 3).

    ingested -> fingerprint_checked -> screened -> reviewing -> challenged -> verifying -> scored -> <final state>

    final states:  awaiting_approval  a severe, trusted malicious verdict that may be proposed for a block
                   needs_person       degraded quorum, possible prompt injection, or a disputed / unproven verdict
                   logged_only        the panel found it benign
                   reported           anything else (suspicious, or malicious below the proposal bar)

A Flow is created when the consensus agent picks a finding up and is saved inside the verdict (`consensus["flow"]`), so the
dashboard, the incident report and the audit trail all read the same record. It also owns the finding's TIME BUDGET: how long
the whole path may take, so one slow local model cannot hold a finding (and the queue behind it) for ever.

Timing uses a monotonic clock and is only for the record; nothing here can change a verdict.
"""
from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from typing import Callable, List, Optional

STATES = ("ingested", "fingerprint_checked", "screened", "reviewing", "challenged", "verifying", "scored")
FINAL_STATES = ("awaiting_approval", "needs_person", "logged_only", "reported")
# Measured 2026-09 to 10: one local 12B model needs about 100 s on CPU, the panel round is capped at 150 s, and a challenge
# round is a second panel round. 480 s lets a normal high-severity finding finish both and still leaves time to verify.
DEFAULT_BUDGET_SECONDS = 480.0


def budget_seconds() -> float:
    """SSAI_FINDING_BUDGET_SECONDS; a blank or non-numeric value means the default."""
    try:
        value = float(os.environ.get("SSAI_FINDING_BUDGET_SECONDS", DEFAULT_BUDGET_SECONDS))
    except ValueError:
        return DEFAULT_BUDGET_SECONDS
    return value if value > 0 else DEFAULT_BUDGET_SECONDS


class Flow:
    def __init__(self, finding_id, budget: Optional[float] = None, clock: Callable[[], float] = time.monotonic):
        self.finding_id = finding_id
        self.budget = budget_seconds() if budget is None else budget
        self._clock = clock
        self._started = clock()
        self._steps: List[dict] = []
        self._open: Optional[dict] = None

    # ── recording ────────────────────────────────────────────────────────────
    def enter(self, state: str, **detail) -> "Flow":
        """Close the step in progress and start `state`."""
        self._close()
        self._open = {"state": state, "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                      "_t0": self._clock(), "detail": {k: v for k, v in detail.items() if v not in (None, "")}}
        return self

    def note(self, **detail) -> None:
        """Add facts to the step in progress (for example: how many models answered)."""
        if self._open is not None:
            self._open["detail"].update({k: v for k, v in detail.items() if v not in (None, "")})

    def skip(self, state: str, why: str) -> None:
        """Record a step that was deliberately not run, so a gap in the record is always explained."""
        self.enter(state, skipped=why)
        self._close()

    def _close(self) -> None:
        if self._open is None:
            return
        step, self._open = self._open, None
        step["seconds"] = round(self._clock() - step.pop("_t0"), 2)
        self._steps.append(step)

    # ── budget ───────────────────────────────────────────────────────────────
    def elapsed(self) -> float:
        return self._clock() - self._started

    def remaining(self) -> float:
        return self.budget - self.elapsed()

    def deadline(self) -> float:
        """The finding's deadline on the monotonic clock, for AiSwarmAnalyzer.analyze(deadline=...)."""
        return self._started + self.budget

    # ── result ───────────────────────────────────────────────────────────────
    def finish(self, final_state: str, **detail) -> dict:
        self._close()
        return {"finding": self.finding_id, "steps": list(self._steps), "final_state": final_state,
                "total_seconds": round(self.elapsed(), 2), "budget_seconds": round(self.budget),
                "over_budget": self.elapsed() > self.budget, **({"detail": detail} if detail else {})}


def final_state(consensus: dict) -> str:
    """Where a finished verdict goes next, judged only from the saved verdict (no hidden state)."""
    quorum = consensus.get("quorum") if isinstance(consensus.get("quorum"), dict) else {}
    verification = consensus.get("verification") if isinstance(consensus.get("verification"), dict) else {}
    if quorum.get("degraded") or consensus.get("panel_mode") == "fallback":
        return "needs_person"
    if verification.get("status") == "disputed":
        return "needs_person"
    evidence = consensus.get("evidence") if isinstance(consensus.get("evidence"), dict) else {}
    if evidence.get("conflict"):
        return "needs_person"                 # a threat feed and the panel disagree
    verdict = consensus.get("consensus_verdict")
    if verdict == "benign":
        return "logged_only"
    severe = str(consensus.get("consensus_severity") or "").upper() in ("CRITICAL", "HIGH")
    strong = int(consensus.get("confidence") or 0) >= 80 and int(consensus.get("ai_count") or 0) >= 2     # the same bar remediation_queue.py uses to propose a block (its defaults: confidence 80, two models)
    if verdict == "malicious" and severe and strong:
        return "awaiting_approval"            # unverified or not, a person decides; the card says which (see local_evidence.py)
    return "reported"
