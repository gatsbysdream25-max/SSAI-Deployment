"""Action-risk policy: ONE place that says, by severity, what SSAI may do on its own (Week 2, 2026-11-18).

Every path that can act without a person asking (docs/audit/week1-automation-map.md) asks this module first:
auto_response.py (when a finding arrives, and again when the AI panel's verdict is saved) and autonomy.py (grants).

    severity        when a finding ARRIVES          after the AI panel's VERDICT                     customer can loosen?
    informational   log only                        log only                                           no
    low             automatic, if switched on       automatic, if switched on                          (may require approval)
    medium          wait for the verdict            automatic only with FULL CONSENSUS and a          (may require approval)
                                                    confirmed direct check; otherwise a person
    high            a person                        a person, except the consensus-gated PAUSE        no
    critical        a person                        a person, except the consensus-gated PAUSE        no

FULL CONSENSUS (rules each have a test in tools/test_action_risk.py):
  * the panel said malicious, the verdict is not degraded, not the stand-in panel, not flagged for prompt injection, and no
    independent check disputes it;
  * at least `min_families` DIFFERENT model families voted malicious (floor 2, the customer can only raise it). The family of a
    voter is looked up HERE, from the hub's own provider registry; the model names inside the verdict are never believed. Two
    voters running the same underlying model family count once. A voter whose model is unknown, or whose provider is switched
    off on this hub, does not count at all;
  * the panel's confidence is at least `min_confidence` (floor 80).
The verdict arrives in a request that the admin key can write, so this gate is only as strong as that key; the direct check
(made by the hub at the moment of acting) and the other hub-side limits are what a forged verdict cannot get past.

The consensus-gated PAUSE (owner decision, 16 November 2026): a high or critical miner or reverse shell may be PAUSED (SIGSTOP,
never killed, never a block) without waiting for a person, only when it is switched on, full consensus holds, a direct check
confirms the process is still running, and an alert channel has been tested. It stays paused until a person decides.
"""
from __future__ import annotations

import re
from typing import Optional, Tuple

SEVERITIES = ("informational", "low", "medium", "high", "critical")
_ALIASES = {"info": "informational", "informational": "informational", "low": "low", "medium": "medium", "med": "medium",
            "moderate": "medium", "high": "high", "severe": "high", "critical": "critical", "crit": "critical"}
MIN_FAMILIES_FLOOR = 2
MIN_CONFIDENCE_FLOOR = 80
DEFAULT_STANDARD = {"min_families": 2, "min_confidence": 90}

# model name -> family. Order matters: the first match wins (hermes and the llama-derived models are Llama underneath).
_FAMILIES = (
    (r"llama|hermes|nous", "meta-llama"),
    (r"mistral|mixtral|codestral|ministral", "mistral"),
    (r"gemma|gemini", "google"),
    (r"\bphi|phi-?\d", "microsoft-phi"),
    (r"qwen", "qwen"),
    (r"deepseek", "deepseek"),
    (r"claude", "anthropic"),
    (r"gpt|\bo[134]\b|o[134]-mini|chatgpt", "openai"),
    (r"grok", "xai"),
    (r"kimi|moonshot", "moonshot"),
    (r"command-?r|cohere", "cohere"),
    (r"granite", "ibm"),
)


def severity(raw) -> str:
    """A known severity. Anything unrecognised counts as HIGH, so a garbled value needs a person rather than less care."""
    return _ALIASES.get(str(raw or "").strip().lower(), "high")


def stricter(*values) -> str:
    """The most serious of several severities (the finding's own and the panel's)."""
    ranked = [severity(v) for v in values if v]
    return max(ranked, key=SEVERITIES.index) if ranked else "high"


def family_of(model: Optional[str]) -> Optional[str]:
    m = str(model or "").strip().lower()
    if not m:
        return None
    for pattern, family in _FAMILIES:
        if re.search(pattern, m):
            return family
    return None


def standard(raw) -> dict:
    """The customer's agreement standard with SSAI's floors applied: it can be made stricter, never looser."""
    out = dict(DEFAULT_STANDARD)
    if isinstance(raw, dict):
        for key, floor, top in (("min_families", MIN_FAMILIES_FLOOR, 10), ("min_confidence", MIN_CONFIDENCE_FLOOR, 100)):
            v = raw.get(key)
            if isinstance(v, (int, float)) and not isinstance(v, bool):
                out[key] = int(min(max(v, floor), top))
    return out


def _hub_voters() -> dict:
    """provider id -> (model, may vote on this hub), from the hub's own registry. A vote's "ai" field is the provider id
    (for example groq, ollama-gemma4). "May vote" = switched on and not weighted out. Never raises."""
    try:
        from agents import ai_swarm_agent as swarm
        overrides, weights = swarm.load_provider_overrides(), swarm.load_weights()
        out = {}
        for p in swarm.PROVIDER_REGISTRY:
            pid = p.get("id")
            if not pid:
                continue
            try:
                on = swarm.provider_enabled(pid, overrides) and not swarm._switched_off(weights.get(pid))
            except Exception:                              # noqa: BLE001
                on = False
            out[str(pid)] = (p.get("model"), bool(on))
        return out
    except Exception:                                      # noqa: BLE001 -- no registry means no voter counts
        return {}


def agreeing_families(consensus: dict, voters: Optional[dict] = None) -> set:
    """The distinct model families among the voters that said malicious, judged from the hub's registry."""
    voters = _hub_voters() if voters is None else voters
    families = set()
    for pos in consensus.get("positions") or []:
        if not isinstance(pos, dict) or str(pos.get("verdict") or "").lower() != "malicious":
            continue
        model, on = voters.get(str(pos.get("ai") or ""), (None, False))
        fam = family_of(model) if on else None
        if fam:
            families.add(fam)
    return families


def full_consensus(consensus, std=None, voters: Optional[dict] = None) -> Tuple[bool, str]:
    """(True, '') when the verdict meets the agreement standard, else (False, the first reason it does not)."""
    if not isinstance(consensus, dict):
        return False, "no verdict"
    std = standard(std)
    q = consensus.get("quorum") if isinstance(consensus.get("quorum"), dict) else {}
    vf = consensus.get("verification") if isinstance(consensus.get("verification"), dict) else {}
    if consensus.get("consensus_verdict") != "malicious":
        return False, "the panel did not say malicious"
    if q.get("degraded") or consensus.get("panel_mode") == "fallback" or q.get("injection"):
        return False, "degraded verdict, stand-in panel or possible prompt injection"
    if vf.get("status") == "disputed":
        return False, "an independent check disagrees"
    try:
        confidence = int(consensus.get("confidence") or 0)
    except (TypeError, ValueError):
        confidence = 0
    if confidence < std["min_confidence"]:
        return False, f"confidence {confidence} is below the standard of {std['min_confidence']}"
    fams = agreeing_families(consensus, voters)
    if len(fams) < std["min_families"]:
        return False, (f"only {len(fams)} independent model famil{'y' if len(fams) == 1 else 'ies'} agreed "
                       f"({', '.join(sorted(fams)) or 'none'}); the standard is {std['min_families']}")
    return True, ""


def at_arrival(sev) -> Tuple[bool, str]:
    """May an automatic action run when a finding first arrives (no verdict yet)? Only for LOW findings."""
    s = severity(sev)
    if s == "low":
        return True, ""
    if s == "informational":
        return False, "informational findings are only logged"
    if s == "medium":
        return False, "medium findings wait for the AI panel's verdict"
    return False, f"{s} findings need a person"


def after_verdict(sev, action: str, consensus, std=None, pause_enabled: bool = False, channel_ok: bool = False,
                  voters: Optional[dict] = None) -> Tuple[bool, str, str]:
    """May an automatic action run once the verdict is saved? Returns (allowed, why not, gate name)."""
    s = severity(sev)
    if s == "informational":
        return False, "informational findings are only logged", ""
    if s == "low":
        return True, "", "low"
    ok, why = full_consensus(consensus, std, voters)
    if s == "medium":
        return (ok, why, "consensus") if ok else (False, f"medium needs full consensus: {why}", "")
    # high and critical: only the consensus-gated pause
    if action != "freeze-process":
        return False, f"{s} findings need a person for anything but a pause", ""
    if not pause_enabled:
        return False, "the consensus-gated pause is switched off", ""
    if not channel_ok:
        return False, "no alert channel has been tested, so the consensus-gated pause cannot run", ""
    if not ok:
        return False, f"consensus-gated pause: {why}", ""
    return True, "", "consensus-pause"


def grant_may_cover(sev) -> bool:
    """Autonomy grants cover low and medium only: high and critical always go to a person (allow_severe was removed)."""
    return severity(sev) in ("low", "medium")


def describe() -> list:
    return [{"severity": "informational", "on_arrival": "log only", "after_verdict": "log only"},
            {"severity": "low", "on_arrival": "automatic if switched on", "after_verdict": "automatic if switched on"},
            {"severity": "medium", "on_arrival": "waits for the verdict",
             "after_verdict": "automatic only with full consensus and a confirmed direct check"},
            {"severity": "high", "on_arrival": "a person", "after_verdict": "a person (pause only: consensus-gated, if on)"},
            {"severity": "critical", "on_arrival": "a person", "after_verdict": "a person (pause only: consensus-gated, if on)"}]
