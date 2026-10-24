"""Independent verification of a consensus (2026-10-20).

The panel can agree for the wrong reason: models from one maker share training data and blind spots, so "4 of 4 agree"
may be one opinion said four times. After a consensus, a model from a DIFFERENT family than the voters is asked the same
question on its own, without being shown the panel's answer (so it cannot anchor on it). The two answers are compared:

    confirmed    the verifier reached the same verdict
    partial      both see a threat but disagree on how bad (malicious vs suspicious)
    disputed     one calls it a threat and the other calls it benign
    unavailable  no independent model could answer (none configured, all down, or a malformed answer)

This module is the decision logic only (no network), so it is cheap to test. AiSwarmAnalyzer.verify() does the call, and
remediation_queue.eligible() refuses to propose a block for a disputed consensus. A verifier never changes the panel's
verdict, it adds a record next to it; a person still decides every block.
"""
from __future__ import annotations

from typing import Dict, Iterable, List, Optional

THREAT_SIDE = {"malicious", "suspicious"}

# model-name fragment -> maker. The MODEL decides, not the host: Groq and OpenRouter serve many makers' models.
_FAMILIES = (
    (("gpt-oss", "gpt-", "openai", "o1", "o3"), "openai"),
    (("gemini", "gemma", "google"), "google"),
    (("claude", "anthropic"), "anthropic"),
    (("llama", "hermes", "foundation-sec", "meta-"), "meta"),
    (("qwen", "alibaba"), "alibaba"),
    (("phi", "microsoft"), "microsoft"),
    (("mistral", "mixtral", "codestral"), "mistral"),
    (("deepseek",), "deepseek"),
    (("kimi", "moonshot"), "moonshot"),
    (("grok", "xai"), "xai"),
    (("granite",), "ibm"),
)


def family_of(provider_or_name, model: Optional[str] = None) -> str:
    """The maker behind a provider, from its model string first and its name second."""
    name = provider_or_name if isinstance(provider_or_name, str) else getattr(provider_or_name, "name", "")
    if model is None and not isinstance(provider_or_name, str):
        model = getattr(provider_or_name, "model", "")
    for text in (str(model or "").lower(), str(name or "").lower()):
        for fragments, family in _FAMILIES:
            if any(f in text for f in fragments):
                return family
    return str(name or "unknown").lower()


def voter_families(consensus: dict, providers: Iterable) -> set:
    """Makers of the models that voted. Uses the recorded model per voter, else the provider currently under that name."""
    by_name = {getattr(p, "name", None): p for p in providers}
    models = consensus.get("models") or {}
    out = set()
    for name in consensus.get("ai_sources") or []:
        out.add(family_of(by_name.get(name) or name, models.get(name)))
    return out


def pick(candidates: List, consensus: dict, providers: Iterable, prefer_local=lambda p: False) -> Optional[object]:
    """The best independent model: not one that already voted, from a maker that did not vote when possible, local first.
    None when nothing independent exists (the record then says so rather than pretending)."""
    voters = set(consensus.get("ai_sources") or [])
    fams = voter_families(consensus, providers)
    pool = [p for p in candidates if getattr(p, "name", None) not in voters]
    if not pool:
        return None
    other_maker = [p for p in pool if family_of(p) not in fams]
    if other_maker:
        pool, independent = other_maker, True
    else:
        independent = False
    pool.sort(key=lambda p: (not prefer_local(p), getattr(p, "name", "")))
    chosen = pool[0]
    chosen._ssai_independent_maker = independent        # remembered for the record, harmless on a provider object
    return chosen


def compare(panel_verdict: str, answer: dict) -> str:
    """confirmed / partial / disputed for a valid verifier answer."""
    mine = str(answer.get("verdict", "")).strip().lower()
    theirs = str(panel_verdict or "").strip().lower()
    if mine == theirs:
        return "confirmed"
    if mine in THREAT_SIDE and theirs in THREAT_SIDE:
        return "partial"
    return "disputed"


def record(status: str, provider=None, answer: Optional[dict] = None, reason: str = "", seconds: float = 0.0) -> Dict[str, object]:
    """The verification entry stored beside the consensus."""
    out: Dict[str, object] = {"status": status}
    if provider is not None:
        out["verifier"] = getattr(provider, "name", None)
        out["family"] = family_of(provider)
        out["independent_maker"] = bool(getattr(provider, "_ssai_independent_maker", False))
    if answer:
        out["verdict"] = str(answer.get("verdict", "")).lower()
        try:
            out["confidence"] = max(0, min(100, int(float(answer.get("confidence", 0)))))
        except (TypeError, ValueError, OverflowError):
            out["confidence"] = 0
        why = answer.get("reasoning") or answer.get("analysis") or ""
        if isinstance(why, str) and why.strip():
            out["reasoning"] = " ".join(why.split())[:300]
    if reason:
        out["reason"] = reason[:200]
    if seconds:
        out["seconds"] = round(seconds, 1)
    return out


def apply(consensus: dict, verification: dict) -> dict:
    """Attach the record and make the quorum say what it means. A disputed consensus can never read as High confidence."""
    consensus["verification"] = verification
    q = consensus.get("quorum")
    status = verification.get("status")
    if isinstance(q, dict) and status in ("confirmed", "partial", "disputed", "unavailable"):
        note = {"confirmed": f"independently confirmed by {verification.get('verifier')}",
                "partial": f"independent check ({verification.get('verifier')}) agrees it is a threat but rates it differently",
                "disputed": f"independent check ({verification.get('verifier')}) DISAGREES",
                "unavailable": "no independent check was possible"}[status]
        q["verification"] = status
        if status == "disputed":
            q["level"] = "Low"
        label = str(q.get("label") or "")
        if note not in label:
            q["label"] = f"{label}; {note}" if label else note
    return consensus
