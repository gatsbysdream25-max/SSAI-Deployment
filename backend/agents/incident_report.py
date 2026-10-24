"""One finding as a report a person can read and act on (consensus plan phase 5).

Shows, in this order: what was found, what the AI panel concluded and how many models stood behind it, what each model said
and why, what this network itself says about it (local proof), what an independent model from another maker thought, what is
proposed, and the timeline of how the finding was handled. Everything comes from the saved verdict; nothing is recomputed or
re-asked, so the report cannot disagree with the record.

`build()` returns plain data (the API serves it as JSON); `to_markdown()` renders the same data for printing or sending to someone.
"""
from __future__ import annotations

import json
from typing import Optional


def _consensus_of(threat: dict) -> dict:
    """Pull the panel's combined verdict out of a finding's stored AI verdict (saved as JSON text); {} if there is none."""
    raw = threat.get("ai_verdict")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            raw = None
    consensus = raw.get("consensus") if isinstance(raw, dict) else None
    return consensus if isinstance(consensus, dict) else {}


def _caveats(consensus: dict) -> list:
    """Plain-words reasons a person should not take this verdict at face value."""
    quorum = consensus.get("quorum") if isinstance(consensus.get("quorum"), dict) else {}
    evidence = consensus.get("evidence") if isinstance(consensus.get("evidence"), dict) else {}
    verification = consensus.get("verification") if isinstance(consensus.get("verification"), dict) else {}
    out = []
    if quorum.get("degraded"):
        out.append("DEGRADED: " + str(quorum.get("degraded_reason") or "too few models answered"))
    if quorum.get("injection"):
        out.append("The evidence contains text addressed to the AI (" + ", ".join(quorum["injection"]) + "); it was judged by local models only.")
    if evidence.get("status") == "unverified":
        out.append("UNVERIFIED: the models are the only evidence; nothing on this network confirms it.")
    if evidence.get("conflict"):
        out.append("A threat feed lists this indicator but the panel said benign.")
    if verification.get("status") == "disputed":
        out.append(f"An independent model ({verification.get('verifier')}) DISAGREES and says {verification.get('verdict')}.")
    elif verification.get("status") == "unavailable":
        out.append("Not independently checked: " + str(verification.get("reason") or "no independent model was available") + ".")
    for o in consensus.get("outliers") or []:
        out.append(f"Outlier: {o.get('ai')} {o.get('why')}.")
    if consensus.get("recalled_from"):
        out.append(f"Reused the verdict of finding {consensus['recalled_from']} for the same indicator; the panel was not asked again.")
    return out


def build(threat: dict, proposal: Optional[dict] = None) -> dict:
    """Collect everything a person needs about one finding into one dict: the finding, the verdict, each model's view,
    caveats, and the timeline."""
    consensus = _consensus_of(threat)
    quorum = consensus.get("quorum") if isinstance(consensus.get("quorum"), dict) else {}
    flow = consensus.get("flow") if isinstance(consensus.get("flow"), dict) else {}
    return {
        "finding": {k: threat.get(k) for k in ("id", "type", "url", "severity", "description", "detected_by", "node_id",
                                                "timestamp", "first_seen", "last_seen", "times_seen")},
        "judged": bool(consensus),
        "verdict": {"verdict": consensus.get("consensus_verdict"), "severity": consensus.get("consensus_severity"), "confidence": consensus.get("confidence"),
                    "label": quorum.get("label"), "agreed": quorum.get("agreed"), "answered": quorum.get("answered"), "panel": quorum.get("panel"),
                    "dropped": quorum.get("dropped") or [], "degraded": bool(quorum.get("degraded")), "panel_mode": consensus.get("panel_mode")},
        "positions": consensus.get("positions") or [],
        "challenge": consensus.get("challenge") or {},
        "local_proof": consensus.get("evidence") or {},
        "independent_check": consensus.get("verification") or {},
        "proposed": {"action": consensus.get("recommended_action"), "mitre": consensus.get("mitre_ttps") or [], "remediation": proposal},
        "caveats": _caveats(consensus),
        "timeline": {"state": flow.get("final_state"), "steps": flow.get("steps") or [], "total_seconds": flow.get("total_seconds"),
                     "budget_seconds": flow.get("budget_seconds"), "over_budget": flow.get("over_budget")},
        "models": consensus.get("models") or {},
    }


def to_markdown(report: dict) -> str:
    """Turn the dict made by build() into a readable Markdown report, section by section."""
    finding, verdict = report["finding"], report["verdict"]
    lines = [f"# Incident report: finding {finding.get('id')}", "",
             f"- **Type:** {finding.get('type')}   **Indicator:** `{finding.get('url')}`   **Seen by:** {finding.get('detected_by')}",
             f"- **First seen:** {finding.get('first_seen') or finding.get('timestamp')}   **Last seen:** {finding.get('last_seen')}   **Times seen:** {finding.get('times_seen')}",
             f"- **Detector's description:** {finding.get('description')}", ""]
    if not report["judged"]:
        return "\n".join(lines + ["## Verdict", "", "The AI panel has not judged this finding yet.", ""])
    lines += ["## Verdict", "", f"**{str(verdict.get('verdict')).upper()}**, severity {verdict.get('severity')}, {verdict.get('confidence')}% confidence.",
              f"{verdict.get('label')}", ""]
    if report["caveats"]:
        lines += ["## Read this first", ""] + [f"- {c}" for c in report["caveats"]] + [""]
    lines += ["## What each model said", ""]
    for position in report["positions"]:
        lines.append(f"- **{position.get('ai')}**: {position.get('verdict')}, {position.get('severity')}, {position.get('confidence')}%. {position.get('reason') or ''}".rstrip())
    challenge = report["challenge"]
    if challenge.get("ran"):
        moved = ", ".join(f"{x['ai']} ({x['from']} -> {x['to']})" for x in challenge.get("changed", [])) or "nobody changed their mind"
        lines += ["", f"Challenge round: {challenge.get('asked')} asked, {challenge.get('answered')} answered; {moved}."]
    elif challenge.get("why"):
        lines += ["", f"Challenge round not run: {challenge['why']}."]
    evidence = report["local_proof"]
    lines += ["", "## What this network says", "", f"**{evidence.get('status', 'not checked')}**: {evidence.get('note', 'local proof was not checked')}"]
    lines += [f"- {proof.get('kind')} from {proof.get('source')} (finding {proof.get('finding', '-')})" for proof in evidence.get("proofs", [])]
    independent = report["independent_check"]
    check = (f"{independent.get('status')} by {independent.get('verifier')} ({independent.get('family')}): {independent.get('verdict') or independent.get('reason') or ''}"
             if independent else "No independent check was made.")
    lines += ["", "## Independent check", "", check]
    proposed = report["proposed"]
    lines += ["", "## Proposed fix", "", proposed.get("action") or "No action was proposed by the panel."]
    if proposed.get("mitre"):
        lines.append("MITRE ATT&CK: " + ", ".join(proposed["mitre"]))
    remediation = proposed.get("remediation")
    if remediation:
        lines.append(f"Remediation proposal: {remediation.get('kind')} {remediation.get('target')} - {remediation.get('status')}"
                     + (f" by {remediation.get('decided_by')}" if remediation.get("decided_by") else ""))
    timeline = report["timeline"]
    lines += ["", "## How it was handled", "", f"Final state: **{timeline.get('state')}**. Took {timeline.get('total_seconds')} s of a {timeline.get('budget_seconds')} s budget."]
    for step in timeline.get("steps", []):
        extra = "; ".join(f"{k}: {x}" for k, x in (step.get("detail") or {}).items())
        lines.append(f"1. {step.get('state')} ({step.get('seconds')} s){': ' + extra if extra else ''}")
    return "\n".join(lines) + "\n"
