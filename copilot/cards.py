"""Adaptive Cards for Teams and Copilot (2026-09-30). Pure functions over the hub's sanitized brief: no SDK, no network.

Every value shown comes from the brief (GET /api/copilot/brief), which has already been through the hub's privacy gate,
so a card can never show more than the text replies do. Schema 1.5 is what Teams renders today.
"""
from datetime import datetime, timezone

from replies import ICON, ORDER, _ago

CONTENT_TYPE = "application/vnd.microsoft.card.adaptive"
SCHEMA = "http://adaptivecards.io/schemas/adaptive-card.json"
COLOR = {"critical": "Attention", "high": "Warning", "medium": "Accent", "low": "Default", "info": "Default"}


def _card(body, actions=None, summary=""):
    card = {"type": "AdaptiveCard", "$schema": SCHEMA, "version": "1.5", "body": body}
    if actions:
        card["actions"] = actions
    if summary:
        card["fallbackText"] = summary          # shown where cards cannot be (notifications, old clients)
    return card


def _open(dashboard_url):
    return [{"type": "Action.OpenUrl", "title": "Open SwarmSentinel", "url": dashboard_url}] if dashboard_url else None


def _now(brief):
    try:
        return datetime.fromisoformat(str(brief.get("generated", "")).replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(timezone.utc)


def _threat_block(t, now, separator=True):
    sev = t.get("severity", "")
    head = " · ".join(x for x in (f"{ICON.get(sev, '')} {sev.upper()}".strip(), t.get("threat_type", ""),
                                   _ago(t.get("timestamp", ""), now)) if x)
    return {"type": "Container", "separator": separator, "spacing": "Medium", "items": [
        {"type": "TextBlock", "text": head, "weight": "Bolder", "color": COLOR.get(sev, "Default"), "wrap": True},
        {"type": "TextBlock", "text": t.get("sanitized_summary", ""), "wrap": True, "spacing": "Small"},
    ]}


def alert_card(t, dashboard_url=None, now=None):
    """One new finding, pushed to a subscribed chat."""
    now = now or datetime.now(timezone.utc)
    sev = t.get("severity", "")
    title = f"SwarmSentinel alert: {sev.upper()} {t.get('threat_type', '')}".strip()
    body = [{"type": "TextBlock", "text": title, "size": "Medium", "weight": "Bolder", "wrap": True,
             "color": COLOR.get(sev, "Default")},
            _threat_block(t, now, separator=False)]
    return _card(body, _open(dashboard_url), summary=title)


def overflow_card(n, dashboard_url=None):
    """More new findings than one round may post: say how many, instead of flooding the chat."""
    text = f"…and {n} more new finding(s). Say **threats** for the latest."
    return _card([{"type": "TextBlock", "text": text, "wrap": True}], _open(dashboard_url), summary=text)


APPROVE_VERB, REJECT_VERB = "ssai.approve", "ssai.reject"


def _proposal_facts(p):
    """Build the label/value rows (action, finding, AI confidence, automatic undo time) shown on a block-proposal card,
    leaving out any the proposal does not have."""
    what = "Block address" if p.get("kind") == "ip" else "Block site (DNS)"
    facts = [{"title": "Action", "value": f"{what}: {p.get('target', '?')}"}]
    if p.get("severity") or p.get("threat_type"):
        facts.append({"title": "Finding", "value": " · ".join(x for x in (str(p.get("severity") or "").upper(),
                                                                          p.get("threat_type") or "") if x)})
    if p.get("confidence") is not None:
        facts.append({"title": "AI confidence", "value": f"{p['confidence']}%"})
    if p.get("ttl_hours"):
        facts.append({"title": "Undone after", "value": f"{p['ttl_hours']} h (automatically)"})
    return facts


def approval_card(p, approvals_enabled=True, dashboard_url=None, note=None):
    """A block proposal with Approve / Reject buttons (Action.Execute: the press comes back to the agent as the signed-in
    person, and the card is replaced with the outcome)."""
    title = "SwarmSentinel wants to block something"
    body = [{"type": "TextBlock", "text": title, "size": "Medium", "weight": "Bolder", "wrap": True, "color": "Warning"},
            {"type": "FactSet", "facts": _proposal_facts(p)}]
    if p.get("reason"):
        body.append({"type": "TextBlock", "text": f"Why: {p['reason']}", "wrap": True, "isSubtle": True})
    if not p.get("target_shown", True):
        body.append({"type": "TextBlock", "wrap": True, "isSubtle": True,
                     "text": "The address is on your network, so it is not shown here. Check it in the dashboard."})
    if note:
        body.append({"type": "TextBlock", "text": note, "wrap": True, "color": "Attention"})
    actions = []
    if approvals_enabled:
        # Echoed back on the press so the replacement card can show the same facts; only `id` is sent to the hub.
        data = {k: p.get(k) for k in ("id", "kind", "target", "target_shown", "severity", "threat_type",
                                      "confidence", "ttl_hours", "reason") if p.get(k) is not None}
        actions = [{"type": "Action.Execute", "title": "Approve block", "verb": APPROVE_VERB, "data": data,
                    "style": "positive"},
                   {"type": "Action.Execute", "title": "Reject", "verb": REJECT_VERB, "data": data}]
    else:
        body.append({"type": "TextBlock", "wrap": True, "isSubtle": True,
                     "text": "Approving from Teams is not set up on this hub yet: decide in the dashboard."})
    actions += _open(dashboard_url) or []
    return _card(body, actions or None, summary=f"{title}: {p.get('target', '')}")


def decided_card(p, outcome, dashboard_url=None):
    """The card after a decision: no buttons, just what happened and who decided."""
    body = [{"type": "TextBlock", "text": outcome, "size": "Medium", "weight": "Bolder", "wrap": True,
             "color": "Good" if p.get("status") == "approved" else "Default"},
            {"type": "FactSet", "facts": _proposal_facts(p)}]
    return _card(body, _open(dashboard_url), summary=outcome)


def status_card(brief, dashboard_url=None):
    """Build the card for 'status': counts of threats per severity over the recent window, plus what is still open."""
    hours = brief.get("window_hours", 24)
    counts = brief.get("counts") or {}
    open_ = brief.get("open") or {}
    still_open = ", ".join(f"{open_[s]} {s}" for s in ORDER if open_.get(s)) or "nothing medium or above"
    body = [
        {"type": "TextBlock", "text": f"SwarmSentinel, last {hours} h", "size": "Medium", "weight": "Bolder"},
        {"type": "ColumnSet", "columns": [
            {"type": "Column", "width": "stretch", "items": [
                {"type": "TextBlock", "text": str(counts.get(s, 0)), "size": "ExtraLarge", "weight": "Bolder",
                 "horizontalAlignment": "Center", "color": COLOR[s] if counts.get(s) else "Default"},
                {"type": "TextBlock", "text": s.capitalize(), "isSubtle": True, "horizontalAlignment": "Center",
                 "spacing": "None"}]} for s in ORDER]},
        {"type": "TextBlock", "text": f"**Still open:** {still_open}", "wrap": True},
    ]
    if brief.get("withheld"):
        body.append({"type": "TextBlock", "text": f"{brief['withheld']} threat(s) held back by the privacy filter.",
                     "isSubtle": True, "wrap": True})
    body.append({"type": "TextBlock", "text": "Say **threats** for details, or **alerts on** to get new ones here.",
                 "isSubtle": True, "wrap": True})
    return _card(body, _open(dashboard_url), summary=f"SwarmSentinel status, still open: {still_open}")


def threats_card(brief, only=None, dashboard_url=None):
    """Build the card for 'threats': one block per recent threat (optionally only one severity), or a short 'none found'
    card."""
    items = [t for t in brief.get("threats") or [] if not only or t.get("severity") == only]
    hours = brief.get("window_hours", 24)
    what = f"{only} threats" if only else "threats (medium and above)"
    if not items:
        text = f"No {what} in the last {hours} h."
        return _card([{"type": "TextBlock", "text": text, "wrap": True}], _open(dashboard_url), summary=text)
    now = _now(brief)
    body = [{"type": "TextBlock", "text": f"Latest {what}, last {hours} h", "size": "Medium", "weight": "Bolder",
             "wrap": True}]
    body += [_threat_block(t, now, separator=i > 0) for i, t in enumerate(items)]
    return _card(body, _open(dashboard_url), summary=f"{len(items)} {what}")
