"""What the SwarmSentinel agent says (2026-09-26). Pure functions: no SDK, no network, so they are easy to test.

Every reply is built from the hub's sanitized brief (GET /api/copilot/brief) and nothing else. The agent has no
AI of its own: SwarmSentinel's models do the analysis, Copilot and Teams are just another way to ask about it.
"""
import re
from datetime import datetime, timezone

HELP = (
    "I'm **SwarmSentinel**. Ask me:\n\n"
    "- **status**: threat counts for the last 24 hours, and what is still open\n"
    "- **threats**: the latest medium, high and critical threats\n"
    "- **critical** or **high**: only those\n"
    "- **alerts on**: post new high and critical findings in this chat as they happen (**alerts medium** or "
    "**alerts critical** to change the level, **alerts off** to stop)\n"
    "- **pending**: blocks SwarmSentinel proposes, with Approve / Reject buttons (approvers only)\n\n"
    "Internal addresses, machine names, user names and credentials are replaced by tokens "
    "(IP_1, HOST_1, SECRET_1 ...) before anything reaches me."
)

ICON = {"critical": "\U0001F534", "high": "\U0001F7E0", "medium": "\U0001F7E1", "low": "⚪", "info": "⚪"}
ORDER = ("critical", "high", "medium", "low", "info")


class HubError(Exception):
    """The hub could not be asked (not configured, unreachable, refused the key). The message is safe to show."""


def intent(text: str):
    """(kind, argument): kind is 'help', 'status', 'threats' (argument: severity filter or None) or 'alerts'
    (argument: 'off', or the lowest severity to post)."""
    t = (text or "").strip().lower()
    if re.search(r"\bunsubscribe\b|\bstop (?:the )?(?:alerts?|notifications?)\b", t):
        return "alerts", "off"
    m = re.search(r"\b(?:alerts?|notifications?|notify me)\s+(on|off|critical|high|medium)\b", t)
    if m:
        return "alerts", "high" if m.group(1) == "on" else m.group(1)
    if re.search(r"\bsubscribe\b", t):
        return "alerts", "high"
    if re.search(r"\b(pending|approvals?|proposals?|approve|blocks? to approve)\b", t):
        return "pending", None
    if not t or re.search(r"\b(help|hi|hello|hey|what can you do)\b|^/help", t):
        return "help", None
    for sev in ("critical", "high"):
        if re.search(rf"\b{sev}\b", t):
            return "threats", sev
    if re.search(r"\b(threats?|alerts?|latest|recent|incidents?|details?|list)\b", t):
        return "threats", None
    return "status", None


def _ago(ts: str, now: datetime) -> str:
    """Describe how long before `now` the timestamp `ts` was, in words like '5 min ago' or '3 days ago'; empty text if
    `ts` cannot be read."""
    try:
        then = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        return ""
    minutes = int((now - then).total_seconds() // 60)
    if minutes < 1:
        return "just now"
    if minutes < 60:
        return f"{minutes} min ago"
    if minutes < 48 * 60:
        return f"{minutes // 60} h ago"
    return f"{minutes // (24 * 60)} days ago"


def _now(brief: dict) -> datetime:
    try:
        return datetime.fromisoformat(str(brief.get("generated", "")).replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(timezone.utc)


def format_status(brief: dict) -> str:
    """Write the plain-text version of the status reply (counts per severity and what is still open)."""
    hours = brief.get("window_hours", 24)
    counts = brief.get("counts") or {}
    open_ = brief.get("open") or {}
    line = " · ".join(f"{s.capitalize()} {counts.get(s, 0)}" for s in ORDER)
    still_open = ", ".join(f"{open_[s]} {s}" for s in ORDER if open_.get(s))
    parts = [f"**SwarmSentinel, last {hours} h**", line,
             f"**Still open:** {still_open}" if still_open else "**Still open:** nothing medium or above"]
    if brief.get("withheld"):
        parts.append(f"_{brief['withheld']} threat(s) held back by the privacy filter._")
    parts.append("Say **threats** for details.")
    return "\n\n".join(parts)


def format_threats(brief: dict, only: str = None) -> str:
    """Write the plain-text list of recent threats, optionally only one severity, each with how long ago it happened."""
    items = [t for t in brief.get("threats") or [] if not only or t.get("severity") == only]
    hours = brief.get("window_hours", 24)
    what = f"{only} threats" if only else "threats (medium and above)"
    if not items:
        return f"No {what} in the last {hours} h."
    now = _now(brief)
    lines = [f"**Latest {what}, last {hours} h**"]
    for i, t in enumerate(items, 1):
        sev = t.get("severity", "")
        head = " · ".join(x for x in (f"{ICON.get(sev, '')} **{sev.upper()}**", t.get("threat_type", ""),
                                           _ago(t.get("timestamp", ""), now)) if x)
        lines.append(f"{i}. {head}\n\n   {t.get('sanitized_summary', '')}")
    return "\n\n".join(lines)


def alerts_reply(level: str, was_on: bool = False) -> str:
    if level == "off":
        return ("Alerts are off for this chat." if was_on else "Alerts were not on for this chat.") + \
            " Say **alerts on** to start them again."
    which = {"critical": "critical findings", "high": "high and critical findings",
             "medium": "medium, high and critical findings"}[level]
    return f"Alerts are on: I'll post new {which} here as SwarmSentinel reports them. Say **alerts off** to stop."


async def answer(text: str, fetch) -> str:
    """The reply to one message. `fetch(limit=...)` returns the hub's brief or raises HubError."""
    kind, only = intent(text)
    if kind == "help":
        return HELP
    try:
        brief = await fetch(limit=20 if only else 5)
    except HubError as exc:
        return f"I can't reach SwarmSentinel right now ({exc})."
    return format_threats(brief, only) if kind == "threats" else format_status(brief)
