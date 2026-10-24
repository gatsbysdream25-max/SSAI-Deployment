"""Approve / Reject pressed on a block-proposal card (2026-09-30). Pure logic: no SDK, so it is easy to test.

The press arrives as the signed-in person. The agent passes that person's own Entra token to the hub, which checks it
against its approver list: the agent never decides who may approve, and the Copilot key alone cannot approve anything.
Whatever happens, the answer is a card that replaces the one that was pressed.
"""
from datetime import datetime

import cards
from replies import HubError

NO_SIGN_IN = ("Sign-in isn't available here, so this can't be approved from Teams yet (Microsoft 365 single sign-on "
              "is set up with the tenant). Decide in the dashboard for now.")


def _when(iso):
    try:
        return datetime.fromisoformat(str(iso).replace("Z", "+00:00")).strftime("%b %d %H:%M UTC")
    except ValueError:
        return ""


def proposal_from(data):
    """The proposal as shown on the pressed card (echoed back in the button's data). Display only: the hub is asked
    about the id alone and answers with its own copy."""
    p = dict(data or {})
    try:
        p["id"] = int(p.get("id"))
    except (TypeError, ValueError):
        p["id"] = None
    return p


async def handle(action, data, user_token, decide, dashboard_url=None):
    """The card to show after Approve / Reject. `decide(id, action, token)` -> (http status, body) or HubError."""
    p = proposal_from(data)
    if action not in ("approve", "reject") or p["id"] is None:
        return cards.approval_card(p, True, dashboard_url, note="That button is out of date. Say **pending** for the list.")
    if not user_token:
        return cards.approval_card(p, True, dashboard_url, note=NO_SIGN_IN)
    try:
        status, body = await decide(p["id"], action, user_token)
    except HubError as exc:
        return cards.approval_card(p, True, dashboard_url, note=f"Couldn't reach SwarmSentinel ({exc}). Nothing changed.")
    body = body if isinstance(body, dict) else {}
    if status == 200 and body.get("ok"):
        done = dict(p, **(body.get("proposal") or {}))
        who = done.get("decided_by") or "you"
        if done.get("status") == "approved":
            until = _when(done.get("expires_at"))
            text = f"Blocked. Approved by {who}." + (f" It is undone automatically on {until}." if until else "")
        else:
            text = f"Rejected by {who}. Nothing was blocked."
        return cards.decided_card(done, text, dashboard_url)
    if status == 409:
        return cards.decided_card(p, f"Already decided: {body.get('error', 'no longer pending')}.", dashboard_url)
    if status == 403:
        return cards.approval_card(p, True, dashboard_url,
                                   note="You're not on this hub's approver list, so nothing changed.")
    if status == 503:
        return cards.approval_card(p, False, dashboard_url)
    if status == 429:
        return cards.approval_card(p, True, dashboard_url, note="Too many failed attempts from here. Wait a few minutes.")
    if status == 502:
        return cards.approval_card(p, True, dashboard_url, note="The block could not be applied. See the dashboard.")
    return cards.approval_card(p, True, dashboard_url, note=f"SwarmSentinel answered HTTP {status}. Nothing changed.")
