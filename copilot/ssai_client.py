"""Fetch SwarmSentinel's sanitized brief for the agent (2026-09-26).

Settings (environment or copilot/.env):
    SSAI_HUB_URL      the hub, e.g. http://192.168.1.10:5000
    SSAI_COPILOT_KEY  the hub's Copilot lane key (the same value as SSAI_COPILOT_KEY in the hub's .env)
"""
import asyncio
import os

import aiohttp

from replies import HubError

TIMEOUT = aiohttp.ClientTimeout(total=10)


def _hub():
    key = os.environ.get("SSAI_COPILOT_KEY", "")
    if not key:
        raise HubError("SSAI_COPILOT_KEY is not set for the agent")
    return os.environ.get("SSAI_HUB_URL", "http://127.0.0.1:5000").rstrip("/"), {"X-Copilot-Key": key}


async def fetch_proposals() -> dict:
    """Pending block proposals: {"approvals_enabled": bool, "proposals": [...]} (sanitized by the hub)."""
    base, headers = _hub()
    try:
        async with aiohttp.ClientSession(timeout=TIMEOUT) as s:
            async with s.get(base + "/api/copilot/remediation", headers=headers) as r:
                if r.status == 401:
                    raise HubError("the hub refused the Copilot key")
                if r.status != 200:
                    raise HubError(f"the hub answered HTTP {r.status}")
                return await r.json()
    except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
        raise HubError(f"the hub did not answer: {type(exc).__name__}") from exc


async def decide(proposal_id: int, action: str, user_token: str) -> tuple:
    """Approve or reject as the signed-in person. Returns (http status, body). The hub checks the person's own Entra
    token against its approver list; the Copilot key alone cannot decide anything."""
    if action not in ("approve", "reject"):
        raise ValueError(action)
    base, headers = _hub()
    headers = dict(headers, Authorization=f"Bearer {user_token}")
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as s:      # a block can take a moment
            async with s.post(f"{base}/api/copilot/remediation/{int(proposal_id)}/{action}", headers=headers) as r:
                try:
                    body = await r.json()
                except (aiohttp.ContentTypeError, ValueError):
                    body = {}
                return r.status, body
    except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
        raise HubError(f"the hub did not answer: {type(exc).__name__}") from exc


async def fetch_brief(hours: int = 24, limit: int = 5, since: str = None, min_severity: str = None) -> dict:
    """The status brief, or with `since` the alert feed: findings reported after that cursor, oldest first, with the
    next cursor in `next_since`."""
    key = os.environ.get("SSAI_COPILOT_KEY", "")
    if not key:
        raise HubError("SSAI_COPILOT_KEY is not set for the agent")
    url = os.environ.get("SSAI_HUB_URL", "http://127.0.0.1:5000").rstrip("/") + "/api/copilot/brief"
    params = {"hours": hours, "limit": limit}
    if since:
        params["since"] = since
    if min_severity:
        params["min_severity"] = min_severity
    try:
        async with aiohttp.ClientSession(timeout=TIMEOUT) as s:
            async with s.get(url, params=params, headers={"X-Copilot-Key": key}) as r:
                if r.status == 401:
                    raise HubError("the hub refused the Copilot key")
                if r.status != 200:
                    raise HubError(f"the hub answered HTTP {r.status}")
                return await r.json()
    except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
        raise HubError(f"the hub did not answer: {type(exc).__name__}") from exc
