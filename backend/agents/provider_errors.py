"""Named reasons a call to an AI provider fails (consensus plan, Phase 1).

A provider that stops answering used to show up as free text ("400 Client Error ... for url ..."). Here every failure
becomes one short name an operator can act on, and the same names are used by the live panel and by the startup
health check (provider_check.py), so the dashboard and the log say the same thing.
"""
from __future__ import annotations

import requests

try:
    from redact import redact as _redact
except ImportError:                       # imported as agents.provider_errors by the web app
    from agents.redact import redact as _redact

OK, NO_KEY = "ok", "no_key"
NO_CREDITS, BAD_KEY, BAD_MODEL, RATE_LIMITED = "no_credits", "bad_key", "bad_model", "rate_limited"
TIMEOUT, UNREACHABLE, PROVIDER_ERROR, ERROR = "timeout", "unreachable", "provider_error", "error"
MALFORMED = "malformed"                   # it answered, but not with a usable vote
QUOTA_USED = "quota_used"                 # a free daily/monthly quota is spent (HTTP 429 that says so): resets on its own, unlike a short rate limit
CAP_REACHED = "cap_reached"               # our own daily request / monthly spend limit for this voice (usage_caps.py)

# Worth one more try: the same request may well work a moment later. Everything else (bad key, no credits, retired
# model) fails the same way every time, and a timeout has already used up its share of the deadline.
RETRYABLE = frozenset({RATE_LIMITED, PROVIDER_ERROR, UNREACHABLE})


def classify(exc: BaseException) -> tuple:
    """(status, exact error text) for a failed request. The provider's own error body is kept: it says why."""
    if isinstance(exc, requests.exceptions.HTTPError) and exc.response is not None:
        code = exc.response.status_code
        try:
            body = exc.response.text[:240].replace("\n", " ")
        except Exception:
            body = ""
        low = body.lower()
        text = _redact(f"HTTP {code}: {body}".strip())
        if code == 402 or "credit balance" in low or "insufficient_quota" in low or ("billing" in low and code != 429):
            return NO_CREDITS, text
        if code in (401, 403):
            return BAD_KEY, text
        if code == 404 or (code == 400 and "model" in low):
            return BAD_MODEL, text
        if code == 429:
            # A per-minute limit clears in seconds and is worth a retry; a spent daily/monthly quota is not.
            if any(w in low for w in ("quota", "exhausted", "per day", "daily", "per month")):
                return QUOTA_USED, text
            return RATE_LIMITED, text
        if code >= 500:
            return PROVIDER_ERROR, text
        return ERROR, text
    if isinstance(exc, requests.exceptions.Timeout):
        return TIMEOUT, "timed out"
    if isinstance(exc, requests.exceptions.ConnectionError):
        return UNREACHABLE, _redact(str(exc))[:200]
    return ERROR, _redact(f"{type(exc).__name__}: {exc}")[:200]
