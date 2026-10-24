"""Limits on what a paid or quota-limited AI voice may cost, and where it may be used (consensus plan section 9.4 and 9.6).

A provider entry in config/ai_models.json may carry:

    daily_request_cap        most requests per UTC day (the free tiers have one: OpenRouter 50, Groq 1,000)
    monthly_spend_cap_usd    hard monthly ceiling, estimated from the prices below
    price_in_per_mtok / price_out_per_mtok   dollars per million input / output tokens (estimates; tokens are guessed as characters / 4)
    allowed_deployments      where this voice may be used at all, e.g. ["home", "lab", "college"]; a bank deployment sets
                             SSAI_DEPLOYMENT=bank and a voice not listed for it never votes (Kimi, for example)

When a cap is reached the voice sits out for the rest of the period, the panel carries on without it, and the health table says
"cap_reached". Counters live in the agents' local state store (state_store.py), so they survive a restart. The spend is an
ESTIMATE kept to stop a runaway bill; the provider's own invoice is the truth, and the cap should be set below what you can afford.
"""
from __future__ import annotations

import os
import threading
from datetime import datetime, timezone
from typing import Callable, Optional, Tuple

_AGENT = "usage"
_lock = threading.Lock()


def deployment() -> str:
    """Which kind of installation this is (SSAI_DEPLOYMENT): home, lab, college, bank ... Default 'home'."""
    return os.environ.get("SSAI_DEPLOYMENT", "home").strip().lower() or "home"


_warned_unset = False


def deployment_allowed(entry: Optional[dict]) -> bool:
    """True if this installation's kind (home, lab, bank ...) is allowed to use the voice described by this entry; no
    list means everyone may."""
    global _warned_unset
    allowed = (entry or {}).get("allowed_deployments")
    if not isinstance(allowed, list) or not allowed:
        return True                                   # no list means no restriction
    if not os.environ.get("SSAI_DEPLOYMENT", "").strip() and not _warned_unset:
        _warned_unset = True
        import logging
        logging.getLogger("usage_caps").warning("SSAI_DEPLOYMENT is not set, so this installation counts as 'home' and voices limited to "
                                                "home/lab/college may vote. A bank or other regulated site must set SSAI_DEPLOYMENT.")
    return deployment() in {str(a).strip().lower() for a in allowed}


def _estimate_cost(entry: dict, prompt_chars: int, answer_chars: int) -> float:
    price_in, price_out = entry.get("price_in_per_mtok") or 0.0, entry.get("price_out_per_mtok") or 0.0
    return (prompt_chars / 4 * price_in + answer_chars / 4 * price_out) / 1_000_000


class Usage:
    def __init__(self, store=None, clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)):
        self._store, self._clock = store, clock

    def _state_store(self):
        """The shared state store, opened the first time it is needed (so importing this module touches no files)."""
        if self._store is None:
            import state_store
            self._store = state_store.store()
        return self._store

    def _keys(self, pid: str) -> Tuple[str, str]:
        now = self._clock()
        return f"{now:%Y-%m-%d}:{pid}:requests", f"{now:%Y-%m}:{pid}:spend"

    def check(self, pid: str, entry: dict) -> Tuple[bool, str]:
        """(True, '') when this voice may be called now, else (False, the reason)."""
        day_key, month_key = self._keys(pid)
        daily, monthly = entry.get("daily_request_cap"), entry.get("monthly_spend_cap_usd")
        with _lock:
            if daily and (self._state_store().get(_AGENT, day_key, 0) or 0) >= daily:
                return False, f"daily request cap of {daily} reached; back tomorrow (UTC)"
            if monthly and float(self._state_store().get(_AGENT, month_key, 0.0) or 0.0) >= monthly:
                return False, f"monthly spend cap of ${monthly:g} reached (estimated); back next month"
        return True, ""

    def count_request(self, pid: str) -> None:
        """One request is about to be made (counted whether or not it succeeds: a failed call still uses a free tier's
        quota)."""
        day_key, _ = self._keys(pid)
        with _lock:
            self._state_store().put(_AGENT, day_key, int(self._state_store().get(_AGENT, day_key, 0) or 0) + 1)

    def add_cost(self, pid: str, entry: dict, prompt_chars: int, answer_chars: int) -> None:
        """An answer arrived: add its estimated cost to this month's spend."""
        _, month_key = self._keys(pid)
        cost = _estimate_cost(entry, prompt_chars, answer_chars)
        if cost:
            with _lock:
                self._state_store().put(_AGENT, month_key, round(float(self._state_store().get(_AGENT, month_key, 0.0) or 0.0) + cost, 6))

    def snapshot(self, pid: str, entry: dict) -> dict:
        """What the dashboard shows beside a voice: today's requests and this month's estimated spend against their caps."""
        day_key, month_key = self._keys(pid)
        with _lock:
            return {"requests_today": int(self._state_store().get(_AGENT, day_key, 0) or 0), "daily_request_cap": entry.get("daily_request_cap"),
                    "spend_month_usd": round(float(self._state_store().get(_AGENT, month_key, 0.0) or 0.0), 4),
                    "monthly_spend_cap_usd": entry.get("monthly_spend_cap_usd")}


_default = Usage()


def check(pid: str, entry: dict) -> Tuple[bool, str]:
    return _default.check(pid, entry)


def count_request(pid: str) -> None:
    _default.count_request(pid)


def add_cost(pid: str, entry: dict, prompt_chars: int, answer_chars: int) -> None:
    _default.add_cost(pid, entry, prompt_chars, answer_chars)


def snapshot(pid: str, entry: dict) -> dict:
    return _default.snapshot(pid, entry)
