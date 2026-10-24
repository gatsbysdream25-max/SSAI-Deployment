"""Proactive alerts: push new SwarmSentinel findings into the Teams / Copilot chats that asked for them (2026-09-30).

A chat subscribes with "alerts on" (default: high and critical) or "alerts medium|high|critical", and stops with
"alerts off". The poller asks the hub for what was reported after its cursor (GET /api/copilot/brief?since=...), so
nothing is sent twice and nothing is skipped; a finding that stays active is re-reported on the hub's own schedule
(critical 5 min, high 1 h, medium 6 h), and comes round again then.

State (subscriptions + cursor) lives in one owner-only JSON file, SSAI_AGENT_STATE (default copilot/instance/state.json):
it holds Teams conversation references, which identify people, so it is never committed.
"""
import asyncio
import json
import logging
import os
import tempfile
from datetime import datetime, timezone

import cards
from replies import HubError

RANK = {"critical": 0, "high": 1, "medium": 2}
DEFAULT_MIN = "high"
PAGE = 20                 # items per hub request
MAX_PAGES = 5             # per round: a backlog is drained over a few rounds, not in one burst
MAX_PER_ROUND = 5         # per chat per round; the rest become one "...and N more" card
MAX_FAILURES = 3          # a chat that keeps refusing (app removed, conversation gone) is dropped

log = logging.getLogger("ssai.alerts")


def _now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def default_state_path():
    here = os.path.dirname(os.path.abspath(__file__))
    return os.environ.get("SSAI_AGENT_STATE") or os.path.join(here, "instance", "state.json")


class Store:
    def __init__(self, path=None):
        self.path = path or default_state_path()
        self.data = self._load()

    def _load(self):
        """Read the saved subscriptions from disk, or start empty if the file is missing or damaged."""
        try:
            with open(self.path, encoding="utf-8") as f:
                d = json.load(f)
            if isinstance(d, dict) and isinstance(d.get("subs"), dict):
                seen = d.get("proposals_seen")
                return {"subs": d["subs"], "since": d.get("since"),
                        "proposals_seen": [i for i in seen if isinstance(i, int)] if isinstance(seen, list) else []}
        except (OSError, ValueError):
            pass
        return {"subs": {}, "since": None}

    def save(self):
        """Write the state to disk safely: write a temporary file (owner-only access) and swap it in, so a crash cannot
        leave a half-written file."""
        folder = os.path.dirname(self.path) or "."
        os.makedirs(folder, mode=0o700, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=folder, prefix=".state-")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(self.data, f, indent=1)
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    @property
    def subs(self):
        return self.data["subs"]

    @property
    def since(self):
        return self.data["since"]

    @since.setter
    def since(self, value):
        self.data["since"] = value

    def subscribe(self, conversation_id, reference, min_severity=DEFAULT_MIN):
        if min_severity not in RANK:
            raise ValueError(min_severity)
        self.subs[conversation_id] = {"reference": reference, "min_severity": min_severity, "failures": 0}
        if self.since is None:
            self.since = _now_iso()                 # alerts start now; the chat asks "threats" for the past
        self.save()

    def unsubscribe(self, conversation_id):
        gone = self.subs.pop(conversation_id, None) is not None
        if gone:
            self.save()
        return gone

    def get(self, conversation_id):
        return self.subs.get(conversation_id)


class Poller:
    """`fetch(since=, min_severity=, limit=)` returns the hub's brief or raises HubError; `send(reference, card)` posts
    one Adaptive Card into a conversation or raises."""

    def __init__(self, store, fetch, send, dashboard_url=None, fetch_proposals=None):
        self.store, self.fetch, self.send, self.dashboard_url = store, fetch, send, dashboard_url
        self.fetch_proposals = fetch_proposals      # new block proposals go to every subscribed chat, once

    async def _proposal_cards(self):
        """Approval cards for proposals no chat has been shown yet (every subscription gets them, whatever its level:
        a proposal needs a person)."""
        if self.fetch_proposals is None:
            return []
        try:
            data = await self.fetch_proposals()
        except HubError as exc:
            log.warning("proposal poll: %s", exc)
            return []
        seen = self.store.data.setdefault("proposals_seen", [])
        fresh = [p for p in data.get("proposals") or [] if p.get("id") is not None and p["id"] not in seen]
        seen.extend(p["id"] for p in fresh)
        del seen[:-500]                             # bounded: ids only grow
        enabled = bool(data.get("approvals_enabled"))
        return [cards.approval_card(p, enabled, self.dashboard_url) for p in fresh]

    async def tick(self):
        """One round. Returns the number of cards posted."""
        subs = dict(self.store.subs)
        if not subs or self.store.since is None:
            self.store.since = _now_iso()           # nobody listening: never build up a backlog to dump later
            self.store.save()
            return 0
        lowest = max((s.get("min_severity", DEFAULT_MIN) for s in subs.values()), key=lambda s: RANK.get(s, 0))
        pending = {cid: [] for cid in subs}
        for _ in range(MAX_PAGES):
            try:
                brief = await self.fetch(since=self.store.since, min_severity=lowest, limit=PAGE)
            except HubError as exc:
                log.warning("alert poll: %s", exc)  # cursor unchanged: the same findings are asked for next round
                break
            items = brief.get("threats") or []
            for t in items:
                for cid, sub in subs.items():
                    if RANK.get(t.get("severity"), 99) <= RANK.get(sub.get("min_severity"), RANK[DEFAULT_MIN]):
                        pending[cid].append(t)
            self.store.since = brief.get("next_since") or self.store.since
            if len(items) + int(brief.get("withheld") or 0) < PAGE:
                break
        proposals = await self._proposal_cards()
        posted = 0
        for cid in subs:
            if pending[cid] or proposals:
                posted += await self._deliver(cid, subs[cid], pending[cid], proposals)
        self.store.save()
        return posted

    async def _deliver(self, cid, sub, items, extra_cards=()):
        """Post the batch of cards (approval cards first, then alerts, capped at MAX_PER_ROUND) into one chat; returns how many were posted.
        A chat that keeps failing is dropped after MAX_FAILURES tries so one dead chat cannot slow the rest.
        """
        now = datetime.now(timezone.utc)
        batch = list(extra_cards) + [cards.alert_card(t, self.dashboard_url, now) for t in items[:MAX_PER_ROUND]]
        if len(items) > MAX_PER_ROUND:
            batch.append(cards.overflow_card(len(items) - MAX_PER_ROUND, self.dashboard_url))
        posted = 0
        try:
            for card in batch:
                await self.send(sub["reference"], card)
                posted += 1
        except Exception as exc:                    # noqa: BLE001 (any channel error: count it, keep the others going)
            live = self.store.get(cid)
            if live is not None:
                live["failures"] = int(live.get("failures", 0)) + 1
                log.warning("alert to a chat failed (%d/%d): %s", live["failures"], MAX_FAILURES, type(exc).__name__)
                if live["failures"] >= MAX_FAILURES:
                    self.store.subs.pop(cid, None)
                    log.warning("dropped a chat's alert subscription after %d failures", MAX_FAILURES)
            return posted
        live = self.store.get(cid)
        if live is not None:
            live["failures"] = 0
        return posted

    async def run(self, interval):
        while True:
            try:
                await self.tick()
            except Exception:                       # noqa: BLE001 (the loop must outlive any one bad round)
                log.exception("alert round failed")
            await asyncio.sleep(interval)
