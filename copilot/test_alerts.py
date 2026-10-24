#!/usr/bin/env python3
"""Adaptive Cards, alert subscriptions and the alert poller (2026-09-30). No SDK and no network needed.
Run:  python copilot/test_alerts.py"""
import asyncio
import json
import os
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import alerts as A  # noqa: E402
import cards as C  # noqa: E402
import replies as R  # noqa: E402


def item(sev, typ="dns-anomaly", summary="[active] something HOST_1", ts="2026-09-30T04:00:00+00:00"):
    return {"severity": sev, "threat_type": typ, "timestamp": ts, "sanitized_summary": summary}


def texts(card):
    """Every string shown on a card (to check nothing unexpected is on it)."""
    out = []

    def walk(x):
        if isinstance(x, dict):
            for k, v in x.items():
                if k in ("text", "title", "fallbackText", "url"):
                    out.append(v)
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)
    walk(card)
    return out


class Cards(unittest.TestCase):
    BRIEF = {"generated": "2026-09-30T05:00:00Z", "window_hours": 24,
             "counts": {"critical": 1, "high": 2, "medium": 0, "low": 3, "info": 0},
             "open": {"critical": 1, "high": 0, "medium": 4}, "withheld": 1,
             "threats": [item("critical", "file-modification"), item("medium")]}

    def test_cards_are_valid_adaptive_cards_that_serialize(self):
        for card in (C.alert_card(item("high")), C.status_card(self.BRIEF), C.threats_card(self.BRIEF),
                     C.threats_card(self.BRIEF, "high"), C.overflow_card(3)):
            self.assertEqual((card["type"], card["version"]), ("AdaptiveCard", "1.5"))
            self.assertTrue(card["body"])
            json.dumps(card)

    def test_alert_card(self):
        card = C.alert_card(item("critical", "file-modification", ts="2026-09-30T04:50:00+00:00"), "http://hub/dashboard")
        shown = " ".join(texts(card))
        self.assertIn("CRITICAL file-modification", shown)
        self.assertIn("HOST_1", shown)
        self.assertEqual(card["actions"][0]["url"], "http://hub/dashboard")
        self.assertEqual(card["body"][0]["color"], "Attention")

    def test_no_button_without_a_dashboard_url(self):
        self.assertNotIn("actions", C.alert_card(item("high")))

    def test_status_card(self):
        shown = " ".join(texts(C.status_card(self.BRIEF)))
        self.assertIn("**Still open:** 1 critical, 4 medium", shown)
        self.assertIn("1 threat(s) held back", shown)

    def test_threats_card_filters_and_says_when_empty(self):
        self.assertEqual(len(C.threats_card(self.BRIEF)["body"]), 3)                 # title + 2 threats
        self.assertIn("No critical threats", " ".join(texts(C.threats_card({"threats": []}, "critical"))))
        self.assertIn("No high threats", " ".join(texts(C.threats_card(self.BRIEF, "high"))))

    def test_odd_brief_does_not_crash(self):
        C.status_card({})
        C.threats_card({"threats": [{}]})
        C.alert_card({})


class Intents(unittest.TestCase):
    def test_alert_commands(self):
        cases = {"alerts on": ("alerts", "high"), "Alerts ON please": ("alerts", "high"), "alerts off": ("alerts", "off"),
                 "alerts critical": ("alerts", "critical"), "alert medium": ("alerts", "medium"),
                 "subscribe": ("alerts", "high"), "unsubscribe": ("alerts", "off"), "stop alerts": ("alerts", "off"),
                 "notify me high": ("alerts", "high"),
                 "latest alerts": ("threats", None), "any high alerts?": ("threats", "high"), "status": ("status", None)}
        for text, want in cases.items():
            self.assertEqual(R.intent(text), want, text)

    def test_alert_replies(self):
        self.assertIn("high and critical", R.alerts_reply("high"))
        self.assertIn("Alerts are off", R.alerts_reply("off", was_on=True))
        self.assertIn("were not on", R.alerts_reply("off", was_on=False))


class StoreCase(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(tempfile.mkdtemp(), "sub", "state.json")
        self.store = A.Store(self.path)

    def test_subscribe_persists_owner_only_and_starts_the_cursor(self):
        self.store.subscribe("c1", {"conversation": {"id": "c1"}}, "critical")
        self.assertIsNotNone(self.store.since)
        again = A.Store(self.path)
        self.assertEqual(again.get("c1")["min_severity"], "critical")
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)

    def test_unsubscribe(self):
        self.store.subscribe("c1", {}, "high")
        self.assertTrue(self.store.unsubscribe("c1"))
        self.assertFalse(self.store.unsubscribe("c1"))
        self.assertIsNone(A.Store(self.path).get("c1"))

    def test_bad_level_and_corrupt_file(self):
        with self.assertRaises(ValueError):
            self.store.subscribe("c1", {}, "low")
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w") as f:
            f.write("{not json")
        self.assertEqual(A.Store(self.path).subs, {})


class Hub:
    """A fake hub alert feed: items in report order; `since` is the index already delivered."""
    def __init__(self, items, fail=False, withhold=()):
        self.items, self.fail, self.withhold, self.calls = items, fail, set(withhold), []

    async def fetch(self, since=None, min_severity="medium", limit=5, **_):
        self.calls.append((since, min_severity, limit))
        if self.fail:
            raise R.HubError("down")
        start = int(since) if since and since.isdigit() else 0
        wanted = A.RANK[min_severity]
        out, withheld, pos = [], 0, start
        for i in range(start, len(self.items)):
            if len(out) + withheld >= limit:
                break
            pos = i + 1
            if A.RANK.get(self.items[i]["severity"], 99) > wanted:
                continue
            if i in self.withhold:
                withheld += 1
            else:
                out.append(self.items[i])
        return {"threats": out, "withheld": withheld, "next_since": str(pos)}


class PollerCase(unittest.TestCase):
    def setUp(self):
        self.store = A.Store(os.path.join(tempfile.mkdtemp(), "state.json"))
        self.sent = []
        self.broken = set()

    async def send(self, reference, card):
        if reference["id"] in self.broken:
            raise RuntimeError("403 conversation gone")
        self.sent.append((reference["id"], card))

    def poll(self, hub, rounds=1):
        p = A.Poller(self.store, hub.fetch, self.send)
        return [asyncio.run(p.tick()) for _ in range(rounds)]

    def subscribe(self, cid, level):
        self.store.subscribe(cid, {"id": cid}, level)
        self.store.since = "0"

    def test_nobody_subscribed_means_no_hub_calls_and_no_backlog(self):
        hub = Hub([item("critical")])
        self.poll(hub)
        self.assertEqual(hub.calls, [])
        self.assertIsNotNone(self.store.since)

    def test_each_chat_gets_its_own_level_once(self):
        hub = Hub([item("medium"), item("high"), item("critical")])
        self.subscribe("everything", "medium")
        self.subscribe("urgent", "critical")
        self.assertEqual(self.poll(hub, rounds=2), [4, 0])                         # nothing is sent twice
        got = {}
        for cid, _card in self.sent:
            got[cid] = got.get(cid, 0) + 1
        self.assertEqual(got, {"everything": 3, "urgent": 1})
        self.assertEqual(hub.calls[0][1], "medium")                                # asks for the widest level needed

    def test_a_flood_becomes_five_cards_and_a_summary(self):
        hub = Hub([item("high") for _ in range(12)])
        self.subscribe("c", "high")
        self.poll(hub)
        cards_ = [c for _cid, c in self.sent]
        self.assertEqual(len(cards_), A.MAX_PER_ROUND + 1)
        self.assertIn("7 more", cards_[-1]["fallbackText"])

    def test_hub_down_keeps_the_cursor(self):
        self.subscribe("c", "high")
        self.poll(Hub([item("high")], fail=True))
        self.assertEqual((self.store.since, self.sent), ("0", []))
        self.poll(Hub([item("high")]))
        self.assertEqual(len(self.sent), 1)                                        # caught up once it is back

    def test_withheld_items_move_on(self):
        self.subscribe("c", "high")
        self.poll(Hub([item("high"), item("high", summary="second")], withhold={0}))
        self.assertEqual(len(self.sent), 1)
        self.assertEqual(self.store.since, "2")

    def test_a_backlog_is_paged(self):
        hub = Hub([item("high") for _ in range(A.PAGE + 3)])
        self.subscribe("c", "high")
        self.poll(hub)
        self.assertEqual(len(hub.calls), 2)
        self.assertEqual(self.store.since, str(A.PAGE + 3))

    def test_a_dead_chat_is_dropped_after_repeated_failures_and_others_still_get_theirs(self):
        self.subscribe("dead", "high")
        self.subscribe("alive", "high")
        self.broken.add("dead")
        for n in range(A.MAX_FAILURES):
            self.poll(Hub([item("high")] * (n + 1)))
        self.assertIsNone(self.store.get("dead"))
        self.assertEqual({cid for cid, _ in self.sent}, {"alive"})

    def test_a_success_resets_the_failure_count(self):
        self.subscribe("c", "high")
        self.broken.add("c")
        self.poll(Hub([item("high")]))
        self.assertEqual(self.store.get("c")["failures"], 1)
        self.broken.clear()
        self.poll(Hub([item("high")] * 2))
        self.assertEqual(self.store.get("c")["failures"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
