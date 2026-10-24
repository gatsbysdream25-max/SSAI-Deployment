#!/usr/bin/env python3
"""Approve / Reject from Teams, agent side (2026-09-30): the card shown for every hub answer, the person's token is what
is sent, proposals reach subscribed chats once. No SDK and no network needed.  Run:  python copilot/test_approvals.py"""
import asyncio
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import alerts as A  # noqa: E402
import approvals as AP  # noqa: E402
import cards as C  # noqa: E402
import replies as R  # noqa: E402

P = {"id": 7, "kind": "ip", "target": "1.2.3.4", "target_shown": True, "severity": "critical",
     "threat_type": "malware-url", "confidence": 92, "ttl_hours": 168, "reason": "malicious, 3 of 3 AIs"}


def shown(card):
    out = []

    def walk(x):
        if isinstance(x, dict):
            out.extend(str(x[k]) for k in ("text", "title", "value") if k in x)
            for v in x.values():
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)
    walk(card)
    return " ".join(out)


def buttons(card):
    return [a for a in card.get("actions", []) if a["type"] == "Action.Execute"]


class Hub:
    def __init__(self, status=200, body=None, error=None):
        self.status, self.body, self.error, self.calls = status, body, error, []

    async def decide(self, pid, action, token):
        self.calls.append((pid, action, token))
        if self.error:
            raise R.HubError(self.error)
        return self.status, self.body if self.body is not None else {}


def press(action="approve", data=None, token="user-token", hub=None):
    hub = hub or Hub()
    return asyncio.run(AP.handle(action, dict(P) if data is None else data, token, hub.decide)), hub


class Card(unittest.TestCase):
    def test_approval_card_has_both_buttons_with_the_id(self):
        card = C.approval_card(P)
        verbs = [(b["verb"], b["data"]["id"]) for b in buttons(card)]
        self.assertEqual(verbs, [(C.APPROVE_VERB, 7), (C.REJECT_VERB, 7)])
        self.assertIn("Block address: 1.2.3.4", shown(card))
        self.assertIn("168 h", shown(card))

    def test_no_buttons_when_the_hub_has_approvals_off(self):
        card = C.approval_card(P, approvals_enabled=False, dashboard_url="http://hub/dashboard")
        self.assertEqual(buttons(card), [])
        self.assertIn("decide in the dashboard", shown(card))

    def test_a_lan_target_says_so(self):
        card = C.approval_card(dict(P, target="a device on your network", target_shown=False))
        self.assertIn("not shown here", shown(card))


class Press(unittest.TestCase):
    def test_the_persons_token_and_only_the_id_go_to_the_hub(self):
        _card, hub = press(data=dict(P, target="evil", id="7"))
        self.assertEqual(hub.calls, [(7, "approve", "user-token")])

    def test_approved(self):
        body = {"ok": True, "proposal": dict(P, status="approved", decided_by="Pat", expires_at="2026-10-07T05:00:00+00:00")}
        card, _ = press(hub=Hub(200, body))
        self.assertIn("Blocked. Approved by Pat", shown(card))
        self.assertIn("Oct 07 05:00 UTC", shown(card))
        self.assertEqual(buttons(card), [])                       # decided: the buttons are gone

    def test_rejected(self):
        card, _ = press("reject", hub=Hub(200, {"ok": True, "proposal": dict(P, status="rejected", decided_by="Pat")}))
        self.assertIn("Rejected by Pat. Nothing was blocked.", shown(card))
        self.assertEqual(buttons(card), [])

    def test_without_sign_in_nothing_is_asked(self):
        card, hub = press(token=None)
        self.assertEqual(hub.calls, [])
        self.assertIn("Sign-in isn't available", shown(card))
        self.assertEqual(len(buttons(card)), 2)                   # still decidable once sign-in exists

    def test_every_refusal_keeps_the_buttons_and_explains(self):
        for status, words in ((403, "not on this hub's approver list"), (429, "Too many failed attempts"),
                              (502, "could not be applied"), (500, "HTTP 500")):
            with self.subTest(status):
                card, _ = press(hub=Hub(status, {"ok": False}))
                self.assertIn(words, shown(card))
                self.assertEqual(len(buttons(card)), 2)

    def test_approvals_turned_off_removes_the_buttons(self):
        card, _ = press(hub=Hub(503, {"ok": False}))
        self.assertEqual(buttons(card), [])

    def test_already_decided(self):
        card, _ = press(hub=Hub(409, {"ok": False, "error": "this proposal is already approved"}))
        self.assertIn("Already decided: this proposal is already approved", shown(card))
        self.assertEqual(buttons(card), [])

    def test_hub_unreachable(self):
        card, _ = press(hub=Hub(error="the hub did not answer: TimeoutError"))
        self.assertIn("Couldn't reach SwarmSentinel", shown(card))

    def test_bad_button_data(self):
        for data in ({}, {"id": "x"}, {"id": None}):
            card, hub = press(data=data)
            self.assertEqual(hub.calls, [])
            self.assertIn("out of date", shown(card))
        card, hub = press("delete")
        self.assertEqual(hub.calls, [])


class Intent(unittest.TestCase):
    def test_pending(self):
        for text in ("pending", "any approvals?", "show proposals", "what needs approval", "approve"):
            self.assertEqual(R.intent(text), ("pending", None), text)
        self.assertEqual(R.intent("alerts on"), ("alerts", "high"))


class PollerProposals(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(tempfile.mkdtemp(), "state.json")
        self.store = A.Store(self.path)
        self.sent = []
        self.data = {"approvals_enabled": True, "proposals": [dict(P)]}

    async def send(self, ref, card):
        self.sent.append((ref["id"], card))

    async def fetch(self, **_):
        return {"threats": [], "withheld": 0, "next_since": "x"}

    async def proposals(self):
        return self.data

    def tick(self):
        return asyncio.run(A.Poller(self.store, self.fetch, self.send, fetch_proposals=self.proposals).tick())

    def test_each_subscribed_chat_gets_a_new_proposal_once_whatever_its_level(self):
        self.store.subscribe("a", {"id": "a"}, "critical")
        self.store.subscribe("b", {"id": "b"}, "medium")
        self.tick()
        self.tick()
        self.assertEqual(sorted(cid for cid, _ in self.sent), ["a", "b"])
        self.assertEqual(len(buttons(self.sent[0][1])), 2)

    def test_seen_survives_a_restart(self):
        self.store.subscribe("a", {"id": "a"}, "high")
        self.tick()
        self.store = A.Store(self.path)
        self.tick()
        self.assertEqual(len(self.sent), 1)

    def test_nobody_subscribed_marks_nothing_seen(self):
        self.tick()
        self.assertEqual(self.store.data.get("proposals_seen", []), [])

    def test_hub_down_for_proposals_still_delivers_findings(self):
        async def down():
            raise R.HubError("down")
        self.store.subscribe("a", {"id": "a"}, "high")
        self.store.since = "0"

        async def fetch(**_):
            return {"threats": [{"severity": "high", "threat_type": "x"}], "withheld": 0, "next_since": "1"}
        asyncio.run(A.Poller(self.store, fetch, self.send, fetch_proposals=down).tick())
        self.assertEqual(len(self.sent), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
