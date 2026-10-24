#!/usr/bin/env python3
"""The agent's replies (2026-09-26). No SDK and no network needed.  Run:  python copilot/test_replies.py"""
import asyncio
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import replies as R  # noqa: E402

BRIEF = {
    "generated": "2026-09-26T05:00:00Z", "window_hours": 24,
    "counts": {"critical": 0, "high": 7, "medium": 2, "low": 1, "info": 448},
    "open": {"critical": 1, "high": 5, "medium": 0},
    "withheld": 0,
    "threats": [
        {"severity": "high", "threat_type": "suspicious-process", "timestamp": "2026-09-26T04:48:00Z",
         "sanitized_summary": "[active] Suspicious process: HOST_1 ran sshpass -p SECRET_1 AI verdict: suspicious, 2 of 3 AIs agreed."},
        {"severity": "medium", "threat_type": "dns-anomaly", "timestamp": "2026-09-26T02:00:00Z",
         "sanitized_summary": "[active] Pi-hole blocking 41% of queries"},
    ],
}


def run(text, brief=BRIEF, error=None):
    calls = []

    async def fetch(limit=5):
        calls.append(limit)
        if error:
            raise R.HubError(error)
        return brief
    return asyncio.run(R.answer(text, fetch)), calls


class Intent(unittest.TestCase):
    def test_routing(self):
        cases = {"": ("help", None), "/help": ("help", None), "hi": ("help", None), "what can you do": ("help", None),
                 "status": ("status", None), "how are things": ("status", None), "show threats": ("threats", None),
                 "latest alerts": ("threats", None), "any critical?": ("threats", "critical"),
                 "high severity threats": ("threats", "high"), "highlight the status": ("status", None)}
        for text, want in cases.items():
            self.assertEqual(R.intent(text), want, text)


class Replies(unittest.TestCase):
    def test_help_does_not_call_the_hub(self):
        reply, calls = run("help")
        self.assertEqual((reply, calls), (R.HELP, []))

    def test_status(self):
        reply, _ = run("status")
        self.assertIn("High 7", reply)
        self.assertIn("Info 448", reply)
        self.assertIn("**Still open:** 1 critical, 5 high", reply)
        self.assertNotIn("0 medium", reply)

    def test_threats_list_with_age_and_verdict(self):
        reply, calls = run("threats")
        self.assertEqual(calls, [5])
        self.assertIn("1. \U0001F7E0 **HIGH** · suspicious-process · 12 min ago", reply)
        self.assertIn("AI verdict: suspicious, 2 of 3 AIs agreed.", reply)
        self.assertIn("2. \U0001F7E1 **MEDIUM** · dns-anomaly · 3 h ago", reply)

    def test_severity_filter_asks_for_more_and_filters(self):
        reply, calls = run("high")
        self.assertEqual(calls, [20])
        self.assertIn("HIGH", reply)
        self.assertNotIn("MEDIUM", reply)
        self.assertEqual(run("critical")[0], "No critical threats in the last 24 h.")

    def test_only_what_the_brief_says(self):
        reply, _ = run("threats")
        for s in ("HOST_1", "SECRET_1"):
            self.assertIn(s, reply)                      # tokens pass through untouched; nothing is looked up

    def test_hub_trouble_is_a_plain_sentence(self):
        reply, _ = run("status", error="the hub refused the Copilot key")
        self.assertEqual(reply, "I can't reach SwarmSentinel right now (the hub refused the Copilot key).")

    def test_withheld_is_mentioned(self):
        reply, _ = run("status", brief=dict(BRIEF, withheld=2))
        self.assertIn("2 threat(s) held back by the privacy filter", reply)

    def test_empty_or_odd_brief_does_not_crash(self):
        self.assertIn("Still open:** nothing", run("status", brief={})[0])
        self.assertIn("No threats", run("threats", brief={"threats": []})[0])
        self.assertIn("1. ", run("threats", brief={"threats": [{"severity": "high"}]})[0])   # missing fields: still a line


try:
    import microsoft_agents.hosting.aiohttp  # noqa: F401
    HAVE_SDK = True
except ImportError:
    HAVE_SDK = False


@unittest.skipUnless(HAVE_SDK, "Agents SDK not installed (pip install -r requirements.txt)")
class AgentBuilds(unittest.TestCase):
    """SDK 1.7 changed what AgentApplication and CloudAdapter require (the Microsoft quickstart still shows the old
    way); building the real app catches the next change in the tests rather than at start-up."""
    def test_the_agent_application_builds_without_credentials(self):
        import agent
        app = agent.build_app()
        self.assertEqual(type(app).__name__, "AgentApplication")
        self.assertIsNotNone(app.adapter)


if __name__ == "__main__":
    unittest.main(verbosity=2)
