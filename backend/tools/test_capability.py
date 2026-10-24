#!/usr/bin/env python3
"""Tests for the machine-capability levels (capability.py). Run:  python3 backend/tools/test_capability.py"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(os.path.dirname(HERE), "agents")]
import capability as cap  # noqa: E402


def machine(**over):
    """A healthy 16 GB Linux server with no AI configured, then changed by the test."""
    base = dict(os="linux", ram_gb=16, disk_free_gb=100, has_systemd=True, has_nmap=True, logs_readable=True,
                cloud_keys=[], local_models=[], role="hub", in_container=False)
    base.update(over)
    return base


class Levels(unittest.TestCase):
    def test_big_server_without_models_is_guard(self):
        r = cap.assess(machine())
        self.assertEqual((r["level"], r["name"]), (2, "Guard"))
        self.assertTrue(any("AI panel" in g["what"] for g in r["cannot"]))

    def test_three_cloud_keys_make_a_panel(self):
        self.assertEqual(cap.assess(machine(cloud_keys=["groq", "gemini", "mistral"]))["level"], 3)

    def test_two_local_models_with_enough_memory_are_sovereign_with_a_third_voice(self):
        r = cap.assess(machine(local_models=["hermes3", "mistral"], cloud_keys=["groq"]))
        self.assertEqual(r["level"], 4)

    def test_models_served_by_another_machine_vote_but_are_not_sovereign(self):
        r = cap.assess(machine(local_models=["a", "b", "c"], models_on_this_machine=False))
        self.assertEqual(r["level"], 3)
        self.assertTrue(any("another machine" in g["why"] for g in r["cannot"]))

    def test_loopback_detection(self):
        self.assertTrue(cap._is_loopback("http://127.0.0.1:11434"))
        self.assertTrue(cap._is_loopback("http://localhost:11434"))
        self.assertFalse(cap._is_loopback("http://192.0.2.5:11434"))

    def test_standalone_two_voter_rule_allows_a_local_only_panel(self):
        self.assertEqual(cap.assess(machine(local_models=["hermes3", "mistral"]), min_voters=2)["level"], 4)
        self.assertEqual(cap.assess(machine(local_models=["hermes3", "mistral"]), min_voters=3)["level"], 2)

    def test_local_models_on_a_small_machine_are_not_sovereign(self):
        r = cap.assess(machine(ram_gb=4, local_models=["a", "b"], cloud_keys=["groq"]))
        self.assertEqual(r["level"], 3)          # a panel, but not one that runs locally

    def test_small_box_is_watch_only_and_told_why(self):
        r = cap.assess(machine(ram_gb=1.2, disk_free_gb=8))
        self.assertEqual(r["level"], 1)
        self.assertTrue(any("2 GB" in g["fix"] or "node" in g["fix"] for g in r["cannot"]))

    def test_too_little_memory_still_reports_instead_of_crashing(self):
        r = cap.assess(machine(ram_gb=0.5))
        self.assertEqual(r["level"], 1)
        self.assertTrue(r["cannot"])

    def test_missing_nmap_is_named_with_its_fix(self):
        r = cap.assess(machine(has_nmap=False))
        self.assertTrue(any("nmap" in g["why"] and "apt install" in g["fix"] for g in r["cannot"]))

    def test_node_role_stays_at_watch(self):
        self.assertEqual(cap.assess(machine(role="node", cloud_keys=["a", "b", "c"]))["level"], 1)

    def test_non_linux_is_unsupported_natively_and_points_at_docker(self):
        r = cap.assess(machine(os="windows"))
        self.assertEqual(r["level"], 0)
        self.assertIn("Docker", r["can"][0])

    def test_a_container_is_told_to_use_the_host_mode_override_not_docker(self):
        r = cap.assess(machine(has_systemd=False, in_container=True, logs_readable=False))
        text = " ".join(g["fix"] for g in r["cannot"])
        self.assertIn("linux-host", text)
        self.assertNotIn("run it in Docker", text)

    def test_no_systemd_is_called_out(self):
        self.assertTrue(any("systemd" in g["why"] for g in cap.assess(machine(has_systemd=False))["cannot"]))

    def test_missing_facts_do_not_raise(self):
        self.assertEqual(cap.assess({})["level"], 0)
        self.assertEqual(cap.assess({"os": "linux"})["level"], 1)


class WhoReallyVotes(unittest.TestCase):
    ENTRIES = {
        "groq": {"kind": "openai", "key_env": "GROQ_API_KEY", "default_on": True},
        "gemini": {"kind": "gemini", "key_env": "GEMINI_API_KEY", "default_on": True},
        "openrouter": {"kind": "openai", "key_env": "OR_KEY", "default_on": False},
        "ollama-hermes3": {"kind": "ollama", "model": "hermes3", "default_on": False},
        "ollama-mistral": {"kind": "ollama", "model": "mistral", "default_on": True},
    }

    def test_a_cloud_key_counts_only_when_the_provider_is_switched_on(self):
        env = {"GROQ_API_KEY": "x", "GEMINI_API_KEY": "y", "OR_KEY": "z"}
        self.assertEqual(cap.voting_cloud(self.ENTRIES, {}, env), ["gemini", "groq"])                     # openrouter is off by default
        self.assertEqual(cap.voting_cloud(self.ENTRIES, {"gemini": False, "openrouter": True}, env), ["groq", "openrouter"])
        self.assertEqual(cap.voting_cloud(self.ENTRIES, {}, {"GROQ_API_KEY": "  "}), [])                  # a blank key is no key

    def test_a_local_model_counts_only_when_described_installed_and_switched_on(self):
        installed = ["hermes3:latest", "mistral:latest", "nomic-embed-text:latest"]
        self.assertEqual(cap.voting_local(self.ENTRIES, {}, installed), ["ollama-mistral"])               # hermes3 is off; the embedder is unknown
        self.assertEqual(cap.voting_local(self.ENTRIES, {"ollama-hermes3": True}, installed), ["ollama-hermes3", "ollama-mistral"])
        self.assertEqual(cap.voting_local(self.ENTRIES, {}, []), [])

    def test_loopback_must_be_a_real_loopback_address(self):
        self.assertFalse(cap._is_loopback("http://127.evil.example:11434"))
        self.assertTrue(cap._is_loopback("http://[::1]:11434"))

    def test_a_container_without_systemd_is_not_called_full_protection(self):
        r = cap.assess(machine(has_systemd=False, in_container=True, cloud_keys=["a", "b", "c"]))
        self.assertEqual(r["level"], 3)
        self.assertFalse(r["host_watching"])
        self.assertIn("not watched", r["summary"])
        self.assertNotIn("full protection", r["summary"])


class Advice(unittest.TestCase):
    def test_advice_follows_memory(self):
        self.assertIn("no local models", cap._model_advice(2)[0])
        self.assertIn("one small", cap._model_advice(4)[0])
        self.assertIn("hermes3 and mistral", cap._model_advice(8)[0])


class Probe(unittest.TestCase):
    def test_probe_reads_this_machine_and_never_leaks_key_values(self):
        os.environ["GROQ_API_KEY"] = "secret-value-1234"
        try:
            facts = cap.probe()
            self.assertIn("ram_gb", facts)
            self.assertNotIn("secret-value-1234", repr(cap.assess(facts)))
            self.assertIn("groq", facts["cloud_keys"])
        finally:
            del os.environ["GROQ_API_KEY"]

    def test_text_report_is_readable(self):
        text = cap.format_text(cap.assess(machine()))
        self.assertIn("Level 2 (Guard)", text)
        self.assertIn("models:", text)


class Route(unittest.TestCase):
    """GET /api/status/capability: admin only, and it never carries a key value."""

    @classmethod
    def setUpClass(cls):
        import tempfile
        tmp = tempfile.mkdtemp()
        os.environ.update(DATA_DIR=tmp, DATABASE_URL=f"sqlite:///{tmp}/cap-test.db", SSAI_API_KEY="cap-test-admin-key",
                          SSAI_PROVIDER_CHECK="0", SSAI_STATE_DB=os.path.join(tmp, "state.db"), GROQ_API_KEY="gsk_should_never_be_shown_1234")
        sys.path[:0] = [os.path.dirname(HERE)]
        import app as appmod
        cls.client = appmod.app.test_client()

    def test_anonymous_is_refused(self):
        self.assertEqual(self.client.get("/api/status/capability").status_code, 401)

    def test_admin_gets_a_level_and_no_secret(self):
        r = self.client.get("/api/status/capability", headers={"X-API-Key": "cap-test-admin-key"})
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertIn(body["level"], range(0, 5))
        self.assertIn("summary", body)
        self.assertNotIn("gsk_should_never_be_shown_1234", r.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
