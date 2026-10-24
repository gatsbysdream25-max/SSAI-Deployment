#!/usr/bin/env python3
"""Direct tests of the panel's pure vote rules (panel_rules.py). Run:  python3 backend/tools/test_panel_rules.py"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(os.path.dirname(HERE), "agents")]
import panel_rules as R  # noqa: E402


def pairs(*ws):
    return [(w, w) for w in ws]


class Verdict(unittest.TestCase):
    def test_a_clear_malicious_majority_wins(self):
        v, agreeing, _, total = R.decide_verdict(["malicious", "malicious", "benign"], pairs(1, 1, 1))
        self.assertEqual((v, agreeing, total), ("malicious", {"malicious"}, 3.0))

    def test_suspicious_wins_when_at_least_half_raise_a_concern_but_not_a_firm_malicious_majority(self):
        v, agreeing, *_ = R.decide_verdict(["malicious", "suspicious", "benign", "benign"], pairs(1, 1, 1, 1))
        self.assertEqual(v, "suspicious")                 # 2 of 4 flag a concern: a tie leans toward caution
        self.assertEqual(agreeing, {"malicious", "suspicious"})

    def test_benign_when_most_say_benign(self):
        self.assertEqual(R.decide_verdict(["benign", "benign", "suspicious"], pairs(1, 1, 1))[0], "benign")

    def test_one_heavy_model_cannot_make_a_malicious_verdict_alone(self):
        # three voters: the heavy one is capped at 40% of the firm weight, so its lone "malicious" cannot exceed half
        v, *_ = R.decide_verdict(["malicious", "benign", "benign"], [(10.0, 10.0), (1.0, 1.0), (1.0, 1.0)])
        self.assertNotEqual(v, "malicious")

    def test_every_weight_zero_falls_back_to_a_plain_majority(self):
        self.assertEqual(R.decide_verdict(["malicious", "malicious", "benign"], pairs(0, 0, 0))[0], "malicious")

    def test_firm_and_flag_weights_are_separate(self):
        # good at flagging concerns but poor at firm calls: the malicious votes do not carry a malicious verdict on their own
        v, *_ = R.decide_verdict(["malicious", "malicious", "benign", "benign", "benign"],
                                 [(0.1, 3.0), (0.1, 3.0), (1.0, 0.5), (1.0, 0.5), (1.0, 0.5)])
        self.assertEqual(v, "suspicious")


class Parts(unittest.TestCase):
    def test_confidence_is_clamped_and_forgiving(self):
        self.assertEqual([R.clamp_confidence(x) for x in (150, -5, "72.9", None, "lots", float("inf"))], [100, 0, 72, 50, 50, 50])

    def test_verdict_of_defaults_to_the_cautious_reading(self):
        self.assertEqual([R.verdict_of(d) for d in ({"verdict": " Malicious "}, {}, {"verdict": "maybe"})], ["malicious", "suspicious", "suspicious"])

    def test_weight_pair_accepts_a_float_a_dict_or_junk(self):
        self.assertEqual(R.vote_weight_pair({"a": 2}, {"ai": "a"}), (2.0, 2.0))
        self.assertEqual(R.vote_weight_pair({"a": {"firm": 0.5, "flag": 3}}, {"ai": "a"}), (0.5, 3.0))
        self.assertEqual(R.vote_weight_pair({"a": "heavy"}, {"ai": "a"}), (1.0, 1.0))
        self.assertEqual(R.vote_weight_pair({}, {"ai": "unknown"}), (1.0, 1.0))
        self.assertEqual(R.vote_weight_pair({"a": -4}, {"ai": "a"}), (0.0, 0.0))

    def test_severity_is_weighted_and_ties_go_up(self):
        group = [({"severity": "high"}, 1.0), ({"severity": "MEDIUM"}, 1.0), ({"severity": "nonsense"}, 0.5)]
        self.assertEqual(R.choose_severity(group, "malicious"), "MEDIUM")    # an unreadable severity counts as MEDIUM: 1.0 + 0.5 beats HIGH's 1.0
        self.assertEqual(R.choose_severity([({"severity": "high"}, 1.0), ({"severity": "low"}, 1.0)], "suspicious"), "HIGH")
        self.assertEqual(R.choose_severity(group, "benign"), "LOW")

    def test_ttps_are_merged_and_the_heaviest_models_action_is_used(self):
        group = [({"mitre_ttps": ["T2", "T1"], "recommended_action": "block it"}, 1.0),
                 ({"mitre_ttps": "T9", "recommended_action": "watch it"}, 3.0), ({"mitre_ttps": [5, "T1"]}, 1.0)]
        ttps, action = R.ttps_and_action(group)
        self.assertEqual(ttps, ["T1", "T2"])                  # the string and the number are ignored; duplicates merge
        self.assertEqual(action, "watch it")
        self.assertEqual(R.ttps_and_action([({}, 1.0)]), ([], "Monitor and log"))


if __name__ == "__main__":
    unittest.main()
