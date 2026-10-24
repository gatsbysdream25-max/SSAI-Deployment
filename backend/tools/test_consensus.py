#!/usr/bin/env python3
"""Tests for AiSwarmAnalyzer._consensus (majority rule, 2026-09-19).
Run:  python3 backend/tools/test_consensus.py"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(os.path.dirname(HERE), 'agents'), os.path.dirname(HERE)]
import ai_swarm_agent as swarm  # noqa: E402

consensus = lambda results, **kw: swarm.AiSwarmAnalyzer._consensus(results, weights=kw.get('weights', {}))   # hermetic: no weights file


def vote(verdict, sev='MEDIUM', conf=80, ai='x', action=None, ttps=None, note=None):
    d = {'verdict': verdict, 'severity': sev, 'confidence': conf, 'ai': ai}
    if action:
        d['recommended_action'] = action
    if ttps:
        d['mitre_ttps'] = ttps
    if note:
        d['specialist_note'] = note
    return d


def verdict_for(*verdicts):
    return consensus([vote(v, ai=f'p{i}') for i, v in enumerate(verdicts)])['consensus_verdict']


class VerdictRule(unittest.TestCase):
    # (votes, expected consensus verdict)
    CASES = [
        (('malicious',), 'malicious'),
        (('benign',), 'benign'),
        (('suspicious',), 'suspicious'),                                  # a lone provider's answer stands
        (('malicious', 'malicious', 'benign'), 'malicious'),
        (('malicious', 'benign', 'benign'), 'benign'),                    # one alarmist cannot flag it
        (('suspicious', 'benign', 'benign'), 'benign'),                   # THE FIX: one hedger no longer wins
        (('suspicious', 'suspicious', 'benign'), 'suspicious'),
        (('malicious', 'suspicious', 'benign'), 'suspicious'),
        (('malicious', 'suspicious', 'suspicious'), 'suspicious'),        # only 1 of 3 is a firm "malicious"
        (('malicious', 'benign'), 'suspicious'),                          # 1-1 split leans toward caution
        (('suspicious', 'benign'), 'suspicious'),
        (('benign', 'benign'), 'benign'),
        (('malicious', 'malicious'), 'malicious'),
        (('malicious', 'malicious', 'benign', 'benign'), 'suspicious'),   # 2-2 tie
        (('malicious', 'benign', 'benign', 'benign'), 'benign'),
        (('malicious', 'malicious', 'malicious', 'benign', 'benign'), 'malicious'),
        (('suspicious',) * 4 + ('benign',), 'suspicious'),
    ]

    def test_table(self):
        for votes, expected in self.CASES:
            self.assertEqual(verdict_for(*votes), expected, votes)

    def test_old_rule_would_have_flagged_a_lone_hedger(self):
        self.assertEqual(verdict_for('suspicious', 'benign', 'benign', 'benign', 'benign'), 'benign')

    def test_unknown_or_garbled_verdicts_abstain_instead_of_voting_suspicious(self):
        # Changed 2026-10-18 (pre-pilot hardening D1): a garbled or missing verdict used to count as "suspicious", so two
        # broken providers could outvote one honest "benign". It is now an abstention (see test_adversarial.py).
        r = consensus([{'verdict': 'MALICIOUS ', 'ai': 'a'}, {'verdict': 'maybe', 'ai': 'b'}, {'ai': 'c'}])
        self.assertEqual(r['votes'], {'malicious': 1, 'suspicious': 0, 'benign': 0})
        self.assertEqual(r['ai_count'], 1)
        self.assertEqual(r['consensus_verdict'], 'malicious')


class Details(unittest.TestCase):
    def test_severity_from_agreeing_providers_only(self):
        r = consensus([vote('malicious', 'HIGH'), vote('malicious', 'HIGH'), vote('malicious', 'CRITICAL'), vote('benign', 'LOW')])
        self.assertEqual(r['consensus_severity'], 'HIGH')                 # most common, not "any provider said CRITICAL"

    def test_severity_tie_goes_to_higher(self):
        r = consensus([vote('malicious', 'MEDIUM'), vote('malicious', 'HIGH')])
        self.assertEqual(r['consensus_severity'], 'HIGH')

    def test_lone_alarmist_severity_ignored_when_panel_says_benign(self):
        r = consensus([vote('benign', 'LOW'), vote('benign', 'LOW'), vote('suspicious', 'CRITICAL')])
        self.assertEqual((r['consensus_verdict'], r['consensus_severity']), ('benign', 'LOW'))

    def test_benign_verdict_is_always_low_severity(self):
        self.assertEqual(consensus([vote('benign', 'HIGH'), vote('benign', 'CRITICAL')])['consensus_severity'], 'LOW')

    def test_unknown_severity_defaults_to_medium(self):
        self.assertEqual(consensus([vote('malicious', 'SEVERE')])['consensus_severity'], 'MEDIUM')

    def test_confidence_averages_only_the_agreeing_side(self):
        r = consensus([vote('malicious', conf=90), vote('malicious', conf=70), vote('benign', conf=10)])
        self.assertEqual(r['confidence'], 80)

    def test_confidence_survives_garbage_values(self):
        r = consensus([vote('malicious', conf='high'), vote('malicious', conf=None), vote('malicious', conf='85'), vote('malicious', conf=999)])
        self.assertTrue(0 <= r['confidence'] <= 100)

    def test_votes_and_agreement_show_how_contested_it_was(self):
        r = consensus([vote('malicious'), vote('malicious'), vote('suspicious'), vote('benign')])
        self.assertEqual(r['votes'], {'malicious': 2, 'suspicious': 1, 'benign': 1})
        self.assertEqual(r['consensus_verdict'], 'suspicious')
        self.assertEqual(r['agreement'], 0.75)
        self.assertEqual(consensus([vote('malicious'), vote('malicious')])['agreement'], 1.0)

    def test_action_and_ttps_come_from_the_agreeing_group(self):
        r = consensus([vote('benign', action='Ignore', ttps=['T9999']), vote('malicious', action='Block the host', ttps=['T1059']),
                       vote('malicious', ttps=['T1105', 'T1059'])])
        self.assertEqual(r['recommended_action'], 'Block the host')
        self.assertEqual(r['mitre_ttps'], ['T1059', 'T1105'])
        self.assertEqual(consensus([vote('malicious')])['recommended_action'], 'Monitor and log')

    def test_output_keeps_every_key_the_dashboard_and_agent_already_use(self):
        r = consensus([vote('malicious', ai='groq', note='n1'), vote('benign', ai='gemini')])
        for key in ('consensus_severity', 'consensus_verdict', 'confidence', 'ai_count', 'ai_sources', 'specialist_notes', 'mitre_ttps', 'recommended_action'):
            self.assertIn(key, r)
        self.assertEqual(r['ai_count'], 2)
        self.assertEqual(r['ai_sources'], ['groq', 'gemini'])
        self.assertEqual(r['specialist_notes'], {'groq': 'n1'})



class Weighted(unittest.TestCase):
    HEDGE_PANEL = [vote('benign', ai='groq'), vote('suspicious', ai='hf'), vote('suspicious', ai='hermes'), vote('suspicious', ai='mistral')]

    def test_reliable_provider_outvotes_three_hedgers(self):
        self.assertEqual(consensus(self.HEDGE_PANEL)['consensus_verdict'], 'suspicious')            # plain majority: 3 of 4 hedge
        w = {'groq': 1.0, 'hf': 0.3, 'hermes': 0.2, 'mistral': 0.1}
        r = consensus(self.HEDGE_PANEL, weights=w)
        self.assertEqual(r['consensus_verdict'], 'benign')
        self.assertEqual(r['votes'], {'malicious': 0, 'suspicious': 3, 'benign': 1})               # raw counts stay visible
        self.assertEqual(r['vote_weights']['groq'], 1.0)

    def test_equal_weights_match_the_plain_majority_for_every_case(self):
        for votes, expected in VerdictRule.CASES:
            panel = [vote(v, ai=f'p{i}') for i, v in enumerate(votes)]
            self.assertEqual(consensus(panel, weights={f'p{i}': 2.5 for i in range(len(votes))})['consensus_verdict'], expected, votes)

    def test_zero_weight_removes_a_vote(self):
        panel = [vote('malicious', ai='bad'), vote('benign', ai='good')]
        self.assertEqual(consensus(panel)['consensus_verdict'], 'suspicious')                       # 1-1 tie leans to caution
        self.assertEqual(consensus(panel, weights={'bad': 0.0, 'good': 1.0})['consensus_verdict'], 'benign')

    def test_all_zero_weights_fall_back_to_plain_majority(self):
        panel = [vote('malicious', ai='a'), vote('malicious', ai='b'), vote('benign', ai='c')]
        self.assertEqual(consensus(panel, weights={'a': 0, 'b': 0, 'c': 0})['consensus_verdict'], 'malicious')

    def test_unlisted_provider_votes_with_weight_one_and_bad_weights_are_ignored(self):
        panel = [vote('malicious', ai='new'), vote('benign', ai='old')]
        self.assertEqual(consensus(panel, weights={'old': 0.1})['consensus_verdict'], 'malicious')   # 'new' defaults to 1.0
        # a non-numeric weight counts as 1.0; a negative weight is clamped to 0 (that vote is removed)
        self.assertEqual(consensus(panel, weights={'new': 'abc', 'old': -5})['consensus_verdict'], 'malicious')
        self.assertEqual(consensus(panel, weights={'new': 'abc', 'old': 'xyz'})['consensus_verdict'], 'suspicious')   # both junk -> 1.0 each: a 1-1 tie

    def test_weighted_confidence_and_severity_follow_the_reliable_provider(self):
        panel = [vote('malicious', sev='HIGH', conf=90, ai='groq', action='Block it'), vote('malicious', sev='CRITICAL', conf=50, ai='hf', action='Panic')]
        r = consensus(panel, weights={'groq': 1.0, 'hf': 0.25})
        self.assertEqual(r['consensus_severity'], 'HIGH')
        self.assertEqual(r['confidence'], 82)                                                       # (90*1 + 50*.25) / 1.25
        self.assertEqual(r['recommended_action'], 'Block it')                                       # heaviest agreeing provider's action
        self.assertEqual(r['agreement'], 1.0)

    def test_no_vote_weights_key_when_everyone_weighs_the_same(self):
        self.assertNotIn('vote_weights', consensus([vote('benign', ai='a'), vote('benign', ai='b')]))


class WeightsFile(unittest.TestCase):
    def setUp(self):
        import json
        import tempfile
        self.json = json
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, 'ai_weights.json')
        self._orig = swarm._WEIGHTS_PATH
        swarm._WEIGHTS_PATH = self.path
        swarm._weights_cache.update(mtime=None, weights={})

    def tearDown(self):
        swarm._WEIGHTS_PATH = self._orig
        swarm._weights_cache.update(mtime=None, weights={})

    def write(self, doc):
        with open(self.path, 'w') as f:
            f.write(doc if isinstance(doc, str) else self.json.dumps(doc))

    def test_missing_file_means_equal_weights(self):
        self.assertEqual(swarm.load_weights(), {})

    def test_provisional_file_is_ignored(self):
        self.write({'provisional': True, 'weights': {'groq': {'weight': 1.0}}})
        self.assertEqual(swarm.load_weights(), {})

    def test_file_without_provisional_flag_is_treated_as_provisional(self):
        self.write({'weights': {'groq': {'weight': 1.0}}})
        self.assertEqual(swarm.load_weights(), {})

    def test_valid_file_is_loaded(self):
        self.write({'provisional': False, 'weights': {'groq': {'weight': 1.0}, 'ollama': {'weight': 0.25}, 'bad': {'weight': -1}}})
        self.assertEqual(swarm.load_weights(), {'groq': 1.0, 'ollama': 0.25})

    def test_corrupt_files_never_raise(self):
        for junk in ('{not json', '[1,2]', '{"provisional": false, "weights": {"a": {"nope": 1}}}', '{"provisional": false, "weights": 7}'):
            self.write(junk)
            swarm._weights_cache.update(mtime=None, weights={})
            self.assertEqual(swarm.load_weights(), {}, junk)

    def test_changes_are_picked_up_without_a_restart(self):
        self.write({'provisional': False, 'weights': {'groq': {'weight': 1.0}}})
        self.assertEqual(swarm.load_weights(), {'groq': 1.0})
        self.write({'provisional': False, 'weights': {'groq': {'weight': 0.5}}})
        os.utime(self.path, (os.path.getmtime(self.path) + 5, os.path.getmtime(self.path) + 5))
        self.assertEqual(swarm.load_weights(), {'groq': 0.5})

    def test_consensus_uses_the_file_by_default(self):
        panel = [vote('benign', ai='groq'), vote('suspicious', ai='hf'), vote('suspicious', ai='hermes')]
        self.assertEqual(swarm.AiSwarmAnalyzer._consensus(panel)['consensus_verdict'], 'suspicious')      # no file yet
        self.write({'provisional': False, 'weights': {'groq': {'weight': 1.0}, 'hf': {'weight': 0.2}, 'hermes': {'weight': 0.2}}})
        self.assertEqual(swarm.AiSwarmAnalyzer._consensus(panel)['consensus_verdict'], 'benign')



class TwoTier(unittest.TestCase):
    W = {'groq': {'firm': 1.0, 'flag': 0.5}, 'hedger': {'firm': 0.0, 'flag': 1.0}}

    def test_firm_weights_decide_malicious_hedger_has_no_say(self):
        r = consensus([vote('malicious', ai='groq'), vote('suspicious', ai='hedger')], weights=self.W)
        self.assertEqual(r['consensus_verdict'], 'malicious')                 # the hedger's firm weight is 0

    def test_flag_weights_decide_suspicious(self):
        r = consensus([vote('benign', ai='groq'), vote('suspicious', ai='hedger')], weights=self.W)
        self.assertEqual(r['consensus_verdict'], 'suspicious')                # hedger's strong flag skill (1.0) beats groq benign (0.5)
        self.assertEqual(consensus([vote('benign', ai='groq'), vote('benign', ai='hedger')], weights=self.W)['consensus_verdict'], 'benign')

    def test_a_float_weight_behaves_exactly_like_equal_firm_and_flag(self):
        panel = [vote('malicious', ai='a'), vote('suspicious', ai='b'), vote('benign', ai='c')]
        as_float = consensus(panel, weights={'a': 0.7, 'b': 0.2, 'c': 0.4})
        as_pair = consensus(panel, weights={'a': {'firm': 0.7, 'flag': 0.7}, 'b': {'firm': 0.2, 'flag': 0.2}, 'c': {'firm': 0.4, 'flag': 0.4}})
        for key in ('consensus_verdict', 'consensus_severity', 'confidence', 'agreement'):
            self.assertEqual(as_float[key], as_pair[key], key)

    def test_output_shows_tiers_only_when_they_differ(self):
        r = consensus([vote('malicious', ai='groq'), vote('suspicious', ai='hedger')], weights=self.W)
        self.assertEqual(r['vote_weights']['groq'], {'firm': 1.0, 'flag': 0.5})
        r2 = consensus([vote('malicious', ai='a'), vote('benign', ai='b')], weights={'a': 0.5, 'b': 0.5})
        self.assertEqual(r2['vote_weights'], {'a': 0.5, 'b': 0.5})

    def test_zero_flag_weight_provider_cannot_flag_but_can_still_be_firm(self):
        w = {'strict_only': {'firm': 1.0, 'flag': 0.0}, 'other': {'firm': 0.0, 'flag': 1.0}}
        self.assertEqual(consensus([vote('malicious', ai='strict_only'), vote('benign', ai='other')], weights=w)['consensus_verdict'], 'malicious')
        self.assertEqual(consensus([vote('suspicious', ai='strict_only'), vote('benign', ai='other')], weights=w)['consensus_verdict'], 'benign')


class TwoTierFile(unittest.TestCase):
    def setUp(self):
        import json
        import tempfile
        self.json = json
        self.path = os.path.join(tempfile.mkdtemp(), 'w.json')

    def load(self, doc):
        with open(self.path, 'w') as f:
            f.write(self.json.dumps(doc))
        return swarm.load_weights(self.path)

    def test_two_tier_entries_and_legacy_entries_together(self):
        w = self.load({'provisional': False, 'weights': {
            'groq': {'weight_firm': 1.0, 'weight_flag': 0.6}, 'ollama': {'weight': 0.25}, 'same': {'weight_firm': 0.4, 'weight_flag': 0.4}}})
        self.assertEqual(w['groq'], {'firm': 1.0, 'flag': 0.6})
        self.assertEqual(w['ollama'], 0.25)
        self.assertEqual(w['same'], 0.4)

    def test_a_bad_entry_is_skipped_but_good_ones_survive(self):
        w = self.load({'provisional': False, 'weights': {'good': {'weight': 1.0}, 'bad': {'weight': 'x'}, 'neg': {'weight': -1},
                                                          'empty': {}, 'wrong_type': 5}})
        self.assertEqual(w, {'good': 1.0})


class OffSwitch(unittest.TestCase):
    def test_switched_off_needs_both_tiers_zero(self):
        self.assertTrue(swarm._switched_off(0))
        self.assertTrue(swarm._switched_off(0.0))
        self.assertTrue(swarm._switched_off({'firm': 0, 'flag': 0}))
        self.assertFalse(swarm._switched_off({'firm': 0, 'flag': 0.2}))
        self.assertFalse(swarm._switched_off(0.1))
        self.assertFalse(swarm._switched_off(None))              # unlisted provider: votes normally
        self.assertFalse(swarm._switched_off('junk'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
