#!/usr/bin/env python3
"""Phase 6 of the consensus plan: adding voices safely. Request and spend caps, per-deployment allow-list, the optional key vault,
and the ablation test that decides whether a voice earns a vote.
Run:  swarmsentinel-env/bin/python3 backend/tools/test_new_voices.py"""
import json
import os
import random
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
sys.path[:0] = [os.path.join(BACKEND, 'agents'), BACKEND, HERE]
import ablation  # noqa: E402
import ai_swarm_agent as swarm  # noqa: E402
import keyvault  # noqa: E402
import model_config  # noqa: E402
import state_store  # noqa: E402
import usage_caps  # noqa: E402

ENTRY = {'daily_request_cap': 3, 'monthly_spend_cap_usd': 0.01, 'price_in_per_mtok': 1000.0, 'price_out_per_mtok': 2000.0}


def usage(day='2026-10-21'):
    store = state_store.StateStore(os.path.join(tempfile.mkdtemp(), 'state.db'))
    now = [datetime.fromisoformat(day + 'T12:00:00+00:00')]
    return usage_caps.Usage(store, clock=lambda: now[0]), now


class Caps(unittest.TestCase):
    def test_the_daily_request_cap_stops_a_voice_and_resets_the_next_day(self):
        u, now = usage()
        for _ in range(3):
            self.assertEqual(u.check('kimi', ENTRY), (True, ''))
            u.count_request('kimi')
        ok, why = u.check('kimi', ENTRY)
        self.assertFalse(ok)
        self.assertIn('daily request cap of 3', why)
        now[0] = datetime.fromisoformat('2026-10-22T00:01:00+00:00')
        self.assertTrue(u.check('kimi', ENTRY)[0])

    def test_the_monthly_spend_cap_uses_the_estimated_price(self):
        u, now = usage()
        u.add_cost('kimi', ENTRY, prompt_chars=4000, answer_chars=0)       # 1000 tokens in at $1000/Mtok = $1
        ok, why = u.check('kimi', ENTRY)
        self.assertFalse(ok)
        self.assertIn('monthly spend cap', why)
        now[0] = datetime.fromisoformat('2026-11-01T00:01:00+00:00')
        self.assertTrue(u.check('kimi', ENTRY)[0])

    def test_a_voice_with_no_caps_is_never_stopped_and_voices_count_separately(self):
        u, _ = usage()
        for _ in range(50):
            u.count_request('groq')
        self.assertTrue(u.check('groq', {})[0])
        u.count_request('kimi')
        self.assertEqual(u.snapshot('kimi', ENTRY)['requests_today'], 1)
        self.assertEqual(u.snapshot('groq', {})['requests_today'], 50)

    def test_a_voice_over_its_cap_sits_out_and_the_health_table_says_why(self):
        import threading

        class Voice:
            name, model = 'kimi', 'm'
            calls = 0

            def analyze(self, prompt):
                Voice.calls += 1
                return json.dumps({'verdict': 'malicious', 'severity': 'HIGH', 'confidence': 80})

        a = swarm.AiSwarmAnalyzer.__new__(swarm.AiSwarmAnalyzer)
        a._providers, a._health, a._health_lock = [], {}, threading.Lock()
        u, _ = usage()
        for _ in range(3):
            u.count_request('kimi')
        with mock.patch.object(usage_caps, '_default', u), mock.patch.object(swarm.model_config, 'get', return_value=ENTRY):
            self.assertIsNone(a._safe_call(Voice(), '{}'))
        self.assertEqual(Voice.calls, 0)                                    # no request left the building
        self.assertEqual(a._health['kimi']['last_error_kind'], 'cap_reached')


class Deployments(unittest.TestCase):
    def test_a_voice_is_only_allowed_where_its_list_says(self):
        entry = {'allowed_deployments': ['home', 'lab', 'college']}
        for where, want in (('home', True), ('college', True), ('bank', False), ('BANK', False)):
            with mock.patch.dict(os.environ, {'SSAI_DEPLOYMENT': where}):
                self.assertEqual(usage_caps.deployment_allowed(entry), want, where)
        self.assertTrue(usage_caps.deployment_allowed({}))                  # no list, no restriction
        with mock.patch.dict(os.environ, {'SSAI_DEPLOYMENT': 'bank'}):
            self.assertTrue(usage_caps.deployment_allowed({'allowed_deployments': []}))

    def test_kimi_does_not_vote_in_a_bank_deployment_even_when_switched_on(self):
        class Kimi:
            name = 'kimi'
        with mock.patch.dict(os.environ, {'SSAI_DEPLOYMENT': 'bank'}):
            self.assertFalse(swarm.panel_allowed(Kimi(), overrides={'kimi': True}, weights={}))

    def test_the_planned_voices_ship_switched_off_with_caps(self):
        for pid in ('openai', 'grok', 'kimi'):
            e = model_config.get(pid)
            self.assertIsNotNone(e, pid)
            self.assertFalse(e['default_on'], pid)
            self.assertFalse(e['verified'], pid)
            self.assertTrue(e.get('monthly_spend_cap_usd') and e.get('daily_request_cap'), pid)
        self.assertNotIn('bank', model_config.get('kimi')['allowed_deployments'])


class Settings(unittest.TestCase):
    def test_bad_cap_values_are_ignored_not_trusted(self):
        raw = {'kind': 'openai', 'model': 'm', 'key_env': 'K', 'daily_request_cap': 'many', 'monthly_spend_cap_usd': -5,
               'price_in_per_mtok': True, 'allowed_deployments': 'bank'}
        e = model_config._clean('x', raw)
        for k in ('daily_request_cap', 'monthly_spend_cap_usd', 'price_in_per_mtok', 'allowed_deployments'):
            self.assertNotIn(k, e)


class Vault(unittest.TestCase):
    def test_the_environment_wins_and_a_missing_vault_is_just_no_key(self):
        entry = {'key_env': 'NEW_VOICE_KEY', 'key_ref': 'ssai/new'}
        with mock.patch.dict(os.environ, {'NEW_VOICE_KEY': 'from-env'}), mock.patch.object(keyvault, 'get', return_value='from-vault') as vault:
            self.assertEqual(model_config.key_of(entry), 'from-env')
            vault.assert_not_called()
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(keyvault, 'get', return_value='from-vault'):
            self.assertEqual(model_config.key_of(entry), 'from-vault')
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(keyvault, '_keyring', return_value=None):
            self.assertEqual(keyvault.get('ssai/new'), '')
            self.assertFalse(keyvault.put('ssai/new', 'x'))

    def test_a_key_is_only_ever_shown_as_its_last_four_characters(self):
        self.assertEqual(keyvault.last4('sk-abcdefgh1234'), '...1234')
        self.assertEqual(keyvault.last4(''), '')
        self.assertNotIn('abcdefgh', keyvault.last4('sk-abcdefgh1234'))


def run_data(candidate_fn, n=60, seed=1):
    """A synthetic benchmark run: two panel models that share 10 blind spots, a third that is sound, and a candidate."""
    rng = random.Random(seed)
    items = [{'id': f'c{i}', 'label': 1 if i < n // 2 else 0, 'half': i % 2} for i in range(n)]
    ids = [i['id'] for i in items]
    hard = set(rng.sample(ids, 10))               # cases every panel model gets wrong (shared blind spots): where a new voice can help
    wrong_a, wrong_b = hard | set(rng.sample(ids, 4)), hard | set(rng.sample(ids, 4))

    def answer(item, wrong):
        truth = item['label'] == 1
        say = (not truth) if item['id'] in wrong else truth
        return {'verdict': 'malicious' if say else 'benign'}
    results = {'a': {i['id']: answer(i, wrong_a) for i in items}, 'b': {i['id']: answer(i, wrong_b) for i in items},
               'c': {i['id']: answer(i, set(rng.sample(ids, 4))) for i in items},
               'cand': {i['id']: candidate_fn(i, rng) for i in items}}
    return items, results


class Ablation(unittest.TestCase):
    def test_a_voice_that_is_right_where_the_panel_is_wrong_earns_a_vote(self):
        items, results = run_data(lambda i, rng: {'verdict': 'malicious' if i['label'] else 'benign'})
        r = ablation.ablate(items, results, 'cand', splits=30)
        self.assertTrue(r['earns_a_vote'], r)
        self.assertGreater(r['catches_panel_misses'], 0)
        self.assertIn('EARNS A VOTE', ablation.to_markdown(r))

    def test_a_voice_that_is_usually_wrong_does_not(self):
        items, results = run_data(lambda i, rng: {'verdict': 'benign' if i['label'] else 'malicious'})
        r = ablation.ablate(items, results, 'cand', splits=30)
        self.assertFalse(r['earns_a_vote'])
        self.assertFalse(r['checks']['gain_big_enough'])

    def test_a_voice_that_often_times_out_does_not_even_when_it_is_right_when_it_answers(self):
        items, results = run_data(lambda i, rng: {'verdict': ('malicious' if i['label'] else 'benign') if rng.random() < 0.6 else None})
        r = ablation.ablate(items, results, 'cand', splits=30)
        self.assertFalse(r['checks']['answered_enough'])
        self.assertFalse(r['earns_a_vote'])

    def test_a_voice_that_adds_nothing_new_does_not_earn_a_vote(self):
        items, results = run_data(lambda i, rng: {'verdict': 'benign'}, seed=3)
        results['cand'] = {k: dict(v) for k, v in results['a'].items()}                 # a copy of model a: same maker, same mistakes
        r = ablation.ablate(items, results, 'cand', splits=30)
        self.assertFalse(r['earns_a_vote'])

    def test_the_report_cannot_be_written_into_production_settings(self):
        for folder in ('instance', 'config'):
            with self.assertRaises(SystemExit):
                ablation._check_output_path(os.path.join(BACKEND, folder, 'report.md'))
        ablation._check_output_path(os.path.join(tempfile.mkdtemp(), 'report.md'))     # anywhere else is fine

    def test_it_needs_a_panel_to_compare_against(self):
        with self.assertRaises(ValueError):
            ablation.ablate([{'id': 'x', 'label': 1}], {'only': {}, 'cand': {}}, 'cand')


if __name__ == '__main__':
    unittest.main()
