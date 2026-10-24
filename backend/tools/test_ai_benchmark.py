#!/usr/bin/env python3
"""Tests for ai_benchmark.py (stdlib only; run:  python3 backend/tools/test_ai_benchmark.py)."""
import json
import os
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(1, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import ai_benchmark as B  # noqa: E402

# The scoring tests below use fake models that read the indicator out of the prompt. The real cloud gate (see TestCloudGate)
# turns public addresses into tokens, which those fakes could not read, so these tests send the plain copy.
REAL_GATE = B.gated_threat_json
B.gated_threat_json = lambda item, provider_name: B.blind_threat_json(item)


def csvrow(i, url, status='online', tags='32-bit,elf,mips,Mozi'):
    q = lambda x: '"%s"' % x
    return ','.join(q(x) for x in (i, '2026-09-19 03:00:00', url, status, '2026-09-19 03:00:00', 'malware_download', tags, 'https://x/%s/' % i, 'rep'))


def feed(n_ip=30, n_dom=30):
    lines = ['################', '# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter']
    for i in range(n_ip):
        lines.append(csvrow(i, f'http://1.2.3.{i}:5{i:04d}/bin.sh'))
    for i in range(n_dom):
        lines.append(csvrow(100 + i, f'http://evil{i}.example-bad.com/payload{i}.exe', tags='None'))
    lines.append(csvrow(999, 'http://9.9.9.9:1/dead', status='offline'))
    lines.append('garbage,line')
    return '\n'.join(lines)


class Fake:
    def __init__(self, name, fn, sleep=0.0, model='m'):
        self.name, self.fn, self.sleep, self.model = name, fn, sleep, model
        self.calls = 0

    def analyze(self, prompt):
        self.calls += 1
        if self.sleep:
            time.sleep(self.sleep)
        return self.fn(prompt)

    def capabilities(self):
        return {'model': self.model}


def reply(verdict, conf=90):
    return json.dumps({'verdict': verdict, 'confidence': conf, 'severity': 'HIGH'})


def oracle_for(items):
    """Fake AI that reads the indicator out of the prompt and answers from ground truth."""
    truth = {i['url']: i['label'] for i in items}

    def fn(prompt):
        for url, lab in truth.items():
            if url in prompt:
                return reply('malicious' if lab else 'benign')
        return 'not json'
    return fn


PROMPT = lambda p, tj: 'analyze:' + tj  # noqa: E731
CFG = {'rpm': 0, 'local_pause': 0, 'max_errors': 3, 'progress': False}


def consensus_stub(results):  # same rule as production AiSwarmAnalyzer._consensus
    v = [r['verdict'] for r in results]
    n, mal, sus = len(v), v.count('malicious'), v.count('suspicious')
    return {'consensus_verdict': 'malicious' if mal > n / 2 else 'suspicious' if sus > 0 else 'benign'}


class TestDataset(unittest.TestCase):
    def test_parse_skips_offline_comments_garbage_and_dedupes(self):
        rows = B.parse_urlhaus_csv(feed(3, 2) + '\n' + csvrow(0, 'http://1.2.3.0:50000/bin.sh'))
        urls = [r['url'] for r in rows]
        self.assertEqual(len(urls), 5)
        self.assertNotIn('http://9.9.9.9:1/dead', urls)
        self.assertEqual(len(urls), len(set(urls)))
        self.assertEqual(rows[-1]['tags'], '')          # 'None' becomes empty
        self.assertIn('Mozi', rows[0]['tags'])

    def test_quoted_comma_url_survives(self):
        rows = B.parse_urlhaus_csv(csvrow(1, 'http://a.com/x,y'))
        self.assertEqual(rows[0]['url'], 'http://a.com/x,y')

    def test_dataset_size_balance_determinism(self):
        rows = B.parse_urlhaus_csv(feed())
        a, b = B.build_dataset(rows, 16, seed=3), B.build_dataset(rows, 16, seed=3)
        self.assertEqual([i['url'] for i in a], [i['url'] for i in b])
        self.assertEqual(sum(i['label'] for i in a), 16)
        self.assertEqual(len(a), 32)
        self.assertEqual(len({i['url'] for i in a}), 32)
        self.assertNotEqual([i['url'] for i in a], [i['url'] for i in B.build_dataset(rows, 16, seed=4)])
        for label in (0, 1):
            halves = [i['half'] for i in a if i['label'] == label]
            self.assertLessEqual(abs(halves.count(0) - halves.count(1)), 1)

    def test_positives_mix_ip_and_domain_and_negatives_mix_hard_easy(self):
        ds = B.build_dataset(B.parse_urlhaus_csv(feed()), 16, seed=1)
        groups = {i['group'] for i in ds}
        self.assertEqual(groups, {'urlhaus-ip', 'urlhaus-domain', 'benign-hard', 'benign-easy'})

    def test_small_feed_does_not_crash(self):
        ds = B.build_dataset(B.parse_urlhaus_csv(feed(2, 1)), 15, seed=1)
        self.assertEqual(sum(i['label'] for i in ds), 3)

    def test_blind_prompt_leaks_no_label_information(self):
        item = {'id': 'm0', 'url': 'http://1.2.3.4:5000/bin.sh', 'label': 1, 'group': 'urlhaus-ip', 'tags': 'Mozi,mirai', 'half': 0}
        text = B.blind_threat_json(item)
        stripped = text.replace(item['url'], '').lower()
        for word in ('malware', 'malicious', 'urlhaus', 'mozi', 'mirai', 'threat intel', 'botnet', 'benign'):
            self.assertNotIn(word, stripped)
        self.assertEqual(json.loads(text)['source'], item['url'])
        self.assertEqual(set(json.loads(text)), {'title', 'category', 'severity', 'source', 'detail', 'agent'})


class TestCalls(unittest.TestCase):
    def call(self, fn):
        return B.call_provider(Fake('p', fn), PROMPT, '{}')

    def test_valid_and_text_wrapped_json(self):
        r = self.call(lambda p: 'Sure! ' + reply('Malicious', '85') + ' hope that helps')
        self.assertEqual((r['verdict'], r['confidence'], r['error']), ('malicious', 85, None))

    def test_failures_are_captured_not_raised(self):
        self.assertIn('no JSON', self.call(lambda p: 'plain text')['error'])
        self.assertIn('empty', self.call(lambda p: '')['error'])
        self.assertIn('invalid JSON', self.call(lambda p: '{not json}')['error'])
        self.assertIn('unrecognized verdict', self.call(lambda p: reply('maybe'))['error'])

        def boom(p):
            e = RuntimeError('429 Too Many Requests')
            e.response = type('R', (), {'text': 'rate limit exceeded body'})()
            raise e
        r = self.call(boom)
        self.assertIsNone(r['verdict'])
        self.assertIn('429', r['error'])
        self.assertIn('rate limit', r['error'])

    def test_missing_confidence_is_none(self):
        r = self.call(lambda p: json.dumps({'verdict': 'benign'}))
        self.assertEqual((r['verdict'], r['confidence']), ('benign', None))


class TestCloudGate(unittest.TestCase):
    """Audit F-12: a benchmark call to a cloud model goes through sanitize_for_cloud, like production. A local model gets the plain copy."""
    item = {'id': 'x1', 'url': 'http://10.1.2.3:8080/payload.sh?user=bob', 'label': 1}

    def setUp(self):
        import tempfile
        import sanitizer
        self.audit = os.path.join(tempfile.mkdtemp(), 'cloud_audit.jsonl')
        self._orig = sanitizer.audit_path
        sanitizer.audit_path = lambda: self.audit
        B.gated_threat_json = REAL_GATE
        self.addCleanup(self.restore)

    def restore(self):
        import sanitizer
        sanitizer.audit_path = self._orig
        B.gated_threat_json = lambda item, provider_name: B.blind_threat_json(item)

    def test_a_cloud_model_sees_tokens_not_the_address_and_the_audit_log_names_the_benchmark(self):
        seen = []
        cloud = Fake('groq', lambda p: seen.append(p) or reply('malicious'))
        B.run_benchmark([self.item], [], [cloud], PROMPT, CFG)
        self.assertEqual(len(seen), 1)
        self.assertNotIn('10.1.2.3', seen[0])
        self.assertIn('IP_1', seen[0])
        with open(self.audit, encoding='utf-8') as f:
            line = json.loads(f.readline())
        self.assertEqual(line['to'], 'benchmark:groq')
        self.assertNotIn('10.1.2.3', json.dumps(line))

    def test_a_local_model_gets_the_plain_copy(self):
        seen = []
        local = Fake('ollama:gemma', lambda p: seen.append(p) or reply('malicious'))
        B.run_benchmark([self.item], [local], [], PROMPT, CFG)
        self.assertIn('10.1.2.3', seen[0])
        self.assertFalse(os.path.exists(self.audit))

    def test_if_the_gate_cannot_write_its_log_nothing_is_sent(self):
        import sanitizer
        sanitizer.audit_path = lambda: os.path.join(self.audit, 'no', 'such', 'dir', 'x.jsonl')
        open(self.audit, 'w').close()                                   # a file where a directory is needed: the write must fail
        cloud = Fake('groq', lambda p: reply('malicious'))
        results, _ = B.run_benchmark([self.item], [], [cloud], PROMPT, CFG)
        self.assertEqual(cloud.calls, 0)
        self.assertIn('withheld by the cloud gate', results['groq']['x1']['error'])


class TestRunning(unittest.TestCase):
    items = B.build_dataset(B.parse_urlhaus_csv(feed()), 8, seed=1)

    def test_circuit_breaker_aborts_after_consecutive_errors(self):
        bad = Fake('bad', lambda p: 'no json here')
        results, meta = B.run_benchmark(self.items, [], [bad], PROMPT, CFG)
        self.assertEqual(bad.calls, 3)
        self.assertTrue(meta['bad']['aborted'])
        self.assertEqual(len(results['bad']), 3)

    def test_success_resets_error_streak(self):
        seq = iter(['x', 'x', reply('benign'), 'x', 'x', reply('benign')] + ['x'] * 50)
        flaky = Fake('flaky', lambda p: next(seq))
        results, meta = B.run_benchmark(self.items[:6], [], [flaky], PROMPT, CFG)
        self.assertFalse(meta['flaky']['aborted'])
        self.assertEqual(flaky.calls, 6)

    def test_local_models_never_run_at_the_same_time(self):
        active, peak, lock = [0], [0], threading.Lock()

        def slow(p):
            with lock:
                active[0] += 1
                peak[0] = max(peak[0], active[0])
            time.sleep(0.01)
            with lock:
                active[0] -= 1
            return reply('benign')
        B.run_benchmark(self.items[:4], [Fake('l1', slow), Fake('l2', slow)], [], PROMPT, CFG)
        self.assertEqual(peak[0], 1)          # two local models share the CPUs: strictly one call at a time
        order = []

        def rec(name):
            def f(p):
                order.append(name)
                return reply('benign')
            return f
        B.run_benchmark(self.items[:3], [Fake('l1', rec('l1')), Fake('l2', rec('l2'))], [], PROMPT, CFG)
        self.assertEqual(order, ['l1'] * 3 + ['l2'] * 3)

    def test_per_provider_rate_override(self):
        slow, fast = Fake('slow', lambda pr: reply('benign')), Fake('fast', lambda pr: reply('benign'))
        t0 = time.time()
        B.run_benchmark(self.items[:3], [], [slow, fast], PROMPT, dict(CFG, rpm=0, rpm_for={'slow': 600}))
        self.assertGreaterEqual(time.time() - t0, 0.19)        # only "slow" is paced; "fast" has no limit

    def test_unparseable_replies_keep_a_raw_snippet(self):
        r = B.call_provider(Fake('p', lambda pr: 'I cannot help with that request ' * 20), PROMPT, '{}')
        self.assertIsNone(r['verdict'])
        self.assertTrue(r['raw'].startswith('I cannot help'))
        self.assertLessEqual(len(r['raw']), 150)

    def test_rate_limit_spaces_cloud_calls(self):
        p = Fake('c', lambda pr: reply('benign'))
        t0 = time.time()
        B.run_benchmark(self.items[:3], [], [p], PROMPT, dict(CFG, rpm=600))     # 0.1s spacing -> >= 0.2s for 3 calls
        self.assertGreaterEqual(time.time() - t0, 0.19)


class TestScoring(unittest.TestCase):
    def test_confusion_math_and_abstentions(self):
        items = [{'id': str(i), 'label': l, 'half': 0} for i, l in enumerate([1, 1, 1, 1, 0, 0, 0, 0, 1])]
        verdicts = {'0': 'malicious', '1': 'malicious', '2': 'benign', '3': 'suspicious',
                    '4': 'malicious', '5': 'benign', '6': 'benign', '7': 'suspicious', '8': None}
        s = B.confusion(items, verdicts, {'malicious'})
        self.assertEqual((s['tp'], s['fn'], s['fp'], s['tn'], s['scored']), (2, 2, 1, 3, 8))     # item 8 abstained
        self.assertAlmostEqual(s['precision'], 2 / 3)
        self.assertAlmostEqual(s['recall'], 0.5)
        self.assertAlmostEqual(s['fpr'], 0.25)
        self.assertAlmostEqual(s['youden'], 0.5 + 0.75 - 1)
        lenient = B.confusion(items, verdicts, {'malicious', 'suspicious'})
        self.assertEqual((lenient['tp'], lenient['fp']), (3, 2))

    def test_no_predictions_gives_none_not_zero_division(self):
        s = B.confusion([{'id': 'a', 'label': 1}], {'a': None}, {'malicious'})
        self.assertIsNone(s['precision'])
        self.assertIsNone(s['recall'])
        self.assertIsNone(s['youden'])

    def test_wilson_interval(self):
        lo, hi = B.wilson(0, 10)
        self.assertEqual(lo, 0.0)
        self.assertAlmostEqual(hi, 0.278, places=2)
        lo, hi = B.wilson(10, 10)
        self.assertAlmostEqual(lo, 0.722, places=2)
        self.assertEqual(hi, 1.0)
        self.assertEqual(B.wilson(0, 0), (None, None))


class TestMerge(unittest.TestCase):
    items = B.build_dataset(B.parse_urlhaus_csv(feed()), 6, seed=5)

    def report(self, name, fn):
        results, meta = B.run_benchmark(self.items, [], [Fake(name, fn)], PROMPT, CFG)
        return {'items': self.items, 'results': results, 'meta': meta}

    def test_merge_combines_providers_run_separately(self):
        a = self.report('a', oracle_for(self.items))
        b = self.report('b', lambda p: reply('malicious'))
        items, results, meta = B.merge_reports([a, b])
        self.assertEqual(set(results), {'a', 'b'})
        self.assertEqual(items, self.items)
        ev = B.evaluate(items, results, consensus_stub)
        self.assertIn('legacy_rule_lenient', ev['consensus_test_half'])

    def test_merge_refuses_different_indicator_sets(self):
        a = self.report('a', oracle_for(self.items))
        other = B.build_dataset(B.parse_urlhaus_csv(feed()), 6, seed=99)
        b = {'items': other, 'results': {'b': {}}, 'meta': {}}
        with self.assertRaises(ValueError):
            B.merge_reports([a, b])

    def test_legacy_rule_flags_any_suspicious_vote(self):
        votes = [{'verdict': 'benign'}, {'verdict': 'benign'}, {'verdict': 'suspicious'}]
        self.assertEqual(B.legacy_consensus(votes)['consensus_verdict'], 'suspicious')
        self.assertEqual(B.legacy_consensus([{'verdict': 'malicious'}, {'verdict': 'malicious'}, {'verdict': 'benign'}])['consensus_verdict'], 'malicious')


class TestWeights(unittest.TestCase):
    items = B.build_dataset(B.parse_urlhaus_csv(feed(60, 60)), 45, seed=3)        # >= 40 per class

    def run_all(self, providers, items=None):
        items = items or self.items
        results, meta = B.run_benchmark(items, [], providers, PROMPT, CFG)
        return items, results, meta

    def test_good_provider_outweighs_chance_level_ones(self):
        items, results, meta = self.run_all([Fake('good', oracle_for(self.items)), Fake('paranoid', lambda p: reply('malicious')),
                                             Fake('blind', lambda p: reply('benign'))])
        w = B.compute_weights(items, results, meta)
        self.assertEqual(w['good']['weight'], 1.0)
        self.assertEqual(w['paranoid']['weight'], 0.0)
        self.assertEqual(w['blind']['weight'], 0.0)

    def test_small_samples_earn_lower_weights_than_large_ones(self):
        small = self.items[:16]
        _, r_small, m = self.run_all([Fake('good', oracle_for(self.items))], small)
        _, r_big, _ = self.run_all([Fake('good', oracle_for(self.items))])
        self.assertLess(B.compute_weights(small, r_small, m)['good']['youden_lb'], B.compute_weights(self.items, r_big, m)['good']['youden_lb'])

    def test_provisional_until_forty_per_class(self):
        items, results, meta = self.run_all([Fake('good', oracle_for(self.items))])
        self.assertFalse(B.build_weights_doc(items, results, meta, {}, 'r.json')['provisional'])
        small = self.items[:30]
        _, r2, _ = self.run_all([Fake('good', oracle_for(self.items))], small)
        doc = B.build_weights_doc(small, r2, meta, {}, 'r.json')
        self.assertTrue(doc['provisional'])
        self.assertLess(doc['n_per_class'], 40)

    def test_alias_maps_benchmark_names_to_production_names_and_rejects_collisions(self):
        items, results, meta = self.run_all([Fake('ollama:wt-mistral', oracle_for(self.items)), Fake('groq', oracle_for(self.items))])
        doc = B.build_weights_doc(items, results, meta, {'ollama:wt-mistral': 'ollama'}, 'r.json')
        self.assertEqual(set(doc['weights']), {'ollama', 'groq'})
        self.assertEqual(doc['weights']['ollama']['harness_name'], 'ollama:wt-mistral')
        with self.assertRaises(ValueError):
            B.build_weights_doc(items, results, meta, {'ollama:wt-mistral': 'groq'}, 'r.json')

    def test_all_chance_level_falls_back_to_equal_weights(self):
        items, results, meta = self.run_all([Fake('a', lambda p: reply('malicious')), Fake('b', lambda p: reply('benign'))])
        self.assertTrue(all(v['weight'] == 1.0 for v in B.compute_weights(items, results, meta).values()))

    def test_providers_with_too_few_scored_items_are_left_out(self):
        items, results, meta = self.run_all([Fake('good', oracle_for(self.items)), Fake('dead', lambda p: 'no json')])
        self.assertNotIn('dead', B.compute_weights(items, results, meta))


class TestWeightModes(unittest.TestCase):
    items = B.build_dataset(B.parse_urlhaus_csv(feed(60, 60)), 45, seed=3)

    def test_a_hedger_that_flags_correctly_is_zero_strict_but_strong_lenient(self):
        truth = {i['url']: i['label'] for i in self.items}

        def hedge(prompt):
            for url, lab in truth.items():
                if url in prompt:
                    return reply('suspicious' if lab else 'benign')
        hedger = Fake('hedger', hedge)
        results, meta = B.run_benchmark(self.items, [], [hedger], PROMPT, CFG)
        strict = B.compute_weights(self.items, results, meta, mode='strict')['hedger']
        lenient = B.compute_weights(self.items, results, meta, mode='lenient')['hedger']
        mean = B.compute_weights(self.items, results, meta, mode='mean')['hedger']
        self.assertEqual(strict['youden_lb'], 0.0)                     # never says a firm "malicious"
        self.assertGreater(lenient['youden_lb'], 0.7)                  # but separates malware from benign perfectly
        self.assertAlmostEqual(mean['youden_lb'], lenient['youden_lb'] / 2, places=3)
        self.assertEqual(lenient['youden_lb_strict'], 0.0)             # both measures are always recorded

    def test_evaluate_reports_every_weighting_scheme_and_equal_matches_plain_majority(self):
        good, hedger = Fake('good', oracle_for(self.items)), Fake('paranoid', lambda p: reply('malicious'))
        results, meta = B.run_benchmark(self.items, [], [good, hedger], PROMPT, CFG)
        ev = B.evaluate(self.items, results, consensus_stub)
        schemes = ev['consensus_test_half']['weighting_schemes']
        self.assertEqual(set(schemes), {'equal', 'strict', 'lenient', 'mean', 'two-tier'})
        self.assertEqual(schemes['equal']['strict']['accuracy'], ev['consensus_test_half']['production_majority_strict']['accuracy'])
        md = B.render_markdown({'when': 't', 'seed': 1, 'groups': {}, 'commit': 'x'}, self.items, ev, meta)
        self.assertIn('## Weighting schemes', md)


class TestTwoTierAndValidation(unittest.TestCase):
    items = B.build_dataset(B.parse_urlhaus_csv(feed(60, 60)), 45, seed=3)

    def hedger(self):
        truth = {i['url']: i['label'] for i in self.items}

        def f(prompt):
            for url, lab in truth.items():
                if url in prompt:
                    return reply('suspicious' if lab else 'benign')
        return Fake('hedger', f)

    def test_weights_carry_both_tiers(self):
        results, meta = B.run_benchmark(self.items, [], [Fake('good', oracle_for(self.items)), self.hedger()], PROMPT, CFG)
        w = B.compute_weights(self.items, results, meta)
        self.assertEqual(w['good']['weight_firm'], 1.0)
        self.assertEqual(w['hedger']['weight_firm'], 0.0)            # never a firm "malicious"
        self.assertGreater(w['hedger']['weight_flag'], 0.7)          # but flags correctly
        doc = B.build_weights_doc(self.items, results, meta, {}, 'r.json')
        self.assertIn('weight_firm', doc['weights']['hedger'])
        self.assertIn('weight_flag', doc['weights']['hedger'])

    def test_evaluate_includes_the_two_tier_scheme(self):
        results, meta = B.run_benchmark(self.items, [], [Fake('good', oracle_for(self.items)), self.hedger()], PROMPT, CFG)
        ev = B.evaluate(self.items, results, consensus_stub)
        self.assertIn('two-tier', ev['consensus_test_half']['weighting_schemes'])

    def test_out_of_sample_validation_uses_weights_from_another_run(self):
        results, meta = B.run_benchmark(self.items, [], [Fake('good', oracle_for(self.items)), self.hedger()], PROMPT, CFG)
        doc = B.build_weights_doc(self.items, results, meta, {}, 'earlier.json')
        fresh = B.build_dataset(B.parse_urlhaus_csv(feed(60, 60)), 30, seed=8)
        fresh_results, fresh_meta = B.run_benchmark(fresh, [], [Fake('good', oracle_for(fresh)), self.hedger_for(fresh)], PROMPT, CFG)
        ev = B.evaluate(fresh, fresh_results, consensus_stub, doc)
        self.assertEqual(ev['validation']['weights_from'], 'earlier.json')
        self.assertEqual(set(ev['validation']['schemes']), {'equal (plain majority)', 'single weight (strict)', 'two-tier weights'})
        md = B.render_markdown({'when': 't', 'seed': 1, 'groups': {}, 'commit': 'x'}, fresh, ev, fresh_meta)
        self.assertIn('Out-of-sample validation', md)

    def hedger_for(self, items):
        truth = {i['url']: i['label'] for i in items}

        def f(prompt):
            for url, lab in truth.items():
                if url in prompt:
                    return reply('suspicious' if lab else 'benign')
        return Fake('hedger', f)


class TestEvaluate(unittest.TestCase):
    items = B.build_dataset(B.parse_urlhaus_csv(feed()), 12, seed=2)

    def run_all(self, providers):
        results, meta = B.run_benchmark(self.items, [], providers, PROMPT, CFG)
        return results, meta, B.evaluate(self.items, results, consensus_stub)

    def test_perfect_vs_always_malicious_and_weighting(self):
        perfect = Fake('perfect', oracle_for(self.items))
        paranoid = Fake('paranoid', lambda p: reply('malicious'))
        blind = Fake('blind', lambda p: reply('benign'))
        results, meta, ev = self.run_all([perfect, paranoid, blind])
        P = ev['providers']
        self.assertAlmostEqual(P['perfect']['strict']['accuracy'], 1.0)
        self.assertAlmostEqual(P['perfect']['strict']['youden'], 1.0)
        self.assertAlmostEqual(P['paranoid']['strict']['fpr'], 1.0)
        self.assertAlmostEqual(P['blind']['strict']['recall'], 0.0)
        c = ev['consensus_test_half']
        w = c['weights_youden_from_calibration_half']
        self.assertEqual((w['perfect'], w['paranoid'], w['blind']), (1.0, 0.0, 0.0))       # chance-level providers get no vote
        self.assertAlmostEqual(c['weighted_vote']['accuracy'], 1.0)
        self.assertEqual(c['best_single_strict'][0], 'perfect')
        self.assertTrue(all('perfect' not in h['wrong'] for h in ev['hard_items']))

    def test_majority_can_be_beaten_by_weighting(self):
        perfect = Fake('perfect', oracle_for(self.items))
        results, meta, ev = self.run_all([perfect, Fake('x', lambda p: reply('malicious')), Fake('y', lambda p: reply('malicious'))])
        c = ev['consensus_test_half']
        self.assertLess(c['production_majority_strict']['accuracy'], c['weighted_vote']['accuracy'])   # 2 wrong voters outvote the good one

    def test_single_provider_has_no_consensus_section(self):
        _, _, ev = self.run_all([Fake('only', oracle_for(self.items))])
        self.assertNotIn('consensus_test_half', ev)

    def test_report_renders_with_dead_and_aborted_providers(self):
        good = Fake('good', oracle_for(self.items))
        dead = Fake('dead', lambda p: (_ for _ in ()).throw(RuntimeError('401 invalid key')))
        results, meta, ev = self.run_all([good, dead])
        md = B.render_markdown({'when': 't', 'seed': 1, 'groups': {}, 'commit': 'abc'}, self.items, ev, meta)
        for heading in ('## Strict', '## Lenient', '## Reliability', '## Caveats', 'ABORTED after repeated errors'):
            self.assertIn(heading, md)
        self.assertIn('n/a', md)                      # the dead provider has no scores, and that must not crash


if __name__ == '__main__':
    unittest.main(verbosity=2)
