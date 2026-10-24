#!/usr/bin/env python3
"""Tests for the recall layer (2026-09-19).
Run:  swarmsentinel-env/bin/python3 backend/tools/test_recall.py"""
import json
import os
import sys
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(os.path.dirname(HERE), 'agents')]
import recall as R  # noqa: E402


def cons(verdict='malicious', n=2, **extra):
    return dict({'consensus_verdict': verdict, 'consensus_severity': 'HIGH', 'ai_count': n}, **extra)


class Clock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


class Normalize(unittest.TestCase):
    def test_equivalent_spellings_share_a_key(self):
        same = ['http://Evil.example.com/a.sh', 'HTTP://evil.example.com:80/a.sh#frag', ' http://evil.example.com/a.sh ',
                'http://user:pw@evil.example.com/a.sh']
        keys = {R.recall_key(u, 'malicious-url') for u in same}
        self.assertEqual(len(keys), 1, keys)
        self.assertNotIn('pw', keys.pop())                                   # credentials never enter the key

    def test_different_indicators_do_not_collide(self):
        a = R.recall_key('http://evil.example.com/a.sh')
        self.assertNotEqual(a, R.recall_key('http://evil.example.com/b.sh'))
        self.assertNotEqual(a, R.recall_key('https://evil.example.com/a.sh'))
        self.assertNotEqual(a, R.recall_key('http://evil.example.com:8080/a.sh'))
        self.assertNotEqual(R.recall_key('http://a.com/x?q=1'), R.recall_key('http://a.com/x?q=2'))

    def test_root_url_forms(self):
        self.assertEqual(R.recall_key('http://a.example.com'), R.recall_key('http://a.example.com/'))

    def test_public_indicators_ignore_the_category(self):
        for ind in ('8.8.4.4', 'evil.example.com', 'https://evil.example.com/x'):
            self.assertEqual(R.recall_key(ind, 'firewall-block'), R.recall_key(ind, 'malicious-url'), ind)

    def test_internal_and_endpoint_indicators_are_scoped_by_category(self):
        for ind in ('192.168.0.5', '10.0.0.7:8080', 'nas.local', 'http://192.168.0.5/admin', '8.8.4.4:22'):
            self.assertNotEqual(R.recall_key(ind, 'suspicious-port'), R.recall_key(ind, 'dns-anomaly'), ind)
            self.assertTrue(R.recall_key(ind, 'Suspicious-Port').startswith('suspicious-port|'), ind)

    def test_masked_empty_and_oversized_have_no_key(self):
        for bad in ('192.168.xxx.xxx', '192.168.xxx.xxx:6667', 'pihole://192.168.xxx.xxx:8081', '10.xxx.xxx.xxx', '', '   ', None,
                    42, 'a' * 5000):
            self.assertIsNone(R.recall_key(bad, 'x'), repr(bad)[:40])

    def test_an_ordinary_domain_containing_xxx_is_not_treated_as_masked(self):
        self.assertIsNotNone(R.recall_key('xxx.example.com'))

    def test_ipv6_and_ip_canonicalisation(self):
        self.assertEqual(R.recall_key('2606:4700:4700:0000:0000:0000:0000:1111'), R.recall_key('2606:4700:4700::1111'))
        self.assertEqual(R.normalize_indicator('8.8.8.8')['kind'], 'ip')

    def test_garbage_url_does_not_raise(self):
        for bad in ('http://', 'http://[::1', 'http://a.com:99999/x', '://x'):
            R.recall_key(bad, 'c')

    def test_candidate_urls_cover_stored_spellings(self):
        c = R.candidate_urls('HTTP://A.example.com:80')
        self.assertIn('http://a.example.com/', c)
        self.assertIn('http://a.example.com', c)
        self.assertEqual(R.candidate_urls('192.168.xxx.xxx'), [])


class Reusable(unittest.TestCase):
    def test_only_complete_answers_are_reusable(self):
        self.assertTrue(R.reusable_consensus(cons()))
        for bad in (None, {}, [], 'x', cons('unknown'), cons(n=0), cons(error='timeout'), {'consensus_verdict': 'malicious'},
                    cons(n='many')):
            self.assertFalse(R.reusable_consensus(bad), bad)

    def test_ttls_favour_keeping_malicious_longer(self):
        self.assertGreater(R.ttl_seconds('malicious'), R.ttl_seconds('benign'))
        self.assertGreaterEqual(R.ttl_seconds('benign'), R.ttl_seconds('suspicious'))
        self.assertEqual(R.ttl_seconds('nonsense'), 0)

    def test_ttl_env_override_and_bad_value(self):
        os.environ['RECALL_TTL_BENIGN'] = '60'
        try:
            self.assertEqual(R.ttl_seconds('benign'), 60)
            os.environ['RECALL_TTL_BENIGN'] = 'soon'
            self.assertEqual(R.ttl_seconds('benign'), 12 * 3600)
        finally:
            del os.environ['RECALL_TTL_BENIGN']


class Cache(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.c = R.RecallCache(max_entries=3, clock=self.clock)

    def test_hit_is_labelled_and_does_not_alter_the_stored_answer(self):
        original = cons()
        self.c.put('http://evil.example.com/a', 'malicious-url', original, threat_id=7)
        self.clock.t += 90
        hit = self.c.get('HTTP://evil.example.com:80/a', 'anything')
        self.assertEqual((hit['recalled_from'], hit['recalled_age_s'], hit['consensus_verdict']), (7, 90, 'malicious'))
        self.assertNotIn('recalled_from', original)                      # the remembered answer itself is untouched
        self.assertNotIn('recalled_from', self.c._data['http://evil.example.com/a']['consensus'])
        self.assertEqual(self.c.stats()['hits'], 1)

    def test_expiry_depends_on_the_verdict(self):
        self.c.put('http://evil.example.com/a', 'u', cons('malicious'), 1)
        self.c.put('http://ok.example.com/b', 'u', cons('benign'), 2)
        self.clock.t += R.ttl_seconds('benign') + 1
        self.assertIsNone(self.c.get('http://ok.example.com/b', 'u'))
        self.assertIsNotNone(self.c.get('http://evil.example.com/a', 'u'))
        self.assertEqual(self.c.stats()['expired'], 1)
        self.assertEqual(len(self.c), 1)

    def test_lru_bound(self):
        for i in range(5):
            self.c.put(f'http://h{i}.example.com/', 'u', cons(), i)
        self.assertEqual(len(self.c), 3)
        self.assertIsNone(self.c.get('http://h0.example.com/', 'u'))
        self.assertIsNotNone(self.c.get('http://h4.example.com/', 'u'))

    def test_recent_use_protects_an_entry_from_eviction(self):
        for i in range(3):
            self.c.put(f'http://h{i}.example.com/', 'u', cons(), i)
        self.c.get('http://h0.example.com/', 'u')
        self.c.put('http://h9.example.com/', 'u', cons(), 9)
        self.assertIsNotNone(self.c.get('http://h0.example.com/', 'u'))
        self.assertIsNone(self.c.get('http://h1.example.com/', 'u'))

    def test_scoped_indicators_do_not_leak_across_categories(self):
        self.c.put('10.0.0.5:22', 'suspicious-port', cons('suspicious'), 1)
        self.assertIsNotNone(self.c.get('10.0.0.5:22', 'suspicious-port'))
        self.assertIsNone(self.c.get('10.0.0.5:22', 'dns-anomaly'))

    def test_masked_and_unusable_answers_are_refused(self):
        self.assertFalse(self.c.put('192.168.xxx.xxx:6667', 'suspicious-port', cons(), 1))
        self.assertFalse(self.c.put('http://a.example.com/', 'u', cons(error='boom'), 1))
        self.assertFalse(self.c.put('http://a.example.com/', 'u', None, 1))
        self.assertIsNone(self.c.get('192.168.xxx.xxx:6667', 'suspicious-port'))
        self.assertEqual(len(self.c), 0)

    def test_a_threat_never_recalls_its_own_verdict(self):
        self.c.put('http://a.example.com/', 'u', cons(), threat_id=5)
        self.assertIsNone(self.c.get('http://a.example.com/', 'u', exclude_id=5))
        self.assertIsNotNone(self.c.get('http://a.example.com/', 'u', exclude_id=6))

    def test_older_answer_does_not_replace_a_newer_one(self):
        self.c.put('http://a.example.com/', 'u', cons('malicious'), 2, at=self.clock.t)
        self.c.put('http://a.example.com/', 'u', cons('benign'), 1, at=self.clock.t - 500)
        self.assertEqual(self.c.get('http://a.example.com/', 'u')['consensus_verdict'], 'malicious')

    def test_seed_from_api_rows(self):
        now = '2026-09-19T20:00:00'
        rows = [
            {'id': 1, 'url': 'http://evil.example.com/a', 'type': 'malicious-url', 'timestamp': now,
             'ai_verdict': json.dumps({'analysis': 'x', 'consensus': cons()})},
            {'id': 2, 'url': '1.2.3.4', 'type': 'firewall-block', 'timestamp': now, 'ai_verdict': {'consensus': cons('benign')}},
            {'id': 3, 'url': 'http://noverdict.example.com/', 'type': 'u', 'timestamp': now, 'ai_verdict': None},
            {'id': 4, 'url': 'http://bad.example.com/', 'type': 'u', 'timestamp': now, 'ai_verdict': '{not json'},
            {'id': 5, 'url': 'http://notime.example.com/', 'type': 'u', 'timestamp': None, 'ai_verdict': {'consensus': cons()}},
            {'id': 6, 'url': '192.168.xxx.xxx', 'type': 'u', 'timestamp': now, 'ai_verdict': {'consensus': cons()}},
            {'id': 7, 'url': 'http://tier1only.example.com/', 'type': 'u', 'timestamp': now, 'ai_verdict': {'analysis': 'text'}},
            'junk', None,
        ]
        c = R.RecallCache(clock=lambda: R._epoch(now) + 60)
        self.assertEqual(c.seed(rows), 2)
        self.assertEqual(c.get('http://evil.example.com/a')['recalled_from'], 1)
        self.assertEqual(c.get('1.2.3.4')['consensus_verdict'], 'benign')
        self.assertEqual(c.seed(None), 0)

    def test_thread_safety_under_contention(self):
        cache = R.RecallCache(max_entries=50)
        errors = []

        def work(k):
            try:
                for i in range(400):
                    cache.put(f'http://h{(i + k) % 80}.example.com/', 'u', cons(), i)
                    cache.get(f'http://h{i % 80}.example.com/', 'u')
            except Exception as e:  # noqa: BLE001
                errors.append(e)
        ts = [threading.Thread(target=work, args=(k,)) for k in range(8)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        self.assertEqual(errors, [])
        self.assertLessEqual(len(cache), 50)

    def test_epoch_parsing(self):
        self.assertEqual(R._epoch('2026-09-19T00:00:00'), R._epoch('2026-09-19T00:00:00Z'))
        self.assertIsNone(R._epoch('nonsense'))
        self.assertIsNone(R._epoch(None))


if __name__ == '__main__':
    unittest.main(verbosity=2)
