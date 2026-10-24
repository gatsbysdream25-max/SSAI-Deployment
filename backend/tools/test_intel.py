#!/usr/bin/env python3
"""Tests for the threat-intel indicator store and feed parsers (2026-09-19).
Run:  swarmsentinel-env/bin/python3 backend/tools/test_intel.py"""
import json
import os
import stat
import sys
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(os.path.dirname(HERE), 'agents')]
import intel as I  # noqa: E402


class Clock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


def tf(**kw):
    row = {'ioc_value': 'evil.example.net', 'ioc_type': 'domain', 'threat_type': 'payload_delivery', 'malware_printable': 'ClearFake',
           'confidence_level': 100}
    row.update(kw)
    return row


def feed(*rows):
    return {str(1000 + i): [r] for i, r in enumerate(rows)}


class ParseThreatFox(unittest.TestCase):
    def test_keeps_public_endpoints_and_domains_only(self):
        rows = feed(
            tf(ioc_type='ip:port', ioc_value='68.64.177.24:80', threat_type='botnet_cc', malware_printable='AdaptixC2'),
            tf(ioc_type='domain', ioc_value='Qo4bT.Www-Tupitea.com.'),
            tf(ioc_type='ip:port', ioc_value='192.168.1.5:80'),                      # private: can never be a remote peer
            tf(ioc_type='ip:port', ioc_value='10.0.0.1:99999'),
            tf(ioc_type='ip:port', ioc_value='8.8.8.8:0'),
            tf(ioc_type='url', ioc_value='http://x.example.com/a'),
            tf(ioc_type='sha256_hash', ioc_value='ab' * 32),
            tf(ioc_type='domain', ioc_value='localhost'),
            tf(ioc_type='domain', ioc_value='has space.com'),
        )
        got = I.parse_threatfox(rows)
        self.assertEqual([(k, v) for k, v, _ in got], [('endpoint', '68.64.177.24:80'), ('domain', 'qo4bt.www-tupitea.com')])
        self.assertEqual(got[0][2]['malware'], 'AdaptixC2')
        self.assertEqual(got[0][2]['threat'], 'botnet_cc')

    def test_confidence_floor(self):
        rows = feed(tf(ioc_value='low.example.net', confidence_level=50), tf(ioc_value='ok.example.net', confidence_level=75),
                    tf(ioc_value='bad.example.net', confidence_level='n/a'), tf(ioc_value='none.example.net', confidence_level=None))
        self.assertEqual([v for _, v, _ in I.parse_threatfox(rows)], ['ok.example.net'])
        self.assertEqual(len(I.parse_threatfox(rows, min_confidence=0)), 3)

    def test_keyed_api_answer_is_read_too(self):
        """abuse.ch's keyed API names the value "ioc" (the retired export called it "ioc_value") and wraps rows in "data"."""
        answer = {'query_status': 'ok', 'data': [{'ioc': '203.0.113.9:8080', 'ioc_type': 'ip:port', 'confidence_level': 90,
                                                   'malware_printable': 'Demo', 'threat_type': 'botnet_cc'},
                                                  {'ioc': 'bad.example.net', 'ioc_type': 'domain', 'confidence_level': 100}]}
        got = I.parse_threatfox(answer)
        self.assertEqual([kind for kind, _, _ in got].count('domain'), 1)
        self.assertIn('bad.example.net', [value for _, value, _ in got])

    def test_malformed_feeds_never_raise(self):
        for junk in (None, [], 'x', 5, {'1': None}, {'1': ['x', None, 3]}, {'1': [{'ioc_type': 'ip:port'}]},
                     {'1': [{'ioc_type': 'ip:port', 'ioc_value': 'noport', 'confidence_level': 90}]}):
            self.assertEqual(I.parse_threatfox(junk), [], junk)


class ParseFeodo(unittest.TestCase):
    def test_lists_public_ips_on_any_port(self):
        got = I.parse_feodo([{'ip_address': '50.16.16.211', 'port': 443, 'malware': 'QakBot'},
                             {'ip_address': '10.0.0.1', 'malware': 'x'}, {'ip_address': 'nope'}, 'x', None, {}])
        self.assertEqual([(k, v, e['malware']) for k, v, e in got], [('ip', '50.16.16.211', 'QakBot')])
        self.assertEqual(I.parse_feodo(None), [])
        self.assertEqual(I.parse_feodo({'a': 1}), [])


class Matching(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.s = I.IntelStore(ttl=1000, max_entries=5, clock=self.clock)
        self.s.add_many([
            ('ip', '50.16.16.211', {'source': 'feodo', 'malware': 'QakBot', 'threat': 'botnet_cc'}),
            ('endpoint', '68.64.177.24:80', {'source': 'threatfox', 'malware': 'Adaptix', 'threat': 'botnet_cc'}),
            ('domain', 'bad.example.net', {'source': 'threatfox', 'malware': 'ClearFake', 'threat': 'payload_delivery'}),
        ])

    def test_ip_listing_matches_on_any_port_endpoint_only_on_its_port(self):
        self.assertEqual(self.s.match_ip('50.16.16.211', 22)['malware'], 'QakBot')
        self.assertEqual(self.s.match_ip('50.16.16.211')['value'], '50.16.16.211')
        self.assertEqual(self.s.match_ip('68.64.177.24', 80)['value'], '68.64.177.24:80')
        self.assertIsNone(self.s.match_ip('68.64.177.24', 443))            # same shared IP, different service: not listed
        self.assertIsNone(self.s.match_ip('68.64.177.24'))

    def test_bad_inputs_do_not_match_or_raise(self):
        for ip in ('192.168.0.5', '127.0.0.1', '', None, 'nope', '999.1.1.1'):
            self.assertIsNone(self.s.match_ip(ip, 80), ip)
        self.assertIsNone(self.s.match_ip('68.64.177.24', 'abc'))

    def test_domain_matches_itself_and_subdomains_not_parents_or_siblings(self):
        for d in ('bad.example.net', 'BAD.example.net.', 'a.b.bad.example.net'):
            self.assertEqual(self.s.match_domain(d)['value'], 'bad.example.net', d)
        for d in ('example.net', 'good.example.net', 'notbad.example.net', 'net', '', None, 'bad.example.net.evil.org'):
            self.assertIsNone(self.s.match_domain(d), d)

    def test_allowlist_wins_even_if_a_feed_lists_it(self):
        self.s.add_many([('domain', 'googleapis.com', {'source': 'threatfox', 'malware': 'x', 'threat': 'payload_delivery'})])
        self.assertIsNone(self.s.match_domain('storage.googleapis.com'))
        os.environ['INTEL_ALLOWLIST'] = 'bad.example.net'
        try:
            self.assertIsNone(self.s.match_domain('bad.example.net'))
        finally:
            del os.environ['INTEL_ALLOWLIST']
        self.assertIsNotNone(self.s.match_domain('bad.example.net'))

    def test_entries_expire_unless_relisted(self):
        self.clock.t += 900
        self.s.add_many([('domain', 'bad.example.net', {'source': 'threatfox', 'malware': 'ClearFake', 'threat': 'payload_delivery'})])
        self.clock.t += 200
        self.assertIsNotNone(self.s.match_domain('bad.example.net'))       # refreshed 200s ago
        self.assertIsNone(self.s.match_ip('50.16.16.211'))                 # last listed 1100s ago > ttl
        self.assertEqual(self.s.prune(), 2)
        self.assertEqual(len(self.s), 1)

    def test_refresh_keeps_first_seen(self):
        first = self.s.match_domain('bad.example.net')['first_seen']
        self.clock.t += 50
        self.s.add_many([('domain', 'bad.example.net', {'source': 'threatfox', 'malware': 'ClearFake', 'threat': 'payload_delivery'})])
        e = self.s.match_domain('bad.example.net')
        self.assertEqual(e['first_seen'], first)
        self.assertEqual(e['seen'], first + 50)

    def test_bound_evicts_the_stalest_listing(self):
        for i in range(6):
            self.s.add_many([('domain', f'd{i}.example.net', {'source': 'threatfox', 'malware': 'x', 'threat': 'botnet_cc'})])
        self.assertEqual(len(self.s), 5)
        self.assertIsNone(self.s.match_ip('50.16.16.211'))                 # oldest went first
        self.assertIsNotNone(self.s.match_domain('d5.example.net'))

    def test_unknown_kinds_and_empty_values_are_ignored(self):
        self.assertEqual(self.s.add_many([('hash', 'abc', {}), ('domain', '', {}), ('ip', None, {})]), 0)

    def test_severity(self):
        self.assertEqual(I.severity_for({'threat': 'botnet_cc'}), 'high')
        self.assertEqual(I.severity_for({'threat': 'payload_delivery'}), 'medium')
        self.assertEqual(I.severity_for(None), 'medium')

    def test_thread_safety(self):
        errors = []

        def work(k):
            try:
                for i in range(300):
                    self.s.add_many([('domain', f'h{(i + k) % 40}.example.net', {'source': 't', 'malware': 'x', 'threat': 'botnet_cc'})])
                    self.s.match_domain(f'x.h{i % 40}.example.net')
                    self.s.stats()
            except Exception as e:  # noqa: BLE001
                errors.append(e)
        ts = [threading.Thread(target=work, args=(k,)) for k in range(8)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertEqual(errors, [])
        self.assertLessEqual(len(self.s), 5)


class Persistence(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(tempfile.mkdtemp(), 'intel.json')
        self.s = I.IntelStore()
        self.s.add_many([('domain', 'bad.example.net', {'source': 'threatfox', 'malware': 'x', 'threat': 'botnet_cc'}),
                         ('ip', '50.16.16.211', {'source': 'feodo', 'malware': 'QakBot', 'threat': 'botnet_cc'})])

    def test_round_trip_is_world_readable_public_data_and_leaves_no_temp_files(self):
        self.s.save(self.path)
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o644)
        self.assertEqual(os.listdir(os.path.dirname(self.path)), ['intel.json'])
        t = I.IntelStore()
        self.assertEqual(t.load(self.path), 2)
        self.assertEqual(t.match_ip('50.16.16.211')['malware'], 'QakBot')
        self.assertIsNotNone(t.updated)

    def test_missing_corrupt_and_hostile_files_give_an_empty_store(self):
        t = I.IntelStore()
        self.assertEqual(t.load(self.path), 0)
        for junk in ('{bad', '[]', '{"entries": 5}', '{"entries": [[1]]}', '{"entries": [["ip", "1.2.3.4", "x"]]}',
                     '{"entries": [["ip", "1.2.3.4", {"seen": "yesterday", "first_seen": 1}]]}', '{"entries": [["evil", "x", {"seen": 1, "first_seen": 1}]]}'):
            with open(self.path, 'w') as f:
                f.write(junk)
            self.assertEqual(I.IntelStore().load(self.path), 0, junk)

    def test_failed_save_leaves_the_previous_cache_intact(self):
        self.s.save(self.path)
        with open(self.path) as f:
            before = f.read()
        orig = json.dump
        json.dump = lambda *a, **k: (_ for _ in ()).throw(OSError('disk full'))
        try:
            with self.assertRaises(OSError):
                self.s.save(self.path)
        finally:
            json.dump = orig
        with open(self.path) as f:
            self.assertEqual(f.read(), before)
        self.assertEqual(os.listdir(os.path.dirname(self.path)), ['intel.json'])

    def test_load_respects_the_bound(self):
        self.s.save(self.path)
        t = I.IntelStore(max_entries=1)
        t.load(self.path)
        self.assertEqual(len(t), 1)


class ParseUrlhausHosts(unittest.TestCase):
    TEXT = ('#####\n# abuse.ch URLhaus Host file\n#\n'
            '127.0.0.1\tBad-Site.example.com\n'
            '127.0.0.1\tevil.example.net.   # trailing comment\n'
            '127.0.0.1\n'                      # no host
            '127.0.0.1\tnot a domain!\n'
            '0.0.0.0 tabs-or-spaces.example.org\n'
            '\n')

    def test_keeps_valid_domains_only(self):
        got = I.parse_urlhaus_hosts(self.TEXT)
        self.assertEqual([v for _k, v, _e in got], ['bad-site.example.com', 'evil.example.net', 'tabs-or-spaces.example.org'])
        self.assertTrue(all(k == 'domain' for k, _v, _e in got))
        self.assertEqual(got[0][2]['source'], 'urlhaus')

    def test_is_medium_not_high(self):
        entry = I.parse_urlhaus_hosts('127.0.0.1\tbad.example.com')[0][2]
        self.assertEqual(I.severity_for(entry), 'medium')

    def test_garbage_gives_nothing(self):
        for junk in (None, 42, {'a': 1}, '', '<html><body>error</body></html>'):
            self.assertEqual(I.parse_urlhaus_hosts(junk), [])

    def test_allowlisted_domains_never_match(self):
        s = I.IntelStore()
        s.add_many(I.parse_urlhaus_hosts('127.0.0.1\tgithub.com\n127.0.0.1\tbad.example.com'))
        self.assertIsNone(s.match_domain('github.com'))
        self.assertIsNotNone(s.match_domain('cdn.bad.example.com'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
