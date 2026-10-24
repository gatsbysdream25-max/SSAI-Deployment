#!/usr/bin/env python3
"""Behaviour of the intel feed agent and the two matchers (connections, DNS) (2026-09-19).
Run:  swarmsentinel-env/bin/python3 backend/tools/test_intel_agents.py"""
import logging
import os
import sys
import tempfile
import time
import types
import unittest

os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(tempfile.mkdtemp(), 'unused.db'))
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(os.path.dirname(HERE), 'agents'), os.path.dirname(HERE)]
import agent_runner as AR  # noqa: E402
import intel as I  # noqa: E402

C2 = {'source': 'feodo', 'malware': 'QakBot', 'threat': 'botnet_cc'}
DELIVERY = {'source': 'threatfox', 'malware': 'ClearFake', 'threat': 'payload_delivery'}


def build(cls):
    a = cls.__new__(cls)
    a.log = logging.getLogger('test-intel')
    a.submitted = []
    a._submit = lambda **kw: a.submitted.append(kw)
    return a


class Resp:
    def __init__(self, body, status=200):
        self._b, self.status_code = body, status

    def json(self):
        if isinstance(self._b, Exception):
            raise self._b
        return self._b

    @property
    def text(self):
        return self._b if isinstance(self._b, str) else ''


class StoreCase(unittest.TestCase):
    def setUp(self):
        self._orig = I.STORE
        I.STORE = AR.intel.STORE = I.IntelStore()

    def tearDown(self):
        I.STORE = AR.intel.STORE = self._orig


class Connections(StoreCase):
    # Real `ss -tnp state established` shape: Recv-Q Send-Q Local:Port Peer:Port [Process]
    SS = ('Recv-Q Send-Q Local Address:Port    Peer Address:Port Process\n'
          '0 0 192.168.1.10:51234 50.16.16.211:443 users:(("python3",pid=42,fd=5))\n'
          '0 0 192.168.1.10:51235 68.64.177.24:80 users:(("curl",pid=43,fd=3))\n'
          '0 0 192.168.1.10:51236 68.64.177.24:443 users:(("curl",pid=44,fd=3))\n'
          '0 0 192.168.1.10:51237 192.168.1.30:22\n'
          '0 0 192.168.1.10:51238 9.9.9.9:4444\n')

    def scan(self, agent):
        orig = AR.subprocess.run
        AR.subprocess.run = lambda *a, **k: types.SimpleNamespace(stdout=self.SS, returncode=0)
        try:
            agent.scan()
        finally:
            AR.subprocess.run = orig

    def test_listed_peers_are_reported_with_process_and_severity(self):
        I.STORE.add_many([('ip', '50.16.16.211', C2), ('endpoint', '68.64.177.24:80', DELIVERY)])
        a = build(AR.NetworkConnAgent)
        a.setup()
        self.scan(a)
        got = {s['url']: s for s in a.submitted if s['threat_type'] == 'intel-match'}
        self.assertEqual(set(got), {'50.16.16.211', '68.64.177.24:80'})           # :443 on the same IP is a different service
        self.assertEqual(got['50.16.16.211']['severity'], 'high')
        self.assertEqual(got['68.64.177.24:80']['severity'], 'medium')
        self.assertIn('QakBot', got['50.16.16.211']['description'])
        self.assertIn('python3', got['50.16.16.211']['description'])
        self.assertIn('curl', got['68.64.177.24:80']['description'])
        self.assertEqual({s['threat_type'] for s in a.submitted}, {'intel-match', 'c2-beacon'})   # port-4444 rule still works

    def test_cooldown_stops_repeat_reports_until_it_lapses(self):
        I.STORE.add_many([('ip', '50.16.16.211', C2)])
        a = build(AR.NetworkConnAgent)
        a.setup()
        self.scan(a)
        self.scan(a)
        self.assertEqual(sum(s['threat_type'] == 'intel-match' for s in a.submitted), 1)
        a._intel_seen['50.16.16.211'] -= a.INTEL_COOLDOWN + 1
        self.scan(a)
        self.assertEqual(sum(s['threat_type'] == 'intel-match' for s in a.submitted), 2)

    def test_empty_store_costs_nothing_and_reports_nothing(self):
        a = build(AR.NetworkConnAgent)
        a.setup()
        self.scan(a)
        self.assertEqual([s for s in a.submitted if s['threat_type'] == 'intel-match'], [])


class Dns(StoreCase):
    def agent(self, queries, total=None):
        a = build(AR.PiHoleAgent)
        a._dns_cursor = None
        a._dns_seen = AR._BoundedDict(100)
        a.interval = 120
        a.paths = []

        def fake_get(path):
            a.paths.append(path)
            return {'queries': queries, 'recordsFiltered': total if total is not None else len(queries)}
        a._get = fake_get
        return a

    def q(self, domain, client='192.168.0.186', status='FORWARDED'):
        return {'domain': domain, 'client': {'ip': client}, 'status': status}

    def test_lookup_of_listed_domain_and_its_subdomains_is_reported(self):
        I.STORE.add_many([('domain', 'bad.example.net', DELIVERY), ('domain', 'c2.example.org', C2)])
        a = self.agent([self.q('cdn.bad.example.net.'), self.q('google.com'), self.q('C2.example.org', client='192.168.0.7')])
        a._check_dns_intel()
        self.assertEqual([(s['url'], s['severity']) for s in a.submitted],
                         [('cdn.bad.example.net', 'medium'), ('c2.example.org', 'high')])
        self.assertIn('192.168.0.186', a.submitted[0]['description'])            # masked later by submit_threat
        self.assertTrue(all(s['threat_type'] == 'intel-match' for s in a.submitted))

    def test_pihole_blocked_lookup_is_low_severity_and_says_so(self):
        I.STORE.add_many([('domain', 'c2.example.org', C2)])
        a = self.agent([self.q('c2.example.org', status='GRAVITY')])
        a._check_dns_intel()
        self.assertEqual(a.submitted[0]['severity'], 'low')
        self.assertIn('blocked', a.submitted[0]['description'])

    def test_repeat_lookups_are_reported_once_per_device_and_domain(self):
        I.STORE.add_many([('domain', 'bad.example.net', DELIVERY)])
        a = self.agent([self.q('bad.example.net')] * 5 + [self.q('bad.example.net', client='192.168.0.99')])
        a._check_dns_intel()
        self.assertEqual(len(a.submitted), 2)                                     # two devices, one report each

    def test_window_advances_and_empty_store_does_no_work(self):
        a = self.agent([])
        a._check_dns_intel()
        self.assertEqual(a.paths, [])                                              # nothing listed: no Pi-hole query at all
        I.STORE.add_many([('domain', 'bad.example.net', DELIVERY)])
        a._check_dns_intel()
        first = a._dns_cursor
        self.assertTrue(abs(first - time.time()) < 5)
        self.assertIn('from=', a.paths[0])
        a._check_dns_intel()
        self.assertGreaterEqual(a._dns_cursor, first)

    def test_junk_rows_do_not_crash(self):
        I.STORE.add_many([('domain', 'bad.example.net', DELIVERY)])
        a = self.agent([{}, {'domain': None}, {'domain': 'bad.example.net', 'client': None}, {'domain': '', 'client': {}}])
        a._check_dns_intel()
        self.assertEqual(len(a.submitted), 1)
        self.assertIn('unknown device', a.submitted[0]['description'])

    def test_busy_network_is_flagged_not_hidden(self):
        I.STORE.add_many([('domain', 'bad.example.net', DELIVERY)])
        a = self.agent([self.q('x.example.com')], total=5000)
        with self.assertLogs('test-intel', level='WARNING') as cm:
            a._check_dns_intel()
        self.assertIn('busy network', cm.output[0])


class FeedAgent(StoreCase):
    TF = {'1': [{'ioc_value': 'bad.example.net', 'ioc_type': 'domain', 'threat_type': 'botnet_cc', 'malware_printable': 'X',
                 'confidence_level': 100}]}
    FEODO = [{'ip_address': '50.16.16.211', 'malware': 'QakBot'}]

    def setUp(self):
        super().setUp()
        self._get, self._post = AR.requests.get, AR.requests.post
        self._key = os.environ.get('ABUSECH_AUTH_KEY')
        os.environ['ABUSECH_AUTH_KEY'] = 'test-key-not-real'      # ThreatFox is asked only when a key is set
        self.tmp = tempfile.mkdtemp()
        self.calls = []
        self._store = AR.state_store._STORE                 # each test gets its own sync log (feeds are "due")
        AR.state_store._STORE = AR.state_store.StateStore(os.path.join(self.tmp, 'state.db'))

    def tearDown(self):
        AR.requests.get, AR.requests.post = self._get, self._post
        if self._key is None:
            os.environ.pop('ABUSECH_AUTH_KEY', None)
        else:
            os.environ['ABUSECH_AUTH_KEY'] = self._key
        AR.state_store._STORE = self._store
        super().tearDown()

    def agent(self, responses):
        def fake(url, **k):
            self.calls.append(url)
            key = 'tf' if 'threatfox' in url else 'uh' if 'urlhaus' in url else 'feodo'
            r = responses.get(key, Resp('', 404))
            if isinstance(r, Exception):
                raise r
            return r
        AR.requests.get = fake
        AR.requests.post = fake                              # the keyed ThreatFox API is asked with POST
        a = build(AR.IntelFeedAgent)
        a.CACHE_PATH = os.path.join(self.tmp, 'intel.json')
        return a

    def test_loads_both_feeds_and_writes_the_cache(self):
        a = self.agent({'tf': Resp(self.TF), 'feodo': Resp(self.FEODO)})
        a.setup()
        a.scan()
        self.assertIsNotNone(I.STORE.match_domain('x.bad.example.net'))
        self.assertIsNotNone(I.STORE.match_ip('50.16.16.211', 1))
        self.assertTrue(os.path.exists(a.CACHE_PATH))

    def test_threatfox_is_left_alone_without_a_key_and_feodo_still_loads(self):
        del os.environ['ABUSECH_AUTH_KEY']
        a = self.agent({'tf': Resp(self.TF), 'feodo': Resp(self.FEODO)})
        a.scan()
        self.assertFalse([u for u in self.calls if 'threatfox' in u], 'no request is made without a key')
        self.assertIsNotNone(I.STORE.match_ip('50.16.16.211', 1))

    def test_the_key_is_sent_as_the_auth_key_header(self):
        seen = {}
        def fake_post(url, **k):
            seen.update(k.get('headers', {}))
            return Resp(self.TF)
        a = self.agent({'feodo': Resp(self.FEODO)})
        AR.requests.post = fake_post
        a.scan()
        self.assertEqual(seen.get('Auth-Key'), 'test-key-not-real')

    def test_one_feed_down_does_not_lose_the_other_or_the_cache(self):
        import requests
        a = self.agent({'tf': requests.exceptions.ConnectionError('down'), 'feodo': Resp(self.FEODO)})
        a.scan()
        self.assertIsNotNone(I.STORE.match_ip('50.16.16.211'))
        self.assertIsNone(I.STORE.match_domain('bad.example.net'))

    def test_total_outage_keeps_serving_the_cached_indicators(self):
        import requests
        a = self.agent({'tf': Resp(self.TF), 'feodo': Resp(self.FEODO)})
        a.scan()
        I.STORE = AR.intel.STORE = I.IntelStore()                                 # restart
        b = self.agent({'tf': requests.exceptions.Timeout('x'), 'feodo': Resp({}, 503)})
        b.setup()
        b.scan()
        self.assertIsNotNone(I.STORE.match_domain('bad.example.net'))             # restored from cache, outage changed nothing

    def test_garbage_responses_are_survived_and_do_not_overwrite_the_cache(self):
        a = self.agent({'tf': Resp(ValueError('not json')), 'feodo': Resp('<html>')})
        a.scan()
        self.assertFalse(os.path.exists(a.CACHE_PATH))
        self.assertEqual(len(I.STORE), 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
