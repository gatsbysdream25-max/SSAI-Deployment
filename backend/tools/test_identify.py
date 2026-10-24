#!/usr/bin/env python3
"""Tests for the admin IP identification module (2026-09-19).
Run:  swarmsentinel-env/bin/python3 backend/tools/test_identify.py"""
import ipaddress
import os
import sys
import tempfile
import time
import types
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.dirname(HERE)]
import identify as I  # noqa: E402

RDAP = {
    'name': 'ARTIKEL10', 'handle': '185.220.101.0 - 185.220.101.31', 'country': 'DE', 'type': 'ASSIGNED PA',
    'startAddress': '185.220.101.0', 'endAddress': '185.220.101.31', 'cidr0_cidrs': [{'v4prefix': '185.220.101.0', 'length': 27}],
    'events': [{'eventAction': 'registration', 'eventDate': '2021-08-19T08:09:49Z'},
               {'eventAction': 'last changed', 'eventDate': '2025-06-18T13:35:44Z'}],
    'entities': [
        {'roles': ['administrative', 'technical'], 'vcardArray': ['vcard', [['fn', {}, 'text', 'Matthias Marx'], ['email', {}, 'text', 'private@person.example']]]},
        {'roles': ['registrant'], 'vcardArray': ['vcard', [['fn', {}, 'text', 'Artikel10 e.V.']]],
         'entities': [{'roles': ['abuse'], 'vcardArray': ['vcard', [['fn', {}, 'text', 'Abuse Handling'], ['email', {}, 'text', 'abuse@isp.example']]]}]},
    ],
}


class Basics(unittest.TestCase):
    def test_scope(self):
        for text, want in (('8.8.8.8', 'public'), ('192.168.0.5', 'lan'), ('10.1.2.3', 'lan'), ('100.64.0.1', 'lan'),
                           ('127.0.0.1', 'special'), ('169.254.1.1', 'special'), ('224.0.0.1', 'special'), ('0.0.0.0', 'special')):
            self.assertEqual(I.scope_of(ipaddress.ip_address(text)), want, text)

    def test_extract_host(self):
        cases = {'203.0.113.7': ('ip', '203.0.113.7'), '203.0.113.7:8080': ('ip', '203.0.113.7'), 'http://203.0.113.8/x': ('ip', '203.0.113.8'),
                 'pihole://192.168.1.30:8081': ('ip', '192.168.1.30'), 'HTTP://Evil.Example.com/a': ('domain', 'evil.example.com'),
                 'evil.example.com:8080/x': ('domain', 'evil.example.com'), '192.168.xxx.xxx:6667': None, '': None, None: None,
                 'not a host': None, 'nodots': None, 'http://': None}
        for raw, want in cases.items():
            self.assertEqual(I.extract_host(raw), want, raw)

    def test_clean_strips_control_characters_and_limits_length(self):
        self.assertEqual(I.clean('a\x00b\nc\x1b[31m'), 'a b c [31m')
        self.assertEqual(len(I.clean('x' * 999, 50)), 50)
        self.assertIsNone(I.clean('   '))
        self.assertIsNone(I.clean(None))


class Registry(unittest.TestCase):
    def test_parse_keeps_organisation_and_role_abuse_address_never_personal_contacts(self):
        r = I.parse_rdap(RDAP)
        self.assertEqual((r['organization'], r['abuse_contact'], r['country'], r['cidr']),
                         ('Artikel10 e.V.', 'abuse@isp.example', 'DE', '185.220.101.0/27'))
        self.assertEqual(r['range'], '185.220.101.0 - 185.220.101.31')
        self.assertEqual(r['registered'], '2021-08-19T08:09:49Z')
        blob = repr(r)
        self.assertNotIn('Matthias', blob)
        self.assertNotIn('private@person', blob)

    def test_individual_registrants_are_not_named(self):
        js = {'name': 'X', 'entities': [{'roles': ['registrant'], 'vcardArray': ['vcard', [['kind', {}, 'text', 'individual'], ['fn', {}, 'text', 'Jane Doe']]]}]}
        self.assertNotIn('organization', I.parse_rdap(js))

    def test_hostile_and_malformed_records(self):
        js = {'name': 'evil\x00\nname<script>' + 'x' * 500, 'country': 'DEU' * 10, 'entities': ['x', None, {'roles': 'abuse'}, {'roles': ['abuse'], 'vcardArray': 5}]}
        r = I.parse_rdap(js)
        self.assertNotIn('\n', r['name'])
        self.assertLessEqual(len(r['name']), 80)
        self.assertLessEqual(len(r['country']), 4)
        for junk in (None, [], 'x', {}, {'entities': 5}, {'events': [None, 'x']}):
            I.parse_rdap(junk)

    def test_fetch_caches_and_only_asks_for_public_addresses(self):
        I._rdap_cache = I._TtlCache()
        calls = []

        def get(url, **kw):
            calls.append(url)
            return types.SimpleNamespace(status_code=200, json=lambda: RDAP)
        self.assertEqual(I.fetch_rdap('185.220.101.1', get)['name'], 'ARTIKEL10')
        I.fetch_rdap('185.220.101.1', get)
        self.assertEqual(calls, ['https://rdap.org/ip/185.220.101.1'])
        with self.assertRaises(ValueError):
            I.fetch_rdap('192.168.0.5', get)
        self.assertEqual(len(calls), 1)

    def test_fetch_failures_raise_and_are_not_cached(self):
        I._rdap_cache = I._TtlCache()
        for resp in (types.SimpleNamespace(status_code=404, json=lambda: {}), types.SimpleNamespace(status_code=200, json=lambda: {})):
            with self.assertRaises(RuntimeError):
                I.fetch_rdap('8.8.4.4', lambda *a, **k: resp)
        self.assertIsNone(I._rdap_cache.get('8.8.4.4'))

    def test_cache_expires_and_is_bounded(self):
        t = [0.0]
        c = I._TtlCache(ttl=10, max_entries=2, clock=lambda: t[0])
        c.put('a', 1)
        c.put('b', 2)
        c.put('c', 3)
        self.assertIsNone(c.get('a'))
        self.assertEqual(c.get('c'), 3)
        t[0] = 11
        self.assertIsNone(c.get('c'))


class DeviceData(unittest.TestCase):
    def test_reverse_and_forward_dns_never_raise(self):
        self.assertEqual(I.reverse_dns('1.2.3.4', lambda ip: ('host.example.com\n', [], [])), 'host.example.com')
        self.assertIsNone(I.reverse_dns('1.2.3.4', lambda ip: (_ for _ in ()).throw(OSError('nx'))))
        self.assertEqual(I.resolve_forward('a.example.com', lambda d, p: [(0, 0, 0, '', ('2.2.2.2', 0)), (0, 0, 0, '', ('1.1.1.1', 0))]), ['1.1.1.1', '2.2.2.2'])
        self.assertEqual(I.resolve_forward('a.example.com', lambda d, p: (_ for _ in ()).throw(OSError('nx'))), [])

    def test_arp_reads_the_neighbour_table_and_pings_once_if_missing(self):
        seen = []

        def run(cmd, **k):
            seen.append(cmd[0])
            out = '192.168.0.9 dev eno1 lladdr AA:BB:CC:00:11:22 STALE\n' if (cmd[0] == 'ip' and 'ping' in seen) else ''
            return types.SimpleNamespace(stdout=out, returncode=0)
        self.assertEqual(I.read_arp('192.168.0.9', run), {'mac': 'aa:bb:cc:00:11:22', 'state': 'stale'})
        self.assertEqual(seen, ['ip', 'ping', 'ip'])
        self.assertIsNone(I.read_arp('192.168.0.9', lambda c, **k: types.SimpleNamespace(stdout='', returncode=1)))
        self.assertIsNone(I.read_arp('192.168.0.9', lambda c, **k: (_ for _ in ()).throw(OSError('no ping'))))

    def test_mac_flags_detect_randomized_and_multicast(self):
        self.assertTrue(I.mac_flags('9a:3e:6f:b1:ee:2d')['randomized'])          # locally administered (bit 1)
        self.assertFalse(I.mac_flags('4c:50:dd:00:00:00')['randomized'])
        self.assertTrue(I.mac_flags('01:00:5e:00:00:01')['multicast'])

    def test_oui_lookup_from_the_ieee_file(self):
        path = os.path.join(tempfile.mkdtemp(), 'oui.txt')
        with open(path, 'w') as f:
            f.write('AA-BB-CC   (hex)\t\tExample Devices Inc.\nAABBCC     (base 16)\t\tExample Devices Inc.\n')
        I._oui.update(loaded=False, map={})
        self.assertEqual(I.oui_vendor('aa:bb:cc:01:02:03', (path,)), 'Example Devices Inc.')
        self.assertIsNone(I.oui_vendor('11:22:33:01:02:03', (path,)))
        I._oui.update(loaded=False, map={})
        self.assertIsNone(I.oui_vendor('aa:bb:cc:01:02:03', ('/no/such/file',)))
        I._oui.update(loaded=False, map={})

    def test_pihole_device_lookup(self):
        data = {'devices': [
            {'hwaddr': '4C:50:DD:00:00:01', 'macVendor': 'Acme\x00 Corp', 'firstSeen': 1, 'lastQuery': 2, 'numQueries': 351,
             'ips': [{'ip': '192.168.0.9', 'name': 'tv.lan'}, {'ip': 'fe80::1', 'name': None}]},
            {'hwaddr': '11:22:33:44:55:66', 'ips': [{'ip': '192.168.0.10', 'name': None}]}]}
        ph = types.SimpleNamespace(get_json=lambda path: data)
        d = I.pihole_device('192.168.0.9', ph)
        self.assertEqual((d['vendor'], d['names'], d['dns_queries']), ('Acme  Corp', ['tv.lan'], 351))
        self.assertIsNone(I.pihole_device('192.168.0.99', ph))

    def test_merge_prefers_pihole_falls_back_to_arp_and_flags_randomized(self):
        ph = {'mac': '4c:50:dd:00:00:01', 'vendor': 'Acme', 'names': ['tv.lan']}
        d = I.merge_device(ph, {'mac': '4c:50:dd:00:00:01', 'state': 'reachable'}, oui=lambda m: 'X')
        self.assertEqual((d['vendor'], d['sources'], d['randomized_mac']), ('Acme', ['Pi-hole', 'ARP'], False))
        d = I.merge_device(None, {'mac': '4c:50:dd:00:00:01', 'state': 'stale'}, oui=lambda m: 'From OUI')
        self.assertEqual((d['vendor'], d['sources']), ('From OUI', ['ARP']))
        d = I.merge_device(None, {'mac': '9a:3e:6f:b1:ee:2d', 'state': 'stale'}, oui=lambda m: 'WRONG')
        self.assertTrue(d['randomized_mac'])
        self.assertNotIn('vendor', d)                                            # a random MAC has no vendor: do not guess
        self.assertEqual(I.merge_device(None, None), {})
        self.assertNotIn('mac', I.merge_device({'mac': 'garbage', 'vendor': 'V'}, None))

    def test_port_check_is_limited_to_private_addresses_and_reports_open_ports(self):
        opened = {22, 8080}

        def connect(addr, timeout):
            if addr[1] in opened:
                return types.SimpleNamespace(close=lambda: None)
            raise OSError('closed')
        got = I.scan_ports('192.168.0.9', ports=(22, 80, 8080), connect=connect)
        self.assertEqual([p['port'] for p in got], [22, 8080])
        with self.assertRaises(ValueError):
            I.scan_ports('8.8.8.8', connect=connect)


class Assembly(unittest.TestCase):
    def deps(self, **over):
        d = dict(rdap=lambda ip: {'organization': 'Cloud Co', 'country': 'US'}, rdns=lambda ip: 'host.example.com',
                 device=lambda ip: {'mac': '4c:50:dd:00:00:01', 'vendor': 'Acme', 'names': ['tv.lan'], 'sources': ['Pi-hole']},
                 scan=lambda ip: [{'port': 80, 'service': 'http'}], forward=lambda dom: ['1.2.3.4'],
                 intel=lambda kind, v: [{'source': 'threatfox', 'malware': 'QakBot', 'threat': 'botnet_cc', 'listed_as': v}],
                 history=lambda kind, v: {'count': 3})
        d.update(over)
        return I.Deps(**d)

    def test_public_ip(self):
        r = I.identify_ip('8.8.4.4', self.deps())
        self.assertEqual(r['scope'], 'public')
        self.assertEqual(r['registry']['organization'], 'Cloud Co')
        self.assertNotIn('device', r)
        self.assertNotIn('open_ports', r)
        self.assertIn('Cloud Co (US)', r['headline'])
        self.assertIn('LISTED by threatfox as QakBot', r['headline'])
        self.assertIn('3 threat record', r['headline'])

    def test_lan_ip_gets_device_details_and_ports_only_on_request(self):
        r = I.identify_ip('192.168.0.9', self.deps())
        self.assertEqual(r['scope'], 'lan')
        self.assertNotIn('registry', r)                                          # never send a private address to a registry
        self.assertNotIn('open_ports', r)
        self.assertIn('Acme device', r['headline'])
        self.assertEqual(I.identify_ip('192.168.0.9', self.deps(), ports=True)['open_ports'][0]['port'], 80)
        self.assertNotIn('open_ports', I.identify_ip('8.8.8.8', self.deps(), ports=True))     # and never scan a public host

    def test_special_addresses_get_no_lookups(self):
        r = I.identify_ip('127.0.0.1', self.deps(rdap=lambda ip: 1 / 0))
        self.assertEqual(r['scope'], 'special')
        self.assertNotIn('registry', r)
        self.assertIn('not a routable address', r['headline'])

    def test_one_failing_source_does_not_lose_the_others(self):
        r = I.identify_ip('8.8.4.4', self.deps(rdap=lambda ip: (_ for _ in ()).throw(RuntimeError('registry down'))))
        self.assertIn('registry', r['errors'])
        self.assertIn('registry down', r['errors']['registry'])
        self.assertEqual(r['reverse_dns'], 'host.example.com')
        self.assertEqual(r['history']['count'], 3)

    def test_slow_source_times_out_instead_of_hanging(self):
        old = I.SECTION_TIMEOUT
        I.SECTION_TIMEOUT = 0.3
        try:
            t0 = time.time()
            r = I.identify_ip('8.8.4.4', self.deps(rdap=lambda ip: time.sleep(2)))
            self.assertLess(time.time() - t0, 1.5)
            self.assertEqual(r['errors']['registry'], 'timed out')
            self.assertEqual(r['reverse_dns'], 'host.example.com')
        finally:
            I.SECTION_TIMEOUT = old

    def test_randomized_mac_headline_explains_itself(self):
        r = I.identify_ip('192.168.0.9', self.deps(device=lambda ip: {'mac': '9a:3e:6f:b1:ee:2d', 'randomized_mac': True}))
        self.assertIn('randomized', r['headline'])
        r = I.identify_ip('192.168.0.9', self.deps(device=lambda ip: {}))
        self.assertIn('not in the ARP or Pi-hole tables', r['headline'])

    def test_bad_ip_raises_for_the_caller_to_report(self):
        with self.assertRaises(ValueError):
            I.identify_ip('not-an-ip', self.deps())

    def test_domain(self):
        r = I.identify_domain('Evil.Example.com', self.deps())
        self.assertEqual(r['domain'], 'evil.example.com')
        self.assertEqual(r['resolves_to'], ['1.2.3.4'])
        self.assertIn('LISTED', r['headline'])
        self.assertIn('resolves to 1.2.3.4', r['headline'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
