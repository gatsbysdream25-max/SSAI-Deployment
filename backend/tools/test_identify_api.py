#!/usr/bin/env python3
"""Identify + real-address storage, end to end through the Flask app (2026-09-19).
Run:  swarmsentinel-env/bin/python3 backend/tools/test_identify_api.py"""
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock

# SAFETY: a throwaway database and API key BEFORE anything imports ssai_config/app (these tests delete rows).
_TMP = tempfile.mkdtemp()
os.environ['DATABASE_URL'] = f'sqlite:///{_TMP}/identify-test.db'
os.environ['SSAI_API_KEY'] = 'testkey-identify'
os.environ['SSAI_VIEWER_KEY'] = 'viewer-key-identify'
KEY = 'testkey-identify'

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
sys.path[:0] = [os.path.join(BACKEND, 'agents'), BACKEND]
import identify as ID  # noqa: E402
import intel  # noqa: E402

LAN = '192.168.0.5'
A = {'url': '192.168.xxx.xxx:8080', 'type': 'suspicious-port', 'severity': 'medium', 'description': 'port 8080 open',
     'detected_by': 't', 'real_url': f'{LAN}:8080'}
B = dict(A, real_url='192.168.0.9:8080')


def fake_deps(calls=None):
    calls = calls if calls is not None else []
    return lambda pihole=None, history=None, intel_lookup=None: ID.Deps(
        rdap=lambda ip: {'organization': 'Cloud Co', 'country': 'US'}, rdns=lambda ip: 'host.example.com',
        device=lambda ip: {'mac': '4c:50:dd:00:00:01', 'vendor': 'Acme', 'names': ['tv.lan'], 'sources': ['Pi-hole']},
        scan=lambda ip: calls.append(('scan', ip)) or [{'port': 80, 'service': 'http'}], forward=lambda d: ['1.2.3.4'],
        history=history, intel=intel_lookup)


class Api(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import app as appmod
        uri = appmod.app.config['SQLALCHEMY_DATABASE_URI']
        if _TMP not in uri:
            raise RuntimeError(f'refusing to run: app is using {uri}, not the test database')
        cls.appmod, cls.app, cls.db = appmod, appmod.app, appmod.db
        from models import Threat
        cls.Threat = Threat
        cls.app.config['TESTING'] = True
        appmod._AUDIT_PATH = os.path.join(_TMP, 'audit.jsonl')

    def setUp(self):
        self.ctx = self.app.app_context()
        self.ctx.push()
        self.db.create_all()
        self.Threat.query.delete()
        self.db.session.commit()
        self.c = self.app.test_client()

    def tearDown(self):
        self.db.session.remove()
        self.ctx.pop()

    def post(self, data):
        return self.c.post('/api/threats/', json=data, headers={'X-API-Key': KEY})

    def rows(self):
        return self.Threat.query.order_by(self.Threat.id).all()

    def get(self, path, key=True, headers=None):
        h = dict(headers or {})
        if not key:
            h['X-SSAI-Viewer'] = 'viewer-key-identify'      # a display: may read, never sees the real address
        if key:
            h['X-API-Key'] = KEY
        return self.c.get(path, headers=h)

    # ── schema ──
    def test_migration_adds_the_column_to_an_existing_database_once(self):
        from sqlalchemy import create_engine, inspect
        path = os.path.join(_TMP, 'old.db')
        con = sqlite3.connect(path)
        con.execute('CREATE TABLE threat (id INTEGER PRIMARY KEY, url VARCHAR(500), type VARCHAR(100))')
        con.execute("INSERT INTO threat (url, type) VALUES ('keep-me', 't')")
        con.commit()
        con.close()
        eng = create_engine(f'sqlite:///{path}')
        self.appmod._ensure_schema(eng)
        self.appmod._ensure_schema(eng)                                   # idempotent
        insp = inspect(eng)
        self.assertIn('real_source', {c['name'] for c in insp.get_columns('threat')})
        self.assertIn('ix_threat_real_source', {i['name'] for i in insp.get_indexes('threat')})
        with eng.connect() as conn:
            self.assertEqual(conn.exec_driver_sql('SELECT url FROM threat').fetchall(), [('keep-me',)])

    # ── ingest + privacy ──
    def test_real_address_is_stored_but_never_exposed_by_any_public_route(self):
        r = self.post(A)
        self.assertEqual(r.status_code, 201)
        self.assertEqual(self.rows()[0].real_source, f'{LAN}:8080')
        self.post(dict(A, url='8.8.4.4', type='c2-beacon', real_url=None))
        for resp in (r, self.get('/api/threats/', key=False), self.get('/api/threats/')):
            self.assertNotIn(LAN, resp.get_data(as_text=True))
            self.assertNotIn('real_source', resp.get_data(as_text=True))
        listed = {t['url']: t for t in self.get('/api/threats/', key=False).get_json()}
        self.assertTrue(listed['192.168.xxx.xxx:8080']['identifiable'])
        self.assertEqual(len(listed['192.168.xxx.xxx:8080']['source_tag']), 6)
        self.assertFalse(listed['8.8.4.4']['identifiable'])
        self.assertIsNone(listed['8.8.4.4']['source_tag'])

    def test_the_ledger_and_importer_never_touch_the_real_address(self):
        for name in ('github_reporter.py', 'import_ledger.py'):
            with open(os.path.join(BACKEND, name)) as f:
                self.assertNotIn('real_source', f.read(), name)
        from datetime import datetime
        self.assertNotIn('real_source', self.Threat(url='x', timestamp=datetime.now()).to_dict())

    def test_source_tag_tells_devices_apart_without_revealing_them(self):
        self.post(A)
        self.post(B)
        tags = [t['source_tag'] for t in self.get('/api/threats/', key=False).get_json()]
        self.assertEqual(len(set(tags)), 2)

    def test_odd_real_url_values_are_handled(self):
        for val, want in ((None, None), ('', None), (12345, '12345'), ('x' * 900, 'x' * 500)):
            self.Threat.query.delete()
            self.db.session.commit()
            self.assertEqual(self.post(dict(A, type='ssh-login', real_url=val)).status_code, 201)
            self.assertEqual(self.rows()[0].real_source, want)

    # ── device-aware dedup ──
    def test_two_devices_behind_one_masked_address_are_two_threats(self):
        self.assertEqual(self.post(A).status_code, 201)
        self.assertEqual(self.post(B).status_code, 201)
        again = self.post(A)
        self.assertEqual((again.status_code, again.get_json().get('deduped')), (200, True))
        self.assertEqual(len(self.rows()), 2)

    def test_a_legacy_dismissed_row_is_adopted_and_keeps_suppressing(self):
        old = self.Threat(url=A['url'], type=A['type'], severity='medium', description='old', detected_by='t', status='dismissed')
        self.db.session.add(old)
        self.db.session.commit()
        r = self.post(A)
        self.assertEqual((r.status_code, r.get_json().get('suppressed')), (200, True))       # the operator's decision still holds
        self.assertEqual(self.db.session.get(self.Threat, old.id).real_source, f'{LAN}:8080')            # ...and the row now knows its device
        self.assertEqual(self.post(A).get_json().get('suppressed'), True)
        self.assertEqual(self.post(B).status_code, 201)                                        # a different device is new information
        self.assertEqual(len(self.rows()), 2)

    def test_agents_without_real_urls_dedup_exactly_as_before(self):
        plain = dict(A)
        del plain['real_url']
        self.assertEqual(self.post(plain).status_code, 201)
        self.assertEqual(self.post(plain).get_json().get('deduped'), True)
        self.assertEqual(len(self.rows()), 1)

    # ── endpoints ──
    def test_identify_is_admin_only_and_never_in_the_read_only_display(self):
        self.post(A)
        tid = self.rows()[0].id
        self.assertEqual(self.get(f'/api/threats/{tid}/identify', key=False).status_code, 401)
        self.assertEqual(self.get(f'/api/threats/{tid}/identify', headers={'X-SSAI-Readonly': '1'}).status_code, 403)
        self.assertEqual(self.get('/api/identify?target=8.8.8.8', key=False).status_code, 401)
        self.assertEqual(self.get('/api/identify?target=8.8.8.8', headers={'X-SSAI-Readonly': '1'}).status_code, 403)
        self.assertEqual(self.get('/api/threats/999999/identify').status_code, 404)

    def test_lan_threat_is_identified_from_the_stored_real_address(self):
        self.post(A)
        self.post(dict(B, type='ssh-login'))                                                   # another device's record: not this one's history
        tid = self.rows()[0].id
        calls = []
        with mock.patch.object(ID, 'default_deps', fake_deps(calls)):
            d = self.get(f'/api/threats/{tid}/identify').get_json()
            self.assertEqual((d['ok'], d['identifiable'], d['ip'], d['scope']), (True, True, LAN, 'lan'))
            self.assertEqual(d['device']['vendor'], 'Acme')
            self.assertEqual(d['history']['count'], 1)
            self.assertEqual(d['address_source'], 'recorded real address')
            self.assertNotIn('open_ports', d)
            self.assertEqual(calls, [])                                                        # no device is probed unless asked
            d = self.get(f'/api/threats/{tid}/identify?ports=1').get_json()
            self.assertEqual(d['open_ports'][0]['port'], 80)
            self.assertEqual(calls, [('scan', LAN)])

    def test_masked_legacy_threat_says_why_it_cannot_be_identified(self):
        self.post(dict(A, real_url=None))
        d = self.get(f'/api/threats/{self.rows()[0].id}/identify').get_json()
        self.assertEqual((d['ok'], d['identifiable']), (True, False))
        self.assertIn('masked', d['reason'])

    def test_public_threat_history_matches_the_address_not_its_prefix_neighbours(self):
        for url in ('http://8.8.4.4/bin.sh', '8.8.4.4:8080', '8.8.4.44', 'http://8.8.4.44/x', '18.8.4.4'):
            self.post({'url': url, 'type': 'malware-url', 'severity': 'high', 'description': 'd', 'detected_by': 't'})
        tid = self.Threat.query.filter_by(url='http://8.8.4.4/bin.sh').one().id
        with mock.patch.object(ID, 'default_deps', fake_deps()):
            d = self.get(f'/api/threats/{tid}/identify').get_json()
        self.assertEqual((d['scope'], d['ip']), ('public', '8.8.4.4'))
        self.assertEqual(d['history']['count'], 2)
        self.assertNotIn('device', d)

    def test_free_form_lookup_and_bad_input(self):
        with mock.patch.object(ID, 'default_deps', fake_deps()):
            d = self.get('/api/identify?target=http://Evil.Example.com/x').get_json()
            self.assertEqual((d['scope'], d['domain'], d['resolves_to']), ('domain', 'evil.example.com', ['1.2.3.4']))
            self.assertEqual(self.get('/api/identify?target=8.8.4.4').get_json()['scope'], 'public')
        for bad in ('', 'not a host', '192.168.xxx.xxx', 'x' * 400):
            self.assertEqual(self.get('/api/identify?target=' + bad).status_code, 400, bad)

    def test_identification_is_audited(self):
        with mock.patch.object(ID, 'default_deps', fake_deps()):
            self.get('/api/identify?target=8.8.4.4&ports=1')
        with open(self.appmod._AUDIT_PATH) as f:
            last = json.loads(f.readlines()[-1])
        self.assertEqual((last['action'], last['target'], last['ports']), ('identify', '8.8.4.4', True))

    # ── feed listings visible to the web app ──
    def test_intel_listings_come_from_the_runner_cache_file(self):
        d = tempfile.mkdtemp()
        st = intel.IntelStore()
        st.add_many([('ip', '50.16.16.211', {'source': 'feodo', 'malware': 'QakBot', 'threat': 'botnet_cc'}),
                     ('endpoint', '50.16.16.211:443', {'source': 'threatfox', 'malware': 'X', 'threat': 'botnet_cc'}),
                     ('domain', 'bad.example.net', {'source': 'threatfox', 'malware': 'ClearFake', 'threat': 'payload_delivery'})])
        st.save(os.path.join(d, 'intel_cache.json'))
        self.appmod._intel_cache.update(mtime=None, store=None)
        with mock.patch.object(self.appmod.ssai_config, 'INSTANCE_DIR', d):
            ip_hits = self.appmod._intel_lookup('ip', '50.16.16.211')
            self.assertEqual(sorted(h['listed_as'] for h in ip_hits), ['50.16.16.211', '50.16.16.211:443'])
            self.assertEqual(self.appmod._intel_lookup('domain', 'a.bad.example.net')[0]['malware'], 'ClearFake')
            self.assertEqual(self.appmod._intel_lookup('ip', '8.8.8.8'), [])
        with mock.patch.object(self.appmod.ssai_config, 'INSTANCE_DIR', tempfile.mkdtemp()):
            self.appmod._intel_cache.update(mtime=None, store=None)
            self.assertEqual(self.appmod._intel_lookup('ip', '50.16.16.211'), [])            # no cache file: quietly no listings

    # ── device names for the IOC / Origin column (2026-11-15) ──
    def test_labels_are_names_only_admin_only_and_this_machine_by_name(self):
        self.post(A)                                                              # LAN device behind a masked address
        self.post({'url': 'localhost:8081', 'type': 'unexpected-listener', 'severity': 'medium', 'detected_by': 't',
                   'node_id': 'office-pc'})
        self.post({'url': 'evil.example.com', 'type': 'malicious-domain', 'severity': 'high', 'detected_by': 't'})
        ids = ','.join(str(r.id) for r in self.rows())
        self.assertEqual(self.get(f'/api/identify/labels?ids={ids}', key=False).status_code, 401)
        self.assertEqual(self.get(f'/api/identify/labels?ids={ids}', headers={'X-SSAI-Readonly': '1'}).status_code, 403)
        ID._label_cache._d.clear()
        with mock.patch.object(ID, 'reverse_dns', lambda ip: None), \
             mock.patch.object(ID, '_arp_only', lambda ip: {'mac': '4c:50:dd:00:00:01'}), \
             mock.patch.object(ID, 'oui_vendor', lambda mac: 'Acme'):
            r = self.get(f'/api/identify/labels?ids={ids}')
        self.assertEqual(r.status_code, 200)
        labels = r.get_json()['labels']
        rows = self.rows()
        self.assertEqual(labels[str(rows[0].id)], {'name': 'Acme device', 'how': 'vendor'})
        self.assertEqual(labels[str(rows[1].id)], {'name': 'office-pc', 'how': 'this-machine'})
        self.assertNotIn(str(rows[2].id), labels)                                  # a domain has no device name
        self.assertNotIn(LAN, r.get_data(as_text=True))                            # the real address never leaves the hub

    def test_labels_bad_ids(self):
        self.assertEqual(self.get('/api/identify/labels?ids=1,x').status_code, 400)
        self.assertEqual(self.get('/api/identify/labels').get_json()['labels'], {})


class DeviceLabel(unittest.TestCase):
    """identify.device_label (2026-11-15 sync): Pi-hole name, then reverse DNS, then the network card's maker."""

    def setUp(self):
        ID._label_cache._d.clear()

    def deps(self, pihole=None, rdns=None, mac=None, vendor=None):
        import types
        return types.SimpleNamespace(pihole=lambda ip: pihole, rdns=lambda ip: rdns,
                                     arp=lambda ip: {'mac': mac} if mac else None, vendor=lambda m: vendor)

    def test_order_pihole_then_reverse_dns_then_vendor(self):
        self.assertEqual(ID.device_label('10.0.0.5', self.deps({'names': ['living-room-tv']}, 'x.lan', '4c:50:dd:00:00:01', 'Acme')),
                         {'name': 'living-room-tv', 'how': 'pi-hole'})
        ID._label_cache._d.clear()
        self.assertEqual(ID.device_label('10.0.0.5', self.deps(None, 'printer.lan', '4c:50:dd:00:00:01', 'Acme'))['how'], 'reverse-dns')
        ID._label_cache._d.clear()
        self.assertEqual(ID.device_label('10.0.0.5', self.deps(None, None, '4c:50:dd:00:00:01', 'Acme')),
                         {'name': 'Acme device', 'how': 'vendor'})

    def test_private_mac_and_nothing_known(self):
        self.assertEqual(ID.device_label('10.0.0.6', self.deps(mac='da:00:00:00:00:01'))['name'], 'phone or laptop (private MAC)')
        self.assertEqual(ID.device_label('10.0.0.7', self.deps()), {'name': None, 'how': None})

    def test_public_addresses_never_ask_the_pihole_or_arp(self):
        import types
        asked = []
        deps = types.SimpleNamespace(pihole=lambda ip: asked.append('pihole'), rdns=lambda ip: 'edge.example.net',
                                     arp=lambda ip: asked.append('arp'), vendor=lambda m: None)
        # Documentation addresses (203.0.113.x) are not "global" to Python; tests use no real public address, so the
        # address is declared public here.
        with mock.patch.object(ID, 'scope_of', lambda ip: 'public'):
            self.assertEqual(ID.device_label('203.0.113.9', deps), {'name': 'edge.example.net', 'how': 'reverse-dns'})
        self.assertEqual(asked, [])

    def test_a_failing_source_is_skipped_and_text_is_cleaned(self):
        import types

        def boom(ip):
            raise OSError('down')
        deps = types.SimpleNamespace(pihole=boom, rdns=lambda ip: 'evil\x1b[31m.lan', arp=boom, vendor=boom)
        self.assertEqual(ID.device_label('10.0.0.8', deps)['name'], 'evil [31m.lan')

    def test_loopback_and_garbage(self):
        self.assertEqual(ID.device_label('127.0.0.1', self.deps(rdns='x')), {'name': None, 'how': 'this-machine'})
        self.assertEqual(ID.device_label('not-an-ip', self.deps()), {'name': None, 'how': None})

    def test_answers_are_cached_for_ten_minutes(self):
        import types
        calls = []
        deps = types.SimpleNamespace(pihole=None, rdns=lambda ip: calls.append(ip) or 'a.lan', arp=None, vendor=None)
        ID.device_label('10.0.0.9', deps)
        ID.device_label('10.0.0.9', deps)
        self.assertEqual(calls, ['10.0.0.9'])
        self.assertEqual(ID._label_cache.ttl, 600)


if __name__ == '__main__':
    unittest.main(verbosity=2)
