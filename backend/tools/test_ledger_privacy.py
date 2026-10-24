#!/usr/bin/env python3
"""The public/exported threat ledger must describe threats, never the people or machines that saw them (2026-09-20).
Run:  swarmsentinel-env/bin/python3 backend/tools/test_ledger_privacy.py"""
import json
import os
import sqlite3
import sys
import tempfile
import unittest

_TMP = tempfile.mkdtemp()
os.environ['DATA_DIR'] = _TMP
os.environ['SSAI_PRIVATE_NAMES'] = 'jdoe, asmith ,ab'          # 'ab' is too short to be a name and must be ignored
os.makedirs(os.path.join(_TMP, 'threat-intel-repo', 'logs'))

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
sys.path[:0] = [BACKEND, os.path.join(BACKEND, 'agents')]
import github_reporter as G  # noqa: E402


def rec(**kw):
    base = {'id': 'x', 'type': 'firewall-block', 'severity': 'low', 'description': '', 'url': '', 'detected_by': 'SyslogAgent',
            'timestamp': '2026-06-07 03:58:47'}
    base.update(kw)
    return base


class Sanitize(unittest.TestCase):
    def setUp(self):
        G.load_private_names(os.path.join(_TMP, 'none.db'))          # no database: names come from the environment and this host

    def test_the_real_leaks_found_in_the_audit(self):
        line = ('2026-06-07T03:58:42.152358+00:00 jdoe kernel: BLOCK]   MAC= SRC=10.182.4.9 DST=52.207.114.59 LEN=60 '
                'TTL=63 PROTO=TCP SPT=59550 DPT=443')
        out = G._sanitize(rec(description=line, url='10.182.4.9'))
        self.assertNotIn('jdoe', out['description'])
        self.assertNotIn('10.182.4.9', json.dumps(out))
        self.assertIn('DST=52.207.114.59', out['description'])                   # the external address is the useful part
        mail = G._sanitize(rec(type='email-quarantine', url='bootcamp@spam.example', detected_by='EmailQuarantineAgent',
                               description='Quarantined email — policy: Spam, from: bootcamp@spam.example, to: student1@college.example, '
                                           'subject: "Tony Robbins, didn\'t partner with us", received: 2026-09-04T11:49:18, status: Needs review'))
        blob = json.dumps(mail)
        for private in ('student1', 'college.example', 'Tony Robbins', 'bootcamp@'):
            self.assertNotIn(private, blob)
        self.assertIn('[sender]@spam.example', blob)                           # the sender's domain is the signal
        self.assertIn('policy: Spam', mail['description'])

    def test_syslog_prefixes_lose_whatever_hostname_they_carry(self):
        out = G._sanitize(rec(description='2026-06-07T03:58:42+00:00 some-other-box sshd[1]: Failed password for root from 203.0.113.9'))
        self.assertNotIn('some-other-box', out['description'])
        self.assertIn('203.0.113.9', out['description'])

    def test_configured_names_hosts_and_users_are_masked_in_every_field_case_insensitively(self):
        out = G._sanitize(rec(description='saw Jdoe and asmith at /home/asmith/x', url='jdoe:8080', detected_by='asmith-agent',
                              node_id='JDOE'))
        self.assertNotRegex(json.dumps(out).lower(), r'jdoe|asmith')
        self.assertEqual(G._mask('nobody-here 203.0.113.9'), 'nobody-here 203.0.113.9')

    def test_names_come_from_the_database_too(self):
        db = os.path.join(tempfile.mkdtemp(), 'x.db')
        c = sqlite3.connect(db)
        c.execute('CREATE TABLE agent (hostname TEXT)')
        c.execute('CREATE TABLE node (hostname TEXT, node_id TEXT)')
        c.execute("INSERT INTO agent VALUES ('kitchen-pc')")
        c.execute("INSERT INTO node VALUES ('garage-laptop', 'garage-node')")
        c.commit()
        c.close()
        names = G.load_private_names(db)
        for n in ('kitchen-pc', 'garage-laptop', 'garage-node', 'jdoe'):
            self.assertIn(n, names)
        self.assertNotIn('ab', names)
        self.assertEqual(G._mask('at kitchen-pc'), 'at [node]')
        self.assertEqual(G._mask('kitchen-pcx stays'), 'kitchen-pcx stays')                  # whole names only

    def test_lan_ranges_are_masked_and_public_addresses_are_not(self):
        out = G._mask('192.168.1.20 10.9.8.7 172.20.5.5 172.32.1.1 8.8.8.8')
        self.assertEqual(out, '192.168.xxx.xxx 10.xxx.xxx.xxx 172.20.xxx.xxx 172.32.1.1 8.8.8.8')

    def test_empty_and_odd_values_do_not_break(self):
        for v in (None, '', 5):
            G._mask(v if not isinstance(v, int) else str(v))
        out = G._sanitize({'type': None, 'description': None, 'url': None})
        self.assertEqual((out['description'], out['url']), ('', None))


class Ledger(unittest.TestCase):
    def setUp(self):
        G.load_private_names(os.path.join(_TMP, 'none.db'))

    def test_new_entries_never_contain_private_data(self):
        ledger = {}
        G.update_ledger(ledger, [
            rec(type='email-quarantine', url='a@evil.example', description='Quarantined email — policy: Phish, from: a@evil.example, '
                                                                           'to: me@school.edu, subject: "hi there", received: 2026-09-04T11:49:18'),
            rec(description='2026-06-07T03:58:42+00:00 jdoe kernel: BLOCK SRC=10.1.2.3 DST=52.207.114.59', url='10.1.2.3')])
        blob = json.dumps(ledger)
        for private in ('me@school.edu', 'school.edu', 'hi there', 'jdoe', '10.1.2.3'):
            self.assertNotIn(private, blob)

    def test_scrubbing_an_existing_ledger_rewrites_recomputes_ids_and_merges(self):
        old = {}
        for i, url in enumerate(('bob@evil.example', 'eve@evil.example')):          # two senders, one domain: the same threat now
            r = rec(type='email-quarantine', url=url, description=f'Quarantined email — policy: Spam, from: {url}, to: me@x.edu, subject: "s{i}"')
            old[f'old{i}'] = dict(r, id=f'old{i}', first_seen=f'2026-06-0{i + 1}', last_seen=f'2026-07-0{i + 1}', times_seen=3 + i)
        old['fw'] = dict(rec(description='2026-06-07T03:58:42+00:00 jdoe kernel: BLOCK SRC=10.9.9.9 DST=52.207.114.59', url='10.9.9.9'),
                         id='fw', first_seen='2026-06-01', last_seen='2026-06-07', times_seen=10)
        old['ext'] = dict(rec(type='malware-url', url='http://198.51.100.7/x.sh', description='malware distribution URL'),
                          id='ext', first_seen='2026-08-01', last_seen='2026-08-02', times_seen=2)
        new, changed, merged = G.scrub_ledger(old)
        self.assertEqual((changed, merged), (3, 1))
        self.assertEqual(len(new), 3)
        mail = [e for e in new.values() if e['type'] == 'email-quarantine'][0]
        self.assertEqual((mail['times_seen'], mail['first_seen'], mail['last_seen']), (7, '2026-06-01', '2026-07-02'))
        self.assertEqual(mail['id'], G.threat_id(mail))                               # ids match what a fresh export would compute
        blob = json.dumps(new)
        for private in ('bob@', 'eve@', 'me@x.edu', 'jdoe', '10.9.9.9'):
            self.assertNotIn(private, blob)
        self.assertIn('http://198.51.100.7/x.sh', blob)                               # threat intel is untouched
        again, changed2, merged2 = G.scrub_ledger(new)
        self.assertEqual((changed2, merged2, len(again)), (0, 0, 3))                    # idempotent

    def test_a_scrubbed_threat_and_a_freshly_exported_one_get_the_same_id(self):
        raw = rec(description='2026-06-07T03:58:42+00:00 jdoe kernel: BLOCK SRC=10.9.9.9 DST=52.207.114.59', url='10.9.9.9')
        fresh = {}
        G.update_ledger(fresh, [raw])
        scrubbed, _, _ = G.scrub_ledger({'old': dict(raw, id='old', first_seen='a', last_seen='b', times_seen=1)})
        self.assertEqual(set(fresh), set(scrubbed))                                   # otherwise every old entry would reappear as new


if __name__ == '__main__':
    unittest.main(verbosity=2)
