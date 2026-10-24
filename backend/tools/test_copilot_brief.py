#!/usr/bin/env python3
"""GET /api/copilot/brief, the Copilot lane's door (2026-09-26): who may call it, and that nothing raw leaves.
Run:  swarmsentinel-env/bin/python3 backend/tools/test_copilot_brief.py"""
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

_TMP = tempfile.mkdtemp()
os.environ['DATA_DIR'] = _TMP
os.environ['DATABASE_URL'] = f'sqlite:///{_TMP}/copilot-test.db'
os.environ['SSAI_API_KEY'] = ADMIN = 'copilot-test-admin-key'
os.environ['SSAI_COPILOT_KEY'] = COPILOT = 'copilot-test-lane-key-0123456789'
os.environ['SSAI_PRIVATE_NAMES'] = 'jdoe,watchtower'
os.environ['SSAI_PROVIDER_CHECK'] = '0'

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
sys.path[:0] = [os.path.join(BACKEND, 'agents'), BACKEND]

RAW = ['192.168.1.30', 'jdoe', '/home/jdoe', '654123', 'hunter2x', 'real-source-10.9.9.9', 'http://10.1.1.1/x']


class Brief(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import app as appmod
        if _TMP not in appmod.app.config['SQLALCHEMY_DATABASE_URI']:
            raise RuntimeError('refusing to run against a non-test database')
        cls.app, cls.db = appmod.app, appmod.db
        cls.app.config['TESTING'] = True

    def setUp(self):
        from models import Threat
        self.ctx = self.app.app_context()
        self.ctx.push()
        self.db.create_all()
        Threat.query.delete()
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        verdict = json.dumps({'consensus': {'consensus_verdict': 'suspicious', 'quorum': {'agreed': 2, 'answered': 3}}})
        rows = [
            ('high', 'suspicious-process', 'Suspicious process: jdoe ran sshpass -p 654123 ssh 192.168.1.30 '
             'cat /home/jdoe/.env --password hunter2x', 1, verdict),
            ('medium', 'dns-anomaly', 'Pi-hole blocking 41% of queries', 2, None),
            ('critical', 'file-modification', 'Critical file modified: /etc/shadow', 30 * 60, None),    # older: 30 h
            ('info', 'threat-feed', 'New feed entry', 3, None),
            ('low', 'suspicious-port', 'Port 8443 open on 192.168.0.35', 4, None),
        ]
        for i, (sev, typ, desc, minutes_ago, v) in enumerate(rows):
            self.db.session.add(Threat(type=typ, severity=sev, description=desc, url='http://10.1.1.1/x',
                                       real_source='real-source-10.9.9.9', status='active', ai_verdict=v,
                                       timestamp=now - timedelta(minutes=minutes_ago)))
        self.db.session.commit()
        audit = os.path.join(_TMP, 'cloud_audit.jsonl')
        import sanitizer
        p = mock.patch.object(sanitizer, 'audit_path', return_value=audit)
        p.start()
        self.addCleanup(p.stop)

    def tearDown(self):
        self.db.session.remove()
        self.ctx.pop()

    def get(self, headers=None, **params):
        q = '&'.join(f'{k}={v}' for k, v in params.items())
        return self.app.test_client().get('/api/copilot/brief' + (f'?{q}' if q else ''), headers=headers or {})

    def test_only_the_copilot_key_or_the_admin_key_get_in(self):
        self.assertEqual(self.get().status_code, 401)
        self.assertEqual(self.get({'X-Copilot-Key': 'wrong'}).status_code, 401)
        self.assertEqual(self.get({'X-API-Key': COPILOT}).status_code, 401)       # the Copilot key is not an API key
        self.assertEqual(self.get({'X-Copilot-Key': COPILOT}).status_code, 200)
        self.assertEqual(self.get({'X-API-Key': ADMIN}).status_code, 200)

    def test_the_copilot_key_opens_nothing_else(self):
        c = self.app.test_client()
        for method, path in (('get', '/api/settings/agents'), ('get', '/api/ai/health'), ('post', '/api/threats/')):
            r = getattr(c, method)(path, headers={'X-Copilot-Key': COPILOT}, json={} if method == 'post' else None)
            self.assertIn(r.status_code, (401, 403), path)

    def test_lane_off_without_a_key_but_an_admin_can_still_preview(self):
        with mock.patch.dict(os.environ, {'SSAI_COPILOT_KEY': ''}):
            self.assertEqual(self.get({'X-Copilot-Key': ''}).status_code, 401)
            self.assertEqual(self.get({'X-API-Key': ADMIN}).status_code, 200)
        with mock.patch.dict(os.environ, {'SSAI_COPILOT_KEY': 'short'}):            # too short to be a real key: off
            self.assertEqual(self.get({'X-Copilot-Key': 'short'}).status_code, 401)

    def test_nothing_raw_leaves(self):
        body = self.get({'X-Copilot-Key': COPILOT}, limit=20, hours=168).get_data(as_text=True)
        for raw in RAW:
            self.assertNotIn(raw, body, raw)
        self.assertIn('SECRET_', body)
        self.assertIn('HOST_', body)

    def test_counts_and_items(self):
        d = self.get({'X-Copilot-Key': COPILOT}).get_json()
        self.assertEqual(d['window_hours'], 24)
        self.assertEqual(d['counts'], {'critical': 0, 'high': 1, 'medium': 1, 'low': 1, 'info': 1})   # 30 h old one is out
        self.assertEqual(d['open'], {'critical': 1, 'high': 1, 'medium': 1})                          # open ignores the window
        self.assertEqual([t['severity'] for t in d['threats']], ['high', 'medium'])                   # newest first, medium+
        self.assertTrue(all(set(t) <= {'severity', 'threat_type', 'timestamp', 'sanitized_summary'} for t in d['threats']))
        self.assertIn('AI verdict: suspicious, 2 of 3 AIs agreed.', d['threats'][0]['sanitized_summary'])
        self.assertTrue(d['threats'][0]['sanitized_summary'].startswith('[active]'))

    def test_limit_and_window_are_bounded(self):
        self.assertEqual(len(self.get({'X-Copilot-Key': COPILOT}, limit=1).get_json()['threats']), 1)
        self.assertEqual(self.get({'X-Copilot-Key': COPILOT}, limit=0).get_json()['threats'], [])
        d = self.get({'X-Copilot-Key': COPILOT}, limit=999, hours=99999).get_json()
        self.assertEqual(d['window_hours'], 168)
        self.assertLessEqual(len(d['threats']), 20)
        self.assertEqual(self.get({'X-Copilot-Key': COPILOT}, limit='x', hours='y').get_json()['window_hours'], 24)

    def test_a_threat_the_gate_refuses_is_counted_not_sent(self):
        import sanitizer
        with mock.patch.object(sanitizer, 'sanitize_for_cloud', return_value={}):
            d = self.get({'X-Copilot-Key': COPILOT}).get_json()
        self.assertEqual(d['threats'], [])
        self.assertEqual(d['withheld'], 2)


class AlertFeed(Brief):
    """?since= / ?min_severity=: the agent's alert poller (2026-09-30)."""

    def feed(self, **params):
        return self.get({'X-Copilot-Key': COPILOT}, **params)

    def test_oldest_first_after_the_cursor_with_a_next_cursor(self):
        start = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
        d = self.feed(since=start.replace('+', '%2B')).get_json()
        self.assertEqual([t['severity'] for t in d['threats']], ['medium', 'high'])       # 2 min ago, then 1 min ago
        again = self.feed(since=d['next_since'].replace('+', '%2B')).get_json()
        self.assertEqual(again['threats'], [])                                             # nothing is sent twice
        self.assertEqual(again['next_since'], d['next_since'])                             # and the cursor holds

    def test_min_severity(self):
        start = (datetime.now(timezone.utc) - timedelta(hours=48)).strftime('%Y-%m-%dT%H:%M:%SZ')
        d = self.feed(since=start, min_severity='high').get_json()
        self.assertEqual([t['severity'] for t in d['threats']], ['critical', 'high'])
        d = self.feed(since=start, min_severity='critical').get_json()
        self.assertEqual([t['severity'] for t in d['threats']], ['critical'])
        self.assertEqual(self.feed(since=start, min_severity='low').status_code, 400)

    def test_limit_pages_through_without_gaps(self):
        start = (datetime.now(timezone.utc) - timedelta(hours=48)).strftime('%Y-%m-%dT%H:%M:%SZ')
        seen, cursor = [], start
        for _ in range(5):
            d = self.feed(since=cursor.replace('+', '%2B'), limit=1).get_json()
            seen += [t['threat_type'] for t in d['threats']]
            cursor = d['next_since']
        self.assertEqual(seen, ['file-modification', 'dns-anomaly', 'suspicious-process'])

    def test_a_withheld_threat_still_moves_the_cursor(self):
        import sanitizer
        start = (datetime.now(timezone.utc) - timedelta(minutes=10)).strftime('%Y-%m-%dT%H:%M:%SZ')
        with mock.patch.object(sanitizer, 'sanitize_for_cloud', return_value={}):
            d = self.feed(since=start).get_json()
        self.assertEqual((d['threats'], d['withheld']), ([], 2))
        self.assertEqual(self.feed(since=d['next_since'].replace('+', '%2B')).get_json()['threats'], [])

    def test_bad_or_ancient_cursor(self):
        self.assertEqual(self.feed(since='yesterday').status_code, 400)
        d = self.feed(since='2001-01-01T00:00:00Z').get_json()                         # clamped to 7 days
        self.assertEqual(len(d['threats']), 3)

    def test_nothing_raw_leaves_the_feed_either(self):
        body = self.feed(since='2001-01-01T00:00:00Z', limit=20).get_data(as_text=True)
        for raw in RAW:
            self.assertNotIn(raw, body, raw)

    def test_status_view_has_no_cursor(self):
        self.assertNotIn('next_since', self.feed().get_json())


if __name__ == '__main__':
    unittest.main(verbosity=2)
