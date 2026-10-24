#!/usr/bin/env python3
"""Dashboard snapshot: unchanged threat lists are not re-sent, legacy pages still get everything, JSON is gzipped (2026-09-30).
Run:  swarmsentinel-env/bin/python3 backend/tools/test_snapshot_delta.py"""
import gzip
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone

_TMP = tempfile.mkdtemp()
os.environ['DATA_DIR'] = _TMP
os.environ['DATABASE_URL'] = f'sqlite:///{_TMP}/snapshot-test.db'
os.environ['SSAI_API_KEY'] = 'snapshot-test-admin-key'
os.environ['SSAI_PROVIDER_CHECK'] = '0'

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
sys.path[:0] = [os.path.join(BACKEND, 'agents'), BACKEND]


class Snapshot(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import app as appmod
        if _TMP not in appmod.app.config['SQLALCHEMY_DATABASE_URI']:
            raise RuntimeError('refusing to run against a non-test database')
        cls.app, cls.db = appmod.app, appmod.db
        cls.app.config['TESTING'] = True
        with cls.app.app_context():
            cls.db.create_all()
            from models import Threat
            cls.Threat = Threat
            for i in range(40):
                cls.db.session.add(Threat(url=f'https://t{i}.example.com/x', type='malware-url', severity='medium',
                                          description='d' * 200, detected_by='test', status='active',
                                          timestamp=datetime.now(timezone.utc)))
            cls.db.session.commit()

    def setUp(self):
        self.c = self.app.test_client()

    def get(self, query='', gz=False):
        r = self.c.get('/api/dashboard_snapshot' + query, headers={'X-API-Key': 'snapshot-test-admin-key', **({'Accept-Encoding': 'gzip'} if gz else {})})
        self.assertEqual(r.status_code, 200)
        body = gzip.decompress(r.data) if r.headers.get('Content-Encoding') == 'gzip' else r.data
        return r, json.loads(body)

    def test_legacy_page_gets_threats_and_collective(self):
        _r, s = self.get()
        self.assertEqual(len(s['threats']), 40)
        self.assertEqual(len(s['collective']), 40)
        self.assertTrue(s['threats_version'])

    def test_new_page_first_poll_gets_threats_but_no_duplicate_collective(self):
        _r, s = self.get('?tv=')
        self.assertEqual(len(s['threats']), 40)
        self.assertIsNone(s['collective'])

    def test_unchanged_list_is_not_resent(self):
        _r, first = self.get('?tv=')
        _r, again = self.get('?tv=' + first['threats_version'])
        self.assertIsNone(again['threats'])
        self.assertEqual(again['threats_version'], first['threats_version'])
        self.assertIn('summary', again)                 # everything else still arrives

    def test_a_status_change_is_resent(self):
        _r, first = self.get('?tv=')
        with self.app.app_context():
            t = self.Threat.query.first()
            t.status = 'dismissed'
            self.db.session.commit()
        try:
            _r, after = self.get('?tv=' + first['threats_version'])
            self.assertIsNotNone(after['threats'])
            self.assertNotEqual(after['threats_version'], first['threats_version'])
        finally:
            with self.app.app_context():
                t = self.Threat.query.filter_by(status='dismissed').first()
                t.status = 'active'
                self.db.session.commit()

    def test_stale_or_bogus_version_gets_the_full_list(self):
        _r, s = self.get('?tv=0000000000000000')
        self.assertEqual(len(s['threats']), 40)

    def test_gzip_only_when_asked(self):
        r, gz = self.get(gz=True)
        self.assertEqual(r.headers.get('Content-Encoding'), 'gzip')
        self.assertIn('Accept-Encoding', r.headers.get('Vary', ''))
        r2, plain = self.get()
        self.assertIsNone(r2.headers.get('Content-Encoding'))
        self.assertEqual(gz['threats_version'], plain['threats_version'])

    def test_small_json_is_left_alone(self):
        r = self.c.get('/health', headers={'Accept-Encoding': 'gzip'})
        self.assertIsNone(r.headers.get('Content-Encoding'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
