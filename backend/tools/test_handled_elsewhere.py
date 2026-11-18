#!/usr/bin/env python3
"""Findings another trusted service already handled (2026-11-18): an e-mail Gmail already put in Spam is stored as a low,
resolved record, not an alert. Only the exact (type, handled_by) pairs in HANDLED_ELSEWHERE do this.
Run:  swarmsentinel-env/bin/python3 backend/tools/test_handled_elsewhere.py"""
import os
import sys
import tempfile
import unittest

_TMP = tempfile.mkdtemp()
os.environ['DATA_DIR'] = _TMP
os.environ['DATABASE_URL'] = f'sqlite:///{_TMP}/handled-test.db'
os.environ['SSAI_API_KEY'] = 'handled-test-admin-key'
os.environ['SSAI_PROVIDER_CHECK'] = '0'

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
sys.path[:0] = [os.path.join(BACKEND, 'agents'), BACKEND]
KEY = {'X-API-Key': 'handled-test-admin-key'}


class HandledElsewhere(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import app as appmod
        if _TMP not in appmod.app.config['SQLALCHEMY_DATABASE_URI']:
            raise RuntimeError('refusing to run against a non-test database')
        cls.app = appmod.app
        cls.app.config['TESTING'] = True
        with cls.app.app_context():
            appmod.db.create_all()

    def post(self, **body):
        base = {'url': 'gmail-message/1a2b', 'type': 'phishing-email', 'severity': 'high',
                'description': 'Signals: Gmail put it in Spam', 'detected_by': 'browser-extension-chrome'}
        base.update(body)
        r = self.app.test_client().post('/api/threats/', json=base, headers=KEY)
        self.assertIn(r.status_code, (200, 201), r.get_json())
        return r.get_json()['threat']

    def test_gmail_spam_is_a_low_resolved_record(self):
        t = self.post(url='gmail-message/aa01', handled_by='gmail-spam')
        self.assertEqual((t['status'], t['severity']), ('resolved', 'low'))
        self.assertIn("Already handled by Gmail's spam filter", t['description'])

    def test_without_the_marker_it_is_an_ordinary_open_finding(self):
        t = self.post(url='gmail-message/aa02')
        self.assertEqual((t['status'], t['severity']), ('active', 'high'))

    def test_only_the_exact_pairs_count(self):
        t = self.post(url='gmail-message/aa03', handled_by='anything-else')
        self.assertEqual(t['status'], 'active')
        t = self.post(url='https://evil.example.net/', type='phishing-link-clicked', handled_by='gmail-spam')
        self.assertEqual((t['status'], t['severity']), ('active', 'high'))    # a click is never "already handled"
        t = self.post(url='203.0.113.9', type='brute-force', handled_by='gmail-spam')
        self.assertEqual(t['status'], 'active')


if __name__ == '__main__':
    unittest.main()
