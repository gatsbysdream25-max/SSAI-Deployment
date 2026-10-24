#!/usr/bin/env python3
"""Finding memory (fingerprints) and the re-alert rule (2026-09-23).
Run:  swarmsentinel-env/bin/python3 backend/tools/test_findings.py"""
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

_TMP = tempfile.mkdtemp()
os.environ['DATA_DIR'] = _TMP
os.environ['DATABASE_URL'] = f'sqlite:///{_TMP}/findings-test.db'
os.environ['SSAI_API_KEY'] = KEY = 'testkey-findings'
os.environ.pop('SSAI_REALERT_MINUTES', None)
os.environ.pop('SSAI_FINGERPRINT_EXEMPT', None)

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
sys.path[:0] = [os.path.join(BACKEND, 'agents'), BACKEND]
import findings  # noqa: E402

NOW = datetime(2026, 9, 23, 12, 0, tzinfo=timezone.utc)


class Fake:
    """The columns findings.py reads and writes."""
    def __init__(self, severity='low', ts=NOW):
        self.severity, self.timestamp = severity, ts
        self.first_seen = self.last_seen = self.last_reported = None
        self.times_seen = self.times_reported = None
        self.status = 'active'


class Fingerprint(unittest.TestCase):
    def test_same_finding_same_fingerprint(self):
        a = findings.fingerprint('open-port', 'srv01', None, '10.0.0.5:22')
        self.assertEqual(a, findings.fingerprint('OPEN-PORT', 'Srv01', None, ' 10.0.0.5:22 '))

    def test_type_machine_or_indicator_changes_it(self):
        base = findings.fingerprint('t', 'm1', None, 'x')
        self.assertNotEqual(base, findings.fingerprint('t2', 'm1', None, 'x'))
        self.assertNotEqual(base, findings.fingerprint('t', 'm2', None, 'x'))
        self.assertNotEqual(base, findings.fingerprint('t', 'm1', None, 'y'))

    def test_real_address_tells_masked_lan_devices_apart(self):
        a = findings.fingerprint('ssh-login', 'srv01', '192.168.0.5', '192.168.xxx.xxx')
        b = findings.fingerprint('ssh-login', 'srv01', '192.168.0.6', '192.168.xxx.xxx')
        self.assertNotEqual(a, b)


class Rule(unittest.TestCase):
    def test_first_sighting_is_remembered(self):
        t = Fake()
        findings.start(t, NOW)
        self.assertEqual((t.times_seen, t.times_reported, t.first_seen, t.last_reported), (1, 1, NOW, NOW))

    def test_repeat_inside_the_interval_is_quiet_but_counted(self):
        t = Fake('medium')
        findings.start(t, NOW)
        d = findings.observe(t, 'medium', NOW + timedelta(minutes=30))
        self.assertEqual(d, {'realert': False, 'reason': 'quiet'})
        self.assertEqual((t.times_seen, t.times_reported), (2, 1))
        self.assertEqual(t.timestamp, NOW)                                  # not moved: nothing new to report
        self.assertEqual(t.last_seen, NOW + timedelta(minutes=30))

    def test_intervals_by_severity(self):
        for sev, minutes in (('critical', 5), ('high', 60), ('medium', 360), ('low', 1440), ('info', 1440)):
            t = Fake(sev)
            findings.start(t, NOW)
            self.assertFalse(findings.observe(t, sev, NOW + timedelta(minutes=minutes - 1))['realert'], sev)
            self.assertTrue(findings.observe(t, sev, NOW + timedelta(minutes=minutes))['realert'], sev)

    def test_an_ongoing_critical_attack_is_never_silenced(self):
        t = Fake('critical')
        findings.start(t, NOW)
        reported = 0
        for minute in range(1, 61):                                          # seen every minute for an hour
            if findings.observe(t, 'critical', NOW + timedelta(minutes=minute))['realert']:
                reported += 1
        self.assertEqual(reported, 12)                                       # every 5 minutes
        self.assertEqual((t.times_seen, t.times_reported), (61, 13))

    def test_low_is_reported_about_once_a_day(self):
        t = Fake('low')
        findings.start(t, NOW)
        n = sum(findings.observe(t, 'low', NOW + timedelta(minutes=m))['realert'] for m in range(1, 3 * 1440, 10))
        self.assertEqual(n, 2)

    def test_getting_worse_is_reported_at_once(self):
        t = Fake('low')
        findings.start(t, NOW)
        d = findings.observe(t, 'critical', NOW + timedelta(seconds=5))
        self.assertEqual(d, {'realert': True, 'reason': 'escalated'})
        self.assertEqual(t.severity, 'critical')

    def test_getting_less_severe_does_not_lower_it_or_report(self):
        t = Fake('high')
        findings.start(t, NOW)
        self.assertFalse(findings.observe(t, 'low', NOW + timedelta(minutes=1))['realert'])
        self.assertEqual(t.severity, 'high')

    def test_interval_is_configurable(self):
        os.environ['SSAI_REALERT_MINUTES'] = '{"critical": 10, "bogus": 3, "low": -5}'
        try:
            self.assertEqual(findings.interval('critical'), timedelta(minutes=10))
            self.assertEqual(findings.interval('low'), timedelta(minutes=1440))     # bad values ignored
        finally:
            os.environ.pop('SSAI_REALERT_MINUTES')

    def test_rows_from_before_finding_memory_still_work(self):
        t = Fake('critical', ts=NOW - timedelta(hours=1))                    # no counters, naive-or-aware timestamp
        self.assertTrue(findings.observe(t, 'critical', NOW)['realert'])
        naive = Fake('critical', ts=(NOW - timedelta(hours=1)).replace(tzinfo=None))
        self.assertTrue(findings.observe(naive, 'critical', NOW)['realert'])

    def test_still_active_message(self):
        t = Fake('critical', ts=NOW - timedelta(hours=3))
        findings.start(t, NOW - timedelta(hours=3))
        t.times_reported, t.times_seen = 12, 12
        self.assertEqual(findings.still_active(t, NOW), 'Still active: first seen 3 hours ago, alerted 12 times')
        t.times_seen = 300
        self.assertIn('seen 300 times', findings.still_active(t, NOW))
        fresh = Fake()
        findings.start(fresh, NOW)
        self.assertIsNone(findings.still_active(fresh, NOW))


class Api(unittest.TestCase):
    """Through the real endpoint, against a throwaway database."""

    @classmethod
    def setUpClass(cls):
        import app as appmod
        if _TMP not in appmod.app.config['SQLALCHEMY_DATABASE_URI']:
            raise RuntimeError('refusing to run against a non-test database')
        cls.appmod, cls.app, cls.db = appmod, appmod.app, appmod.db
        cls.app.config['TESTING'] = True
        cls.c = cls.app.test_client()

    def setUp(self):
        self.ctx = self.app.app_context()
        self.ctx.push()
        from models import Threat
        Threat.query.delete()
        self.db.session.commit()

    def tearDown(self):
        self.ctx.pop()

    def post(self, **kw):
        body = {'type': 'suspicious-process', 'url': 'proc:nc', 'severity': 'medium', 'description': 'd', 'detected_by': 'test'}
        body.update(kw)
        return self.c.post('/api/threats/', json=body, headers={'X-API-Key': KEY})

    def rows(self):
        from models import Threat
        return Threat.query.order_by(Threat.id).all()

    def age(self, minutes):
        """Pretend the last report happened `minutes` ago."""
        for t in self.rows():
            t.last_reported = datetime.now(timezone.utc) - timedelta(minutes=minutes)
            t.timestamp = t.last_reported
        self.db.session.commit()

    def test_a_repeat_is_one_row_and_quiet(self):
        r1 = self.post()
        self.assertEqual(r1.status_code, 201)
        r2 = self.post()
        self.assertEqual(r2.status_code, 200)
        self.assertTrue(r2.get_json()['deduped'])
        self.assertFalse(r2.get_json()['realert'])
        rows = self.rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0].times_seen, rows[0].times_reported), (2, 1))

    def test_event_types_are_remembered_too(self):
        for _ in range(5):
            self.post(type='ssh-login', url='192.168.xxx.xxx', severity='low')
        self.assertEqual(len(self.rows()), 1)

    def test_different_indicator_or_machine_is_a_new_finding(self):
        self.post(url='a')
        self.post(url='b')
        self.assertEqual(len(self.rows()), 2)

    def test_re_alert_after_the_interval_with_count_and_duration(self):
        self.post(severity='critical', type='service-failure', url='svc:x')
        self.age(6)
        r = self.post(severity='critical', type='service-failure', url='svc:x')
        j = r.get_json()
        self.assertTrue(j['realert'])
        self.assertEqual(j['reason'], 'interval')
        self.assertIn('alerted 2 times', j['message'])
        self.assertEqual(j['threat']['alert_count'], 2)
        self.assertEqual(len(self.rows()), 1)

    def test_escalation_reports_at_once(self):
        self.post(severity='low')
        j = self.post(severity='high').get_json()
        self.assertTrue(j['realert'])
        self.assertEqual(j['threat']['severity'], 'high')

    def test_dismissed_finding_stays_quiet_until_reopened(self):
        t = self.post().get_json()['threat']
        self.c.put(f"/api/threats/{t['id']}", json={'status': 'dismissed'}, headers={'X-API-Key': KEY})
        self.age(60 * 24 * 3)
        j = self.post().get_json()
        self.assertTrue(j.get('suppressed'))
        self.assertEqual(len(self.rows()), 1)
        self.c.post(f"/api/threats/{t['id']}/reopen", headers={'X-API-Key': KEY})
        self.assertTrue(self.post().get_json()['deduped'])

    def test_every_occurrence_types_are_not_merged(self):
        self.post(type='email-quarantine', url='sender@x')
        self.post(type='email-quarantine', url='sender@x')
        self.assertEqual(len(self.rows()), 2)

    def test_old_rows_without_a_fingerprint_are_adopted(self):
        from models import Threat
        old = Threat(type='dns-anomaly', url='bad.example', severity='medium', description='d', detected_by='t', status='active')
        self.db.session.add(old)
        self.db.session.commit()
        j = self.post(type='dns-anomaly', url='bad.example').get_json()
        self.assertTrue(j['deduped'])
        self.assertEqual(len(self.rows()), 1)
        self.assertTrue(self.rows()[0].fingerprint)

    def test_listing_shows_the_memory(self):
        self.post()
        self.post()
        row = self.c.get('/api/threats/', headers={'X-API-Key': KEY}).get_json()[0]
        self.assertEqual((row['occurrences'], row['alert_count']), (2, 1))
        self.assertIn('first_seen', row)
        self.assertNotIn('fingerprint', row)


if __name__ == '__main__':
    unittest.main(verbosity=2)
