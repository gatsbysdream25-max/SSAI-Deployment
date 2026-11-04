#!/usr/bin/env python3
"""The Windows agent carrying out actions a person approved: the fixed list, the safety rules, the undo timers.
Windows itself is replaced by a fake that records what would have been run.
Run:  swarmsentinel-env/bin/python3 backend/tools/test_windows_response.py"""
import json
import os
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone

_TMP = tempfile.mkdtemp()
os.environ['SSAI_AGENT_HOME'] = os.path.join(_TMP, 'agent-home')

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
sys.path[:0] = [os.path.join(os.path.dirname(BACKEND), 'windows_agent')]

from ssai_agent import agent, config, hub, response  # noqa: E402

HUB_IP = '203.0.113.200'


class Settings:
    api = f'http://{HUB_IP}:5000/api'
    node_id = 'pc'
    token = 'ssn_x'


class Client:
    def __init__(self):
        self.queue, self.reports = [], []

    def fetch_actions(self):
        out, self.queue = self.queue, []
        return out

    def report_action(self, action_id, ok, detail, undone=False):
        self.reports.append((action_id, ok, detail, undone))
        return True


class Windows:
    """A fake `run`: remembers every command; answers by keyword. Default: everything succeeds."""
    def __init__(self):
        self.calls, self.rules = [], {}
        self.dns = '192.168.1.1\n8.8.8.8\n'
        self.profiles = 'Domain|Allow|Allow\nPrivate|Block|Allow\nPublic|Block|NotConfigured\n'
        self.boot = 'boot-start\n'          # what the scheduled-task question answers: starts at boot
        self.fail = set()

    def __call__(self, args, timeout=30):
        self.calls.append(list(args))
        text = ' '.join(args)
        for key in self.fail:
            if key in text:
                return 1, '', 'refused by test'
        if args[0] == 'netsh':
            name = next(a for a in args if a.startswith('name='))[5:]
            if 'delete' in args:
                if name not in self.rules:
                    return 1, 'No rules match the specified criteria.', ''
                del self.rules[name]
                return 0, 'Deleted 1 rule(s).\nOk.', ''
            self.rules[name] = args
            return 0, 'Ok.', ''
        if args[0] == 'powershell.exe':
            script = args[-1]
            if 'Get-DnsClientServerAddress' in script:
                return 0, self.dns, ''
            if 'Get-NetFirewallProfile' in script:
                return 0, self.profiles, ''
            if 'Get-ScheduledTask' in script:
                return 0, self.boot, ''
            return 0, 'stopped', ''
        return 0, '', ''

    def ps(self):
        return [c[-1] for c in self.calls if c[0] == 'powershell.exe']


class Base(unittest.TestCase):
    def setUp(self):
        self.now = 1_000_000.0
        self.win = Windows()
        self.client = Client()
        self.mode = 'approve'
        self.path = os.path.join(tempfile.mkdtemp(), 'response.json')
        self.hosts = os.path.join(tempfile.mkdtemp(), 'hosts')
        with open(self.hosts, 'w') as f:
            f.write('127.0.0.1 localhost\n')
        self.r = self.make()

    def make(self, settings=Settings):
        return response.Responder(self.client, settings, path=self.path, run=self.win, clock=lambda: self.now,
                                  hosts_path=self.hosts, mode=lambda: self.mode)

    def action(self, aid, name, args=None, ttl=None, minutes=30):
        return {'id': aid, 'action': name, 'args': args or {}, 'ttl_hours': ttl,
                'valid_until': (datetime.now(timezone.utc) + timedelta(minutes=minutes)).isoformat()}

    def run_action(self, *a, **kw):
        self.client.queue.append(self.action(*a, **kw))
        self.r.tick()
        return self.client.reports[-1]


class BlockAddress(Base):
    def test_blocks_both_directions_and_remembers_to_undo(self):
        aid, ok, detail, undone = self.run_action(7, 'block-ip', {'ip': '198.51.100.7'}, ttl=2)
        self.assertEqual((aid, ok, undone), (7, True, False), detail)
        self.assertEqual(sorted(self.win.rules), ['SSAI-block-7-in', 'SSAI-block-7-out'])
        self.assertIn('remoteip=198.51.100.7', self.win.rules['SSAI-block-7-out'])
        self.assertEqual(self.r.undo[0]['undo_at'], self.now + 2 * 3600)
        self.assertEqual(json.load(open(self.path))['undo'][0]['ip'], '198.51.100.7')   # on disk, so a restart keeps the timer

    def test_the_timer_lifts_it_and_tells_the_hub_even_after_a_restart(self):
        self.run_action(7, 'block-ip', {'ip': '198.51.100.7'}, ttl=2)
        self.r = self.make()                                  # the agent restarted
        self.now += 2 * 3600 - 1
        self.r.tick()
        self.assertEqual(len(self.win.rules), 2)
        self.now += 2
        self.r.tick()
        self.assertEqual(self.win.rules, {})
        self.assertEqual(self.client.reports[-1][0::3], (7, True))
        self.assertEqual(self.r.undo, [])

    def test_refuses_what_it_must_never_block(self):
        for ip in ('192.168.1.50', '10.1.2.3', '100.64.0.1', '127.0.0.1', 'fe80::1', '8.8.8.8', '192.168.1.1', HUB_IP, 'nonsense'):
            _, ok, detail, _ = self.run_action(abs(hash(ip)) % 100000, 'block-ip', {'ip': ip})
            self.assertFalse(ok, ip)
        self.assertEqual(self.win.rules, {})
        self.assertEqual(self.r.undo, [])

    def test_fails_closed_when_it_cannot_list_dns_and_gateway(self):
        self.win.fail.add('Get-DnsClientServerAddress')
        _, ok, detail, _ = self.run_action(1, 'block-ip', {'ip': '198.51.100.7'})
        self.assertFalse(ok)
        self.assertIn('nothing is blocked', detail)
        self.assertEqual(self.win.rules, {})

    def test_a_firewall_refusal_leaves_nothing_behind(self):
        self.win.fail.add('dir=in')
        _, ok, detail, _ = self.run_action(2, 'block-ip', {'ip': '198.51.100.7'})
        self.assertFalse(ok)
        self.assertEqual(self.win.rules, {})                  # the outbound rule that did go in was removed again
        self.assertEqual(self.r.undo, [])

    def test_an_undo_that_fails_is_kept_and_tried_again(self):
        self.run_action(3, 'block-ip', {'ip': '198.51.100.7'}, ttl=1)
        self.now += 3601
        self.win.fail.add('delete rule')
        self.r.tick()
        self.assertEqual(len(self.r.undo), 1)
        self.win.fail.clear()
        self.r.tick()
        self.assertEqual((self.r.undo, self.win.rules), ([], {}))

    def test_a_person_can_undo_early(self):
        self.run_action(4, 'block-ip', {'ip': '198.51.100.7'}, ttl=24)
        self.client.queue.append(self.action(5, 'undo', {'of': 4}))
        self.r.tick()
        self.assertEqual(self.win.rules, {})
        self.assertIn((4, True, 'undone at a person\'s request', True), self.client.reports)
        self.assertTrue(self.client.reports[-1][1])
        _, ok, detail, _ = self.run_action(6, 'undo', {'of': 4})
        self.assertFalse(ok)                                  # nothing left to undo


class BlockName(Base):
    def test_adds_and_removes_only_its_own_hosts_lines(self):
        _, ok, detail, _ = self.run_action(8, 'block-domain', {'domain': 'Evil.Example.com.'}, ttl=1)
        self.assertTrue(ok, detail)
        text = open(self.hosts).read()
        self.assertIn('0.0.0.0 evil.example.com # SSAI-8', text)
        self.assertTrue(text.startswith('127.0.0.1 localhost\n'))
        self.now += 3601
        self.r.tick()
        self.assertEqual(open(self.hosts).read(), '127.0.0.1 localhost\n')

    def test_refuses_things_that_are_not_domains(self):
        for bad in ('', 'localhost', '1.2.3.4', 'a b.com', 'x.com\n0.0.0.0 evil', '-bad.com', 'ok.com # SSAI-1'):
            self.assertFalse(self.run_action(abs(hash(bad)) % 100000, 'block-domain', {'domain': bad})[1], repr(bad))
        self.assertEqual(open(self.hosts).read(), '127.0.0.1 localhost\n')

    def test_never_blocks_the_hubs_own_name_or_a_parent_of_it(self):
        class ByName(Settings):
            api = 'http://hub.example.net:5000/api'
        self.r = self.make(ByName)
        for domain in ('hub.example.net', 'example.net'):
            _, ok, detail, _ = self.run_action(abs(hash(domain)) % 100000, 'block-domain', {'domain': domain})
            self.assertFalse(ok, domain)
            self.assertIn("hub's own address", detail)
        self.assertEqual(open(self.hosts).read(), '127.0.0.1 localhost\n')
        self.assertTrue(self.run_action(50, 'block-domain', {'domain': 'other-example.net'})[1])   # a different name is fine


class Defender(Base):
    def test_scan_and_remove_use_defender(self):
        self.assertTrue(self.run_action(1, 'defender-scan')[1])
        self.assertTrue(self.run_action(2, 'defender-remove')[1])
        scripts = ' '.join(self.win.ps())
        self.assertIn('Start-MpScan', scripts)
        self.assertIn('Remove-MpThreat', scripts)

    def test_a_scan_still_running_is_not_a_failure(self):
        original = self.win.__call__

        def slow(args, timeout=30):
            if 'Start-MpScan' in args[-1]:
                return -1, '', 'timed out'
            return original(args, timeout)
        self.r.run = slow
        self.assertIn('still running', self.run_action(1, 'defender-scan')[2])


class KillProcess(Base):
    def test_stops_a_named_process_and_checks_the_name_in_windows(self):
        _, ok, detail, _ = self.run_action(1, 'kill-process', {'pid': 4242, 'image': 'evil.exe'})
        self.assertTrue(ok, detail)
        script = self.win.ps()[-1]
        self.assertIn('Get-Process -Id 4242', script)
        self.assertIn("'evil.exe'", script)
        self.assertIn('SystemRoot', script)                   # never a program from the Windows folder
        self.assertEqual(self.r.undo, [])                     # nothing to undo

    def test_never_stops_windows_defender_or_itself(self):
        before = len(self.win.calls)
        for pid, image in ((4, 'x.exe'), (900, 'lsass.exe'), (901, 'MsMpEng.exe'), (902, 'ssai-agent.exe'), (os.getpid(), 'python.exe'),
                           (903, "a'; calc; '.exe"), (904, '..\\cmd.exe'), (905, 'notexe')):
            self.assertFalse(self.run_action(pid + 1000, 'kill-process', {'pid': pid, 'image': image})[1], (pid, image))
        self.assertEqual(len(self.win.calls), before)         # none of them reached PowerShell

    def test_a_failure_inside_windows_is_reported(self):
        self.win.fail.add('Stop-Process')
        self.assertFalse(self.run_action(1, 'kill-process', {'pid': 4242, 'image': 'evil.exe'})[1])


class Isolate(Base):
    def test_blocks_everything_but_the_hub_and_restores_the_old_settings(self):
        _, ok, detail, _ = self.run_action(9, 'isolate-host', ttl=1)
        self.assertTrue(ok, detail)
        self.assertIn(f'remoteip={HUB_IP}', self.win.rules['SSAI-isolate-allow-9'])
        self.assertIn('-DefaultInboundAction Block -DefaultOutboundAction Block', self.win.ps()[-1])
        self.now += 3601
        self.r.tick()
        scripts = ' '.join(self.win.ps())
        self.assertIn('-Name Private -DefaultInboundAction Block -DefaultOutboundAction Allow', scripts)   # what it was before
        self.assertIn('-Name Public -DefaultInboundAction Block -DefaultOutboundAction NotConfigured', scripts)
        self.assertEqual(self.win.rules, {})

    def test_refuses_when_it_could_not_restore_afterwards(self):
        self.win.profiles = 'garbage'
        self.assertFalse(self.run_action(1, 'isolate-host')[1])
        self.assertFalse(any('-DefaultOutboundAction Block' in s for s in self.win.ps()))
        self.assertEqual(self.r.undo, [])

    def test_refuses_when_the_hub_is_known_by_name(self):
        class ByName(Settings):
            api = 'http://hub.example.net:5000/api'
        self.r = self.make(ByName)
        _, ok, detail, _ = self.run_action(1, 'isolate-host')
        self.assertFalse(ok)
        self.assertIn('IP number', detail)

    def test_a_local_hub_needs_no_allow_rule(self):
        class Local(Settings):
            api = 'http://localhost:5000/api'
        self.r = self.make(Local)
        self.assertTrue(self.run_action(1, 'isolate-host')[1])
        self.assertEqual(self.win.rules, {})

    def test_not_twice_and_a_failed_switch_is_rolled_back(self):
        self.assertTrue(self.run_action(1, 'isolate-host')[1])
        self.assertFalse(self.run_action(2, 'isolate-host')[1])
        self.r.undo.clear()
        self.win.rules.clear()
        self.win.fail.add('Set-NetFirewallProfile -All')
        self.assertFalse(self.run_action(3, 'isolate-host')[1])
        self.assertEqual((self.r.undo, self.win.rules), ([], {}))

    def test_refuses_when_the_agent_does_not_start_at_boot(self):
        self.win.boot = ''                                    # the task has no start-at-boot trigger
        _, ok, detail, _ = self.run_action(1, 'isolate-host')
        self.assertFalse(ok)
        self.assertIn('-AutoStart On', detail)
        self.assertFalse(any('-DefaultOutboundAction Block' in s for s in self.win.ps()))
        self.assertEqual(self.r.undo, [])

    def test_refuses_when_it_cannot_tell_whether_the_agent_starts_at_boot(self):
        self.win.fail.add('Get-ScheduledTask')
        self.assertFalse(self.run_action(1, 'isolate-host')[1])
        self.assertEqual(self.r.undo, [])

    def test_lift_everything_undoes_blocks_and_isolation_at_once(self):
        self.run_action(1, 'block-ip', {'ip': '198.51.100.7'}, ttl=24)
        self.run_action(2, 'isolate-host', ttl=1)
        self.run_action(3, 'block-domain', {'domain': 'evil.example.com'}, ttl=24)
        self.assertEqual(len(self.r.undo), 3)
        self.assertEqual(self.r.lift_everything(), (3, 0))
        self.assertEqual((self.r.undo, self.win.rules), ([], {}))
        self.assertEqual(open(self.hosts).read(), '127.0.0.1 localhost\n')
        self.assertIn('-Name Private -DefaultInboundAction Block -DefaultOutboundAction Allow', ' '.join(self.win.ps()))

    def test_lift_everything_keeps_what_it_could_not_undo(self):
        self.run_action(1, 'block-ip', {'ip': '198.51.100.7'}, ttl=24)
        self.win.fail.add('delete rule')
        self.assertEqual(self.r.lift_everything(), (0, 1))
        self.assertEqual(len(self.r.undo), 1)                 # still there, so the timer will try again


class Rules(Base):
    def test_an_action_runs_once(self):
        self.run_action(1, 'defender-scan')
        n = len(self.win.calls)
        self.client.queue.append(self.action(1, 'defender-scan'))
        self.r.tick()
        self.assertEqual(len(self.win.calls), n)
        self.r = self.make()                                  # and not after a restart either
        self.client.queue.append(self.action(1, 'defender-scan'))
        self.r.tick()
        self.assertEqual(len(self.win.calls), n)

    def test_an_action_that_waited_too_long_is_dropped(self):
        _, ok, detail, _ = self.run_action(1, 'defender-scan', minutes=-5)
        self.assertFalse(ok)
        self.assertIn('too long', detail)
        self.assertEqual(self.win.calls, [])

    def test_an_unknown_action_is_refused_not_run(self):
        _, ok, detail, _ = self.run_action(1, 'format-disk')
        self.assertFalse(ok)
        self.assertEqual(self.win.calls, [])

    def test_in_mode_off_it_never_asks_but_still_lifts_what_it_did(self):
        self.run_action(1, 'block-ip', {'ip': '198.51.100.7'}, ttl=1)
        self.mode = 'off'
        self.client.queue.append(self.action(2, 'defender-scan'))
        self.now += 3601
        self.r.tick()
        self.assertEqual(self.win.rules, {})                  # the block still ran out
        self.assertEqual(len(self.client.queue), 1)           # and the queue was never read

    def test_time_limits_are_clamped(self):
        self.run_action(1, 'block-ip', {'ip': '198.51.100.7'}, ttl=99999)
        self.assertEqual(self.r.undo[0]['undo_at'], self.now + 24 * 7 * 3600)

    def test_a_crash_inside_an_action_is_reported_not_raised(self):
        self.r.handlers['defender-scan'] = lambda *a: 1 / 0
        _, ok, detail, _ = self.run_action(1, 'defender-scan')
        self.assertFalse(ok)


class Settings_and_wiring(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.mkdtemp()
        os.environ['SSAI_AGENT_HOME'] = self.folder
        os.environ['SSAI_AGENT_NO_LOCK'] = '1'

    def test_response_is_off_unless_an_administrator_turns_it_on(self):
        self.assertEqual(config.response_mode(), 'off')
        config.save_settings(config.Settings(api='http://h/api', node_id='n', token='t'))
        self.assertEqual(config.response_mode(), 'off')
        config.save_response_mode('approve')
        self.assertEqual(config.response_mode(), 'approve')
        config.save_settings(config.Settings(api='http://h/api', node_id='n', token='new'))     # re-enrolling keeps the choice
        self.assertEqual(config.response_mode(), 'approve')
        self.assertEqual(config.load_settings().token, 'new')
        config.save_response_mode('everything')
        self.assertEqual(config.response_mode(), 'off')

    def test_the_hub_client_asks_and_reports(self):
        seen = []

        def transport(method, url, payload, token):
            seen.append((method, url, payload))
            return 200, {'actions': [{'id': 1, 'action': 'defender-scan'}]} if url.endswith('/poll') else {'status': 'done'}
        client = hub.HubClient(config.Settings(api='http://h/api', node_id='n', token='t'), transport)
        self.assertEqual(client.fetch_actions()[0]['id'], 1)
        self.assertTrue(client.report_action(1, True, 'fine', undone=True))
        self.assertEqual(seen[0][:2], ('POST', 'http://h/api/node/actions/poll'))
        self.assertEqual(seen[1][1:], ('http://h/api/node/actions/1/result', {'ok': True, 'detail': 'fine', 'undone': True}))
        garbage = hub.HubClient(config.Settings(api='http://h/api', node_id='n', token='t'), lambda *a: (200, {'actions': 'x'}))
        self.assertEqual(garbage.fetch_actions(), [])
        down = hub.HubClient(config.Settings(api='http://h/api', node_id='n', token='t'), lambda *a: (0, {}))
        self.assertEqual(down.fetch_actions(), [])

    def test_the_runner_starts_the_responder_on_its_own_thread(self):
        started = threading.Event()

        class Fake:
            def run_forever(self, stop):
                started.set()

        class Client:
            credential_rejected = False

            def register(self, *a):
                pass
        stop = threading.Event()
        stop.set()
        agent.AgentRunner(Client(), None, [], responder=Fake()).run_forever(stop)
        self.assertTrue(started.wait(2))


if __name__ == '__main__':
    unittest.main(verbosity=1)
