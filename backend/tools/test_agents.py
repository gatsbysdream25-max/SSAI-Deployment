#!/usr/bin/env python3
"""Tests for the agent catalog, operator switches, and live start/stop (2026-09-19).
Run:  swarmsentinel-env/bin/python3 backend/tools/test_agents.py"""
import os
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(os.path.dirname(HERE), 'agents'), os.path.dirname(HERE)]
import agent_catalog as C  # noqa: E402
import agent_runner as R  # noqa: E402

TIERS = {'core', 'ai', 'intel', 'optional'}


class LoggingSetup(unittest.TestCase):
    def test_unwritable_log_file_falls_back_to_console_only(self):
        import logging
        handlers = R._build_log_handlers('/proc/no-such-dir/agents.log')
        self.assertEqual(len(handlers), 1)
        self.assertIsInstance(handlers[0], logging.StreamHandler)

    def test_writable_log_file_is_size_rotated(self):
        from logging.handlers import RotatingFileHandler
        path = os.path.join(tempfile.mkdtemp(), 'agents.log')
        handlers = R._build_log_handlers(path)
        rot = [h for h in handlers if isinstance(h, RotatingFileHandler)]
        self.assertEqual(len(rot), 1)
        self.assertGreater(rot[0].maxBytes, 0)
        self.assertGreater(rot[0].backupCount, 0)
        for h in handlers:
            h.close()


class CatalogPolicy(unittest.TestCase):
    def test_every_runner_agent_is_in_the_catalog_and_vice_versa(self):
        in_runner = {c.name_id for c in R.AGENTS}
        self.assertEqual(in_runner - set(C.CATALOG), set(), 'agents missing from the catalog')
        self.assertEqual(set(C.CATALOG) - in_runner, set(), 'catalog entries with no agent class')

    def test_entries_are_well_formed(self):
        for name, m in C.CATALOG.items():
            self.assertIn(m['tier'], TIERS, name)
            self.assertIsInstance(m['default_on'], bool, name)
            self.assertTrue(m['notes'].strip(), name)

    def test_local_llm_analyzers_are_off_by_default(self):
        for name in ('LocalAnalyzerAgent',):
            self.assertFalse(C.CATALOG[name]['default_on'], name)
            self.assertEqual(C.CATALOG[name]['tier'], 'optional')

    def test_optional_tier_is_exactly_the_off_by_default_set(self):
        self.assertEqual({n for n, m in C.CATALOG.items() if not m['default_on']}, {n for n, m in C.CATALOG.items() if m['tier'] == 'optional'})

    def test_cheap_detectors_and_the_ai_consensus_stay_on(self):
        for name in ('AuthLogAgent', 'NetworkScanAgent', 'HostHealthAgent', 'IntelFeedAgent', 'SwarmConsensusAgent'):
            self.assertTrue(C.CATALOG[name]['default_on'], name)

    def test_the_retired_cosmos_agent_is_gone(self):
        self.assertFalse(hasattr(R, 'CosmosDBSyncAgent'))
        self.assertNotIn('CosmosDBSyncAgent', C.CATALOG)


class Overrides(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(tempfile.mkdtemp(), 'agents.json')

    def test_missing_or_corrupt_file_gives_no_overrides(self):
        self.assertEqual(C.load_overrides(self.path), {})
        for junk in ('{bad', '[1]', '{"enabled": 3}', '{"enabled": {"a": "yes", "b": 0, "c": true}}'):
            with open(self.path, 'w') as f:
                f.write(junk)
            data = C.load_overrides(self.path)
            self.assertNotIn('a', data)
            self.assertNotIn('b', data)

    def test_precedence(self):
        self.assertTrue(C.agent_enabled('AuthLogAgent', {}))
        self.assertFalse(C.agent_enabled('LocalAnalyzerAgent', {}))
        self.assertTrue(C.agent_enabled('SomeFutureAgent', {}))                      # unknown agents run
        self.assertTrue(C.agent_enabled('LocalAnalyzerAgent', {'LocalAnalyzerAgent': True}))
        self.assertFalse(C.agent_enabled('AuthLogAgent', {'AuthLogAgent': False}))

    def test_round_trip_is_atomic_and_keeps_other_choices(self):
        C.set_agent_enabled('LocalAnalyzerAgent', True, self.path)
        C.set_agent_enabled('SyslogAgent', False, self.path)
        C.set_agent_enabled('LocalAnalyzerAgent', False, self.path)
        self.assertEqual(C.load_overrides(self.path), {'LocalAnalyzerAgent': False, 'SyslogAgent': False})
        self.assertFalse(os.path.exists(self.path + '.tmp'))

    def test_default_path_cache_reflects_changes(self):
        orig = C._PATH
        C._PATH = self.path
        C._cache.update(mtime=None, data={})
        try:
            self.assertFalse(C.agent_enabled('LocalAnalyzerAgent'))
            C.set_agent_enabled('LocalAnalyzerAgent', True)
            self.assertTrue(C.agent_enabled('LocalAnalyzerAgent'))
        finally:
            C._PATH = orig
            C._cache.update(mtime=None, data={})


class PlanReconcile(unittest.TestCase):
    def test_table(self):
        cases = [
            ({}, {'a', 'b'}, (['a', 'b'], [])),                                   # cold start
            ({'a': True, 'b': True}, {'a', 'b'}, ([], [])),                       # steady state
            ({'a': True, 'b': True}, {'a'}, ([], ['b'])),                         # switched off
            ({'a': True}, {'a', 'b'}, (['b'], [])),                               # switched on
            ({'a': False, 'b': True}, {'a', 'b'}, (['a'], [])),                   # died: restart
            ({'a': False}, set(), ([], [])),                                      # dead and unwanted: leave alone
            ({'a': True}, set(), ([], ['a'])),
        ]
        for running, wanted, expected in cases:
            self.assertEqual(C.plan_reconcile(running, wanted), expected, (running, wanted))


class Lifecycle(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self._register, self._heartbeat = R.register, R.heartbeat
        R.register = lambda *a, **k: self.calls.append(('register', a[0]))
        R.heartbeat = lambda name, **k: self.calls.append(('heartbeat', name, k.get('status')))
        self.path = os.path.join(tempfile.mkdtemp(), 'agents.json')
        self._orig = C._PATH
        C._PATH = self.path
        C._cache.update(mtime=None, data={})

    def tearDown(self):
        R.register, R.heartbeat = self._register, self._heartbeat
        C._PATH = self._orig
        C._cache.update(mtime=None, data={})

    def fake(self, name):
        class Fake(R.BaseAgent):
            name_id = name
            role = 'test'
            description = 'test agent'
            interval = 0.02
            scans = 0

            def scan(inner):
                inner.scans += 1
        return Fake

    def test_thread_stop_attribute_is_not_shadowed(self):
        agent = self.fake('LifecycleA')()
        self.assertNotIsInstance(getattr(agent, '_stop', None), threading.Event)   # the old bug: Event shadowed Thread._stop
        self.assertIsInstance(agent._stop_evt, threading.Event)

    def test_stop_ends_the_thread_and_join_works(self):
        agent = self.fake('LifecycleB')()
        agent.start()
        time.sleep(0.15)
        self.assertGreater(agent.scans, 1)
        agent.stop()
        agent.join(timeout=2)                                  # used to risk TypeError: 'Event' object is not callable
        self.assertFalse(agent.is_alive())

    def test_sync_starts_stops_and_restarts_live(self):
        import logging
        log = logging.getLogger('test-runner')
        A, B, D = self.fake('LiveA'), self.fake('LiveB'), self.fake('LiveD')
        by_name = {c.name_id: c for c in (A, B, D)}
        running = {}
        started, stopped = R._sync_agents(by_name, running, log)
        self.assertEqual((sorted(started), stopped), (['LiveA', 'LiveB', 'LiveD'], []))
        self.assertTrue(all(t.is_alive() for t in running.values()))
        C.set_agent_enabled('LiveB', False)                    # operator switches B off in the menu
        started, stopped = R._sync_agents(by_name, running, log)
        self.assertEqual((started, stopped), ([], ['LiveB']))
        self.assertNotIn('LiveB', running)
        self.assertIn(('heartbeat', 'LiveB', 'disabled'), self.calls)   # the menu shows it as off, not "active"
        running['LiveD'].stop()                                # D dies on its own
        running['LiveD'].join(timeout=2)
        started, stopped = R._sync_agents(by_name, running, log)
        self.assertEqual(started, ['LiveD'])
        self.assertTrue(running['LiveD'].is_alive())           # restarted
        C.set_agent_enabled('LiveB', True)                     # switched back on
        started, _ = R._sync_agents(by_name, running, log)
        self.assertEqual(started, ['LiveB'])
        for t in running.values():
            t.stop()
            t.join(timeout=2)


class HostHealthWithoutSystemd(unittest.TestCase):
    def test_a_machine_with_no_systemctl_is_skipped_quietly_not_failed_every_minute(self):
        from unittest import mock
        agent = R.HostHealthAgent.__new__(R.HostHealthAgent)
        agent.log = mock.Mock()
        agent._states, agent._told_no_systemd = {}, False   # not setup(): that would baseline the real critical files
        with mock.patch.object(R.shutil, 'which', return_value=None), mock.patch.object(R.subprocess, 'run') as run:
            agent._check_services()
            agent._check_services()
        run.assert_not_called()                       # nothing was attempted
        self.assertEqual(agent.log.info.call_count, 1)  # and it said so only once


class Requirements(unittest.TestCase):
    """An agent with nothing to watch on this machine stays off by itself (a laptop with no Pi-hole)."""

    def setUp(self):
        from unittest import mock
        self.mock = mock

    def test_pihole_agent_needs_a_pihole_to_be_configured(self):
        with self.mock.patch.dict(os.environ, {'PIHOLE_IP': '', 'PIHOLE_PASSWORD': ''}):
            self.assertIn('PIHOLE_IP', C.unmet_requirement('PiHoleAgent'))
            self.assertFalse(C.agent_enabled('PiHoleAgent', {}))
        with self.mock.patch.dict(os.environ, {'PIHOLE_IP': '10.0.0.2', 'PIHOLE_PASSWORD': ''}):
            self.assertEqual(C.unmet_requirement('PiHoleAgent'), 'PIHOLE_PASSWORD not set')
            self.assertFalse(C.agent_enabled('PiHoleAgent', {}))
        with self.mock.patch.dict(os.environ, {'PIHOLE_IP': '10.0.0.2', 'PIHOLE_PASSWORD': 'x'}):
            self.assertEqual(C.unmet_requirement('PiHoleAgent'), '')
            self.assertTrue(C.agent_enabled('PiHoleAgent', {}))

    def test_network_scan_needs_nmap(self):
        with self.mock.patch.object(C.shutil, 'which', return_value=None):
            self.assertIn('nmap', C.unmet_requirement('NetworkScanAgent'))
            self.assertFalse(C.agent_enabled('NetworkScanAgent', {}))
        with self.mock.patch.object(C.shutil, 'which', return_value='/usr/bin/nmap'):
            self.assertTrue(C.agent_enabled('NetworkScanAgent', {}))

    def test_the_operator_can_still_force_an_agent_on(self):
        with self.mock.patch.dict(os.environ, {'PIHOLE_IP': '', 'PIHOLE_PASSWORD': ''}):
            self.assertTrue(C.agent_enabled('PiHoleAgent', {'PiHoleAgent': True}))

    def test_agents_with_no_requirement_are_unaffected(self):
        self.assertEqual(C.unmet_requirement('AuthLogAgent'), '')
        self.assertEqual(C.unmet_requirement('SomeFutureAgent'), '')

    def test_every_requirement_names_a_real_agent(self):
        self.assertEqual(set(C.REQUIRES) - set(C.CATALOG), set())


class MergedAgents(unittest.TestCase):
    def test_a_switch_made_for_an_old_analyzer_carries_over_to_the_merged_one(self):
        path = os.path.join(tempfile.mkdtemp(), 'agents.json')
        with open(path, 'w') as f:
            f.write('{"enabled": {"HermesAnalyzerAgent": true, "OllamaAnalyzerAgent": false}}')
        self.assertTrue(C.load_overrides(path)['LocalAnalyzerAgent'])
        with open(path, 'w') as f:
            f.write('{"enabled": {"HermesAnalyzerAgent": true, "LocalAnalyzerAgent": false}}')
        self.assertFalse(C.load_overrides(path)['LocalAnalyzerAgent'])     # an explicit choice for the new name wins
        with open(path, 'w') as f:
            f.write('{"enabled": {"HermesAnalyzerAgent": false}}')
        self.assertNotIn('LocalAnalyzerAgent', C.load_overrides(path))

    def test_retired_names_are_not_current_agents(self):
        self.assertEqual(C.RETIRED & {c.name_id for c in R.AGENTS}, set())

    def test_roster_is_the_consolidated_set(self):
        names = {c.name_id for c in R.AGENTS}
        for gone in ('PortMonitorAgent', 'NetworkConnAgent', 'ServiceWatchAgent', 'DiskSpaceAgent', 'FileIntegrityAgent',
                     'OllamaAnalyzerAgent', 'HermesAnalyzerAgent', 'WatchtowerAnalyzerAgent', 'ThreatFeedAgent',
                     'BrowserExtAgent'):
            self.assertNotIn(gone, names)
        for kept in ('SocketWatchAgent', 'HostHealthAgent', 'LocalAnalyzerAgent'):
            self.assertIn(kept, names)
        self.assertEqual(len(names), len(R.AGENTS), 'duplicate agent names')

    def test_socket_watch_checks_listeners_every_second_cycle_and_connections_every_cycle(self):
        from unittest import mock
        agent = R.SocketWatchAgent.__new__(R.SocketWatchAgent)
        agent._cycle = 0
        with mock.patch.object(agent, '_scan_connections') as conns, mock.patch.object(agent, '_scan_listeners') as lst:
            for _ in range(4):
                agent.scan()
        self.assertEqual((conns.call_count, lst.call_count), (4, 2))

    def test_host_health_runs_slow_checks_on_a_timer_and_survives_a_failing_check(self):
        from unittest import mock
        agent = R.HostHealthAgent.__new__(R.HostHealthAgent)
        agent.log = mock.Mock()
        agent._slow_due = 0.0
        with mock.patch.object(agent, '_check_services', side_effect=RuntimeError('boom')) as svc, \
                mock.patch.object(agent, '_check_disk') as disk, mock.patch.object(agent, '_check_files') as files:
            agent.scan()        # first look: everything runs, and the failing services check does not stop the others
            agent.scan()        # 60 s later in real life: only the cheap check is due again
        self.assertEqual((svc.call_count, disk.call_count, files.call_count), (2, 1, 1))
        self.assertTrue(agent.log.error.called)

    def test_local_analyzer_runs_the_slow_tier_less_often(self):
        from unittest import mock
        agent = R.LocalAnalyzerAgent.__new__(R.LocalAnalyzerAgent)
        agent._next_due = {}
        seen = []
        with mock.patch.object(agent, '_scan_tier', side_effect=lambda t: seen.append(t['label'])), \
                mock.patch.object(R.time, 'monotonic', side_effect=[0, 300, 600, 900]):
            for _ in range(4):
                agent.scan()
        self.assertEqual(seen.count('Ollama'), 4)
        self.assertEqual(seen.count('Hermes'), 4)
        self.assertEqual(seen.count('Watchtower'), 2)   # at 0 s and 900 s only


if __name__ == '__main__':
    unittest.main(verbosity=2)
