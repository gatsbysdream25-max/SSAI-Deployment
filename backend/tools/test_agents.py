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
        for name in ('OllamaAnalyzerAgent', 'HermesAnalyzerAgent', 'WatchtowerAnalyzerAgent'):
            self.assertFalse(C.CATALOG[name]['default_on'], name)
            self.assertEqual(C.CATALOG[name]['tier'], 'optional')

    def test_optional_tier_is_exactly_the_off_by_default_set(self):
        self.assertEqual({n for n, m in C.CATALOG.items() if not m['default_on']}, {n for n, m in C.CATALOG.items() if m['tier'] == 'optional'})

    def test_cheap_detectors_and_the_ai_consensus_stay_on(self):
        for name in ('AuthLogAgent', 'NetworkScanAgent', 'FileIntegrityAgent', 'IntelFeedAgent', 'SwarmConsensusAgent'):
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
        self.assertFalse(C.agent_enabled('WatchtowerAnalyzerAgent', {}))
        self.assertTrue(C.agent_enabled('SomeFutureAgent', {}))                      # unknown agents run
        self.assertTrue(C.agent_enabled('WatchtowerAnalyzerAgent', {'WatchtowerAnalyzerAgent': True}))
        self.assertFalse(C.agent_enabled('AuthLogAgent', {'AuthLogAgent': False}))

    def test_round_trip_is_atomic_and_keeps_other_choices(self):
        C.set_agent_enabled('HermesAnalyzerAgent', True, self.path)
        C.set_agent_enabled('SyslogAgent', False, self.path)
        C.set_agent_enabled('HermesAnalyzerAgent', False, self.path)
        self.assertEqual(C.load_overrides(self.path), {'HermesAnalyzerAgent': False, 'SyslogAgent': False})
        self.assertFalse(os.path.exists(self.path + '.tmp'))

    def test_default_path_cache_reflects_changes(self):
        orig = C._PATH
        C._PATH = self.path
        C._cache.update(mtime=None, data={})
        try:
            self.assertFalse(C.agent_enabled('OllamaAnalyzerAgent'))
            C.set_agent_enabled('OllamaAnalyzerAgent', True)
            self.assertTrue(C.agent_enabled('OllamaAnalyzerAgent'))
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


class ServiceWatchWithoutSystemd(unittest.TestCase):
    def test_a_machine_with_no_systemctl_is_skipped_quietly_not_failed_every_minute(self):
        from unittest import mock
        agent = R.ServiceWatchAgent.__new__(R.ServiceWatchAgent)
        agent.log = mock.Mock()
        agent.setup()
        with mock.patch.object(R.shutil, 'which', return_value=None), mock.patch.object(R.subprocess, 'run') as run:
            agent.scan()
            agent.scan()
        run.assert_not_called()                       # nothing was attempted
        self.assertEqual(agent.log.info.call_count, 1)  # and it said so only once


if __name__ == '__main__':
    unittest.main(verbosity=2)
