#!/usr/bin/env python3
"""Tests for model/data lineage of AI verdicts (2026-10-09).
Run:  swarmsentinel-env/bin/python3 backend/tools/test_lineage.py"""
import json
import os
import re
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(os.path.dirname(HERE), 'agents'), os.path.dirname(HERE), HERE]
os.environ.setdefault('SSAI_PROVIDER_CHECK', '0')
import lineage as L  # noqa: E402
import state_store as S  # noqa: E402
import ai_swarm_agent as asa  # noqa: E402


class P:
    """A stand-in panel member (a cloud provider unless base_url is on this network)."""

    def __init__(self, name, model, base_url='https://api.example.com/v1', local=False):
        self.name, self.model, self.base_url, self._local = name, model, base_url, local

    def capabilities(self):
        return {'provider': self.name, 'model': self.model, 'local': self._local}


class Analyzer:
    def __init__(self, *providers):
        self._providers = list(providers)


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.store = S.StateStore(os.path.join(self.dir, 'state.db'))
        for p in (mock.patch.object(L, '_instance_dir', return_value=self.dir),
                  mock.patch.object(asa, 'load_weights', return_value={}),
                  mock.patch.object(asa, 'load_provider_overrides', return_value={}),
                  mock.patch.object(asa, 'provider_enabled', return_value=True),
                  mock.patch.dict(os.environ, {'SSAI_VERSION': 'test-1', 'SSAI_REQUIRE_PROVIDER_APPROVAL': '0'})):
            p.start()
            self.addCleanup(p.stop)


class Manifest(Base):
    def test_same_panel_same_id(self):
        a = Analyzer(P('groq', 'm1'), P('gemini', 'g1'))
        self.assertEqual(L.manifest_id(L.build_manifest(a)), L.manifest_id(L.build_manifest(Analyzer(*reversed(a._providers)))))

    def test_model_swap_changes_the_id_and_is_described(self):
        old = L.build_manifest(Analyzer(P('groq', 'openai/gpt-oss-20b')))
        new = L.build_manifest(Analyzer(P('groq', 'openai/gpt-oss-120b')))
        self.assertNotEqual(L.manifest_id(old), L.manifest_id(new))
        self.assertEqual(L.diff(old, new), ['groq model: openai/gpt-oss-20b -> openai/gpt-oss-120b'])

    def test_added_removed_and_config_changes_are_described(self):
        old = L.build_manifest(Analyzer(P('groq', 'm')))
        with open(os.path.join(self.dir, 'ai_weights.json'), 'w') as f:
            json.dump({'groq': 2.0}, f)
        new = L.build_manifest(Analyzer(P('gemini', 'g')))
        d = L.diff(old, new)
        self.assertIn('provider removed from panel: groq (m)', d)
        self.assertIn('provider added to panel: gemini (g)', d)
        self.assertIn('config file changed: instance/ai_weights.json', d)

    def test_snapshot_keeps_override_files_for_rollback_but_not_in_the_id(self):
        with open(os.path.join(self.dir, 'ai_models.json'), 'w') as f:
            f.write('{"providers": {"groq": {"model": "x"}}}')
        m = L.build_manifest(Analyzer(P('groq', 'x')))
        self.assertEqual(m['snapshot']['ai_models.json'], '{"providers": {"groq": {"model": "x"}}}')
        self.assertEqual(L.manifest_id(m), L.manifest_id(dict(m, snapshot={})))

    def test_cloud_endpoint_host_recorded_not_the_path(self):
        m = L.build_manifest(Analyzer(P('groq', 'm', 'https://api.groq.com/openai/v1?key=nope')))
        self.assertEqual(m['members'][0]['endpoint_host'], 'api.groq.com')
        self.assertNotIn('nope', json.dumps(m))

    def test_providers_held_back_by_the_gate_are_not_in_the_manifest(self):
        with mock.patch.object(asa.provider_approval, 'cloud_allowed', return_value=False):
            m = L.build_manifest(Analyzer(P('groq', 'm')))
        self.assertEqual(m['members'], [])


class Tracking(Base):
    def test_events_only_when_something_moved(self):
        t = L.Tracker(self.store)
        mid, ch = t.refresh(Analyzer(P('groq', 'm1')))
        self.assertEqual(ch, ['first manifest recorded'])
        self.assertEqual(t.refresh(Analyzer(P('groq', 'm1'))), (mid, []))
        mid2, ch2 = t.refresh(Analyzer(P('groq', 'm2')))
        self.assertNotEqual(mid, mid2)
        self.assertEqual(ch2, ['groq model: m1 -> m2'])
        ev = self.store.lineage_events()
        self.assertEqual([e['new_id'] for e in ev], [mid2, mid])
        self.assertEqual(ev[0]['old_id'], mid)
        self.assertEqual(self.store.get_manifest(mid)['members'][0]['model'], 'm1')

    def test_tracker_picks_up_where_the_last_process_stopped(self):
        L.Tracker(self.store).refresh(Analyzer(P('groq', 'm1')))
        t2 = L.Tracker(S.StateStore(self.store.path))
        self.assertEqual(t2.refresh(Analyzer(P('groq', 'm1')))[1], [])            # no spurious "change" after restart

    def test_stamp_ties_a_verdict_to_the_manifest_and_models(self):
        t = L.Tracker(self.store)
        mid, _ = t.refresh(Analyzer(P('groq', 'm1'), P('gemini', 'g1')))
        c = {'consensus_verdict': 'malicious', 'ai_sources': ['groq', 'gemini'], 'models': {'groq': 'm1-exact'}}
        t.stamp(c, {'feodo': '2026-10-09T00:00:00+00:00'})
        self.assertEqual(c['lineage']['manifest'], mid)
        self.assertEqual(c['lineage']['models'], {'groq': 'm1-exact', 'gemini': 'g1'})   # the answering model wins
        self.assertEqual(c['lineage']['code_version'], 'test-1')
        self.assertEqual(c['lineage']['intel'], {'feodo': '2026-10-09T00:00:00+00:00'})


class PanelStampsModels(unittest.TestCase):
    def test_analyze_records_the_model_behind_each_answer(self):
        a = asa.AiSwarmAnalyzer.__new__(asa.AiSwarmAnalyzer)
        import threading
        a._health, a._health_lock = {}, threading.Lock()

        class Prov:
            def __init__(self, name, model):
                self.name, self.model, self.base_url = name, model, 'http://127.0.0.1:11434'

            def analyze(self, prompt):
                return '{"verdict": "malicious", "confidence": 90, "severity": "HIGH"}'

        class Sev:
            name = 'HIGH'

        class Ev:
            title, detail, source, agent, category, severity = 't', 'd', 's', 'a', 'c', Sev()

        with mock.patch.object(asa, '_is_local_provider', return_value=True):
            out = a._analyze_with(Ev(), [Prov('l1', 'llama3'), Prov('l2', 'mistral')], {})
        self.assertEqual(out['models'], {'l1': 'llama3', 'l2': 'mistral'})


class Version(unittest.TestCase):
    def test_env_wins(self):
        with mock.patch.dict(os.environ, {'SSAI_VERSION': 'v9'}):
            self.assertEqual(L.code_version(), 'v9')

    def test_git_checkout_is_read_without_running_git(self):
        with mock.patch.dict(os.environ, {'SSAI_VERSION': ''}):
            v = L.code_version()
        # A git checkout gives the 12-character commit; a release package gives its VERSION file, e.g. 'v0.1.2 (df1ec3a4ee60)'.
        self.assertTrue(v == 'unknown' or len(v) == 12 or re.fullmatch(r'\S+ \([0-9a-f]{12}\)', v), v)


class Restore(Base):
    def test_rollback_puts_back_the_override_files_of_that_manifest(self):
        import lineage_cli
        path = os.path.join(self.dir, 'ai_weights.json')
        with open(path, 'w') as f:
            f.write('{"groq": 1.0}')
        t = L.Tracker(self.store)
        good, _ = t.refresh(Analyzer(P('groq', 'm1')))
        with open(path, 'w') as f:
            f.write('{"groq": 0}')                                          # a bad edit
        with open(os.path.join(self.dir, 'ai_providers.json'), 'w') as f:
            f.write('{"enabled": {"groq": false}}')                         # a file that did not exist before
        t.refresh(Analyzer(P('groq', 'm1')))
        plan = lineage_cli.plan_restore(self.store, good, self.dir)
        self.assertEqual(sorted(os.path.basename(p_) for p_, _ in plan), ['ai_providers.json', 'ai_weights.json'])
        lineage_cli.apply_restore(plan)
        with open(path) as f:
            self.assertEqual(f.read(), '{"groq": 1.0}')
        self.assertFalse(os.path.exists(os.path.join(self.dir, 'ai_providers.json')))
        self.assertTrue(any(n.startswith('ai_weights.json.bak-') for n in os.listdir(self.dir)))
        self.assertEqual(lineage_cli.plan_restore(self.store, good, self.dir), [])

    def test_unknown_manifest(self):
        import lineage_cli
        with self.assertRaises(LookupError):
            lineage_cli.plan_restore(self.store, 'nope', self.dir)


if __name__ == '__main__':
    unittest.main(verbosity=2)
