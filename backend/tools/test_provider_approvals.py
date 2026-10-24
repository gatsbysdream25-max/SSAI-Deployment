#!/usr/bin/env python3
"""The third-party AI approval process (2026-10-09). This test IS the gate in the integration process: adding a cloud
provider to config/ai_models.json without an approval entry and a written record in docs/third-party-ai/ fails it.
Run:  swarmsentinel-env/bin/python3 backend/tools/test_provider_approvals.py"""
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
REPO = os.path.dirname(BACKEND)
sys.path[:0] = [os.path.join(BACKEND, 'agents'), BACKEND]
os.environ.setdefault('SSAI_PROVIDER_CHECK', '0')
import provider_approval as PA  # noqa: E402
import model_config  # noqa: E402
import ai_swarm_agent as asa  # noqa: E402

SHIPPED = PA.load(override_path=os.path.join(tempfile.mkdtemp(), 'none.json'))
ITEMS = PA.checklist_items()


def cloud_providers():
    out = []
    for pid, e in model_config.load(override_path=os.path.join(tempfile.mkdtemp(), 'none.json')).items():
        if e['kind'] == 'ollama' and asa._private_endpoint(model_config.endpoint_of(e)):
            continue
        out.append(pid)
    return out


class Records(unittest.TestCase):
    def test_every_cloud_provider_has_an_entry_and_a_written_record(self):
        for pid in cloud_providers():
            with self.subTest(provider=pid):
                self.assertIn(pid, SHIPPED, f'{pid} is in ai_models.json but has no entry in provider_approvals.json')
                rec = SHIPPED[pid].get('record')
                self.assertTrue(rec and os.path.isfile(os.path.join(REPO, rec)), f'{pid}: record file {rec} missing')

    def test_copilot_integration_has_a_record(self):
        self.assertIn('microsoft-copilot', SHIPPED)
        self.assertTrue(os.path.isfile(os.path.join(REPO, SHIPPED['microsoft-copilot']['record'])))

    def test_entries_are_well_formed(self):
        for pid, e in SHIPPED.items():
            with self.subTest(provider=pid):
                self.assertIn(e.get('status'), PA.STATUSES)
                self.assertEqual(set(e.get('checklist') or {}), set(ITEMS), 'checklist keys must match checklist_items')
                self.assertTrue(all(isinstance(v, bool) for v in e['checklist'].values()))
                self.assertEqual(PA.problems(e), [], f'{pid} is marked approved but incomplete')

    def test_every_record_names_the_four_layers_and_the_checklist(self):
        for pid, e in SHIPPED.items():
            with self.subTest(provider=pid), open(os.path.join(REPO, e['record']), encoding='utf-8') as f:
                text = f.read().lower()
            for word in ('infrastructure', 'configuration', 'data submitted', 'checklist', 'status'):
                self.assertIn(word, text, f'{e["record"]} lacks a "{word}" section')

    def test_ids_in_the_record_files_match(self):
        for pid, e in SHIPPED.items():
            with self.subTest(provider=pid), open(os.path.join(REPO, e['record']), encoding='utf-8') as f:
                self.assertIn(f'`{pid}`', f.read(), f'{e["record"]} does not name its provider id `{pid}`')


class Logic(unittest.TestCase):
    def entries(self, **over):
        e = {'status': 'approved', 'reviewed': '2026-10-09', 'reviewer': 'Security lead',
             'checklist': {k: True for k in ITEMS}}
        e.update(over)
        return {'groq': e}

    def test_complete_approval_counts(self):
        self.assertEqual(PA.status('groq', self.entries()), 'approved')

    def test_incomplete_approval_is_only_pending(self):
        e = self.entries(checklist=dict({k: True for k in ITEMS}, audit_rights=False))
        self.assertEqual(PA.status('groq', e), 'pending')
        self.assertEqual(PA.status('groq', self.entries(reviewer=None)), 'pending')

    def test_extra_models_share_their_providers_approval(self):
        self.assertEqual(PA.base_id('groq-llama-3.3-70b', self.entries()), 'groq')
        self.assertEqual(PA.status('groq-llama-3.3-70b', self.entries()), 'approved')
        self.assertEqual(PA.status('nobody', self.entries()), 'unlisted')

    def test_gate_is_off_unless_switched_on(self):
        pending = self.entries(status='pending')
        with mock.patch.dict(os.environ, {'SSAI_REQUIRE_PROVIDER_APPROVAL': '0'}):
            self.assertTrue(PA.cloud_allowed('groq', pending))
            self.assertFalse(PA.cloud_allowed('groq', self.entries(status='rejected')))     # rejected is always out
        with mock.patch.dict(os.environ, {'SSAI_REQUIRE_PROVIDER_APPROVAL': '1'}):
            self.assertFalse(PA.cloud_allowed('groq', pending))
            self.assertFalse(PA.cloud_allowed('unknown-provider', pending))
            self.assertTrue(PA.cloud_allowed('groq', self.entries()))

    def test_instance_override_merges_item_by_item(self):
        d = tempfile.mkdtemp()
        shipped = os.path.join(d, 'shipped.json')
        inst = os.path.join(d, 'inst.json')
        with open(shipped, 'w') as f:
            json.dump({'checklist_items': {'a': '', 'b': ''},
                       'providers': {'groq': {'status': 'pending', 'checklist': {'a': False, 'b': False}}}}, f)
        with open(inst, 'w') as f:
            json.dump({'providers': {'groq': {'status': 'approved', 'reviewed': '2026-10-09', 'checklist': {'a': True}}}}, f)
        e = PA.load(shipped, inst)['groq']
        self.assertEqual(e['checklist'], {'a': True, 'b': False})
        self.assertEqual(e['status'], 'approved')


class PanelGate(unittest.TestCase):
    class Prov:
        def __init__(self, name, base_url):
            self.name, self.base_url = name, base_url

    def setUp(self):
        for p in (mock.patch.object(asa, 'load_weights', return_value={}),
                  mock.patch.object(asa, 'load_provider_overrides', return_value={}),
                  mock.patch.object(asa, 'provider_enabled', return_value=True)):
            p.start()
            self.addCleanup(p.stop)

    def test_enforced_gate_keeps_unapproved_cloud_out_but_local_in(self):
        cloud = self.Prov('groq', 'https://api.groq.com/openai/v1')
        local = asa._OllamaModelProvider.__new__(asa._OllamaModelProvider)
        local.name, local.base_url = 'ollama-hermes3', 'http://192.168.1.20:11434'
        with mock.patch.dict(os.environ, {'SSAI_REQUIRE_PROVIDER_APPROVAL': '1'}):
            self.assertFalse(asa.panel_allowed(cloud))
            self.assertTrue(asa.panel_allowed(local))
        with mock.patch.dict(os.environ, {'SSAI_REQUIRE_PROVIDER_APPROVAL': '0'}):
            self.assertTrue(asa.panel_allowed(cloud))                     # default: nothing changes for existing installs


if __name__ == '__main__':
    unittest.main(verbosity=2)
