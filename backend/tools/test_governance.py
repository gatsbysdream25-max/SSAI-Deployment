#!/usr/bin/env python3
"""GET /api/status/governance (2026-10-09): admin-only evidence page (approvals, red team, lineage, sync log).
Run:  swarmsentinel-env/bin/python3 backend/tools/test_governance.py"""
import os
import sys
import tempfile
import unittest

_TMP = tempfile.mkdtemp()
os.environ['DATA_DIR'] = _TMP
os.environ['DATABASE_URL'] = f'sqlite:///{_TMP}/gov-test.db'
os.environ['SSAI_API_KEY'] = ADMIN = 'governance-test-admin-key'
os.environ['SSAI_PROVIDER_CHECK'] = '0'
os.environ['SSAI_STATE_DB'] = os.path.join(_TMP, 'state.db')

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
sys.path[:0] = [os.path.join(BACKEND, 'agents'), BACKEND]


class Governance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import app as appmod
        if _TMP not in appmod.app.config['SQLALCHEMY_DATABASE_URI']:
            raise RuntimeError('refusing to run against a non-test database')
        cls.app = appmod.app
        cls.app.config['TESTING'] = True
        with cls.app.app_context():
            appmod.db.create_all()
        from agents import redteam, state_store
        st = state_store.store()
        st.save_manifest('abc123def456', {'members': [{'provider': 'groq', 'model': 'm'}], 'snapshot': {'ai_weights.json': '{}'}})
        st.log_lineage_change(None, 'abc123def456', ['first manifest recorded'])
        st.sync_finish(st.sync_start('feodo'), True, 200, 12)
        redteam.write_audit({'ts': '2026-10-09T00:00:00+00:00', 'passed': 13, 'failed': 0, 'skipped': 0,
                             'code_version': 'x', 'results': []}, os.path.join(_TMP, 'backend', 'instance', 'redteam_audit.jsonl'))

    def get(self, key=None):
        h = {'X-API-Key': key} if key else {}
        return self.app.test_client().get('/api/status/governance', headers=h)

    def test_anonymous_and_wrong_key_are_refused(self):
        self.assertEqual(self.get().status_code, 401)
        self.assertEqual(self.get('wrong').status_code, 401)

    def test_admin_gets_the_evidence(self):
        r = self.get(ADMIN)
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        ids = {p['id'] for p in body['providers']}
        self.assertIn('groq', ids)
        self.assertIn('microsoft-copilot', ids)
        self.assertFalse(body['approval_enforced'])
        self.assertEqual(body['lineage']['current']['manifest_id'], 'abc123def456')
        self.assertNotIn('snapshot', body['lineage']['current'])           # file contents are not served
        self.assertEqual(body['lineage']['events'][0]['changes'], ['first manifest recorded'])
        self.assertEqual(body['syncs'][0]['source'], 'feodo')
        self.assertEqual(body['redteam']['last_run']['passed'], 13)


if __name__ == '__main__':
    unittest.main(verbosity=2)
