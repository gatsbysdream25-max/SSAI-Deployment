#!/usr/bin/env python3
"""The Microsoft Copilot / Teams settings card (2026-11-04): who may use it, what it accepts, where values land, and that no
secret is ever sent back. Also the clearer error when a provider key cannot be saved.
Run:  swarmsentinel-env/bin/python3 backend/tools/test_microsoft_settings.py"""
import os
import sys
import tempfile
import unittest
from unittest import mock

_TMP = tempfile.mkdtemp()
os.environ['DATA_DIR'] = _TMP
os.environ['DATABASE_URL'] = f'sqlite:///{_TMP}/ms-test.db'
os.environ['SSAI_API_KEY'] = ADMIN = 'ms-test-admin-key'
os.environ['SSAI_PROVIDER_CHECK'] = '0'

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
sys.path[:0] = [os.path.join(BACKEND, 'agents'), BACKEND]

TENANT = '11111111-2222-3333-4444-555555555555'
APP = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
PERSON = '99999999-8888-7777-6666-000000000001'
SECRET = 'Zx9~very-secret-value-0123456789'


class MicrosoftSettings(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import app as appmod
        if _TMP not in appmod.app.config['SQLALCHEMY_DATABASE_URI']:
            raise RuntimeError('refusing to run against a non-test database')
        cls.appmod, cls.app = appmod, appmod.app
        cls.app.config['TESTING'] = True

    def setUp(self):
        self.dir = tempfile.mkdtemp(dir=_TMP)
        self.env = os.path.join(self.dir, '.env')
        with open(self.env, 'w') as f:
            f.write('SSAI_API_KEY=keep-me\n')
        os.makedirs(os.path.join(self.dir, 'copilot'))
        for patch in (mock.patch.object(self.appmod, '_ENV_PATH', self.env),
                      mock.patch('routes.microsoft._restart_hub_soon', return_value=True)):
            patch.start()
            self.addCleanup(patch.stop)
        self.addCleanup(lambda: [os.environ.pop(k, None) for k in
                                 ('SSAI_COPILOT_KEY', 'SSAI_COPILOT_TENANT_ID', 'SSAI_COPILOT_AUDIENCE', 'SSAI_COPILOT_APPROVERS')])
        self.c = self.app.test_client()
        self.h = {'X-API-Key': ADMIN}

    def post(self, body):
        return self.c.post('/api/settings/microsoft', json=body, headers=self.h)

    def read(self, path):
        if not os.path.exists(path):
            return ''
        with open(path, encoding='utf-8') as f:
            return f.read()

    def test_only_an_admin_may_read_or_change_it(self):
        self.assertEqual(self.c.get('/api/settings/microsoft').status_code, 401)
        self.assertEqual(self.c.post('/api/settings/microsoft', json={'tenant_id': TENANT}).status_code, 401)
        self.assertEqual(self.c.get('/api/settings/microsoft', headers=self.h).status_code, 200)

    def test_saving_writes_both_files_and_never_returns_a_secret(self):
        r = self.post({'tenant_id': TENANT, 'app_id': APP, 'app_secret': SECRET, 'approvers': PERSON})
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        body = r.get_data(as_text=True)
        self.assertNotIn(SECRET, body)
        data = r.get_json()
        self.assertTrue(data['app_secret_set'])
        self.assertTrue(data['lane_key_set'])
        self.assertTrue(data['approvals_from_teams'])               # tenant + audience (defaults to the app id) + approver
        hub, bot = self.read(self.env), os.path.join(self.dir, 'copilot', '.env')
        self.assertIn('SSAI_API_KEY=keep-me', hub)                  # unrelated lines are kept
        self.assertIn(f'SSAI_COPILOT_TENANT_ID={TENANT}', hub)
        self.assertIn(f'SSAI_COPILOT_AUDIENCE={APP}', hub)
        self.assertNotIn(SECRET, hub)                               # the secret lives only in copilot/.env
        self.assertIn(SECRET, self.read(bot))
        key = [ln.split('=', 1)[1] for ln in hub.splitlines() if ln.startswith('SSAI_COPILOT_KEY=')][0]
        self.assertIn(f'SSAI_COPILOT_KEY={key}', self.read(bot))     # the bot and the hub share one lane key
        self.assertNotIn(key, body)
        if os.name == 'posix':
            self.assertEqual(os.stat(bot).st_mode & 0o777, 0o600)

    def test_a_later_save_keeps_what_was_set_and_the_same_key(self):
        self.post({'tenant_id': TENANT, 'app_id': APP, 'app_secret': SECRET, 'approvers': PERSON})
        before = self.read(self.env)
        self.post({'hub_url': 'http://192.168.1.10:5000'})
        after = self.read(self.env)
        self.assertEqual(before, after)                             # the hub file did not change; key stays the same
        self.assertIn(SECRET, self.read(os.path.join(self.dir, 'copilot', '.env')))

    def test_bad_values_are_refused_before_anything_is_written(self):
        for body in ({'tenant_id': 'not-a-guid'}, {'app_id': '123'}, {'approvers': 'bob@example.com'},
                     {'audience': 'http://evil.example'}, {'app_secret': 'two words'},
                     {'app_secret': 'line\nbreak'}, {'hub_url': 'ftp://x'}):
            r = self.post(body)
            self.assertEqual(r.status_code, 400, body)
        self.assertEqual(self.read(self.env), 'SSAI_API_KEY=keep-me\n')
        self.assertFalse(os.path.exists(os.path.join(self.dir, 'copilot', '.env')))

    def test_clear_removes_every_microsoft_setting(self):
        self.post({'tenant_id': TENANT, 'app_id': APP, 'app_secret': SECRET, 'approvers': PERSON})
        r = self.post({'clear': True})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.read(self.env).strip(), 'SSAI_API_KEY=keep-me')
        self.assertNotIn(SECRET, self.read(os.path.join(self.dir, 'copilot', '.env')))
        self.assertFalse(r.get_json()['lane_key_set'])

    def test_an_unwritable_folder_gives_a_plain_message_and_the_fix(self):
        with mock.patch('routes.microsoft.envfile.set_values', side_effect=PermissionError(13, 'Permission denied')):
            r = self.post({'tenant_id': TENANT})
        self.assertEqual(r.status_code, 500)
        self.assertIn('chown', r.get_json()['fix'])

    def test_a_provider_key_that_cannot_be_saved_says_why(self):
        with mock.patch('envfile.set_values', side_effect=PermissionError(13, 'Permission denied')):
            r = self.c.post('/api/setup/activate', json={'provider_id': 'groq', 'api_key': 'gsk_testtesttesttest'}, headers=self.h)
        self.assertEqual(r.status_code, 500)
        msg = r.get_json()['error']
        self.assertIn('Permission denied', msg)
        self.assertIn('chown', msg)

    def test_the_update_token_is_admin_only_stored_owner_only_and_never_returned(self):
        token = 'github_pat_11AAAAAAA0abcdefghijklmnopqrstuvwxyz0123456789'
        url = '/api/settings/update-token'
        self.assertEqual(self.c.post(url, json={'token': token}).status_code, 401)
        self.assertEqual(self.c.get(url).status_code, 401)
        self.assertFalse(self.c.get(url, headers=self.h).get_json()['set'])
        r = self.c.post(url, json={'token': token}, headers=self.h)
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        self.assertNotIn(token, r.get_data(as_text=True))
        path = os.path.join(self.dir, '.update-token')
        self.assertEqual(self.read(path).strip(), token)
        if os.name == 'posix':
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        got = self.c.get(url, headers=self.h)
        self.assertTrue(got.get_json()['set'])
        self.assertNotIn(token, got.get_data(as_text=True))
        for bad in ('short', 'has space in it 12345678901234567890', 'line' + chr(10) + 'break12345678901234567890', 12345):
            self.assertEqual(self.c.post(url, json={'token': bad}, headers=self.h).status_code, 400, bad)
        self.assertEqual(self.read(path).strip(), token)            # a refused value changes nothing
        self.assertEqual(self.c.post(url, json={'clear': True}, headers=self.h).status_code, 200)
        self.assertFalse(os.path.exists(path))


if __name__ == '__main__':
    unittest.main(verbosity=2)
