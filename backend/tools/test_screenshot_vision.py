#!/usr/bin/env python3
"""Screenshot -> threat draft. Audit F-01 (2026-10-20): an image cannot be redacted, so it is never sent to a cloud AI. It is read
by a vision model on this network (an Ollama server at a private address) or not at all.
Each test fails without the fix: the old code posted the image to Anthropic or Gemini whenever a key was set.
Run:  swarmsentinel-env/bin/python3 backend/tools/test_screenshot_vision.py"""
import base64
import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

_TMP = tempfile.mkdtemp()
os.environ['DATA_DIR'] = _TMP
os.environ['DATABASE_URL'] = f'sqlite:///{_TMP}/vision-test.db'
os.environ['SSAI_API_KEY'] = ADMIN = 'vision-test-admin-key'

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
sys.path[:0] = [os.path.join(BACKEND, 'agents'), BACKEND]
import ai_swarm_agent as swarm  # noqa: E402

IMAGE = b'\x89PNG\r\n\x1a\n' + b'not-really-a-png' * 10
GEMINI_KEY, ANTHROPIC_KEY = 'AIzaFAKEFAKEFAKEFAKEFAKEFAKEFAKE12345', 'sk-ant-FAKEFAKEFAKEFAKEFAKE'
DRAFT = {'threat_type': 'phishing-email', 'severity': 'high', 'description': 'A fake login page.', 'confidence': 88}
LOCAL = 'http://127.0.0.1:11434'
LOCAL_ENTRY = {'kind': 'ollama', 'model': 'gemma4:12b', 'endpoint': LOCAL}


def ollama_reply(payload):
    return mock.Mock(status_code=200, raise_for_status=lambda: None, json=lambda: {'response': payload})


def env(**kw):
    """Exactly these variables, nothing inherited from the machine's real .env."""
    keep = ('ANTHROPIC_API_KEY', 'GEMINI_API_KEY', 'SSAI_CLOUD_VISION', 'SSAI_VISION_PROVIDER', 'SSAI_VISION_MODEL')
    base = {k: v for k, v in os.environ.items() if k not in keep}
    base.update(kw)
    return mock.patch.dict(os.environ, base, clear=True)


def reader(entry=LOCAL_ENTRY):
    """Pretend the model config names this entry as the vision reader."""
    return mock.patch.object(swarm.model_config, 'get', return_value=entry)


class Analyze(unittest.TestCase):
    def test_cloud_keys_never_send_an_image_anywhere(self):
        for flag in ({}, {'SSAI_CLOUD_VISION': '1'}):
            with env(GEMINI_API_KEY=GEMINI_KEY, ANTHROPIC_API_KEY=ANTHROPIC_KEY, **flag), reader(None), \
                    mock.patch.object(swarm.requests, 'post') as post:
                self.assertIsNone(swarm.analyze_screenshot_image(IMAGE))
            post.assert_not_called()

    def test_with_a_reader_the_only_destination_is_the_local_server_and_no_key_is_sent(self):
        with env(GEMINI_API_KEY=GEMINI_KEY, ANTHROPIC_API_KEY=ANTHROPIC_KEY), reader(), \
                mock.patch.object(swarm.requests, 'post', return_value=ollama_reply(json.dumps(DRAFT))) as post:
            out = swarm.analyze_screenshot_image(IMAGE, 'image/png')
        self.assertEqual((out['threat_type'], out['severity'], out['source']), ('phishing-email', 'high', 'ollama-gemma4'))
        self.assertEqual(post.call_count, 1)
        args, kw = post.call_args
        self.assertEqual(args[0], LOCAL + '/api/generate')
        self.assertNotIn('headers', kw)                                                 # no credentials go with it
        self.assertEqual(kw['json']['images'], [base64.b64encode(IMAGE).decode()])
        self.assertEqual(kw['json']['model'], 'gemma4:12b')
        self.assertNotIn(GEMINI_KEY + ANTHROPIC_KEY, json.dumps(kw))

    def test_a_reader_that_is_not_on_this_network_is_refused(self):
        for endpoint in ('https://api.example.com', 'http://203.0.113.9:11434', 'http://ollama.example.org'):
            with env(), reader(dict(LOCAL_ENTRY, endpoint=endpoint)), mock.patch.object(swarm.requests, 'post') as post:
                self.assertIsNone(swarm.analyze_screenshot_image(IMAGE), endpoint)
                self.assertIn('not on this network', swarm.screenshot_unavailable_reason())
            post.assert_not_called()

    def test_a_cloud_model_cannot_be_named_as_the_reader(self):
        with env(SSAI_VISION_PROVIDER='groq'), reader({'kind': 'openai', 'model': 'x', 'endpoint': 'https://api.groq.com/openai/v1'}), \
                mock.patch.object(swarm.requests, 'post') as post:
            self.assertIsNone(swarm.analyze_screenshot_image(IMAGE))
            self.assertIn('not a local Ollama model', swarm.screenshot_unavailable_reason())
        post.assert_not_called()

    def test_the_audit_line_names_the_reader_and_never_holds_the_image(self):
        with env(), reader(), mock.patch.object(swarm.requests, 'post', return_value=ollama_reply(json.dumps(DRAFT))), \
                self.assertLogs(swarm.log, 'INFO') as logs:
            swarm.analyze_screenshot_image(IMAGE)
        line = [m for m in logs.output if 'Screenshot read by' in m]
        self.assertEqual(len(line), 1)
        self.assertIn(hashlib.sha256(IMAGE).hexdigest()[:12], line[0])
        self.assertNotIn(base64.b64encode(IMAGE).decode()[:20], '\n'.join(logs.output))

    def test_an_old_cloud_switch_is_ignored_with_a_warning(self):
        with env(SSAI_CLOUD_VISION='1'), reader(), mock.patch.object(swarm.requests, 'post', return_value=ollama_reply(json.dumps(DRAFT))), \
                self.assertLogs(swarm.log, 'WARNING') as logs:
            swarm.analyze_screenshot_image(IMAGE)
        self.assertTrue(any('no longer used' in m for m in logs.output))

    def test_json_wrapped_in_prose_is_recovered_and_garbage_is_not_a_draft(self):
        with env(), reader(), mock.patch.object(swarm.requests, 'post',
                                                return_value=ollama_reply('Sure! ```json\n' + json.dumps(DRAFT) + '\n``` hope it helps')):
            self.assertEqual(swarm.analyze_screenshot_image(IMAGE)['severity'], 'high')
        for junk in ('I cannot help with that', '{not json}', '', '}{'):
            with env(), reader(), mock.patch.object(swarm.requests, 'post', return_value=ollama_reply(junk)):
                self.assertIsNone(swarm.analyze_screenshot_image(IMAGE), junk)

    def test_a_down_server_or_a_model_without_vision_is_a_none_not_a_crash(self):
        with env(), reader(), mock.patch.object(swarm.requests, 'post', side_effect=OSError('connection refused')):
            self.assertIsNone(swarm.analyze_screenshot_image(IMAGE))
        bad = mock.Mock(status_code=400, raise_for_status=mock.Mock(side_effect=RuntimeError('model does not support images')))
        with env(), reader(), mock.patch.object(swarm.requests, 'post', return_value=bad):
            self.assertIsNone(swarm.analyze_screenshot_image(IMAGE))


class Route(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import app as appmod
        if _TMP not in appmod.app.config['SQLALCHEMY_DATABASE_URI']:
            raise RuntimeError('refusing to run against a non-test database')
        cls.app, cls.db = appmod.app, appmod.db
        cls.app.config['TESTING'] = True
        appmod._AUDIT_PATH = os.path.join(_TMP, 'audit.jsonl')

    def setUp(self):
        self.ctx = self.app.app_context()
        self.ctx.push()
        self.db.create_all()

    def tearDown(self):
        self.db.session.remove()
        self.ctx.pop()

    def post(self, data=None, headers=None):
        return self.app.test_client().post('/api/threats/from_screenshot', data=data, content_type='multipart/form-data',
                                           headers={'X-API-Key': ADMIN} if headers is None else headers)

    def upload(self, content=IMAGE, mime='image/png', **extra):
        return {'image': (io.BytesIO(content), 'shot.png', mime), **extra}

    def test_it_needs_the_admin_key(self):
        self.assertEqual(self.post(self.upload(), headers={}).status_code, 401)
        self.assertEqual(self.post(self.upload(), headers={'X-API-Key': 'wrong'}).status_code, 401)

    def test_bad_uploads_are_rejected_before_any_ai_is_called(self):
        with mock.patch('routes.threats.analyze_screenshot_image') as analyze:
            self.assertEqual(self.post({}).status_code, 400)                                                     # no image field
            self.assertEqual(self.post(self.upload(mime='image/gif')).status_code, 400)                          # not png/jpeg/webp
            self.assertEqual(self.post(self.upload(b'x' * (8 * 1024 * 1024 + 1))).status_code, 413)              # over 8 MB
        analyze.assert_not_called()

    def test_a_draft_becomes_a_threat_with_the_provider_recorded_and_the_severity_normalized(self):
        with mock.patch('routes.threats.analyze_screenshot_image', return_value=dict(DRAFT, severity='HIGH', source='ollama-gemma4')):
            r = self.post(self.upload(url='https://phish.example/login'))
        self.assertEqual(r.status_code, 201)
        body = r.get_json()
        self.assertEqual((body['ai_confidence'], body['threat']['severity'], body['threat']['type']), (88, 'medium', 'phishing-email'))
        self.assertIn('not yet checked by the panel; it rated this high', body['threat']['description'])   # F-16: a draft, capped
        self.assertEqual(body['threat']['url'], 'https://phish.example/login')
        self.assertEqual(body['threat']['detected_by'], 'screenshot-upload:ollama-gemma4')

    def test_a_nonsense_severity_falls_back_to_low(self):
        with mock.patch('routes.threats.analyze_screenshot_image', return_value=dict(DRAFT, severity='apocalyptic', source='gemini')):
            r = self.post(self.upload())
        self.assertEqual(r.get_json()['threat']['severity'], 'low')

    def test_no_provider_answering_is_a_503_that_says_what_to_do(self):
        with mock.patch('routes.threats.analyze_screenshot_image', return_value=None):
            r = self.post(self.upload())
        self.assertEqual(r.status_code, 503)
        self.assertIn('SSAI_VISION_PROVIDER', r.get_json()['error'])

    def test_with_no_local_reader_the_route_explains_and_never_calls_the_ai(self):
        with env(), reader(None), mock.patch('routes.threats.analyze_screenshot_image') as analyze:
            r = self.post(self.upload())
        self.assertEqual(r.status_code, 503)
        self.assertIn('never sent to cloud AI', r.get_json()['error'])
        self.assertIn('none is set up', r.get_json()['error'])
        analyze.assert_not_called()


if __name__ == '__main__':
    unittest.main(verbosity=1)
