#!/usr/bin/env python3
"""Secrets must not survive into logs or stored error messages (2026-09-20).
Run:  swarmsentinel-env/bin/python3 backend/tools/test_redact.py"""
import io
import logging
import os
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(os.path.dirname(HERE), 'agents')]
import redact as R  # noqa: E402


class Redact(unittest.TestCase):
    def gone(self, text, secret):
        out = R.redact(text)
        self.assertNotIn(secret, out, text)
        self.assertIn('[redacted]', out, text)
        return out

    def test_the_exact_shape_of_the_leak_that_started_this(self):
        e = ('429 Client Error: Too Many Requests for url: '
             'https://generativelanguage.googleapis.com/v1beta/models/gemini:generateContent?key=AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q')
        out = self.gone(e, 'AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q')
        self.assertIn('generateContent?key=[redacted]', out)                 # the rest of the message stays useful

    def test_query_strings_headers_and_json_bodies(self):
        cases = [
            ('GET /x?a=1&api_key=abcdef123456&b=2', 'abcdef123456'), ('GET /x?token=zzzzzz999999', 'zzzzzz999999'),
            ('Authorization: Bearer abcDEF123456789xyz', 'abcDEF123456789xyz'), ('authorization: basic dXNlcjpwYXNzd29yZA==', 'dXNlcjpwYXNzd29yZA'),
            ("headers={'X-API-Key': 'super-secret-value-123'}", 'super-secret-value-123'), ('x-goog-api-key: AbCdEf123456', 'AbCdEf123456'),
            ('{"api_key": "abcdefghijk", "model": "m"}', 'abcdefghijk'), ('password=hunter2hunter2 next', 'hunter2hunter2'),
            ('sid=SESSION_ABCDEF_123 done', 'SESSION_ABCDEF_123'),
        ]
        for text, secret in cases:
            self.gone(text, secret)

    def test_well_known_key_formats_anywhere(self):
        for k in ('gsk_' + 'a' * 40, 'sk-ant-api03-' + 'b' * 30, 'hf_' + 'c' * 34, 'ghp_' + 'd' * 36, 'ssn_' + 'e' * 43, 'AIza' + 'f' * 35):
            self.gone(f'provider said no for {k} again', k)

    def test_exact_values_of_secret_looking_environment_variables(self):
        with mock.patch.dict(os.environ, {'MY_SERVICE_TOKEN': 'an-unusual-format/0987654321', 'SSH_AUTH_SOCK': '/tmp/ssh-XXXXXXXX/agent.1',
                                          'HOME': '/home/someone', 'SHORT_KEY': 'abc'}):
            self.gone('connect failed using an-unusual-format/0987654321 as credential', 'an-unusual-format/0987654321')
            self.assertEqual(R.redact('socket /tmp/ssh-XXXXXXXX/agent.1 ok'), 'socket /tmp/ssh-XXXXXXXX/agent.1 ok')   # not a secret
            self.assertEqual(R.redact('the value abc is fine'), 'the value abc is fine')                                  # too short to be a key

    def test_ordinary_text_is_left_alone(self):
        for text in ('Heartbeat: 15/15 agents alive', 'keyboard tokenizer monkey', 'inside=abc123456789 outside', 'THREAT [HIGH] c2-beacon: 203.0.113.9:4444',
                     'PiHoleAgent disabled — set PIHOLE_IP and PIHOLE_PASSWORD (a Pi-hole app password)', 'GET /api/threats/?limit=50 200',
                     'consensus: malicious (2 AI(s): groq, gemini)', '', 'key', 'the token is valid'):
            self.assertEqual(R.redact(text), text, text)

    def test_non_strings_and_empty_input_pass_through(self):
        for v in (None, 5, [], {'a': 1}, b'bytes'):
            self.assertEqual(R.redact(v), v)


class LogHook(unittest.TestCase):
    def setUp(self):
        R.install_log_redaction()
        self.buf = io.StringIO()
        self.h = logging.StreamHandler(self.buf)
        self.h.setFormatter(logging.Formatter('%(name)s %(message)s'))
        self.log = logging.getLogger('redact-test')
        self.log.setLevel(logging.INFO)
        self.log.propagate = False
        self.log.addHandler(self.h)

    def tearDown(self):
        self.log.removeHandler(self.h)

    def test_every_logging_style_is_covered(self):
        secret = 'AIza' + 'Z' * 35
        e = Exception(f'boom for url: https://x.example/y?key={secret}')
        self.log.warning('f-string %s', 'a')                                   # sanity
        self.log.warning(f'Screenshot analysis failed: {e}')                    # pre-formatted (the original bug)
        self.log.warning('Screenshot analysis failed: %s', e)                   # lazy %s with an exception object
        self.log.warning('key is %s', secret)                                   # lazy %s with a string
        self.log.error('failed', exc_info=False)
        out = self.buf.getvalue()
        self.assertNotIn(secret, out)
        self.assertEqual(out.count('[redacted]'), 3)

    def test_installing_twice_does_not_double_wrap_and_broken_records_do_not_raise(self):
        f1 = logging.getLogRecordFactory()
        R.install_log_redaction()
        self.assertIs(logging.getLogRecordFactory(), f1)
        self.log.info('%d items %s', 3, {'k': 'v'})                             # non-string args untouched
        self.log.info('bad format %s %s', 'only-one')                          # logging swallows this itself: must not crash us
        self.assertIn('3 items', self.buf.getvalue())


if __name__ == '__main__':
    unittest.main(verbosity=2)
