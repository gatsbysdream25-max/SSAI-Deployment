#!/usr/bin/env python3
"""Tests for the request each AI provider sends (regressions found by the benchmark, 2026-09-19).
Run:  python3 backend/tools/test_ai_providers.py"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(os.path.dirname(HERE), 'agents'), os.path.dirname(HERE)]
import ai_swarm_agent as swarm  # noqa: E402


class FakeResp:
    def __init__(self, data, status=200):
        self._d, self.status_code = data, status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f'HTTP {self.status_code}')

    def json(self):
        return self._d


class Capture:
    def __init__(self, reply):
        self.reply, self.calls = reply, []

    def __call__(self, url, headers=None, json=None, timeout=None):
        self.calls.append({'url': url, 'headers': headers, 'json': json, 'timeout': timeout})
        return FakeResp(self.reply)


OPENAI_REPLY = {'choices': [{'message': {'content': '{"verdict":"benign"}'}}]}
ANTHROPIC_REPLY = {'content': [{'text': '{"verdict":"benign"}'}]}


class ProviderRequests(unittest.TestCase):
    def setUp(self):
        self._post = swarm.requests.post
        self._env = dict(os.environ)

    def tearDown(self):
        swarm.requests.post = self._post
        os.environ.clear()
        os.environ.update(self._env)

    def run_provider(self, provider, reply=OPENAI_REPLY):
        cap = Capture(reply)
        swarm.requests.post = cap
        out = provider.analyze('PROMPT')
        self.assertEqual(len(cap.calls), 1)
        return cap.calls[0], out

    def test_groq_reasoning_model_gets_low_effort_and_room_to_answer(self):
        call, out = self.run_provider(swarm._OpenAICompatProvider('groq', 'X_KEY', 'https://api.groq.com/openai/v1', 'openai/gpt-oss-20b'))
        self.assertEqual(call['json']['reasoning_effort'], 'low')
        self.assertGreaterEqual(call['json']['max_tokens'], 1500)
        self.assertEqual(out, '{"verdict":"benign"}')

    def test_non_reasoning_openai_compat_model_is_unchanged(self):
        call, _ = self.run_provider(swarm._OpenAICompatProvider('cerebras', 'X_KEY', 'https://api.cerebras.ai/v1', 'llama3.1-8b'))
        self.assertNotIn('reasoning_effort', call['json'])
        self.assertEqual(call['json']['max_tokens'], 600)

    def test_gemini_default_model_gets_large_budget_and_low_effort(self):
        os.environ.pop('GEMINI_MODEL', None)
        os.environ['GEMINI_API_KEY'] = 'k'
        g = swarm._GeminiProvider()
        call, _ = self.run_provider(g)
        self.assertEqual(call['json']['max_tokens'], 2000)
        self.assertEqual(call['json']['reasoning_effort'], 'low')
        self.assertIn('generativelanguage.googleapis.com', call['url'])

    def test_older_gemini_models_do_not_get_reasoning_effort(self):
        for model in ('gemini-1.5-flash', 'gemini-2.0-flash'):
            os.environ['GEMINI_API_KEY'], os.environ['GEMINI_MODEL'] = 'k', model
            call, _ = self.run_provider(swarm._GeminiProvider())
            self.assertNotIn('reasoning_effort', call['json'], model)

    def test_huggingface_uses_the_router_and_chat_format(self):
        os.environ['HF_TOKEN'] = 't'
        os.environ.pop('HF_MODEL', None)
        h = swarm._HuggingFaceProvider()
        call, out = self.run_provider(h)
        self.assertEqual(call['url'], 'https://router.huggingface.co/v1/chat/completions')
        self.assertNotIn('api-inference', call['url'])
        self.assertEqual(call['json']['messages'], [{'role': 'user', 'content': 'PROMPT'}])
        self.assertEqual(call['json']['model'], 'meta-llama/Llama-3.1-8B-Instruct')
        self.assertEqual(call['headers']['Authorization'], 'Bearer t')
        self.assertEqual(out, '{"verdict":"benign"}')
        self.assertEqual(swarm._REGISTRY_BY_ID['huggingface']['model'], h.model)   # dashboard shows the real model

    def test_huggingface_model_can_still_be_overridden(self):
        os.environ['HF_TOKEN'], os.environ['HF_MODEL'] = 't', 'meta-llama/Llama-3.3-70B-Instruct'
        call, _ = self.run_provider(swarm._HuggingFaceProvider())
        self.assertEqual(call['json']['model'], 'meta-llama/Llama-3.3-70B-Instruct')

    def test_http_errors_still_raise_so_health_tracking_sees_them(self):
        swarm.requests.post = lambda *a, **k: FakeResp({}, 402)
        os.environ['HF_TOKEN'] = 't'
        with self.assertRaises(RuntimeError):
            swarm._HuggingFaceProvider().analyze('p')

    def ollama(self, **attrs):
        class Local(swarm._OllamaProvider):
            def _discover(self):          # no network in tests
                pass
        p = Local()
        p.base_url, p.model = 'http://h:11434', 'm'
        for k, v in attrs.items():
            setattr(p, k, v)
        return p

    def test_ollama_json_mode_is_off_by_default(self):
        os.environ.pop('OLLAMA_JSON_MODE', None)
        call, out = self.run_provider(self.ollama(), {'response': '{"verdict":"benign"}'})
        self.assertNotIn('format', call['json'])
        self.assertEqual(out, '{"verdict":"benign"}')

    def test_ollama_json_mode_via_env_or_attribute(self):
        os.environ['OLLAMA_JSON_MODE'] = '1'
        call, _ = self.run_provider(self.ollama(), {'response': '{}'})
        self.assertEqual(call['json']['format'], 'json')
        os.environ['OLLAMA_JSON_MODE'] = '0'
        call, _ = self.run_provider(self.ollama(json_mode=True), {'response': '{}'})          # attribute wins (used by the benchmark)
        self.assertEqual(call['json']['format'], 'json')
        call, _ = self.run_provider(self.ollama(json_mode=False), {'response': '{}'})
        self.assertNotIn('format', call['json'])

    def test_anthropic_request_unchanged(self):
        os.environ['ANTHROPIC_API_KEY'] = 'k'
        call, out = self.run_provider(swarm._AnthropicProvider(), ANTHROPIC_REPLY)
        self.assertEqual(call['json']['model'], 'claude-haiku-4-5-20251001')
        self.assertEqual(out, '{"verdict":"benign"}')


if __name__ == '__main__':
    unittest.main(verbosity=2)
