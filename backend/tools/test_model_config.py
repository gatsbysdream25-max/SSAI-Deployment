#!/usr/bin/env python3
"""Model config file, provider health check and quorum reporting (2026-09-23).
Run:  swarmsentinel-env/bin/python3 backend/tools/test_model_config.py"""
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

os.environ['SSAI_PROVIDER_CHECK'] = '0'
HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
sys.path[:0] = [os.path.join(BACKEND, 'agents'), BACKEND]
import ai_swarm_agent as swarm  # noqa: E402
import model_config  # noqa: E402
import provider_check  # noqa: E402
import requests  # noqa: E402


def write(d, name, doc):
    p = os.path.join(d, name)
    with open(p, 'w') as f:
        json.dump(doc, f)
    return p


class ConfigFile(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()

    def test_shipped_defaults_are_valid_and_cover_every_registry_provider(self):
        cfg = model_config.load(model_config.DEFAULT_PATH, os.path.join(self.d, 'none.json'))
        # every provider built into the code has a shipped default; extras added only in this machine's
        # instance/ai_models.json are allowed (that file is where an operator adds them)
        self.assertEqual(swarm._REGISTRY_BASE - set(cfg), set())
        for pid, e in cfg.items():
            self.assertIn(e['kind'], model_config.KINDS, pid)
            self.assertTrue(e['model'], pid)
            self.assertFalse(any(k in e for k in ('api_key', 'key', 'token')), f'{pid}: keys never live in the config')

    def test_instance_override_changes_one_line_and_can_add_a_local_voice(self):
        base = write(self.d, 'base.json', {'providers': {'groq': {'kind': 'openai', 'model': 'a', 'endpoint': 'http://x', 'key_env': 'K'}}})
        over = write(self.d, 'over.json', {'providers': {
            'groq': {'model': 'b'},
            'ollama-x': {'kind': 'ollama', 'model': 'phi4:14b', 'endpoint': 'http://10.0.0.9:11434'}}})
        cfg = model_config.load(base, over)
        self.assertEqual(cfg['groq']['model'], 'b')
        self.assertEqual(cfg['groq']['endpoint'], 'http://x')          # untouched fields survive
        self.assertEqual(cfg['ollama-x']['endpoint'], 'http://10.0.0.9:11434')

    def test_override_can_remove_a_provider(self):
        base = write(self.d, 'base.json', {'providers': {'g': {'kind': 'openai', 'model': 'a', 'key_env': 'K'}}})
        over = write(self.d, 'over.json', {'providers': {'g': {'remove': True}}})
        self.assertEqual(model_config.load(base, over), {})

    def test_bad_entries_are_dropped_not_fatal(self):
        base = write(self.d, 'base.json', {'providers': {
            'nokind': {'model': 'a', 'key_env': 'K'}, 'nomodel': {'kind': 'openai', 'key_env': 'K'},
            'nokey': {'kind': 'openai', 'model': 'a'}, 'good': {'kind': 'openai', 'model': 'a', 'key_env': 'K'}}})
        self.assertEqual(list(model_config.load(base, os.path.join(self.d, 'x.json'))), ['good'])

    def test_unreadable_file_is_ignored(self):
        p = os.path.join(self.d, 'bad.json')
        open(p, 'w').write('{not json')
        self.assertEqual(model_config.load(p, p), {})

    def test_env_overrides_keep_old_env_files_working(self):
        e = {'model': 'default-model', 'model_env': 'TEST_MODEL_ENV', 'endpoint': 'http://a/', 'endpoint_env': 'TEST_EP_ENV'}
        self.assertEqual(model_config.model_of(e), 'default-model')
        with mock.patch.dict(os.environ, {'TEST_MODEL_ENV': 'from-env', 'TEST_EP_ENV': 'http://b/'}):
            self.assertEqual(model_config.model_of(e), 'from-env')
            self.assertEqual(model_config.endpoint_of(e), 'http://b')

    def test_a_config_only_provider_appears_in_the_registry_and_stays_off(self):
        ids = {p['id'] for p in swarm.PROVIDER_REGISTRY}
        self.assertTrue({'ollama-phi4', 'ollama-gemma4', 'ollama-hermes3', 'ollama-mistral'} <= ids)
        self.assertFalse(swarm._REGISTRY_BY_ID['ollama-phi4']['default_on'])   # unmeasured: never on by itself


class LocalVoice(unittest.TestCase):
    def tags(self, names):
        r = mock.Mock(ok=True)
        r.json.return_value = {'models': [{'name': n} for n in names]}
        return r

    def test_available_only_when_server_answers_and_model_is_pulled(self):
        with mock.patch.object(swarm.requests, 'get', return_value=self.tags(['phi4:14b'])):
            self.assertTrue(swarm._OllamaModelProvider('ollama-phi4', 'http://h:11434', 'phi4:14b').available)
        with mock.patch.object(swarm.requests, 'get', return_value=self.tags(['mistral:latest'])):
            p = swarm._OllamaModelProvider('ollama-phi4', 'http://h:11434', 'phi4:14b')
            self.assertFalse(p.available)
            self.assertIn('ollama pull phi4:14b', p.problem)
        with mock.patch.object(swarm.requests, 'get', return_value=self.tags(['mistral:latest'])):
            self.assertTrue(swarm._OllamaModelProvider('m', 'http://h:11434', 'mistral').available)   # bare name means :latest

    def test_unreachable_server_says_so(self):
        with mock.patch.object(swarm.requests, 'get', side_effect=requests.exceptions.ConnectionError('Connection refused')):
            p = swarm._OllamaModelProvider('ollama-phi4', 'http://h:11434', 'phi4:14b')
        self.assertFalse(p.available)
        self.assertIn('not reachable (connection refused)', p.problem)


def http_error(code, body):
    r = requests.Response()
    r.status_code = code
    r._content = body.encode()
    return requests.exceptions.HTTPError(str(code), response=r)


class HealthCheck(unittest.TestCase):
    def test_each_failure_gets_its_own_name(self):
        cases = [
            (http_error(400, '{"error":{"message":"Your credit balance is too low to access the Anthropic API"}}'), provider_check.NO_CREDITS),
            (http_error(402, 'Payment Required'), provider_check.NO_CREDITS),
            (http_error(401, 'invalid api key'), provider_check.BAD_KEY),
            (http_error(403, 'forbidden'), provider_check.BAD_KEY),
            (http_error(404, 'model_not_found'), provider_check.BAD_MODEL),
            (http_error(400, 'The model `x` does not exist'), provider_check.BAD_MODEL),
            (http_error(429, 'quota exceeded'), provider_check.QUOTA_USED),      # spent quota: the provider rests
            (http_error(429, 'slow down'), provider_check.RATE_LIMITED),         # short limit: retried, does not rest
            (http_error(503, 'overloaded'), provider_check.PROVIDER_ERROR),
            (requests.exceptions.ReadTimeout('slow'), provider_check.TIMEOUT),
            (requests.exceptions.ConnectionError('refused'), provider_check.UNREACHABLE),
            (ValueError('odd'), provider_check.ERROR),
        ]
        for exc, want in cases:
            self.assertEqual(provider_check.classify(exc)[0], want, repr(exc))

    def test_exact_error_text_is_kept_and_keys_are_redacted(self):
        _, text = provider_check.classify(http_error(401, 'bad key AIzaSyA1234567890123456789012345678901234'))
        self.assertIn('HTTP 401', text)
        self.assertNotIn('AIzaSyA1234567890123456789012345678901234', text)

    def entry(self, **kw):
        e = {'id': 'x', 'kind': 'openai', 'model': 'm', 'endpoint': 'http://e', 'key_env': 'X_KEY', 'tier': 'free'}
        e.update(kw)
        return e

    def test_missing_key_is_reported_without_a_request(self):
        with mock.patch.object(swarm.requests, 'post') as post:
            os.environ.pop('X_KEY', None)
            r = provider_check.check_provider('x', self.entry())
        post.assert_not_called()
        self.assertEqual((r['status'], r['reachable'], r['working']), ('no_key', None, False))
        self.assertIn('X_KEY', r['detail'])

    def test_working_provider_and_failing_provider_rows(self):
        ok = mock.Mock()
        ok.raise_for_status.return_value = None
        ok.json.return_value = {'choices': [{'message': {'content': 'OK'}}]}
        with mock.patch.dict(os.environ, {'X_KEY': 'k'}), mock.patch.object(swarm.requests, 'post', return_value=ok):
            good = provider_check.check_provider('x', self.entry())
        self.assertEqual((good['status'], good['reachable'], good['working']), ('ok', True, True))
        bad = mock.Mock()
        bad.raise_for_status.side_effect = http_error(402, 'no credits')
        with mock.patch.dict(os.environ, {'X_KEY': 'k'}), mock.patch.object(swarm.requests, 'post', return_value=bad):
            r = provider_check.check_provider('x', self.entry())
        self.assertEqual((r['status'], r['reachable'], r['working']), ('no_credits', True, False))
        self.assertTrue(r['hint'])

    def test_table_and_summary(self):
        rows = [dict(provider='a', model='m1', in_panel=True, reachable=True, working=True, detail='answers', status='ok'),
                dict(provider='b', model='m2', in_panel=True, reachable=False, working=False, detail='timed out', status='timeout', hint='no answer in time'),
                dict(provider='c', model='m3', in_panel=False, reachable=None, working=False, detail='not configured: set C', status='no_key')]
        table = provider_check.format_table(rows)
        self.assertIn('PROVIDER', table)
        self.assertIn('timed out', table)
        s = provider_check.summary(rows)
        self.assertEqual((s['configured'], s['in_panel'], s['in_panel_working'], s['not_working']), (2, 2, 1, ['b']))


class Quorum(unittest.TestCase):
    def r(self, ai, verdict, conf=90):
        return {'ai': ai, 'verdict': verdict, 'severity': 'HIGH', 'confidence': conf}

    def test_full_agreement_of_a_full_panel(self):
        res = [self.r(n, 'malicious') for n in 'abcd']
        q = swarm.AiSwarmAnalyzer._consensus(res, weights={}, panel=list('abcd'))['quorum']
        self.assertEqual((q['agreed'], q['answered'], q['panel'], q['dropped'], q['level']), (4, 4, 4, [], 'High'))
        self.assertEqual(q['label'], 'High confidence, 4 of 4 agreed')

    def test_dropped_providers_show_at_once(self):
        res = [self.r(n, 'malicious') for n in 'abcd']
        q = swarm.AiSwarmAnalyzer._consensus(res, weights={}, panel=list('abcdef'))['quorum']
        self.assertEqual(q['dropped'], ['e', 'f'])
        self.assertFalse(q['complete'])
        self.assertIn('4 of 6 models answered', q['label'])
        self.assertIn('e, f', q['label'])

    def test_a_two_model_result_never_looks_like_a_six_model_result(self):
        two = swarm.AiSwarmAnalyzer._consensus([self.r('a', 'malicious'), self.r('b', 'malicious')], weights={}, panel=['a', 'b'])['quorum']
        six = swarm.AiSwarmAnalyzer._consensus([self.r(n, 'malicious') for n in 'abcdef'], weights={}, panel=list('abcdef'))['quorum']
        self.assertNotEqual(two['label'], six['label'])
        self.assertEqual(two['level'], 'Medium')                       # capped: two voices are never "High"
        self.assertEqual(six['level'], 'High')
        self.assertIn('only 2 models', two['label'])

    def test_one_answer_is_always_low(self):
        q = swarm.AiSwarmAnalyzer._consensus([self.r('a', 'malicious', 99)], weights={}, panel=['a'])['quorum']
        self.assertEqual(q['level'], 'Low')

    def test_split_panel_counts_only_the_winning_side(self):
        res = [self.r('a', 'malicious'), self.r('b', 'malicious'), self.r('c', 'benign'), self.r('d', 'benign'), self.r('e', 'benign')]
        out = swarm.AiSwarmAnalyzer._consensus(res, weights={}, panel=list('abcde'))
        self.assertEqual(out['consensus_verdict'], 'benign')
        self.assertEqual(out['quorum']['agreed'], 3)
        self.assertEqual(out['quorum']['level'], 'Medium')             # 3 of 5 is a majority, not a strong one

    def test_without_a_panel_argument_the_answerers_are_the_panel(self):
        q = swarm.AiSwarmAnalyzer._consensus([self.r('a', 'benign'), self.r('b', 'benign'), self.r('c', 'benign')], weights={})['quorum']
        self.assertEqual((q['panel'], q['dropped'], q['agreed']), (3, [], 3))


class HeatCap(unittest.TestCase):
    def test_num_thread_is_read_from_the_config_and_sent_to_ollama(self):
        d = tempfile.mkdtemp()
        base = write(d, "b.json", {"providers": {"ollama-x": {"kind": "ollama", "model": "m", "num_thread": 4}, "ollama-y": {"kind": "ollama", "model": "m", "num_thread": 999}}})
        cfg = model_config.load(base, os.path.join(d, "none.json"))
        self.assertEqual(cfg["ollama-x"]["num_thread"], 4)
        self.assertNotIn("num_thread", cfg["ollama-y"])           # out of range: ignored

    def test_analyze_limits_threads_only_when_asked(self):
        p = swarm._OllamaProvider.__new__(swarm._OllamaProvider)
        p.base_url, p.model = "http://h:11434", "m"
        resp = mock.Mock()
        resp.json.return_value = {"response": "{}"}
        with mock.patch.object(swarm.requests, "post", return_value=resp) as post:
            p.analyze("x")
            self.assertNotIn("options", post.call_args.kwargs["json"])
            p.num_thread = 4
            p.analyze("x")
            self.assertEqual(post.call_args.kwargs["json"]["options"], {"num_thread": 4})
            del p.num_thread
            with mock.patch.dict(os.environ, {"OLLAMA_NUM_THREAD": "3"}):
                p.analyze("x")
            self.assertEqual(post.call_args.kwargs["json"]["options"], {"num_thread": 3})


if __name__ == '__main__':
    unittest.main(verbosity=2)
