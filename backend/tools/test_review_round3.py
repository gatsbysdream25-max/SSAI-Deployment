#!/usr/bin/env python3
"""Fixes from the second 2026-10-18 pass: provider health after a timeout, re-discovery of providers that were down at start,
Home view state across refreshes, escaping on the settings pages, deploy-script checks. Each test fails on the old code.
Run:  swarmsentinel-env/bin/python3 backend/tools/test_review_round3.py"""
import os
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

_TMP = tempfile.mkdtemp()
os.environ['DATA_DIR'] = _TMP
os.environ['SSAI_PROVIDER_CHECK'] = '0'
os.environ['SSAI_STATE_DB'] = os.path.join(_TMP, 'state.db')

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
ROOT = os.path.dirname(BACKEND)
sys.path[:0] = [os.path.join(BACKEND, 'agents'), BACKEND]

from agents import ai_swarm_agent as swarm  # noqa: E402


def analyzer():
    a = object.__new__(swarm.AiSwarmAnalyzer)
    a._health = {}
    a._health_lock = threading.Lock()
    a._providers = []
    return a


class Slow:
    name = 'slow'
    model = 'm'

    def __init__(self, gate):
        self.gate = gate

    def analyze(self, _prompt):
        self.gate.wait(5)
        return '{"verdict": "malicious", "confidence": 80, "severity": "HIGH", "reasoning": "x"}'


class Health(unittest.TestCase):
    def test_an_answer_after_the_deadline_does_not_make_the_provider_look_healthy(self):
        a = analyzer()
        gate, closed = threading.Event(), threading.Event()
        closed.set()                       # the round is already over when the slow answer arrives
        gate.set()
        a._safe_call(Slow(gate), '{}', closed)
        self.assertIsNone(a.get_health().get('slow', {}).get('last_success'))

    def test_an_answer_in_time_counts(self):
        a = analyzer()
        gate = threading.Event()
        gate.set()
        a._safe_call(Slow(gate), '{}', threading.Event())
        self.assertTrue(a.get_health()['slow']['last_success'])

    def test_a_provider_that_was_down_at_start_rejoins_the_panel(self):
        a = analyzer()
        a._providers = []
        calls = []

        class P:
            name = 'ollama'

        a._init_providers = lambda: calls.append(1) or [P()]
        with mock.patch.object(swarm.model_config, 'load', return_value={'ollama': {'kind': 'ollama'}}):
            a._maybe_rediscover()                       # first call only starts the clock
            self.assertEqual(calls, [])
            a.__dict__['_last_discovery'] = time.monotonic() - 10_000
            a._maybe_rediscover()
            for _ in range(50):                         # the probing runs on its own thread
                if calls:
                    break
                time.sleep(0.05)
        self.assertEqual(calls, [1])
        time.sleep(0.1)
        self.assertEqual([p.name for p in a._providers], ['ollama'])
        self.assertIn('ollama', a.get_health())


    def test_providers_with_no_key_are_not_re_probed_forever(self):
        a = analyzer()
        a.__dict__['_last_discovery'] = time.monotonic() - 10_000
        a._init_providers = lambda: self.fail('nothing configured is missing')
        cfg = {'openai': {'kind': 'openai', 'key_env': 'NO_SUCH_KEY_ENV_XYZ'}}
        with mock.patch.object(swarm.model_config, 'load', return_value=cfg):
            a._maybe_rediscover()


class Pages(unittest.TestCase):
    def test_layout_collective_feed_spans_the_bottom_and_github_defender_sit_in_the_sidebar(self):
        html = self.read('backend/templates/dashboard.html')
        self.assertNotIn('panels-3col">', html)
        aside = html.split('<aside>')[1].split('</aside>')[0]
        for ident in ('id="gh-recent"', 'id="gh-total"', 'id="defender-log"'):
            self.assertIn(ident, aside)
        self.assertNotIn('id="collective-log"', aside)
        self.assertIn('id="collective-panel"', html.split('</aside>')[1])

    def test_tooltips_do_not_depend_on_the_native_title_delay(self):
        html = self.read('backend/templates/dashboard.html')
        self.assertIn('id="ssai-tip"', html)
        self.assertIn("host.removeAttribute('title')", html)
        self.assertIn('if (tbody._lastHtml !== rowsHtml)', html)

    def test_open_state_is_kept_by_identity_not_position(self):
        html = self.read('backend/templates/dashboard.html')
        self.assertIn('data-okey="${esc(idsAttr)}"', html)
        self.assertIn('data-okey="${esc(p.provider)}"', html)
        self.assertNotIn('open.push(i)', html)

    def test_a_stalled_poll_times_out_and_a_signed_out_page_says_so(self):
        html = self.read('backend/templates/dashboard.html')
        self.assertIn('ctl.abort()', html)
        self.assertIn("r.status === 401", html)

    def test_switched_off_agents_stay_listed_when_none_are_running(self):
        html = self.read('backend/templates/dashboard.html')
        self.assertNotIn('if (!agents.length) {', html)

    def read(self, rel):
        return open(os.path.join(ROOT, rel), encoding='utf-8').read()

    def test_home_lists_keep_what_the_person_opened_across_refreshes(self):
        html = self.read('backend/templates/dashboard.html')
        self.assertIn('function setHomeHtml(', html)
        for raw in ("getElementById('home-ai-list').innerHTML", "listEl.innerHTML =",
                    "getElementById('home-card-list-preview').innerHTML", "getElementById('home-ai-list-preview').innerHTML"):
            self.assertNotIn(raw, html, raw)

    def test_polling_does_not_stack_and_ignores_error_pages(self):
        html = self.read('backend/templates/dashboard.html')
        self.assertIn('if (document.hidden || _polling) return;', html)
        self.assertIn("if (!r.ok) throw new Error('snapshot '", html)

    def test_settings_and_setup_escape_what_the_server_returns(self):
        s = self.read('backend/templates/settings.html')
        for raw in ('>${a.name}<', '>${a.notes}<', 'value="${cfg.url}"', 'value="${cfg.model}"'):
            self.assertNotIn(raw, s, raw)
        self.assertNotIn('href="${p.signup_url}"', self.read('backend/templates/setup.html'))

    def test_deploy_scripts(self):
        self.assertIn('systemctl is-active --quiet ssai-agents || return 1', self.read('deploy/update-lib.sh'))   # the shared health check lives here now
        tls = self.read('deploy/check-tls.sh')
        self.assertIn('--hub-port', tls)
        self.assertIn("unsafe-inline", tls)
        self.assertNotIn('|| code80=000', tls)
        self.assertIn('gthread', self.read('deploy/systemd/swarmsentinel.service.in'))
        self.assertIn('gthread', self.read('docker/supervisord.conf'))
        self.assertIn('mv "$ENV_FILE.tmp" "$ENV_FILE"', self.read('docker/docker-entrypoint.sh'))
        self.assertIn('test_harden.sh', self.read('.github/workflows/ci.yml'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
