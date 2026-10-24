#!/usr/bin/env python3
"""Every call the agent runner makes to the hub's own read API carries the key (reads are protected since 2026-10-18).
Run:  swarmsentinel-env/bin/python3 backend/tools/test_runner_auth.py"""
import os
import re
import unittest

SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'agents', 'agent_runner.py')


class RunnerAuth(unittest.TestCase):
    def test_no_bare_session_get_on_the_hub_api(self):
        text = open(SRC, encoding='utf-8').read()
        self.assertEqual(re.findall(r"SESSION\.get\(f'\{API\}", text), [], 'use _api_get so the key is sent')

    def test_api_get_sends_the_key(self):
        import sys
        from unittest import mock
        os.environ['SSAI_API_KEY'] = 'runner-test-key'
        sys.path[:0] = [os.path.dirname(SRC), os.path.dirname(os.path.dirname(SRC))]
        import agent_runner
        with mock.patch.object(agent_runner, 'API_KEY', 'runner-test-key'), \
                mock.patch.object(agent_runner.SESSION, 'get') as get:
            agent_runner._api_get('http://hub/api/threats/', timeout=5)
        self.assertEqual(get.call_args.kwargs['headers']['X-API-Key'], 'runner-test-key')


if __name__ == '__main__':
    unittest.main(verbosity=2)
