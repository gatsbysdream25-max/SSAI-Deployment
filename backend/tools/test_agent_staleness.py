#!/usr/bin/env python3
"""A silent agent shows as offline, and deleting a machine removes its agents (2026-10-24: a laptop that was removed from
the hub stayed on the dashboard as nine "active" agents for a day).
Run:  swarmsentinel-env/bin/python3 backend/tools/test_agent_staleness.py"""
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

_TMP = tempfile.mkdtemp()
os.environ['DATA_DIR'] = _TMP
os.environ['DATABASE_URL'] = f'sqlite:///{_TMP}/agent-staleness-test.db'
os.environ['SSAI_API_KEY'] = ADMIN = 'agent-staleness-admin-key'
os.environ['SSAI_PROVIDER_CHECK'] = '0'

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
sys.path[:0] = [os.path.join(BACKEND, 'agents'), BACKEND]


def minutes_ago(minutes):
    return datetime.now(timezone.utc) - timedelta(minutes=minutes)


class AgentStaleness(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import app as appmod
        if _TMP not in appmod.app.config['SQLALCHEMY_DATABASE_URI']:
            raise RuntimeError('refusing to run against a non-test database')
        cls.app, cls.db = appmod.app, appmod.db
        cls.app.config['TESTING'] = True

    def setUp(self):
        from models import Agent, Node
        self.Agent, self.Node = Agent, Node
        self.ctx = self.app.app_context()
        self.ctx.push()
        self.db.create_all()
        Agent.query.delete()
        Node.query.filter(Node.node_id != 'hub').delete()
        self.db.session.commit()

    def tearDown(self):
        self.db.session.remove()
        self.ctx.pop()

    def add_agent(self, name, minutes, status='active'):
        self.db.session.add(self.Agent(name=name, status=status, last_seen=minutes_ago(minutes)))
        self.db.session.commit()

    def shown(self, name):
        return self.Agent.query.filter_by(name=name).first().to_dict()['status']

    def test_a_recent_agent_is_active_and_a_silent_one_is_offline(self):
        self.add_agent('Fresh', 1)
        self.add_agent('Silent', 25 * 60)
        self.assertEqual(self.shown('Fresh'), 'active')
        self.assertEqual(self.shown('Silent'), 'offline')

    def test_only_a_stored_active_status_is_replaced(self):
        self.add_agent('Resting', 25 * 60, status='idle')
        self.assertEqual(self.shown('Resting'), 'idle')

    def test_the_count_ignores_silent_agents(self):
        self.add_agent('Fresh', 1)
        self.add_agent('Silent', 25 * 60)
        self.assertEqual(self.Agent.active_count(), 1)

    def test_the_stale_limit_can_be_changed(self):
        self.add_agent('Slow', 30)
        os.environ['SSAI_AGENT_STALE_MINUTES'] = '60'
        try:
            self.assertEqual(self.shown('Slow'), 'active')
        finally:
            del os.environ['SSAI_AGENT_STALE_MINUTES']
        self.assertEqual(self.shown('Slow'), 'offline')

    def test_deleting_a_machine_removes_its_agents_and_only_its_agents(self):
        self.db.session.add(self.Node(node_id='laptop', hostname='l', status='active', registered=minutes_ago(5), last_seen=minutes_ago(5)))
        self.add_agent('AuthLogAgent@laptop', 1)
        self.add_agent('AuthLogAgent@laptop2', 1)
        self.add_agent('HubAgent', 1)
        reply = self.app.test_client().delete('/api/nodes/laptop', headers={'X-API-Key': ADMIN})
        self.assertEqual(reply.status_code, 200)
        names = sorted(a.name for a in self.Agent.query.all())
        self.assertEqual(names, ['AuthLogAgent@laptop2', 'HubAgent'])


if __name__ == '__main__':
    unittest.main()
