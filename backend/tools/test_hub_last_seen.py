#!/usr/bin/env python3
"""The hub's own "last seen" refreshes while its agents check in (2026-09-26: it only changed at start-up).
Run:  swarmsentinel-env/bin/python3 backend/tools/test_hub_last_seen.py"""
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

_TMP = tempfile.mkdtemp()
os.environ['DATA_DIR'] = _TMP
os.environ['DATABASE_URL'] = f'sqlite:///{_TMP}/hub-last-seen-test.db'
os.environ['SSAI_API_KEY'] = ADMIN = 'hub-last-seen-admin-key'
os.environ['SSAI_PROVIDER_CHECK'] = '0'

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
sys.path[:0] = [os.path.join(BACKEND, 'agents'), BACKEND]
import auth  # noqa: E402

OLD = datetime.now(timezone.utc) - timedelta(hours=13)


class HubLastSeen(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import app as appmod
        if _TMP not in appmod.app.config['SQLALCHEMY_DATABASE_URI']:
            raise RuntimeError('refusing to run against a non-test database')
        cls.app, cls.db = appmod.app, appmod.db
        cls.app.config['TESTING'] = True
        from routes import agents as agents_route
        cls.route = agents_route

    def setUp(self):
        from models import Agent, Node
        self.Agent, self.Node = Agent, Node
        self.ctx = self.app.app_context()
        self.ctx.push()
        self.db.create_all()
        self.assertIsNotNone(Node.hub(), 'start-up registers the hub row')
        Node.query.filter_by(node_id='remote-node').delete()
        Agent.query.filter(Agent.name.in_(['HubAgent', 'ScanAgent@remote-node'])).delete(synchronize_session=False)
        self.token = auth.new_token()
        self.db.session.add(Node(node_id='remote-node', hostname='r', status='active',
                                 token_hash=auth.hash_secret(self.token), registered=OLD, last_seen=OLD))
        self.db.session.add(Agent(name='HubAgent', status='active'))
        self.db.session.add(Agent(name='ScanAgent@remote-node', status='active'))
        Node.hub().last_seen = OLD
        self.db.session.commit()
        self.route._hub_touch['at'] = 0.0
        auth.node_ingest = auth.SlidingWindow(10000, 60)

    def tearDown(self):
        self.db.session.remove()
        self.ctx.pop()

    def beat(self, name, key):
        return self.app.test_client().post('/api/agents/heartbeat', json={'agentId': name}, headers={'X-API-Key': key})

    def hub_age(self):
        self.db.session.expire_all()
        seen = self.Node.hub().last_seen
        seen = seen if seen.tzinfo else seen.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - seen).total_seconds()

    def test_the_hubs_own_agent_heartbeat_refreshes_last_seen(self):
        self.assertEqual(self.beat('HubAgent', ADMIN).status_code, 200)
        self.assertLess(self.hub_age(), 60)

    def test_refresh_is_throttled(self):
        self.beat('HubAgent', ADMIN)
        self.Node.hub().last_seen = OLD
        self.db.session.commit()
        self.beat('HubAgent', ADMIN)                                   # within HUB_TOUCH_EVERY: no write
        self.assertGreater(self.hub_age(), 3600)
        self.route._hub_touch['at'] -= self.route.HUB_TOUCH_EVERY + 1  # the window has passed
        self.beat('HubAgent', ADMIN)
        self.assertLess(self.hub_age(), 60)

    def test_a_remote_nodes_heartbeat_does_not_refresh_the_hub(self):
        self.assertEqual(self.beat('ScanAgent@remote-node', self.token).status_code, 200)
        self.assertGreater(self.hub_age(), 3600)

    def test_unauthenticated_heartbeat_changes_nothing(self):
        self.assertEqual(self.beat('HubAgent', 'wrong').status_code, 401)
        self.assertGreater(self.hub_age(), 3600)


if __name__ == '__main__':
    unittest.main(verbosity=2)
