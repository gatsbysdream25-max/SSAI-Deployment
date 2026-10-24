from flask import Blueprint, request, jsonify
from models import db, Agent, Node
from datetime import datetime, timezone
import json
import time

from auth import identity, node_rate_limited

agents_bp = Blueprint('agents', __name__)


def _check_auth():
    """Any authenticated caller: the admin key or an enrolled node's own token."""
    return identity() is not None


def _gate(agent_id):
    """A node may only speak for its own agents (named <agent>@<its node id>), and only so fast."""
    who = identity()
    if who is not None and who.kind == 'node':
        if node_rate_limited(who.node):
            return jsonify({'error': 'rate limited'}), 429
        name, _, owner = str(agent_id).rpartition('@')
        if not name or '@' in name or owner != who.node.node_id:      # exactly <agent>@<this node>
            return jsonify({'error': f"this machine's agents must be named <agent>@{who.node.node_id}"}), 403
    return None

# The hub's own Node.last_seen. An enrolled machine's is refreshed by identity() whenever its token is used; the hub's
# local agent runner uses the admin key, so nothing refreshed the hub's row after start-up (the dashboard showed
# "last seen 13h ago", 2026-09-26). Its agents' heartbeats now refresh it, at most every HUB_TOUCH_EVERY seconds.
HUB_TOUCH_EVERY = 30
_hub_touch = {'at': 0.0}


def _touch_hub():
    """Refresh the hub's own Node.last_seen, at most every HUB_TOUCH_EVERY seconds, so the dashboard does not show the
    hub as long unseen."""
    now = time.monotonic()
    if now - _hub_touch['at'] < HUB_TOUCH_EVERY:
        return
    _hub_touch['at'] = now
    node = Node.hub()
    if node is not None:
        node.last_seen = datetime.now(timezone.utc)      # committed with the heartbeat below


@agents_bp.route('/', methods=['GET'])
def get_agents():
    agents = Agent.query.order_by(Agent.last_seen.desc()).all()
    return jsonify([a.to_dict() for a in agents])

@agents_bp.route('/register', methods=['POST'])
def register_agent():
    """Register an agent, or refresh one already known, so it shows on the dashboard. Needs the admin key or an enrolled
    node's token; a node may only register agents named <agent>@<its own node id>."""
    if not _check_auth():
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json()
    if not data:
        return jsonify({'error': 'JSON body required'}), 400
    agent_id = data.get('agentId') or data.get('name')
    if not agent_id:
        return jsonify({'error': 'agentId required'}), 400
    denied = _gate(agent_id)
    if denied:
        return denied
    agent = Agent.query.filter_by(name=agent_id).first()
    if not agent:
        agent = Agent(
            name=agent_id,
            type=data.get('agentMode', data.get('type', 'scanner')),
            role=data.get('role', ''),
            description=data.get('description', ''),
            hostname=data.get('hostname', ''),
            platform=data.get('platform', ''),
            status='active',
        )
        db.session.add(agent)
    else:
        agent.last_seen   = datetime.now(timezone.utc)
        agent.status      = 'active'
        agent.role        = data.get('role', agent.role or '')
        agent.description = data.get('description', agent.description or '')
        agent.hostname    = data.get('hostname', agent.hostname or '')
        agent.platform    = data.get('platform', agent.platform or '')
    db.session.commit()
    return jsonify({'success': True, 'agent': agent.to_dict()}), 201

@agents_bp.route('/heartbeat', methods=['POST'])
def heartbeat():
    """An agent's regular 'still alive' call: updates its status, last-seen time, counters and AI-provider health.
    Unknown agents get a 404 (register first). Counters that are not numbers are ignored."""
    # FIX (M2): heartbeat now requires the same API key as register, and no longer
    # silently auto-creates unknown agents — previously register was the one that
    # required auth (and always failed with SSAI_API_KEY unset) while heartbeat had
    # no auth at all and would happily create an "agent" record for any caller.
    if not _check_auth():
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json()
    if not data:
        return jsonify({'error': 'JSON body required'}), 400
    agent_id = data.get('agentId') or data.get('name')
    if not agent_id:
        return jsonify({'error': 'agentId required'}), 400
    denied = _gate(agent_id)
    if denied:
        return denied
    agent = Agent.query.filter_by(name=agent_id).first()
    if not agent:
        return jsonify({'error': 'unknown agent — register first'}), 404
    agent.status    = data.get('status', 'active')
    agent.last_seen = datetime.now(timezone.utc)
    if 'scan_count' in data:
        try:
            agent.scans_count = int(data['scan_count'])
        except (TypeError, ValueError):
            pass
    if 'threat_count' in data:
        try:
            agent.threats_found = int(data['threat_count'])
        except (TypeError, ValueError):
            pass
    if data.get('last_scan'):
        try:
            agent.last_scan = datetime.fromisoformat(data['last_scan'])
        except (ValueError, TypeError):
            agent.last_scan = datetime.now(timezone.utc)
    if 'provider_health' in data:
        try:
            agent.provider_health = json.dumps(data['provider_health'])
        except (TypeError, ValueError):
            pass
    who = identity()
    if who is not None and who.kind == 'admin':          # the hub's own runner (a node's token refreshed its own row)
        _touch_hub()
    db.session.commit()
    return jsonify(agent.to_dict())
