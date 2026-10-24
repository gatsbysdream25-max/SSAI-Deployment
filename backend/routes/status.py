import os

from flask import Blueprint, jsonify, request
from models import Threat, Agent
from auth import is_admin

status_bp = Blueprint('status', __name__)

@status_bp.route('/', methods=['GET'])
def get_status():
    """Quick counts (all threats, active threats, active agents) for health displays."""
    total_threats = Threat.query.count()
    active_threats = Threat.query.filter_by(status='active').count()
    active_agents = Agent.active_count()
    return jsonify({
        'total_threats': total_threats,
        'active_threats': active_threats,
        'active_agents': active_agents,
        'system_status': 'operational'
    })


@status_bp.route('/governance', methods=['GET'])
def governance():
    """Admin-only, read-only: the evidence a customer's security team asks for (2026-10-09).
    Third-party provider approvals, whether the gate is enforced, the latest red-team runs, the AI panel's lineage
    (current manifest + recent changes) and the outside-data sync log. Nothing here is sent anywhere."""
    if not is_admin():
        return jsonify({'error': 'Unauthorized'}), 401
    from agents import provider_approval, redteam, state_store
    try:
        limit = max(1, min(int(request.args.get('limit', 10)), 100))
    except ValueError:
        limit = 10
    st = state_store.StateStore(readonly=True)   # written by the agents (maybe root); this process only reads
    runs = redteam.read_audit(limit)
    current = st.current_manifest_id()
    manifest = st.get_manifest(current) if current else None
    if manifest:
        manifest.pop('snapshot', None)              # config file contents stay on disk; use tools/lineage_cli.py
    return jsonify({
        'providers': provider_approval.summary(),
        'approval_enforced': provider_approval.enforced(),
        'redteam': {
            'last_run': runs[0] if runs else None,
            'history': [{k: r.get(k) for k in ('ts', 'passed', 'failed', 'skipped', 'code_version')} for r in runs],
        },
        'lineage': {'current': manifest, 'events': st.lineage_events(limit)},
        'syncs': st.recent_syncs(limit * 3),
    })


@status_bp.route('/capability', methods=['GET'])
def capability_report():
    """Admin-only: what this machine can protect (level, what it can and cannot do, and how to improve it). Reads the
    machine; sends nothing."""
    if not is_admin():
        return jsonify({'error': 'Unauthorized'}), 401
    from agents import capability
    from agents.ai_swarm_agent import MIN_VOTERS
    return jsonify(capability.report(os.environ.get('OLLAMA_URL', 'http://127.0.0.1:11434'), MIN_VOTERS))


@status_bp.route('/update', methods=['GET'])
def update_status():
    """Admin-only: is a newer SwarmSentinel release published? Shown on the Settings page. It only reads; applying an
    update is done on the machine with deploy/update.sh, never from the browser. An install that is a git checkout
    (the developer's own hub) updates from git instead, so it reports that and is not asked about releases."""
    if not is_admin():
        return jsonify({'error': 'Unauthorized'}), 401
    from agents import release_check
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    if os.path.isdir(os.path.join(root, '.git')):
        return jsonify({'managed_by': 'git', 'enabled': False})
    answer = release_check.check(root, use_cache=True)
    answer['managed_by'] = 'package'
    return jsonify(answer)
