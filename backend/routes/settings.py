"""Settings the Settings page changes: which agents run, and where the local AI analyzers send their work.

Both need the admin key. Agent switches take effect within about 30 seconds without a restart; AI routing edits the shared .env
file and restarts the agent runner.
"""
import os
import re

from flask import Blueprint, jsonify, request

import auth as _auth
from models import Agent, Threat, db
from request_helpers import _clean_str

settings_bp = Blueprint("settings", __name__)


def _env_path():
    """The .env file, looked up when needed: app.py owns the setting and tests point it somewhere else."""
    from app import _ENV_PATH
    return _ENV_PATH


_AI_ROUTING_KEYS = {
    'ollama':     {'url': 'OLLAMA_URL',     'model': 'OLLAMA_MODEL',     'severity': 'high+'},
    'hermes':     {'url': 'HERMES_URL',     'model': 'HERMES_MODEL',     'severity': 'medium'},
    'watchtower': {'url': 'WATCHTOWER_URL', 'model': 'WATCHTOWER_MODEL', 'severity': 'low'},
}


# Accepts only http:// or https:// then a host name, IP or [IPv6]:port made of safe characters, an optional :port and an optional simple path. No spaces or newlines, so a value cannot add extra lines to .env.
_ROUTING_URL = re.compile(r'^https?://[A-Za-z0-9.\-\[\]:]{1,253}(?::\d{1,5})?(?:/[\w.\-/~%]*)?$')


# A model name: 1 to 128 letters, digits and . - _ : / @ only (for example llama3:8b).
_ROUTING_MODEL = re.compile(r'^[\w.\-:/@]{1,128}$')


def _read_env_file():
    """Read the KEY=value lines of the .env file into a dict (blank lines and # comments are skipped). Returns an empty
    dict when the file is missing."""
    values = {}
    if os.path.exists(_env_path()):
        with open(_env_path()) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#') or '=' not in line:
                    continue
                k, v = line.split('=', 1)
                values[k.strip()] = v.strip()
    return values


@settings_bp.route('/api/settings/agents', methods=['GET'])
def get_agents_menu():
    """Every agent in the catalog with its tier, whether it runs, and what it has found: the Settings menu."""
    if not _auth.is_admin():
        return jsonify({'error': 'Unauthorized'}), 401
    from datetime import datetime as _dt, timedelta as _td, timezone as _tz
    from sqlalchemy import func as _func
    from agents.agent_catalog import CATALOG, load_overrides, agent_enabled
    overrides = load_overrides()
    cutoff = _dt.now(_tz.utc).replace(tzinfo=None) - _td(days=30)
    counts = dict(db.session.query(Threat.detected_by, _func.count(Threat.id))
                  .filter(Threat.timestamp > cutoff).group_by(Threat.detected_by).all())
    rows = {a.name: a for a in Agent.query.all()}
    out = []
    for name, meta in CATALOG.items():
        row = rows.get(name)
        out.append({'name': name, 'tier': meta['tier'], 'default_on': meta['default_on'], 'notes': meta['notes'],
                    'enabled': agent_enabled(name, overrides), 'status': row.status if row else 'never started',
                    'last_seen': row.last_seen.isoformat() if row and row.last_seen else None,
                    'findings_30d': counts.get(name, 0)})
    return jsonify(out)


@settings_bp.route('/api/settings/agents', methods=['POST'])
def set_agent_menu():
    """Switch an agent on or off. The agent runner picks the change up within about 30 seconds: no restart."""
    if not _auth.is_admin():
        return jsonify({'error': 'Unauthorized'}), 401
    from agents.agent_catalog import CATALOG, set_agent_enabled
    body = request.get_json(silent=True) or {}
    name = _clean_str(body.get('agent', ''), 64)
    enabled = body.get('enabled')
    if not isinstance(enabled, bool):
        return jsonify({'error': 'enabled must be true or false'}), 400
    if name not in CATALOG:
        return jsonify({'error': f'Unknown agent: {name}'}), 404
    set_agent_enabled(name, enabled)
    return jsonify({'status': 'ok', 'agent': name, 'enabled': enabled, 'applies_within_seconds': 30})


@settings_bp.route('/api/settings/ai_routing', methods=['GET'])
def get_ai_routing():
    """Admin only: the URL and model each local analyzer (ollama, hermes, watchtower) uses, falling back to the defaults
    when .env does not set them."""
    if not _auth.is_admin():
        return jsonify({'error': 'Unauthorized'}), 401
    env = _read_env_file()
    # Mirrors agent_runner.py's own fallback logic so displayed values match
    # what's actually in effect, not just what's literally in .env.
    ollama_url = env.get('OLLAMA_URL', os.environ.get('OLLAMA_URL', 'http://127.0.0.1:11434'))
    effective_defaults = {
        'OLLAMA_URL': ollama_url, 'OLLAMA_MODEL': 'llama3',
        'HERMES_URL': ollama_url, 'HERMES_MODEL': 'hermes3',
        'WATCHTOWER_URL': ollama_url, 'WATCHTOWER_MODEL': 'mistral',
    }
    out = {}
    for agent, keys in _AI_ROUTING_KEYS.items():
        out[agent] = {
            'url':      env.get(keys['url'], effective_defaults[keys['url']]),
            'model':    env.get(keys['model'], effective_defaults[keys['model']]),
            'severity': keys['severity'],
        }
    return jsonify(out)


@settings_bp.route('/api/settings/ai_routing', methods=['POST'])
def set_ai_routing():
    """Admin only: change those URLs and models after checking each value, write them to .env, then try to restart the
    agent runner. `restarted` is false when that restart did not work."""
    if not _auth.is_admin():
        return jsonify({'error': 'Unauthorized'}), 401
    import subprocess as _subprocess
    import envfile
    data = request.get_json(force=True, silent=True)
    if not isinstance(data, dict):
        return jsonify({'error': 'expected a JSON object'}), 400
    # Only these settings, only well-formed values (code review 2026-09-30, finding 5: a newline in a value used to
    # inject arbitrary KEY=... lines into .env, and a non-object body was a 500).
    updates = {}
    for agent, keys in _AI_ROUTING_KEYS.items():
        part = data.get(agent)
        if part is None:
            continue
        if not isinstance(part, dict):
            return jsonify({'error': f'{agent}: expected an object'}), 400
        if 'url' in part:
            url = part['url']
            if not (isinstance(url, str) and _ROUTING_URL.match(url)):
                return jsonify({'error': f'{agent}: url must be http(s)://host[:port][/path]'}), 400
            updates[keys['url']] = url
        if 'model' in part:
            model = part['model']
            if not (isinstance(model, str) and _ROUTING_MODEL.match(model)):
                return jsonify({'error': f'{agent}: invalid model name'}), 400
            updates[keys['model']] = model
    if not updates:
        return jsonify({'error': 'nothing to change'}), 400
    try:
        envfile.set_values(_env_path(), updates)            # validated, locked, atomic; other lines kept as they are
    except envfile.EnvError as e:
        return jsonify({'error': str(e)}), 400

    try:
        result = _subprocess.run(['sudo', '/usr/bin/systemctl', 'restart', 'ssai-agents'],
                                  capture_output=True, text=True, timeout=15)
        restarted = result.returncode == 0
    except Exception:
        restarted = False

    return jsonify({'ok': True, 'restarted': restarted})
