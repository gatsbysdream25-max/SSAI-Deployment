"""The port allowlist: "stop flagging this port for this threat type, network-wide" (the /api/allowlist routes).

A deliberate, disclosed trade-off, not an oversight: an entry silences a kind of finding everywhere, so changing the list needs the
admin key. NetworkScanAgent (agents/agent_runner.py) reads the same file before it submits a threat.
"""
import os
from datetime import datetime, timezone

from flask import Blueprint, jsonify, request

import ssai_config
import auth as _auth
from request_helpers import _clean_str

allowlist_bp = Blueprint("allowlist", __name__)
# ── Threat allowlist (added 2026-08-19) ─────────────────────────────────────
# Scoped to (threat_type, port), not a specific device: mask_private_ip()
# collapses every LAN IP to the same "192.168.xxx.xxx" string on this /24
# network, so per-host targeting isn't possible with the data actually
# stored anywhere in the system. An entry here means "stop flagging this
# port for this threat type, network-wide" — a deliberate, disclosed
# trade-off (see project memory), not an oversight. Checked by
# NetworkScanAgent in agent_runner.py before it ever submits a threat.
_ALLOWLIST_PATH = ssai_config.ALLOWLIST_PATH


def _read_allowlist():
    """The saved allowlist entries, or an empty list when the file is missing or unreadable."""
    import json as _json_al
    if not os.path.exists(_ALLOWLIST_PATH):
        return []
    try:
        with open(_ALLOWLIST_PATH) as f:
            return _json_al.load(f)
    except (OSError, ValueError):
        return []


def _write_allowlist(entries):
    import json as _json_al
    os.makedirs(os.path.dirname(_ALLOWLIST_PATH), exist_ok=True)
    with open(_ALLOWLIST_PATH, 'w') as f:
        _json_al.dump(entries, f, indent=2)


@allowlist_bp.route('/api/allowlist', methods=['GET'])
def get_allowlist():
    if not _auth.is_admin():
        return jsonify({'error': 'Unauthorized'}), 401
    return jsonify(_read_allowlist())


@allowlist_bp.route('/api/allowlist', methods=['POST'])
def add_allowlist():
    """Admin only: add a (threat type, port) entry. The id is a hash of type and port, so adding the same pair twice is
    harmless and is reported as already_exists."""
    if not _auth.is_admin():
        return jsonify({'error': 'Unauthorized'}), 401
    import hashlib as _hashlib_al
    data = request.get_json(silent=True) or {}
    ttype = _clean_str(data.get('type', ''), 64)
    try:
        port = int(data.get('port'))
    except (TypeError, ValueError):
        return jsonify({'error': 'port is required and must be an integer'}), 400
    if not ttype:
        return jsonify({'error': 'type is required'}), 400
    note = _clean_str(data.get('note', ''), 256)
    entry_id = _hashlib_al.sha256(f'{ttype}:{port}'.encode()).hexdigest()[:12]
    entries = _read_allowlist()
    if any(e['id'] == entry_id for e in entries):
        return jsonify({'ok': True, 'id': entry_id, 'already_exists': True})
    entries.append({
        'id':       entry_id,
        'type':     ttype,
        'port':     port,
        'note':     note,
        'added_at': datetime.now(timezone.utc).isoformat(),
    })
    _write_allowlist(entries)
    return jsonify({'ok': True, 'id': entry_id}), 201


@allowlist_bp.route('/api/allowlist/<entry_id>', methods=['DELETE'])
def remove_allowlist(entry_id):
    """Admin only: delete one entry by id; 404 when there is no such entry."""
    if not _auth.is_admin():
        return jsonify({'error': 'Unauthorized'}), 401
    entries = _read_allowlist()
    kept = [e for e in entries if e['id'] != entry_id]
    if len(kept) == len(entries):
        return jsonify({'error': 'not found'}), 404
    _write_allowlist(kept)
    return jsonify({'ok': True})
