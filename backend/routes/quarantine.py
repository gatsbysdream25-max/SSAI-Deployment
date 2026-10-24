"""Email quarantine import (the /api/quarantine/import route).

No Microsoft Graph or EOP credentials exist yet, so ingestion is manual: quarantine exports are POSTed here (copy and paste from
the admin portal, or scripted later), landed on disk, and EmailQuarantineAgent (agents/agent_runner.py) turns unprocessed entries
into findings on its normal poll.
"""
import hashlib
from datetime import datetime, timezone

from flask import Blueprint, jsonify, request

import auth as _auth
from request_helpers import _clean_str

quarantine_bp = Blueprint("quarantine", __name__)


def _dropbox_path():
    """The dropbox file, looked up when needed: app.py owns the setting and tests point it somewhere else."""
    from app import _QUARANTINE_DROPBOX_PATH
    return _QUARANTINE_DROPBOX_PATH


@quarantine_bp.route('/api/quarantine/import', methods=['POST'])
def import_quarantine():
    """Admin only: accept a list of exported quarantined emails and add the new ones to the dropbox file that
    EmailQuarantineAgent reads. Replies with how many were new."""
    if not _auth.is_admin():
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json(silent=True) or {}
    items = data.get('items')
    if not isinstance(items, list) or not items:
        return jsonify({'error': 'items must be a non-empty array'}), 400
    import quarantine_dropbox
    # Locked read-modify-write shared with EmailQuarantineAgent: neither side can drop the other's changes.
    added, total = quarantine_dropbox.update(_dropbox_path(), lambda entries: _add_quarantine_items(entries, items))
    return jsonify({'ok': True, 'added': added, 'total': total}), 201


def _add_quarantine_items(entries, items):
    """Append the new, valid items to `entries` (in place). Returns (added, total)."""
    existing_ids = {e.get('id') for e in entries if isinstance(e, dict)}
    added = 0
    # At most 500 items per request, so one huge upload cannot flood the file.
    for raw in items[:500]:
        if not isinstance(raw, dict):
            continue
        received_time  = _clean_str(raw.get('received_time', ''), 64)
        subject        = _clean_str(raw.get('subject', ''), 512)
        sender         = _clean_str(raw.get('sender', ''), 256)
        policy_type    = _clean_str(raw.get('policy_type', ''), 64)
        release_status = _clean_str(raw.get('release_status', ''), 64)
        policy_name    = _clean_str(raw.get('policy_name', ''), 128)
        expires        = _clean_str(raw.get('expires', ''), 64)
        recipient      = _clean_str(raw.get('recipient', ''), 256)
        tags           = _clean_str(raw.get('tags', ''), 128)
        if not (subject or sender):
            continue
        # The id is a hash of the fields that identify an email, so importing the same email twice is skipped.
        entry_id = hashlib.sha256(
            f'{received_time}:{subject}:{sender}:{recipient}'.encode()
        ).hexdigest()[:16]
        if entry_id in existing_ids:
            continue
        entries.append({
            'id':              entry_id,
            'received_time':   received_time,
            'subject':         subject,
            'sender':          sender,
            'policy_type':     policy_type,
            'release_status':  release_status,
            'policy_name':     policy_name,
            'expires':         expires,
            'recipient':       recipient,
            'tags':            tags,
            'imported_at':     datetime.now(timezone.utc).isoformat(),
            'processed':       False,
        })
        existing_ids.add(entry_id)
        added += 1
    return added, len(entries)
