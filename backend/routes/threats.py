from flask import Blueprint, request, jsonify
from models import db, Threat, normalize_severity
from agents.ai_swarm_agent import analyze_screenshot_image, screenshot_unavailable_reason
from datetime import datetime, timezone
from sqlalchemy import or_

from auth import identity, is_admin, node_rate_limited
import findings

threats_bp = Blueprint('threats', __name__)


def _check_auth():
    """Admin only (dismiss, resolve, block, update...). Submitting a threat also accepts an enrolled node."""
    return is_admin()

_VALID_SEVERITIES = {'info', 'low', 'medium', 'high', 'critical'}

# Threat types that represent an ongoing *condition* (still true on rescan)
# rather than a distinct *event* (happened at this moment) — only these are
# deduped on resubmission. ssh-login/brute-force/file-modification/
# suspicious-process are left alone: each occurrence is a separate thing an
# operator should see, not a restatement of the same fact.
_STATEFUL_TYPES = {
    'suspicious-port', 'disk-full', 'service-failure',
    'unexpected-listener', 'dns-anomaly', 'malicious-domain', 'malware-url', 'intel-match',
}

def _as_text(v):
    """Coerce caller-supplied JSON values to str|None for String/Text columns.

    SQLite only binds None/int/float/str/bytes; a JSON object or array here
    raises an unhandled sqlite3.ProgrammingError at commit time (HTTP 500).
    """
    if v is None or isinstance(v, str):
        return v
    return str(v)

def _threat_from_data(data):
    """Build an unsaved Threat from submitted JSON. Values are made safe for the database, an unknown severity becomes
    'low', and the admin-only real address is kept from `real_url`."""
    raw_sev = data.get('severity', 'medium')
    severity = normalize_severity(raw_sev)
    if severity not in _VALID_SEVERITIES:
        severity = 'low'
    return Threat(
        url         = _as_text(data.get('url')),
        type        = _as_text(data.get('type')),
        severity    = severity,
        description = _as_text(data.get('description')),
        detected_by = _as_text(data.get('detected_by') or data.get('agentId', 'extension')),
        real_source = (_as_text(data.get('real_url')) or '')[:500] or None,
        node_id     = (_as_text(data.get('node_id')) or '')[:200] or None,
    )

@threats_bp.route('/', methods=['GET'])
def get_threats():
    """List threats newest first, a page at a time. Optional filters: severity, unanalyzed and needs_consensus."""
    # FIX #9: server-side pagination — was loading all 4400+ rows on every request.
    # Default limit 200; callers pass ?limit=N&offset=M.
    # Also support optional ?severity= and ?unanalyzed=true filters so AI agents
    # can fetch only what they need (fix #13 — avoids massive client-side filtering).
    try:
        limit = min(int(request.args.get('limit', 200)), 1000)
    except (TypeError, ValueError):
        limit = 200
    try:
        offset = max(0, int(request.args.get('offset', 0)))
    except (TypeError, ValueError):
        offset = 0

    q = Threat.query

    sev_filter = request.args.get('severity', '').strip().lower()
    if sev_filter in _VALID_SEVERITIES:
        q = q.filter(Threat.severity == sev_filter)
    elif sev_filter == 'high+':
        # Convenience: severity=high+ means high or critical
        q = q.filter(Threat.severity.in_(['high', 'critical']))

    if request.args.get('unanalyzed', '').lower() in ('true', '1', 'yes'):
        q = q.filter(Threat.ai_analyzed == False)  # noqa: E712
    # needs_consensus: not yet judged by the AI panel. A tier-one local analyzer (Ollama/Hermes/Watchtower, optional)
    # marks a threat analysed when it stores its own verdict, so ?unanalyzed=true hid exactly those threats from the
    # panel and they were never escalated (code review 2026-09-30, finding 9).
    if request.args.get('needs_consensus', '').lower() in ('true', '1', 'yes'):
        q = q.filter(or_(Threat.ai_analyzed == False, Threat.ai_verdict.is_(None),  # noqa: E712
                         ~Threat.ai_verdict.like('%"consensus"%')))

    q = q.order_by(Threat.timestamp.desc())
    threats = q.offset(offset).limit(limit).all()
    return jsonify([t.to_dict() for t in threats])

@threats_bp.route('/recall', methods=['GET'])
def recall_verdicts():
    """What the swarm already concluded about an indicator, so nobody analyses (or documents) it twice.

    ?url=<indicator>&category=<threat type>[&exclude_id=N] -> {found, consensus, threat_id, timestamp}
    with no ?url -> the most recent threats that carry a consensus, used to warm an agent's recall cache."""
    import time
    from agents import recall
    url = (request.args.get('url') or '').strip()
    if not url:
        try:
            limit = max(1, min(int(request.args.get('limit', 500)), 1000))
        except (TypeError, ValueError):
            limit = 500
        rows = (Threat.query.filter(Threat.ai_verdict.like('%"consensus"%'))
                .order_by(Threat.timestamp.desc()).limit(limit).all())
        return jsonify([t.to_dict() for t in rows])

    category = (request.args.get('category') or '').strip()
    cands = recall.candidate_urls(url)
    if not cands:                                        # empty, oversized or masked: nothing to match on
        return jsonify({'found': False})
    q = Threat.query.filter(Threat.url.in_(cands), Threat.ai_verdict.like('%"consensus"%'))
    if recall.is_scoped(url):
        q = q.filter(Threat.type == category)
    try:
        exclude_id = int(request.args.get('exclude_id', ''))
    except ValueError:
        exclude_id = None
    if exclude_id is not None:
        q = q.filter(Threat.id != exclude_id)
    now = time.time()
    for t in q.order_by(Threat.timestamp.desc()).limit(10).all():
        row = t.to_dict()
        c = recall.consensus_of(row)
        at = recall._epoch(row.get('timestamp'))
        if c is not None and at is not None and now - at <= recall.ttl_seconds(c.get('consensus_verdict')):
            return jsonify({'found': True, 'consensus': c, 'threat_id': t.id, 'timestamp': row['timestamp']})
    return jsonify({'found': False})


@threats_bp.route('/<int:threat_id>/report', methods=['GET'])
def incident_report(threat_id):
    """The incident report for one finding: verdict, quorum, each model's position, local proof, proposed fix, timeline.
    ?format=md returns it as Markdown text. Admin only: it names detectors and indicators in full."""
    if not is_admin():
        return jsonify({'error': 'Unauthorized'}), 401
    from agents import incident_report as ir
    threat = db.session.get(Threat, threat_id)
    if threat is None:
        return jsonify({'error': 'not found'}), 404
    proposal = None
    try:
        from models import PendingRemediation
        row = PendingRemediation.query.filter_by(threat_id=threat_id).order_by(PendingRemediation.id.desc()).first()
        proposal = row.to_dict() if row else None
    except Exception:                                    # noqa: BLE001 -- a report without the proposal is still a report
        proposal = None
    report = ir.build(threat.to_dict(), proposal)
    if request.args.get('format') == 'md':
        return ir.to_markdown(report), 200, {'Content-Type': 'text/markdown; charset=utf-8'}
    return jsonify(report)


@threats_bp.route('/related', methods=['GET'])
def related_findings():
    """Other findings about the same indicator in the last 30 days, in compact form: the local proof the consensus agent checks a
    verdict against (agents/local_evidence.py). ?url=<indicator>[&exclude_id=N] -> [{id, type, detected_by, severity, times_seen, timestamp}]"""
    from datetime import timedelta
    from agents import recall
    cands = recall.candidate_urls((request.args.get('url') or '').strip())
    if not cands:                                        # empty, oversized or masked: nothing to match on
        return jsonify([])
    q = Threat.query.filter(Threat.url.in_(cands), Threat.timestamp >= datetime.now(timezone.utc) - timedelta(days=30))
    try:
        q = q.filter(Threat.id != int(request.args.get('exclude_id', '')))
    except ValueError:
        pass
    rows = q.order_by(Threat.timestamp.desc()).limit(25).all()
    return jsonify([{'id': t.id, 'type': t.type, 'detected_by': t.detected_by, 'severity': t.severity,
                     'times_seen': t.times_seen, 'status': t.status,
                     'timestamp': t.timestamp.isoformat() if t.timestamp else None} for t in rows])


def _find_existing(threat):
    """The earlier finding this one repeats, or None if it is new. Also sets the new finding's fingerprint."""
    # FIX (2026-08-19): agents (NetworkScanAgent etc.) resubmit on every scan
    # interval with no memory of prior sightings, so a single ongoing
    # condition (e.g. one open port) piled up thousands of duplicate 'active'
    # rows over months, and dismissing/resolving one did nothing — a fresh
    # row just reappeared next cycle. Dedup on the same (url, type) signature:
    #   - an existing 'active' row for this signature -> bump its timestamp
    #     instead of inserting a duplicate (still "ongoing", not "new").
    #   - an existing 'dismissed'/'resolved' row -> the operator already
    #     acted on this exact signature; suppress recreation entirely. Use
    #     the reopen endpoint to resume detection if the condition changes.
    tracked = threat.type not in findings.every_occurrence_types()
    threat.fingerprint = findings.fingerprint(threat.type, threat.node_id, threat.real_source, threat.url)
    existing = None
    if tracked:
        # Finding memory (findings.py): the same type + machine + indicator is ONE finding, however often it is seen.
        existing = (Threat.query.filter_by(fingerprint=threat.fingerprint)
                    .order_by(Threat.timestamp.desc()).first())
    if existing is None and threat.type in _STATEFUL_TYPES:
        q = Threat.query.filter_by(url=threat.url, type=threat.type)
        if threat.real_source:
            # Every LAN address shares one masked url, so devices are told apart by their real address. A row recorded
            # before real addresses were kept (real_source NULL) is adopted by the first device that matches it, which
            # preserves the operator's earlier dismiss/resolve decisions.
            q = (q.filter(or_(Threat.real_source == threat.real_source, Threat.real_source.is_(None)))
                  .order_by((Threat.real_source == threat.real_source).desc()))
        if threat.node_id:
            # the same condition on two machines (a full disk, an open port) is two threats; rows from before machines
            # were named (node_id NULL) are adopted by the first machine that matches them, as with real_source
            q = (q.filter(or_(Threat.node_id == threat.node_id, Threat.node_id.is_(None)))
                  .order_by((Threat.node_id == threat.node_id).desc()))
        existing = q.order_by(Threat.timestamp.desc()).first()
    return existing


def _record_repeat(existing, threat, now):
    """Note a repeat sighting of an earlier finding. Returns the reply to send, or None when the earlier row is in some other state
    and the new one should be created."""
    if threat.real_source and not existing.real_source:
        existing.real_source = threat.real_source
    if threat.node_id and not existing.node_id:
        existing.node_id = threat.node_id
    if not existing.fingerprint:
        existing.fingerprint = threat.fingerprint        # a row from before fingerprints: remembered from now on
    if existing.status == 'active':
        # Seen recently: stay quiet, note the sighting. Still active after the severity's interval: report it
        # again, with the count and how long it has been going (a re-alert), so an ongoing attack is not silenced.
        decision = findings.observe(existing, threat.severity, now)
        db.session.commit()
        out = {'success': True, 'threat': existing.to_dict(), 'deduped': True,
               'realert': decision['realert'], 'reason': decision['reason']}
        if decision['realert']:
            out['message'] = findings.still_active(existing, now)
        return jsonify(out), 200
    if existing.status in ('dismissed', 'resolved'):
        findings.sighted(existing, now)                  # the operator already acted: quiet, but keep counting
        db.session.commit()
        return jsonify({'success': True, 'suppressed': True, 'reason': existing.status}), 200
    return None


@threats_bp.route('/', methods=['POST'])
def submit_threat():
    """Ingest a threat (admin key or an enrolled node's token). A repeat of a finding already known is merged into it
    instead of creating a duplicate; otherwise a new row is saved and 201 returned."""
    # FIX (2026-08-20): this was the last open ingest endpoint — anyone on
    # the LAN could inject an arbitrary threat row. All real callers
    # (agent_runner.py's submit_threat(), the browser extension) already
    # send X-API-Key as of this same change.
    who = identity()
    if who is None:
        return jsonify({'error': 'Unauthorized'}), 401
    if who.kind == 'node' and node_rate_limited(who.node):
        return jsonify({'error': 'rate limited'}), 429
    data = request.get_json()
    if not data:
        return jsonify({'error': 'JSON body required'}), 400
    threat = _threat_from_data(data)
    if who.kind == 'node':
        threat.node_id = who.node.node_id      # a node speaks only for itself, whatever the request claims
        threat.detected_by = f"{(threat.detected_by or 'node')[:60]}@{who.node.node_id}"[:100]     # the hub, not the node, says who reported

    now = datetime.now(timezone.utc)
    existing = _find_existing(threat)
    if existing:
        reply = _record_repeat(existing, threat, now)
        if reply is not None:
            return reply

    findings.start(threat, now)
    db.session.add(threat)
    db.session.commit()
    return jsonify({'success': True, 'threat': threat.to_dict()}), 201


@threats_bp.route('/<int:id>/reopen', methods=['POST'])
def reopen_threat(id):
    """Clear a dismissed/resolved threat back to active so it can be
    re-detected and re-reported again (e.g. the operator wants to re-check
    a previously-suppressed host:port)."""
    if not _check_auth():
        return jsonify({'error': 'Unauthorized'}), 401
    threat = Threat.query.get_or_404(id)
    threat.status = 'active'
    db.session.commit()
    return jsonify(threat.to_dict())

@threats_bp.route('/collective', methods=['GET'])
def collective_threats():
    threats = Threat.query.order_by(Threat.timestamp.desc()).limit(100).all()
    return jsonify({
        'success': True,
        'threats': [t.to_dict() for t in threats],
        'total':   Threat.query.count()
    })

@threats_bp.route('/<int:id>', methods=['PUT'])
def update_threat(id):
    """Admin only: change a threat's status and/or store the AI verdict on it. A consensus inside the verdict may queue a
    block proposal for a person to approve."""
    if not _check_auth():
        return jsonify({'error': 'Unauthorized'}), 401
    threat = Threat.query.get_or_404(id)
    data = request.get_json()
    if not data:
        return jsonify({'error': 'JSON body required'}), 400
    threat.status = data.get('status', threat.status)
    # FIX #7: allow external callers (AI agents) to mark a threat as analyzed
    # and store the verdict JSON in ai_verdict.
    if 'ai_analyzed' in data:
        threat.ai_analyzed = bool(data['ai_analyzed'])
    consensus = None
    if 'ai_verdict' in data:
        import json as _j
        verdict_data = data['ai_verdict']
        threat.ai_verdict  = _j.dumps(verdict_data) if isinstance(verdict_data, dict) else verdict_data
        threat.ai_analyzed = True
        if isinstance(verdict_data, dict):
            consensus = verdict_data.get('consensus')
    db.session.commit()
    # A fresh high-confidence "malicious" consensus proposes a block/sinkhole for an operator to
    # approve or reject; it never acts on its own. See remediation_queue.py.
    if consensus is not None:
        try:
            import remediation_queue
            from app import _never_block_ips
            remediation_queue.propose(threat, consensus, never_block_ips=_never_block_ips())
        except Exception as e:                 # noqa: BLE001 -- a proposal failing must never break the verdict save
            import logging
            logging.getLogger(__name__).warning('remediation_queue.propose failed for threat %s: %s', id, e)
    return jsonify(threat.to_dict())


_ALLOWED_IMAGE_TYPES = {"image/png", "image/jpeg", "image/webp"}
_MAX_IMAGE_BYTES = 8 * 1024 * 1024  # 8MB


@threats_bp.route('/from_screenshot', methods=['POST'])
def submit_threat_from_screenshot():
    """Admin only: draft a finding from an uploaded screenshot (png, jpeg or webp, at most 8MB) read by a local vision
    model. The draft is capped at medium severity until the whole panel has judged it."""
    # Same auth gate as submit_threat() above — this is another ingest path,
    # not exempt from the X-API-Key requirement.
    if not _check_auth():
        return jsonify({'error': 'Unauthorized'}), 401

    if 'image' not in request.files:
        return jsonify({'error': "multipart field 'image' required"}), 400
    file = request.files['image']
    mime_type = file.mimetype
    if mime_type not in _ALLOWED_IMAGE_TYPES:
        return jsonify({'error': f'unsupported image type {mime_type}; use png/jpeg/webp'}), 400

    image_bytes = file.read(_MAX_IMAGE_BYTES + 1)
    if len(image_bytes) > _MAX_IMAGE_BYTES:
        return jsonify({'error': 'image too large, 8MB max'}), 413

    why_not = screenshot_unavailable_reason()
    if why_not:
        return jsonify({
            'error': 'screenshots are read only by a local vision model and never sent to cloud AI, and none is set up: '
                     + why_not + '. Submit the finding manually via POST /api/threats/'
        }), 503
    verdict = analyze_screenshot_image(image_bytes, mime_type)
    if not verdict:
        return jsonify({
            'error': 'the local vision model did not return a usable draft (is it running and does it support images? '
                     'see SSAI_VISION_PROVIDER); submit manually via POST /api/threats/'
        }), 503

    severity = normalize_severity(verdict.get('severity', 'medium'))
    if severity not in _VALID_SEVERITIES:
        severity = 'low'

    # One model's reading of one picture is a draft, not a finding (audit F-16): it is capped at medium so the whole panel, not this
    # model, decides whether it is high or critical, and the description says where it came from.
    drafted = severity
    if severity in ('high', 'critical'):
        severity = 'medium'
    note = f"[Drafted by {verdict.get('source', 'a local model')} from a screenshot, not yet checked by the panel" + (f"; it rated this {drafted}]" if drafted != severity else "]")
    threat = Threat(
        url=_as_text(request.form.get('url') or 'screenshot-upload'),
        type=_as_text(verdict.get('threat_type', 'other')),
        severity=severity,
        description=f"{note} {_as_text(verdict.get('description'))}"[:2000],
        detected_by=f"screenshot-upload:{verdict.get('source', 'ai')}",
    )
    db.session.add(threat)
    db.session.commit()
    return jsonify({
        'success': True,
        'threat': threat.to_dict(),
        'ai_confidence': verdict.get('confidence'),
    }), 201
