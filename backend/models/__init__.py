from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta, timezone

db = SQLAlchemy()

_SEVERITY_NORM = {
    'notice':  'low',
    'warn':    'medium',
    'warning': 'medium',
    'err':     'high',
    'error':   'high',
    'crit':    'critical',
    'alert':   'critical',
    'emerg':   'critical',
}

def normalize_severity(raw):
    if not raw:
        return 'low'
    v = raw.strip().lower()
    return _SEVERITY_NORM.get(v, v)


def _source_tag(real):
    """A short, non-reversible label for the real address behind a masked one, so the dashboard can tell devices apart
    (group and count them separately) without ever receiving the address itself."""
    if not real:
        return None
    import hashlib
    import os
    salt = os.environ.get('SSAI_API_KEY', '') or 'ssai'
    return hashlib.sha256(f'{salt}|{real}'.encode()).hexdigest()[:6]


class Threat(db.Model):
    # FIX (2026-08-18): partial index — every analyzer query filters ai_analyzed=0,
    # and that set is tiny relative to 85k+ total rows, so a partial index is smaller
    # and faster than indexing every row regardless of value.
    __table_args__ = (
        db.Index('ix_threat_ai_analyzed_pending', 'ai_analyzed',
                 sqlite_where=db.text('ai_analyzed = 0')),
        # FIX (2026-08-19): submit_threat()'s dedup lookup (filter_by(url=..., type=...))
        # runs on every threat submission from every agent, every cycle — was a full
        # table scan against 85k+ rows with no supporting index.
        db.Index('ix_threat_type_url', 'type', 'url'),
    )
    id          = db.Column(db.Integer, primary_key=True)
    url         = db.Column(db.String(500))
    type        = db.Column(db.String(100))
    severity    = db.Column(db.String(50), index=True)   # FIX #15: index for filter_by(severity=...)
    description = db.Column(db.Text)
    detected_by = db.Column(db.String(100))
    node_id     = db.Column(db.String(200))
    status      = db.Column(db.String(50), default='active', index=True)  # FIX #15: index for filter_by(status=...)
    timestamp   = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)  # FIX #15: index for order_by(timestamp)
    # FIX #7: proper ai_analyzed flag and ai_verdict column instead of fragile LIKE '%verdict%' heuristic
    ai_analyzed = db.Column(db.Boolean, default=False, nullable=False)  # partial index below — only unanalyzed rows are ever filtered
    ai_verdict  = db.Column(db.Text, nullable=True)   # stores JSON blob from AiSwarmAnalyzer._consensus()
    # ADMIN-ONLY: the real address behind a masked `url` (192.168.0.5 behind 192.168.xxx.xxx). Never add it to
    # to_dict(), the GitHub ledger or any export; only the authenticated identify endpoint may read it.
    real_source = db.Column(db.String(500), nullable=True, index=True)
    # Finding memory (see findings.py): the same finding is one row, remembered by fingerprint, and re-reported on a
    # schedule while it is still active. `timestamp` is when it was last REPORTED; `last_seen` is the latest sighting.
    fingerprint    = db.Column(db.String(40), nullable=True, index=True)
    first_seen     = db.Column(db.DateTime, nullable=True)
    last_seen      = db.Column(db.DateTime, nullable=True)
    last_reported  = db.Column(db.DateTime, nullable=True)
    times_seen     = db.Column(db.Integer, nullable=True)
    times_reported = db.Column(db.Integer, nullable=True)

    def to_dict(self):
        """The threat as a JSON-ready dict for the API. The real address behind a masked url is left out on purpose: only
        `identifiable` (true/false) is shown."""
        import findings
        sev = (self.severity or 'low').lower()
        return {
            'id':             self.id,
            'url':            self.url,
            'source':         self.url,
            'type':           self.type,
            'category':       self.type,
            'severity':       sev,
            'severity_label': sev.upper(),
            'description':    self.description,
            'detected_by':    self.detected_by,
            'node_id':        self.node_id,
            'status':         self.status,
            'timestamp':      _utc_iso(self.timestamp),
            'ai_analyzed':    bool(self.ai_analyzed),
            'ai_verdict':     self.ai_verdict,
            'identifiable':   bool(self.real_source),        # true/false only: the address itself is not exposed here
            'source_tag':     _source_tag(self.real_source),
            'first_seen':     _utc_iso(self.first_seen or self.timestamp),
            'last_seen':      _utc_iso(self.last_seen or self.timestamp),
            'occurrences':    self.times_seen or 1,
            'alert_count':    self.times_reported or 1,
            'still_active':   findings.still_active(self) if self.status == 'active' else None,
        }


class Agent(db.Model):
    id              = db.Column(db.Integer, primary_key=True)
    name            = db.Column(db.String(100))
    type            = db.Column(db.String(100))
    role            = db.Column(db.String(100))
    description     = db.Column(db.String(300))
    hostname        = db.Column(db.String(200))
    platform        = db.Column(db.String(50))
    status          = db.Column(db.String(50), default='idle')
    last_seen       = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    tasks_completed = db.Column(db.Integer, default=0)
    scans_count     = db.Column(db.Integer, default=0)
    threats_found   = db.Column(db.Integer, default=0)
    last_scan       = db.Column(db.DateTime, nullable=True)
    # Per-provider {last_success, last_error, last_error_msg} from
    # AiSwarmAnalyzer.get_health(), JSON-encoded — SwarmConsensusAgent is the
    # only writer today, but this isn't agent-specific by design.
    provider_health = db.Column(db.Text, nullable=True)

    # An agent that has not checked in for this long is shown as offline, whatever status it last stored. Agents report every
    # 30 seconds or so, and a machine that was removed or switched off never sends a final "I am stopping" message.
    STALE_AFTER_MINUTES = 15

    @classmethod
    def _fresh_cutoff(cls):
        import os
        minutes = float(os.environ.get('SSAI_AGENT_STALE_MINUTES', cls.STALE_AFTER_MINUTES))
        return datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=minutes)

    @classmethod
    def active_count(cls):
        """How many agents are active AND have checked in recently (the dashboard's agent count)."""
        return cls.query.filter(cls.status == 'active', cls.last_seen >= cls._fresh_cutoff()).count()

    def shown_status(self):
        """The stored status, except that a silent 'active' agent is reported as 'offline'."""
        seen = self.last_seen
        if self.status == 'active' and seen is not None:
            seen = seen.replace(tzinfo=None) if seen.tzinfo is None else seen.astimezone(timezone.utc).replace(tzinfo=None)
            if seen < self._fresh_cutoff():
                return 'offline'
        return self.status

    def to_dict(self):
        """The agent as a JSON-ready dict. provider_health is stored as JSON text and decoded here; text that cannot be
        decoded becomes None."""
        import json as _json
        try:
            health = _json.loads(self.provider_health) if self.provider_health else None
        except ValueError:
            health = None
        return {
            'id':              self.id,
            'name':            self.name,
            'type':            self.type,
            'role':            self.role or self.type,
            'description':     self.description or '',
            'hostname':        self.hostname or '',
            'platform':        self.platform or '',
            'status':          self.shown_status(),
            'last_seen':       _utc_iso(self.last_seen),
            'tasks_completed': self.tasks_completed,
            'scan_count':      self.scans_count or 0,
            'threat_count':    self.threats_found or 0,
            'last_scan':       _utc_iso(self.last_scan),
            'provider_health': health,
        }


class Node(db.Model):
    """Represents a registered SSAI installation (machine/device)."""

    @classmethod
    def hub(cls):
        """This hub's own row, named the way app._register_hub_node names it: the hostname, or '<host>-hub' when an
        enrolled machine already owns the plain hostname."""
        import socket
        host = socket.gethostname()
        for _ in range(3):
            node = cls.query.filter_by(node_id=host).first()
            if node is not None and node.token_hash:
                host = host + '-hub'
                continue
            return node
        return None
    id          = db.Column(db.Integer, primary_key=True)
    node_id     = db.Column(db.String(200), unique=True, index=True)
    hostname    = db.Column(db.String(200))
    platform    = db.Column(db.String(50))
    tier        = db.Column(db.String(50), default='free')
    eula_ver    = db.Column(db.String(20))
    status      = db.Column(db.String(50), default='active')
    token       = db.Column(db.String(200))
    last_seen   = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    registered  = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    agent_count = db.Column(db.Integer, default=0)
    ai_capabilities = db.Column(db.Text, default="[]")
    ai_count = db.Column(db.Integer, default=0)
    # Credential (see auth.py). Only a SHA-256 hash of the token is stored; `token` is the retired plaintext column of the
    # old open registration and is cleared on start.
    token_hash  = db.Column(db.String(64), nullable=True, index=True)
    token_hint  = db.Column(db.String(12), nullable=True)      # first characters, so an admin can tell tokens apart
    enrolled_at = db.Column(db.DateTime, nullable=True)
    revoked_at  = db.Column(db.DateTime, nullable=True)

    def to_dict(self):
        """The machine as a JSON-ready dict. The token and its hash are never included; `credential` only says revoked,
        active or none."""
        return {
            'id':          self.id,
            'node_id':     self.node_id,
            'name':        self.hostname or self.node_id,
            'hostname':    self.hostname or '',
            'platform':    self.platform or '',
            'tier':        self.tier,
            'status':      self.status,
            'last_seen':   _utc_iso(self.last_seen),
            'registered':  _utc_iso(self.registered),
            'agent_count': self.agent_count,
            'ai_count':    self.ai_count or 0,
            'credential':  'revoked' if self.status == 'revoked' else ('active' if self.token_hash else 'none'),
            'enrolled_at': _utc_iso(self.enrolled_at),
        }


def _utc_iso(dt):
    """SQLite hands datetimes back without a zone. They are stored in UTC, so say so: a browser reads a bare time as
    local, which showed the hub as 'last seen -14304s ago' in a UTC-4 timezone (2026-09-26)."""
    if dt is None:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).isoformat()


class EnrollmentCode(db.Model):
    """A single-use, short-lived code an admin creates so one machine can enroll (only its hash is stored)."""
    id         = db.Column(db.Integer, primary_key=True)
    code_hash  = db.Column(db.String(64), unique=True, index=True, nullable=False)
    node_id    = db.Column(db.String(200), nullable=True)      # set when the code is for one named machine (re-enrolment)
    created_at = db.Column(db.DateTime, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used_at    = db.Column(db.DateTime, nullable=True)
    used_by    = db.Column(db.String(200), nullable=True)
    created_by = db.Column(db.String(100), nullable=True)


# FIX #8: GithubSync table to track committed threat count — replaces hardcoded zeros
class GithubSync(db.Model):
    id              = db.Column(db.Integer, primary_key=True)
    threat_id       = db.Column(db.Integer, db.ForeignKey('threat.id'), nullable=False, index=True)
    committed_at    = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    commit_sha      = db.Column(db.String(40), nullable=True)
    repo            = db.Column(db.String(200), default='gatsbysdream25-max/SwarmSentinel')

    def to_dict(self):
        return {
            'id':           self.id,
            'threat_id':    self.threat_id,
            'committed_at': _utc_iso(self.committed_at),
            'commit_sha':   self.commit_sha,
            'repo':         self.repo,
        }


class AutonomyGrant(db.Model):
    """One narrow permission to act without asking (autonomy.py). Rows are never edited: a grant is created, then it expires or is
    revoked; changing the terms means a new grant, so the history of what SSAI was allowed to do is always complete."""
    id                  = db.Column(db.Integer, primary_key=True)
    category            = db.Column(db.String(100), nullable=False)    # exactly one threat type, e.g. malicious-domain
    action              = db.Column(db.String(20), nullable=False)     # block-ip | block-domain
    severities          = db.Column(db.String(100), nullable=False)    # comma list, normally low,medium
    min_confidence      = db.Column(db.Integer, nullable=False)
    min_ai_count        = db.Column(db.Integer, nullable=False)
    require_verified    = db.Column(db.Boolean, nullable=False, default=True)
    ttl_hours           = db.Column(db.Integer, nullable=False)        # every automatic block is undone after this
    rate_limit_per_hour = db.Column(db.Integer, nullable=False)
    expires_at          = db.Column(db.DateTime, nullable=False)
    granted_by          = db.Column(db.String(100), nullable=False)
    granted_at          = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    revoked_at          = db.Column(db.DateTime, nullable=True)
    revoked_by          = db.Column(db.String(100), nullable=True)

    def to_dict(self):
        return {'id': self.id, 'category': self.category, 'action': self.action, 'severities': self.severities.split(','),
                'min_confidence': self.min_confidence, 'min_ai_count': self.min_ai_count, 'require_verified': self.require_verified,
                'ttl_hours': self.ttl_hours, 'rate_limit_per_hour': self.rate_limit_per_hour, 'expires_at': _utc_iso(self.expires_at),
                'granted_by': self.granted_by, 'granted_at': _utc_iso(self.granted_at),
                'revoked_at': _utc_iso(self.revoked_at), 'revoked_by': self.revoked_by}


# Approve-first remediation queue: a high-confidence multi-AI "malicious" verdict proposes a block instead of applying it, so a
# person always has the last word. Every approved block gets an expiry (ttl) and is reverted by RemediationSweepAgent, so an
# approval is never a silent forever-block.
class PendingRemediation(db.Model):
    __table_args__ = (
        db.Index('ix_pendingremediation_status', 'status'),
    )
    id           = db.Column(db.Integer, primary_key=True)
    threat_id    = db.Column(db.Integer, db.ForeignKey('threat.id'), nullable=False, index=True)
    kind         = db.Column(db.String(20))            # 'ip' | 'domain' — see remediation.classify_target()
    target       = db.Column(db.String(500))
    reason       = db.Column(db.Text)                  # human-readable: verdict, confidence, agreement, sources
    confidence   = db.Column(db.Integer, nullable=True)
    status       = db.Column(db.String(20), default='pending')  # pending|approved|rejected|expired|rolled_back
    proposed_at  = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    decided_at   = db.Column(db.DateTime, nullable=True)
    decided_by   = db.Column(db.String(100), nullable=True)
    expires_at   = db.Column(db.DateTime, nullable=True)  # set on approval; RemediationSweepAgent auto-rolls-back past this
    rolled_back_at = db.Column(db.DateTime, nullable=True)

    def to_dict(self):
        """The proposal as a JSON-ready dict for the API and dashboard, with times as UTC ISO text."""
        return {
            'id':             self.id,
            'threat_id':      self.threat_id,
            'kind':           self.kind,
            'target':         self.target,
            'reason':         self.reason,
            'confidence':     self.confidence,
            'status':         self.status,
            'proposed_at':    _utc_iso(self.proposed_at),
            'decided_at':     _utc_iso(self.decided_at),
            'decided_by':     self.decided_by,
            'expires_at':     _utc_iso(self.expires_at),
            'rolled_back_at': _utc_iso(self.rolled_back_at),
        }
