"""The web app: the dashboard, the API every agent and machine talks to, sign-in, and database start-up.

Request flow for the one thing that matters most (blocking an address):
  dashboard button -> a route here -> remediation_queue.py (a PROPOSAL, never an action) -> a signed-in person approves
  -> remediation.py applies it -> the audit file is written FIRST. Who may call what is decided in auth.py.

Read top to bottom: set-up, rate limiting and the read-only guards first, then the dashboard page, security headers, the data
the dashboard polls, threat actions (resolve, dismiss, block), identifying an address, the setup wizard, and finally database
start-up. Whole groups of routes live in their own files and are registered below as blueprints:
  routes/login.py       sign-in, single sign-on, changing the admin password
  routes/nodes.py       machines that report here: enrolment codes, heartbeats, the shared signal feed
  routes/allowlist.py   the port allowlist
  routes/quarantine.py  e-mail quarantine import
  routes/settings.py    agent on/off switches and AI routing
  routes/threats.py, agents.py, status.py, remediation.py, autonomy.py, copilot.py   the rest of the API
docs/code-map.md says where each other file fits.
"""
import sys
if __name__ == "__main__":        # `python app.py`: let `from app import ...` in the route files find THIS module, not load a second copy
    sys.modules.setdefault("app", sys.modules["__main__"])
from flask import Flask, jsonify, request, redirect, g
import ssai_config
ssai_config.ensure_dirs()
# Load .env into environment
try:
    from dotenv import load_dotenv as _load_dotenv
    _load_dotenv(ssai_config.ENV_PATH)
except ImportError:
    pass


from flask_cors import CORS
from routes.threats import threats_bp
from routes.agents import agents_bp
from routes.status import status_bp
from routes.remediation import remediation_bp
from routes.autonomy import autonomy_bp
from routes.copilot import copilot_bp
from routes.nodes import nodes_bp
from routes.settings import settings_bp
from routes.quarantine import quarantine_bp
from routes.allowlist import allowlist_bp
from routes.login import login_bp, _safe_next      # sign-in routes; _safe_next is re-exported for tests
import os
import hashlib
import secrets
from datetime import datetime, timezone

app = Flask(__name__)
os.umask(0o077)                                          # files this process creates (the database, keys, logs) are owner-only
from agents import redact as _redact_mod                 # noqa: E402
_redact_mod.install_log_redaction()                      # no API key or token may reach a log line
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024      # a node or key holder cannot exhaust memory with a giant body (screenshots: 8 MB)


@app.errorhandler(413)
def _too_large(_e):
    return jsonify({'error': 'request too large'}), 413

CORS(app, origins=[
    "chrome-extension://*",
    "moz-extension://*",
    # LAN access controlled at network level — no CORS wildcard for RFC1918
    "http://localhost:*",
])

# ─── Rate limiting + input validation for open contribution endpoints ──────
import time as _time
import threading as _rl_thr
from collections import defaultdict as _defaultdict

_rl_lock   = _rl_thr.Lock()
_rl_hits   = _defaultdict(list)   # ip -> [timestamps]
_RL_WINDOW = 60      # seconds
_RL_MAX    = 30      # max requests per window per IP

def _rate_limited(bucket):
    """True when this caller (by IP address) has already made more than _RL_MAX requests to this bucket in the last
    _RL_WINDOW seconds. Each call counts as one more request; it stops one address hammering an endpoint."""
    ip  = _auth.client_ip()      # X-Forwarded-For only from SSAI_TRUSTED_PROXIES: it is otherwise attacker-controlled
    key = f'{bucket}:{ip}'
    now = _time.monotonic()
    with _rl_lock:
        hits = [t for t in _rl_hits[key] if now - t < _RL_WINDOW]
        hits.append(now)
        _rl_hits[key] = hits
        if len(_rl_hits) > 10000:                # every address ever seen used to stay in memory (review minor)
            for k in [k for k, v in _rl_hits.items() if not v or now - v[-1] >= _RL_WINDOW]:
                del _rl_hits[k]
        return len(hits) > _RL_MAX

import auth as _auth
from request_helpers import _clean_str

def _check_auth():
    # FIX (2026-08-19): these app.py-level mutating routes (block/resolve/
    # dismiss a threat, allowlist writes, AI-routing writes, provider-key
    # activation) shipped without the X-API-Key gate that routes/threats.py
    # and routes/agents.py already enforce on their own mutations — same
    # protocol, just missed when these were added directly in app.py.
    return _auth.is_admin()          # the admin key only; an enrolled node's token is not an admin credential


def _is_readonly():
    """Read-only viewer mode (wall display / kiosk): a trusted front end marks its requests with
    X-SSAI-Readonly: 1. The header can only ever REDUCE access, so it is safe if a client spoofs it."""
    return request.headers.get('X-SSAI-Readonly') == '1'


@app.before_request
def _enforce_readonly():
    """Runs before every request. On a read-only display (wall screen) refuse anything that changes data, plus the setup
    and settings pages, so the display cannot be used to change keys or settings."""
    if not _is_readonly():
        return None
    blocked = (request.method not in ('GET', 'HEAD', 'OPTIONS')
               or request.path in ('/setup', '/settings')
               or request.path.startswith(('/api/setup', '/api/settings')))
    if not blocked:
        return None
    if request.path in ('/setup', '/settings'):
        return ('<!doctype html><title>Read-only display</title><body style="font-family:sans-serif;'
                'background:#0e0f13;color:#d7d9dd;padding:40px"><h2>Read-only display</h2>'
                '<p>Settings and API keys can only be changed from a trusted computer, not from this display.</p>',
                403, {'Content-Type': 'text/html'})
    return jsonify({'error': 'read-only display'}), 403


# Threat data and the deployment's posture (which agents and AI providers run) are readable only by a signed-in admin,
# the admin key, or the display's viewer key (auth.is_viewer). Left public on purpose: /health and the three aggregate
# counters (/api/status/, /api/stats, /api/cloud_status), which an uptime probe needs and which name nothing.
# tools/test_route_auth.py lists every route, so a new data endpoint cannot slip past this set unnoticed.
READ_PROTECTED = frozenset((
    '/api/summary', '/api/threats/', '/api/threats/collective', '/api/threats/recall', '/api/threats/related', '/api/collective',
    '/api/dashboard_snapshot', '/api/signal/feed', '/api/agents/', '/api/ai_swarm', '/api/github_stats',
))


@app.before_request
def _require_reader():
    if request.method in ('GET', 'HEAD') and request.path in READ_PROTECTED and not _auth.can_read():
        return jsonify({'error': 'sign in, or present the viewer key'}), 401
    return None


app.config["SQLALCHEMY_DATABASE_URI"] = ssai_config.SQLALCHEMY_DATABASE_URI
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"connect_args": {"timeout": 5}}  # busy_timeout: WAL removes most contention, this turns residual collisions into brief waits instead of exceptions
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False


from sqlalchemy import event as _sa_event                    # noqa: E402
from sqlalchemy.engine import Engine as _SaEngine            # noqa: E402


@_sa_event.listens_for(_SaEngine, "connect")
def _tune_sqlite(dbapi_conn, _record):
    """Every SQLite connection: write-ahead log (readers never block the writer, which the dashboard polls rely on), a 5 s
    wait on a locked database instead of an immediate error, and NORMAL sync (safe with WAL: a power cut can lose the last
    commit but never corrupts the file). Before this only an old database file happened to be in WAL mode; a new install
    was not."""
    if dbapi_conn.__class__.__module__.split(".")[0] != "sqlite3":
        return
    try:
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA busy_timeout=5000")
        cur.execute("PRAGMA synchronous=NORMAL")
        cur.close()
    except Exception:                                         # noqa: BLE001 -- a read-only or in-memory database: run untuned
        pass


_KNOWN_DEFAULT_SECRETS = {"swarmsentinel-secret-change-in-prod", "changeme", "change-me", "secret", ""}


def _load_secret_key():
    """The key that signs session cookies. A value from .env is used if it is real; a missing or well-known one (the old
    source default, a placeholder) is replaced by a random key kept in instance/secret_key (owner-only), because anyone
    who knows the signing key can forge an admin session."""
    key = os.environ.get("SECRET_KEY", "").strip()
    if len(key) >= 16 and key.lower() not in _KNOWN_DEFAULT_SECRETS:
        return key
    path = os.path.join(ssai_config.INSTANCE_DIR, "secret_key")
    try:
        with open(path) as f:
            existing = f.read().strip()
        if len(existing) >= 32:
            return existing
    except OSError:
        pass
    generated = secrets.token_hex(32)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(generated)
        return generated
    except FileExistsError:                       # another worker created it first: use theirs, once it has finished writing
        for _ in range(100):
            try:
                with open(path) as f:
                    existing = f.read().strip()
                if len(existing) >= 32:
                    return existing
            except OSError:
                pass
            _time.sleep(0.05)
        return generated
    except OSError:
        return generated                          # unwritable directory: sessions then last only until restart


app.config["SECRET_KEY"] = _load_secret_key()
app.config.update(
    SESSION_COOKIE_NAME="ssai_session",
    SESSION_COOKIE_HTTPONLY=True,                  # page scripts cannot read the session
    SESSION_COOKIE_SAMESITE="Lax",                 # not sent on cross-site POSTs; state changes also need the CSRF token
    SESSION_COOKIE_SECURE=os.environ.get("SSAI_COOKIE_SECURE", "").lower() in ("1", "true", "yes"),   # set when served over HTTPS
    PERMANENT_SESSION_LIFETIME=12 * 3600,
)

from models import db, Node, Agent, Threat
db.init_app(app)

app.register_blueprint(threats_bp, url_prefix="/api/threats")
app.register_blueprint(agents_bp,  url_prefix="/api/agents")
app.register_blueprint(status_bp,  url_prefix="/api/status")
app.register_blueprint(remediation_bp, url_prefix="/api/remediation")
app.register_blueprint(autonomy_bp, url_prefix="/api/autonomy")      # permissions to act without asking (phase 7)
app.register_blueprint(allowlist_bp)                               # /api/allowlist
app.register_blueprint(quarantine_bp)                              # /api/quarantine/import
app.register_blueprint(settings_bp)                                # /api/settings/agents, /api/settings/ai_routing
app.register_blueprint(nodes_bp)                                   # /api/node/*, /api/nodes/*, /api/signal*
app.register_blueprint(login_bp)                                   # /login, /logout, /api/admin/password
app.register_blueprint(copilot_bp, url_prefix="/api/copilot")      # Copilot lane: sanitized brief only


# ─── Standard endpoints ──────────────────────────────────────────────────────
@app.route("/health")
def health():
    return jsonify({
        "service": "swarmsentinel-backend",
        "status":  "healthy",
        "version": "0.3.0-patent-pending",
    })


@app.route("/")
def root():
    """Plain index of the API (name, version, main endpoints) for anyone who opens the server's base address."""
    return jsonify({
        "message": "SwarmSentinel Backend API v0.3.0",
        "patent":  "Provisional Filed 2026-02-22",
        "endpoints": [
            "/api/nodes", "/api/node/register", "/api/node/heartbeat",
            "/api/agents/", "/api/threats/", "/api/threats/collective",
            "/api/signal", "/api/signal/feed", "/api/status/", "/health",
        ],
    })


@app.route("/api/stats", methods=["GET"])
def get_stats():
    """Headline counts (nodes, agents, threats) for the dashboard. Agents that are switched off are not counted."""
    return jsonify({
        "total_nodes":   Node.query.count(),
        "active_nodes":  Node.query.filter_by(status="active").count(),
        "total_agents":  Agent.query.filter(Agent.status != "disabled").count(),
        "active_agents": Agent.query.filter_by(status="active").count(),
        "total_threats": Threat.query.count(),
        "status":        "operational",
    })


# --- Unified Dashboard UI ---
from flask import render_template as _render_template
import os as _os2
app.template_folder = _os2.path.join(_os2.path.dirname(__file__), 'templates')

@app.route('/dashboard')
def dashboard():
    """Anyone may look; only a signed-in admin gets the action buttons. The page never contains the API key: a signed-in
    admin receives a CSRF token instead, and a kiosk or anonymous viewer receives nothing that could change anything."""
    kiosk = _is_readonly() or request.args.get('readonly') == '1'
    admin = _auth.session_admin() and not kiosk
    resp = app.make_response(_render_template('dashboard.html', csrf_token=_auth.csrf_token() if admin else '',
                                              readonly=not admin, kiosk=kiosk, signed_in=admin, show_login=(not admin and not kiosk)))
    resp.headers['Cache-Control'] = 'no-store'
    return resp


def _admin_page(template):
    """Setup and Settings change the system: a signed-in admin only (a read-only kiosk never gets here: _enforce_readonly
    refuses these paths first)."""
    from urllib.parse import quote
    if not _auth.session_admin():
        return redirect('/login?next=' + quote(request.path))
    resp = app.make_response(_render_template(template, csrf_token=_auth.csrf_token(), readonly=False))
    resp.headers['Cache-Control'] = 'no-store'
    return resp


def _is_https():
    """Did this request arrive over HTTPS? Direct TLS, or a trusted proxy (SSAI_TRUSTED_PROXIES) that terminated it and
    said so. X-Forwarded-Proto from anyone else is ignored: a client could claim HTTPS to earn an HSTS header."""
    if request.is_secure:
        return True
    trusted = {p.strip() for p in os.environ.get('SSAI_TRUSTED_PROXIES', '').split(',') if p.strip()}
    return request.remote_addr in trusted and request.headers.get('X-Forwarded-Proto', '').lower() == 'https'


# What a page may load and where it may talk. Scripts run only from this site's files or from a <script> carrying this
# request's one-time nonce, and the pages have no inline event handlers (static/ssai-actions.js runs their buttons), so
# markup injected into a page cannot execute. Styles still allow inline attributes (low risk, many in the dashboard).
# No plugins, no <base> tricks, forms and fetches only to this site, framing only by this site. Google Fonts is the one
# outside host.
CSP = ("default-src 'self'; script-src 'self' 'nonce-{nonce}'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
       "font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; "
       "form-action 'self'; frame-ancestors 'self'")


@app.before_request
def _csp_nonce():
    g.csp_nonce = secrets.token_urlsafe(16)


@app.context_processor
def _csp_context():
    return {'csp_nonce': getattr(g, 'csp_nonce', '')}


@app.after_request
def _security_headers(resp):
    """Runs after every response and adds browser-protection headers (no content sniffing, no framing by other sites, a
    Content-Security-Policy that limits which scripts may run, and optionally HSTS) so a hostile page or injected
    script cannot abuse the dashboard."""
    resp.headers.setdefault('X-Content-Type-Options', 'nosniff')
    resp.headers.setdefault('X-Frame-Options', 'SAMEORIGIN')        # nobody else may frame the dashboard (clickjacking)
    resp.headers.setdefault('Referrer-Policy', 'same-origin')
    csp = os.environ.get('SSAI_CSP', 'on').lower()
    if csp != 'off':        # SSAI_CSP=report-only while testing a change; off only to rule the policy out when debugging
        resp.headers.setdefault('Content-Security-Policy-Report-Only' if csp == 'report-only' else 'Content-Security-Policy',
                                CSP.format(nonce=getattr(g, 'csp_nonce', '')))
    # HSTS tells browsers to refuse plain HTTP for this host from now on, so it is sent only on a request that really
    # was HTTPS, and only when the operator has turned it on (after confirming HTTPS works end to end).
    if os.environ.get('SSAI_HSTS', '').lower() in ('1', 'true', 'yes') and _is_https():
        resp.headers.setdefault('Strict-Transport-Security', 'max-age=31536000')
    return resp


GZIP_MIN_BYTES = 2048


@app.after_request
def _gzip_json(resp):
    """Compress larger JSON answers (2026-09-30). The dashboard polls every 5 s; its snapshot is ~10x smaller gzipped."""
    if (resp.direct_passthrough or resp.status_code < 200 or resp.status_code >= 300
            or resp.mimetype != 'application/json' or 'Content-Encoding' in resp.headers
            or 'gzip' not in request.headers.get('Accept-Encoding', '').lower()):
        return resp
    body = resp.get_data()
    if len(body) < GZIP_MIN_BYTES:
        return resp
    import gzip as _gzip
    resp.set_data(_gzip.compress(body, compresslevel=5))
    resp.headers['Content-Encoding'] = 'gzip'
    resp.headers.add('Vary', 'Accept-Encoding')
    return resp

# --- AI Swarm aggregate endpoint ---
import json as _json

@app.route('/api/ai_swarm', methods=['GET'])
def get_ai_swarm():
    """Totals for the dashboard's AI card: how many AI models the active nodes report, how many nodes have any, and a
    count per provider/model."""
    # FIX (2026-08-20): a dead/stale node with ai_count > 0 used to inflate
    # this panel forever — same bug family as the NODE_ID fix, different
    # code path. Only count nodes actually marked active.
    nodes = Node.query.filter(Node.ai_count > 0, Node.status == 'active').all()
    total_ai = sum(n.ai_count for n in nodes)
    models_agg = {}
    for n in nodes:
        try:
            caps = _json.loads(n.ai_capabilities or '[]')
            for c in caps:
                key = c.get('provider','?') + '/' + c.get('model','')
                models_agg[key] = models_agg.get(key, 0) + 1
        except Exception:
            # a machine that reported unreadable model data simply adds nothing to the count
            pass
    return jsonify({'total_ai_count': total_ai, 'nodes_with_ai': len(nodes), 'models': models_agg})

@app.route('/api/github_stats', methods=['GET'])
def github_stats():
    """How many threats the GitHub ledger reporter has already committed and how many are still waiting, read from its
    saved state file."""
    import json as _json
    state_file = ssai_config.GITHUB_STATE_PATH
    last_push = None
    last_id = 0
    baseline = 0
    if os.path.exists(state_file):
        try:
            with open(state_file) as f:
                state = _json.load(f)
            last_push = state.get('last_push')
            last_id = state.get('last_id', 0)
            baseline = state.get('committed_baseline', 0)
        except (OSError, ValueError):
            pass
    # 'committed' = rows at/below the reporter cursor minus a user-set baseline (reset without touching the cursor)
    total_committed = max(0, (Threat.query.filter(Threat.id <= last_id).count() if last_id else 0) - baseline)
    pending = Threat.query.filter(Threat.id > last_id).count() if last_id else Threat.query.count()
    return jsonify({'enabled': True, 'repo': 'gatsbysdream25-max/SwarmSentinel',
                    'total_committed': total_committed, 'pending': pending,
                    'last_commit': last_push})


@app.route('/api/summary', methods=['GET'])
def get_summary():
    """Dashboard summary: threat counts by severity, how many the AI has analysed, and active node and agent totals. The
    database does the adding up so this stays fast."""
    from sqlalchemy import func as _func
    # FIX (2026-08-18): was 5 separate .count() calls plus a full Node.query.all()
    # just to sum ai_count in Python — same SQL-side aggregation pattern already
    # used by /api/dashboard_snapshot, applied here so this endpoint (kept as a
    # fast-rollback fallback) doesn't lag behind it in cost.
    sev_counts = dict(
        db.session.query(Threat.severity, _func.count(Threat.id))
        .group_by(Threat.severity).all()
    )
    total = sum(sev_counts.values())
    # FIX (2026-08-18): was filtering description LIKE '%verdict%', a stale heuristic
    # that predates the proper ai_analyzed column (see models FIX #7) — always returned
    # near-zero even with tens of thousands of real analyses recorded.
    ai_done  = Threat.query.filter_by(ai_analyzed=True).count()
    node_agg = db.session.query(
        _func.count(Node.id), _func.sum(Node.ai_count)
    ).filter(Node.status == 'active').first()
    nodes    = node_agg[0] or 0
    total_ai = node_agg[1] or 0
    return jsonify({
        'total_threats': total,
        'by_severity': {
            'CRITICAL': sev_counts.get('critical', 0),
            'HIGH':     sev_counts.get('high', 0),
            'MEDIUM':   sev_counts.get('medium', 0),
            'LOW':      sev_counts.get('low', 0),
            'INFO':     sev_counts.get('info', 0),
        },
        'ai_analyzed':  ai_done,
        'swarm': {'instance_count': nodes, 'swarm_total': Agent.query.filter(Agent.status != 'disabled').count()},
        'ai_swarm': {'active_count': total_ai},
    })


# NOTE (2026-08-18): "Hub" here means SwarmSentinel's own multi-node swarm
# (pro1 + pro2 + watchtower), not the old Azure Cosmos hub that's been
# decommissioned. These two routes were referenced by the dashboard's
# frontend JS but never implemented on the backend.
@app.route('/api/collective', methods=['GET'])
def collective_intel():
    threats = Threat.query.order_by(Threat.timestamp.desc()).limit(50).all()
    return jsonify([t.to_dict() for t in threats])


# ── Remediation actions (added 2026-08-18) ─────────────────────────────────
def _audit_status_change(action, t, previous):
    """Resolve/dismiss decide whether a threat is ever alerted on again, so they are audited like a block is."""
    import remediation
    try:
        remediation.audit(_AUDIT_PATH, action=action, threat_id=t.id, previous_status=previous, ok=True,
                          by=request.remote_addr)
    except OSError as e:
        app.logger.warning(f'audit log not writable ({action} threat {t.id}): {e}')


@app.route('/api/threats/<int:threat_id>/resolve', methods=['POST'])
def resolve_threat(threat_id):
    if not _check_auth():
        return jsonify({'error': 'Unauthorized'}), 401
    t = Threat.query.get_or_404(threat_id)
    previous, t.status = t.status, 'resolved'
    db.session.commit()
    _audit_status_change('resolve', t, previous)
    return jsonify({'ok': True, 'id': threat_id, 'status': 'resolved'})


@app.route('/api/threats/<int:threat_id>/dismiss', methods=['POST'])
def dismiss_threat(threat_id):
    if not _check_auth():
        return jsonify({'error': 'Unauthorized'}), 401
    t = Threat.query.get_or_404(threat_id)
    previous, t.status = t.status, 'dismissed'
    db.session.commit()
    _audit_status_change('dismiss', t, previous)
    return jsonify({'ok': True, 'id': threat_id, 'status': 'dismissed'})


def _never_block_ips():
    """Addresses block_threat() will always refuse, regardless of who asks
    or what the threat says. Self + gateway are hardcoded; SSAI_NEVER_BLOCK
    in .env extends the list (comma-separated) for anything else that
    should never get cut off, e.g. an admin workstation."""
    import socket as _socket_nb
    ips = {'127.0.0.1'}
    try:
        ips.add(_socket_nb.gethostbyname(_socket_nb.gethostname()))
    except OSError:
        pass
    try:
        s = _socket_nb.socket(_socket_nb.AF_INET, _socket_nb.SOCK_DGRAM)
        s.connect(('10.255.255.255', 1))
        ips.add(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    gw_env = os.environ.get('LAN_GATEWAY_IP', '').strip()
    if gw_env:
        ips.add(gw_env)
    extra = os.environ.get('SSAI_NEVER_BLOCK', '')
    ips.update(x.strip() for x in extra.split(',') if x.strip())
    return ips


_AUDIT_PATH = os.path.join(ssai_config.INSTANCE_DIR, 'remediation_audit.jsonl')


def _add_column(engine, table, name, sqltype, index=None):
    """ALTER TABLE ADD COLUMN, tolerating another worker (or an earlier run) having added it a moment ago."""
    try:
        with engine.begin() as conn:
            conn.exec_driver_sql(f'ALTER TABLE {table} ADD COLUMN {name} {sqltype}')
    except Exception as e:                     # noqa: BLE001  (driver-specific error types)
        if 'duplicate column' not in str(e).lower() and 'already exists' not in str(e).lower():
            raise
    if index:
        with engine.begin() as conn:
            conn.exec_driver_sql(f'CREATE INDEX IF NOT EXISTS {index} ON {table} ({name})')


_NEW_COLUMNS = {           # table -> [(column, SQL type, index name or None)] added after a database may already exist
    'threat': [('real_source', 'VARCHAR(500)', 'ix_threat_real_source'),
               ('fingerprint', 'VARCHAR(40)', 'ix_threat_fingerprint'), ('first_seen', 'TIMESTAMP', None),
               ('last_seen', 'TIMESTAMP', None), ('last_reported', 'TIMESTAMP', None),
               ('times_seen', 'INTEGER', None), ('times_reported', 'INTEGER', None)],
    'node': [('token_hash', 'VARCHAR(64)', 'ix_node_token_hash'), ('token_hint', 'VARCHAR(12)', None),
             ('enrolled_at', 'TIMESTAMP', None), ('revoked_at', 'TIMESTAMP', None)],
}


def _ensure_schema(engine=None):
    """create_all() only makes missing tables; add columns introduced after a database was first created."""
    from sqlalchemy import inspect as _inspect
    engine = engine or db.engine
    insp = _inspect(engine)
    for table, columns in _NEW_COLUMNS.items():
        if not insp.has_table(table):
            continue
        have = {c['name'] for c in insp.get_columns(table)}
        for name, sqltype, index in columns:
            if name not in have:
                _add_column(engine, table, name, sqltype, index)
    if insp.has_table('node') and 'token' in {c['name'] for c in insp.get_columns('node')}:
        with engine.begin() as conn:          # tokens from the old open registration were never checked: not credentials
            conn.exec_driver_sql('UPDATE node SET token = NULL WHERE token IS NOT NULL')


def _remediate(threat_id, action, person=None):
    """Block or unblock what a threat points at, and say plainly what happened (see remediation.py).

    An IP gets firewall rules on this host; a domain goes on the Pi-hole deny list; anything that cannot be blocked
    safely (a masked LAN address, a protected domain) is refused with the reason. Every attempt is audited."""
    import remediation
    t = Threat.query.get_or_404(threat_id)
    who = request.remote_addr
    try:
        target = remediation.classify_target(t.url)
        # never let a block take this box, its gateway, or an operator-designated machine off the network
        if action == 'block' and target['kind'] == 'ip' and target['value'] in _never_block_ips():
            raise remediation.TargetError(f"refusing to block {target['value']}: protected address "
                                          "(this host, the gateway, or listed in SSAI_NEVER_BLOCK)")
        if action == 'block':
            import remediation_queue
            if remediation_queue._never_block(target, _never_block_ips()):
                raise remediation.TargetError(f"refusing to block {target['value']}: an address inside the organisation")
            who = f"{person or 'key'} @ {_auth.client_ip()}"[:100]
            remediation.audit_before_acting(_AUDIT_PATH, action='block', stage='intent', threat_id=threat_id, target=target['value'], by=who)
        detail = remediation.block(target, threat_id) if action == 'block' else remediation.unblock(target)
    except remediation.TargetError as e:
        remediation.audit(_AUDIT_PATH, action=action, threat_id=threat_id, ok=False, error=str(e), by=who)
        return jsonify({'ok': False, 'error': str(e)}), 400
    except remediation.RemediationError as e:
        remediation.audit(_AUDIT_PATH, action=action, threat_id=threat_id, target=t.url, ok=False, error=str(e), by=who)
        return jsonify({'ok': False, 'error': str(e)}), 502
    t.status = 'blocked' if action == 'block' else 'active'
    db.session.commit()
    remediation.audit(_AUDIT_PATH, action=action, threat_id=threat_id, kind=target['kind'], target=target['value'],
                      ok=True, detail=detail, by=who)
    out = {'ok': True, 'id': threat_id, 'status': t.status, 'action': action, 'kind': target['kind'],
           'target': target['value'], 'detail': detail}
    if target['kind'] == 'ip':
        out['blocked_ip'] = target['value']
    return jsonify(out)


@app.route('/api/threats/<int:threat_id>/block', methods=['POST'])
def block_threat(threat_id):
    """Admin only: block the address behind a threat. When the setup requires a person's approval, an API key alone is
    refused (and audited) because the agents hold the same key, so a program must not make this decision."""
    if not _check_auth():
        return jsonify({'error': 'Unauthorized'}), 401
    person = _auth.approving_person()
    if person is None and _auth.person_required_for_approval():       # the agents hold the same key, so a key is not a person's decision
        import remediation
        remediation.audit(_AUDIT_PATH, action='block', threat_id=threat_id, ok=False, by=_auth.client_ip(),
                          error='refused: blocking needs a signed-in person, not an API key')
        return jsonify({'ok': False, 'error': 'blocking needs a signed-in person: use the dashboard (an API key is held by programs)'}), 403
    return _remediate(threat_id, 'block', person)


@app.route('/api/threats/<int:threat_id>/unblock', methods=['POST'])
def unblock_threat(threat_id):
    if not _check_auth():
        return jsonify({'error': 'Unauthorized'}), 401
    return _remediate(threat_id, 'unblock')


# ── Admin IP identification ─────────────────────────────────────────────────
_intel_cache = {'mtime': None, 'store': None}


def _intel_store():
    """Read-only view of the feed indicators the agent runner keeps in instance/intel_cache.json (public data)."""
    from agents import intel
    path = os.path.join(ssai_config.INSTANCE_DIR, 'intel_cache.json')
    try:
        m = os.stat(path).st_mtime
    except OSError:
        return None
    if _intel_cache['mtime'] != m:
        st = intel.IntelStore()
        st.load(path)
        _intel_cache.update(mtime=m, store=st)
    return _intel_cache['store']


def _intel_lookup(kind, value):
    """Look an IP address or domain up in the downloaded threat-intelligence lists. Returns a list of matches (empty when
    the lists are not loaded)."""
    st = _intel_store()
    if st is None:
        return []
    if kind == 'ip':
        hits = [h for h in [st.match_ip(value)] if h] + st.endpoints_for(value)
    else:
        hits = [h for h in [st.match_domain(value)] if h]
    return [{'source': h['source'], 'malware': h['malware'], 'threat': h['threat'], 'listed_as': h['value'],
             'first_listed': h.get('first_seen'), 'last_listed': h.get('seen')} for h in hits]


def _identify_history(kind, value):
    """What this installation has already recorded about the address (matched on the masked url and the real one)."""
    from sqlalchemy import or_ as _or, func as _func
    from agents import recall

    def spellings(col):
        return [col == value, col.like(f'{value}:%'), col.like(f'{value}/%'), col.like(f'%://{value}'),
                col.like(f'%://{value}:%'), col.like(f'%://{value}/%'), col.like(f'%://{value}?%')]
    cond = _or(*spellings(Threat.url), *spellings(Threat.real_source))
    n, first, last = db.session.query(_func.count(Threat.id), _func.min(Threat.timestamp),
                                      _func.max(Threat.timestamp)).filter(cond).one()
    if not n:
        return {'count': 0}
    by_type = dict(db.session.query(Threat.type, _func.count(Threat.id)).filter(cond).group_by(Threat.type).all())
    rows = Threat.query.filter(cond).order_by(Threat.timestamp.desc()).limit(8).all()
    verdict = next((c.get('consensus_verdict') for c in (recall.consensus_of(r.to_dict()) for r in rows) if c), None)
    return {'count': n, 'first_seen': first.isoformat() if first else None, 'last_seen': last.isoformat() if last else None,
            'by_type': by_type, 'ai_verdict': verdict,
            'recent': [{'id': r.id, 'type': r.type, 'severity': r.severity, 'status': r.status,
                        'detected_by': r.detected_by, 'time': r.timestamp.isoformat()} for r in rows]}


def _identify(kind, value, ports):
    """Gather everything known about an address (what this hub has recorded, threat-intelligence matches, Pi-hole DNS
    filter data, and an optional port probe) and return it as a dict."""
    import identify
    import remediation
    # The database needs this request's app context, which the lookup worker threads do not have: read it here.
    try:
        hist = _identify_history(kind, value)
    except Exception as e:                       # noqa: BLE001  (reported as a failed section; the rest still answers)
        hist = e

    def history(_kind, _value):
        if isinstance(hist, Exception):
            raise hist
        return hist
    deps = identify.default_deps(pihole=remediation.PiHole(), history=history, intel_lookup=_intel_lookup)
    return (identify.identify_ip(value, deps, ports=ports) if kind == 'ip' else identify.identify_domain(value, deps))


def _identify_guard():
    """Identification reveals real LAN addresses and probes devices: admin (API key) only, never the read-only display."""
    if _is_readonly():
        return jsonify({'error': 'Not available in the read-only display'}), 403
    if not _check_auth():
        return jsonify({'error': 'Unauthorized'}), 401
    return None


@app.route('/api/threats/<int:threat_id>/identify', methods=['GET'])
def identify_threat(threat_id):
    """Admin only: identify the device or host behind one stored threat, using the real address kept for it. Says 'not
    identifiable' when only the masked address exists."""
    import identify
    import remediation
    denied = _identify_guard()
    if denied:
        return denied
    t = Threat.query.get_or_404(threat_id)
    ext = identify.extract_host(t.real_source or t.url)
    if ext is None:
        return jsonify({'ok': True, 'identifiable': False, 'threat_id': threat_id,
                        'reason': 'This address is masked and no real address was kept for it (it was recorded before '
                                  'SwarmSentinel started keeping real addresses, or SSAI_STORE_REAL_ADDRESSES is off). '
                                  'New detections of the same device will be identifiable.'})
    ports = request.args.get('ports') == '1'
    remediation.audit(_AUDIT_PATH, action='identify', threat_id=threat_id, target=ext[1], ports=ports, by=request.remote_addr)
    out = _identify(ext[0], ext[1], ports)
    out.update(ok=True, identifiable=True, threat_id=threat_id, address_source='recorded real address' if t.real_source else 'threat address')
    return jsonify(out)


@app.route('/api/identify', methods=['GET'])
def identify_address():
    """Admin only: identify any IP address, domain or URL typed in (?target=...). Add ports=1 to also probe the device's
    open ports."""
    import identify
    import remediation
    denied = _identify_guard()
    if denied:
        return denied
    ext = identify.extract_host(request.args.get('target', ''))
    if ext is None:
        return jsonify({'ok': False, 'error': 'enter an IP address, a domain or a URL'}), 400
    ports = request.args.get('ports') == '1'
    remediation.audit(_AUDIT_PATH, action='identify', target=ext[1], ports=ports, by=request.remote_addr)
    out = _identify(ext[0], ext[1], ports)
    out['ok'] = True
    return jsonify(out)


# Where the quarantine dropbox file lives (the import route is in routes/quarantine.py; it asks for this path when it runs).
_QUARANTINE_DROPBOX_PATH = ssai_config.QUARANTINE_DROPBOX_PATH


# The shared .env file (the AI routing routes in routes/settings.py ask for this path when they run).
_ENV_PATH = ssai_config.ENV_PATH




@app.route('/api/cloud_status', methods=['GET'])
def cloud_status():
    return jsonify({'connected': True, 'mode': 'local-swarm'})


# ── Deploy 3 (2026-08-18): batched dashboard snapshot ───────────────────────
# Replaces the dashboard's 8-separate-fetches-every-5-seconds pattern
# (threats, agents, defender, nodes, collective, cloud_status, summary,
# ai_swarm, github_stats) with one endpoint, computed with SQL-side
# aggregation instead of the Python-side Node.query.all()+sum() pattern in
# the original get_summary(). Old endpoints are left in place, unremoved,
# until this one's proven in production.
def _snapshot_counts():
    """Totals for the dashboard: threats by severity, how many the AI judged, active machines, agents."""
    from sqlalchemy import func as _func
    # One query, SQL-side conditional aggregation — replaces get_summary()'s
    # 6 separate .count() calls plus a full Node.query.all() just to sum
    # ai_count in Python.
    sev_counts = dict(
        db.session.query(Threat.severity, _func.count(Threat.id))
        .group_by(Threat.severity).all()
    )
    node_agg = db.session.query(
        _func.count(Node.id), _func.sum(Node.ai_count)
    ).filter(Node.status == 'active').first()
    return {
        'sev_counts': sev_counts,
        'total_threats': sum(sev_counts.values()),
        'ai_analyzed': Threat.query.filter_by(ai_analyzed=True).count(),
        'active_node_count': node_agg[0] or 0,
        'total_ai_from_nodes': node_agg[1] or 0,
        'swarm_total': Agent.query.filter(Agent.status != 'disabled').count(),
    }


def _snapshot_models():
    """Which AI models the active machines report, as ({"provider/model": number of machines}, machines with AI)."""
    import json as _json2
    # Same shape as /api/ai_swarm. FIX (2026-08-20): filter to active nodes, same reason as get_ai_swarm() above.
    ai_nodes = Node.query.filter(Node.ai_count > 0, Node.status == 'active').all()
    models_agg = {}
    for n in ai_nodes:
        try:
            for c in _json2.loads(n.ai_capabilities or '[]'):
                key = c.get('provider', '?') + '/' + c.get('model', '')
                models_agg[key] = models_agg.get(key, 0) + 1
        except Exception:
            # a machine that reported unreadable model data simply adds nothing to the count
            pass
    return models_agg, len(ai_nodes)


def _snapshot_github(total_threats):
    """What the ledger pusher reports (same logic as /api/github_stats): (last push time, committed so far, still
    waiting)."""
    import json as _json2
    state_file = ssai_config.GITHUB_STATE_PATH
    last_push, last_id, baseline = None, 0, 0
    if os.path.exists(state_file):
        try:
            with open(state_file) as f:
                state = _json2.load(f)
            last_push = state.get('last_push')
            last_id = state.get('last_id', 0)
            baseline = state.get('committed_baseline', 0)
        except (OSError, ValueError):
            pass
    total_committed = max(0, (Threat.query.filter(Threat.id <= last_id).count() if last_id else 0) - baseline)
    pending = Threat.query.filter(Threat.id > last_id).count() if last_id else total_threats
    return last_push, total_committed, pending


def _snapshot_provider_health():
    """Each AI provider's live/dead state, as last reported by SwarmConsensusAgent ({} if it has not reported)."""
    import json as _json2
    # GAP FIX (2026-09-05): per-provider live/dead visibility — previously a
    # dead/deprecated model ID (e.g. Gemini, Groq) just shrank the consensus
    # panel with no operator-visible signal. Reported by agent_runner.py's
    # SwarmConsensusAgent over the existing heartbeat channel (it owns the
    # live AiSwarmAnalyzer instance; this process doesn't).
    swarm_agent_row = Agent.query.filter_by(name='SwarmConsensusAgent').first()
    if swarm_agent_row and swarm_agent_row.provider_health:
        try:
            return _json2.loads(swarm_agent_row.provider_health)
        except ValueError:
            pass
    return {}


def _snapshot_threats():
    """The newest 300 findings and a short fingerprint of them, so the page can skip re-downloading an unchanged list."""
    import json as _json2
    threats = [t.to_dict() for t in Threat.query.order_by(Threat.timestamp.desc()).limit(300).all()]
    version = hashlib.sha256(_json2.dumps(threats, sort_keys=True, default=str).encode()).hexdigest()[:16]
    return threats, version


@app.route('/api/dashboard_snapshot', methods=['GET'])
def dashboard_snapshot():
    """Everything the dashboard shows, in one reply (polled every few seconds, so the work is a handful of aggregates)."""
    counts = _snapshot_counts()
    sev_counts = counts['sev_counts']
    models_agg, nodes_with_ai = _snapshot_models()
    last_push, total_committed, pending = _snapshot_github(counts['total_threats'])

    # 2026-09-30: the 300 threats were ~90% of every 5 s poll and rarely change between polls. The page sends back
    # the version it holds (?tv=); when it still matches, `threats` is null and the page keeps what it has. Hashing
    # the serialized rows (not DB columns) catches every visible change, including time-based fields like still_active.
    # Pages that send no ?tv= (an old cached copy, e.g. the kiosk tablet) get the full list and `collective` as before.
    threats, threats_version = _snapshot_threats()
    client_tv = request.args.get('tv')
    legacy_client = client_tv is None
    unchanged = bool(client_tv) and client_tv == threats_version

    return jsonify({
        'threats':    None if unchanged else threats,
        'threats_version': threats_version,
        'agents':     [a.to_dict() for a in Agent.query.order_by(Agent.last_seen.desc()).all()],
        # No Windows Defender bridge exists yet (planned native client feature,
        # not built) — represented honestly instead of a silent 404 every cycle.
        'defender':   None,
        'nodes':      [n.to_dict() for n in Node.query.order_by(Node.last_seen.desc()).all()],
        'collective': threats[:50] if legacy_client else None,     # new pages build it from `threats`
        'cloud_status': {'connected': True, 'mode': 'local-swarm'},
        'summary': {
            'total_threats': counts['total_threats'],
            'by_severity': {
                'CRITICAL': sev_counts.get('critical', 0),
                'HIGH':     sev_counts.get('high', 0),
                'MEDIUM':   sev_counts.get('medium', 0),
                'LOW':      sev_counts.get('low', 0),
                'INFO':     sev_counts.get('info', 0),
            },
            'ai_analyzed': counts['ai_analyzed'],
            'swarm': {'instance_count': counts['active_node_count'], 'swarm_total': counts['swarm_total']},
            'ai_swarm': {'active_count': counts['total_ai_from_nodes']},
        },
        'ai_swarm': {
            'total_ai_count': counts['total_ai_from_nodes'],
            'nodes_with_ai': nodes_with_ai,
            'models': models_agg,
            'provider_health': _snapshot_provider_health(),
        },
        'github_stats': {
            'enabled': True, 'repo': 'gatsbysdream25-max/SwarmSentinel',
            'total_committed': total_committed, 'pending': pending,
            'last_commit': last_push,
        },
    })


# --- Setup Wizard routes ---

@app.route('/setup')
def setup_page():
    return _admin_page('setup.html')


@app.route('/settings')
def settings_page():
    return _admin_page('settings.html')

@app.route('/api/setup/providers', methods=['GET'])
def setup_providers():
    """Setup wizard (admin only): list the AI providers and whether each is set up."""
    if not _check_auth():
        return jsonify({'error': 'Unauthorized'}), 401
    try:
        import sys
        sys.path.insert(0, ssai_config.BACKEND_DIR)
        from agents.ai_swarm_agent import AiSwarmAnalyzer
        return jsonify(AiSwarmAnalyzer.get_provider_registry())
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/setup/activate', methods=['POST'])
def setup_activate():
    """Setup wizard (admin only): check and save one provider's API key into the .env file, then refresh the dashboard's
    AI card. The reply says how many providers are now configured; the separate agent process may take a moment to
    pick the key up."""
    if not _check_auth():
        return jsonify({'error': 'Unauthorized'}), 401
    from agents.ai_swarm_agent import PROVIDER_REGISTRY, save_env_key
    body = request.get_json(silent=True) or {}
    pid  = _clean_str(body.get('provider_id',''), 64)
    key  = body.get('api_key','')
    if not isinstance(key, str):
        key = ''
    key = key.strip()
    if any(c in key for c in ('\n', '\r', '\x00')):
        return jsonify({'error': 'api_key contains invalid characters'}), 400
    key = key[:512]
    if not pid:
        return jsonify({'error': 'provider_id required'}), 400
    reg = next((p for p in PROVIDER_REGISTRY if p['id'] == pid), None)
    if not reg:
        return jsonify({'error': f'Unknown provider: {pid}'}), 404
    env_key = reg.get('env_key')
    if not env_key:
        return jsonify({'error': 'no env_key for this provider'}), 400
    ok = save_env_key(env_key, key)
    if not ok:
        return jsonify({'error': 'Failed to write .env'}), 500
    # The dashboard's AI card is rebuilt from the real panel (configured, switched on, approved), the same way every
    # other change refreshes it; hand-editing ai_capabilities here ignored the on/off switches and the approval gate
    # (code review 2026-09-30, finding 7).
    _sync_hub_ai()
    # BUG FIX (2026-09-05): was hardcoded to 0 regardless of outcome, so the
    # "activated — 0 providers now active" toast lied to the operator every
    # time. This process only knows which providers are *configured* (a key
    # is present in the environment) — whether the separate agent-runner
    # process has actually picked it up is what /api/dashboard_snapshot's
    # provider_health now reports.
    from agents.ai_swarm_agent import AiSwarmAnalyzer
    active_count = sum(1 for p in AiSwarmAnalyzer.get_provider_registry() if p.get('active'))
    return jsonify({'status': 'ok', 'active_count': active_count})

@app.route('/api/setup/enable', methods=['POST'])
def setup_enable():
    """Switch a provider on or off for the consensus panel without touching its key. Paid, quota-limited and
    unmeasured providers are off by default and offered here as an opt-in."""
    if not _check_auth():
        return jsonify({'error': 'Unauthorized'}), 401
    from agents.ai_swarm_agent import PROVIDER_REGISTRY, set_provider_enabled, AiSwarmAnalyzer
    body = request.get_json(silent=True) or {}
    pid = _clean_str(body.get('provider_id', ''), 64)
    enabled = body.get('enabled')
    if not isinstance(enabled, bool):
        return jsonify({'error': 'enabled must be true or false'}), 400
    if not any(p['id'] == pid for p in PROVIDER_REGISTRY):
        return jsonify({'error': f'Unknown provider: {pid}'}), 404
    set_provider_enabled(pid, enabled)
    _sync_hub_ai()
    reg = next(p for p in AiSwarmAnalyzer.get_provider_registry() if p['id'] == pid)
    return jsonify({'status': 'ok', 'provider_id': pid, 'enabled': reg['enabled'], 'active': reg['active']})


@app.route('/api/setup/reload', methods=['POST'])
def setup_reload():
    if not _check_auth():
        return jsonify({'error': 'Unauthorized'}), 401
    _sync_hub_ai()
    from agents.ai_swarm_agent import AiSwarmAnalyzer
    active_count = sum(1 for p in AiSwarmAnalyzer.get_provider_registry() if p.get('active'))
    return jsonify({'status': 'ok', 'active_count': active_count})

@app.route('/api/ai/health', methods=['GET'])
def ai_health():
    """The last provider health check (which AI providers work, and the exact error where not). Admin only."""
    if not _check_auth():
        return jsonify({'error': 'Unauthorized'}), 401
    from agents import provider_check
    doc = provider_check.load_last()
    doc['summary'] = provider_check.summary(doc['providers']) if doc.get('providers') else None
    return jsonify(doc)


@app.route('/api/ai/health/check', methods=['POST'])
def ai_health_check():
    """Run the provider health check now (one tiny request per configured cloud provider) and return the table."""
    if not _check_auth():
        return jsonify({'error': 'Unauthorized'}), 401
    from agents import provider_check
    rows = provider_check.check_all()
    provider_check.save(rows)
    return jsonify({'providers': rows, 'summary': provider_check.summary(rows), 'table': provider_check.format_table(rows)})


@app.route('/api/ai/recheck', methods=['POST'])
def ai_recheck():
    """Check one provider now (the "Check now" button). If it answers, it comes off rest and rejoins the panel."""
    if not _check_auth():
        return jsonify({'error': 'Unauthorized'}), 401
    from agents import model_config, provider_check, provider_rest
    pid = _clean_str((request.get_json(silent=True) or {}).get('provider_id', ''), 64)
    cfg = model_config.load()
    if pid not in cfg:
        return jsonify({'error': f'Unknown provider: {pid}'}), 404
    row = provider_check.check_provider(pid, cfg[pid])
    if row['working']:
        provider_rest.wake(pid)
    elif provider_rest.is_resting(pid):
        provider_rest.still_out(pid, f"{row['status']}: {row['detail']}")
    return jsonify({'provider_id': pid, 'working': row['working'], 'status': row['status'],
                    'detail': row['detail'], 'hint': row.get('hint', ''), 'resting': provider_rest.is_resting(pid)})


import contextlib as _contextlib


@_contextlib.contextmanager
def _startup_lock():
    """One worker at a time through the startup block: gunicorn runs several workers and every one executes it on
    import. On a brand-new database they used to race, and the loser died with a UNIQUE violation (worker failed to boot)."""
    fh = None
    try:
        try:
            import fcntl
            os.makedirs(ssai_config.INSTANCE_DIR, exist_ok=True)
            fh = open(os.path.join(ssai_config.INSTANCE_DIR, '.startup.lock'), 'a')
            fcntl.flock(fh, fcntl.LOCK_EX)
        except (ImportError, OSError):
            fh = None            # no fcntl, or an unwritable directory: the tolerant statements below still hold
        yield
    finally:
        if fh is not None:
            fh.close()           # closing releases the lock


def _hub_node():
    """This hub's own Node row, found the same way _register_hub_node names it (an enrolled machine may own the plain
    hostname, then the hub is '<host>-hub')."""
    return Node.hub()


def _sync_hub_ai():
    """Show the hub's real AI panel on the dashboard (AI SWARM card, 'AIs active'). ai_capabilities used to be written
    only when a key was entered in /setup, so switching providers on or off, editing .env or changing a model left the
    card showing the panel of weeks ago (2026-09-26: it still listed Anthropic and a retired Hugging Face model)."""
    try:
        from agents.ai_swarm_agent import panel_members
        node = _hub_node()
        if node is None:
            return
        caps = panel_members()
        node.ai_capabilities, node.ai_count = _json.dumps(caps), len(caps)
        db.session.commit()
    except Exception as exc:                  # noqa: BLE001 -- a stale card must never stop the app starting
        db.session.rollback()
        app.logger.warning(f'could not refresh the hub AI panel: {exc}')


def _register_hub_node():
    """Make this hub machine appear in /api/nodes. Looked up by node id (unique), never by hostname: an enrolled machine
    that happens to share the hub's hostname must not be mistaken for the hub."""
    import socket as _sock
    import platform as _plat
    from sqlalchemy.exc import IntegrityError
    host = _sock.gethostname()
    for _ in range(3):
        node = Node.query.filter_by(node_id=host).first()
        if node is not None and node.token_hash:
            host = host + '-hub'          # an enrolled machine already owns this name
            continue
        now = datetime.now(timezone.utc)
        if node is None:
            db.session.add(Node(node_id=host, hostname=host, platform=_plat.system(), status='active',
                                registered=now, last_seen=now))
        else:
            node.status, node.last_seen, node.platform = 'active', now, _plat.system()
        try:
            db.session.commit()
            return
        except IntegrityError:            # another worker registered the hub an instant ago; look again
            db.session.rollback()


def _secure_instance_dir():
    """Owner-only permissions on the data directory and the files in it. The database now holds real LAN addresses and
    the keys sign sessions, so other accounts on the host must not be able to read them."""
    d = ssai_config.INSTANCE_DIR
    try:
        os.chmod(d, 0o700)
        names = os.listdir(d)
    except OSError:
        return
    for name in names:
        path = os.path.join(d, name)
        if name == 'intel_cache.json' or not os.path.isfile(path):      # public feed data, read by the web app
            continue
        try:
            os.chmod(path, 0o600)
        except OSError:                                                # owned by another account (e.g. root): theirs to set
            pass


def _startup_db():
    with _startup_lock():
        db.create_all()
        _ensure_schema()
        _register_hub_node()
        _sync_hub_ai()
        _secure_instance_dir()


with app.app_context():
    _startup_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host=os.environ.get("SSAI_BIND", "0.0.0.0"), port=port, debug=False)       # 127.0.0.1 behind a TLS proxy