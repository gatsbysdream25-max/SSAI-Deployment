"""Who is calling, and what may they do.

Two kinds of caller present a key in the X-API-Key header (or `Authorization: Bearer`):

  * the ADMIN key (SSAI_API_KEY in the hub's .env): everything, as before;
  * a NODE token ("ssn_..."), issued to one enrolled machine: it may register that machine's agents and submit
    threats from that machine, and nothing else. It cannot dismiss, block, change settings, read the setup keys or
    create other credentials, and everything it submits is stamped with its own node id, whatever the request says.

A node gets its token by trading a single-use ENROLLMENT CODE (created by an admin, valid for an hour by default) at
POST /api/node/register, so the admin key never has to be copied to a machine. Tokens and codes are stored only as
SHA-256 hashes: both are long random values, so a fast hash is enough and a database leak reveals nothing usable.
Revoking a node kills its token immediately.

This module holds the pieces with no Flask routes so they can be tested on their own.
"""
import hashlib
import hmac
import os
import re
import secrets
import threading
import time
from collections import defaultdict, deque

from flask import request

NODE_TOKEN_PREFIX = 'ssn_'
_CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'          # no 0/O/1/I: codes get read aloud and retyped
_NODE_ID_BAD = re.compile(r'[^A-Za-z0-9._-]+')
_MISSING = object()
_ENV_KEY = "ssai.identity"


def hash_secret(value):
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def new_token():
    return NODE_TOKEN_PREFIX + secrets.token_urlsafe(32)


def new_code():
    """XXXX-XXXX-XXXX-XXXX from a 32-symbol alphabet: 80 bits."""
    raw = ''.join(secrets.choice(_CODE_ALPHABET) for _ in range(16))
    return '-'.join(raw[i:i + 4] for i in range(0, 16, 4))


def normalize_code(text):
    """Accept the code however it was typed (case, spaces, dashes); '' if it cannot be a code."""
    raw = re.sub(r'[^A-Za-z0-9]', '', str(text or '')).upper()
    return raw if len(raw) == 16 and all(c in _CODE_ALPHABET for c in raw) else ''


def clean_node_id(text, fallback=''):
    """A machine name safe to use in an agent id and a URL: letters, digits, dot, dash, underscore; up to 64."""
    s = _NODE_ID_BAD.sub('-', str(text or '')).strip('-._')[:64]
    return s or fallback


# ── who is calling ───────────────────────────────────────────────────────────

class Identity:
    __slots__ = ('kind', 'node')

    def __init__(self, kind, node=None):
        self.kind, self.node = kind, node


def presented_key():
    key = request.headers.get('X-API-Key', '')
    if not key:
        auth = request.headers.get('Authorization', '')
        if auth.lower().startswith('bearer '):
            key = auth[7:].strip()
    return key


def _touch(node):
    """Record that the node was heard from, at most every 30 s so an ingest burst is not a write burst."""
    from datetime import datetime, timezone
    from models import db
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    if node.last_seen is None or (now - node.last_seen).total_seconds() > 30:
        node.last_seen = now
        db.session.commit()


def identity():
    """The caller's Identity for this request, or None: an API key, a node token, or a signed-in admin session."""
    cached = request.environ.get(_ENV_KEY, _MISSING)      # per REQUEST (never g: an app context can outlive a request)
    if cached is not _MISSING:
        return cached
    who = None
    key = presented_key()
    if key:
        admin = os.environ.get('SSAI_API_KEY', '')
        if admin and hmac.compare_digest(key.encode('utf-8'), admin.encode('utf-8')):
            who = Identity('admin')
        elif key.startswith(NODE_TOKEN_PREFIX):
            from models import Node
            node = Node.query.filter_by(token_hash=hash_secret(key), status='active').first()
            if node is not None:
                _touch(node)
                who = Identity('node', node)
    if who is None and session_admin() and (request.method in ("GET", "HEAD", "OPTIONS") or _csrf_ok()):
        who = Identity("admin")          # a signed-in person; state-changing calls must also carry the CSRF token
    request.environ[_ENV_KEY] = who
    return who


def is_admin():
    who = identity()
    return bool(who and who.kind == 'admin')


def approving_person():
    """The signed-in PERSON making this request, as a short label, or None when the call came from a program.

    The admin API key is also held by the agents, so a call that carries only the key proves a credential, not a person (audit F-04).
    A person is a live browser session (SSO subject, or the password login) with its CSRF token on a state-changing call."""
    if not (session_admin() and _csrf_ok()):
        return None
    return str(session.get('sso') or 'password-login')[:60]


def person_required_for_approval():
    """Approving a block needs a signed-in person unless the operator turned that off (SSAI_APPROVAL_REQUIRES_PERSON=0, for a
    deployment with no human console, which then accepts the admin key)."""
    return os.environ.get('SSAI_APPROVAL_REQUIRES_PERSON', '1').strip().lower() not in ('0', 'false', 'no', 'off')


# A wall display or kiosk may READ threat data without a login. Its trusted front end (the kiosk's nginx) adds this
# header with the viewer key, so the key lives on the proxy and never in a page or a browser. The viewer key opens
# the read-only data endpoints and nothing else: it is deliberately NOT an Identity, so no route that accepts a
# machine or an admin can ever treat it as one.
VIEWER_HEADER = 'X-SSAI-Viewer'


def is_viewer():
    expected = os.environ.get('SSAI_VIEWER_KEY', '')
    sent = request.headers.get(VIEWER_HEADER, '')
    return bool(expected and sent and hmac.compare_digest(sent.encode('utf-8'), expected.encode('utf-8')))


def can_read():
    """May this caller read threat data and the deployment's posture? A signed-in admin, the admin key, or the viewer key."""
    return is_admin() or is_viewer()


# ── rate limiting ────────────────────────────────────────────────────────────

def client_ip():
    """The caller's address. X-Forwarded-For is honoured ONLY from proxies listed in SSAI_TRUSTED_PROXIES: anyone
    else could put any value there and walk around a per-address limit."""
    remote = request.remote_addr or 'unknown'
    trusted = {p.strip() for p in os.environ.get('SSAI_TRUSTED_PROXIES', '').split(',') if p.strip()}
    if remote in trusted:
        # Walk the chain from the right, skipping our own proxies: the first address a trusted proxy did not vouch for is the
        # client. The LEFTMOST entry is whatever the client sent (a proxy that appends keeps it), so it can be forged freely.
        chain = [a.strip() for a in request.headers.get('X-Forwarded-For', '').split(',') if a.strip()]
        for hop in reversed(chain):
            if hop not in trusted:
                return hop
    return remote


class SlidingWindow:
    """At most `limit` events per `window` seconds per key (per process; the hub runs a few workers, so the effective
    ceiling is a small multiple of the setting)."""

    def __init__(self, limit, window, clock=time.monotonic, max_keys=10000):
        self.limit, self.window, self.clock, self.max_keys = limit, window, clock, max_keys
        self._hits = defaultdict(deque)
        self._lock = threading.Lock()

    def _prune(self, dq, now):
        while dq and now - dq[0] >= self.window:
            dq.popleft()

    def hit(self, key):
        """Count an event; True if it is within the limit."""
        now = self.clock()
        with self._lock:
            dq = self._hits[key]
            self._prune(dq, now)
            if len(dq) >= self.limit:
                return False
            dq.append(now)
            if len(self._hits) > self.max_keys:                 # bound memory under a key-spraying attacker
                for k in [k for k, v in self._hits.items() if not v][:1000] or list(self._hits)[:1000]:
                    self._hits.pop(k, None)
            return True

    def count(self, key):
        now = self.clock()
        with self._lock:
            dq = self._hits.get(key)
            if dq is None:
                return 0
            self._prune(dq, now)
            return len(dq)


def _env_int(name, default):
    try:
        return max(1, int(os.environ.get(name, default)))
    except ValueError:
        return default


# Enrollment: 5 wrong codes per address per 5 minutes, then a lockout until the window passes.
enroll_failures = SlidingWindow(_env_int('SSAI_ENROLL_MAX_FAILURES', 5), 300)
# A node's ingest calls: default 600 a minute (10 a second) per node.
node_ingest = SlidingWindow(_env_int('SSAI_NODE_RATE_PER_MIN', 600), 60)


def node_rate_limited(node):
    return not node_ingest.hit(node.node_id)


# ── admin login (people); the API key above is for machines ──────────────────
# The dashboard used to embed the admin key in every page, so anyone who could open the page held the key. Now people
# sign in with a password and get a signed, HttpOnly session cookie plus a CSRF token; pages never contain the key.
# The API key keeps working for machines (the hub's own agents, scripts, the browser extension).
import json
from werkzeug.security import check_password_hash, generate_password_hash
from flask import session

SESSION_MAX_AGE = 12 * 3600
MIN_PASSWORD_LEN = 12
MAX_PASSWORD_LEN = 200                      # scrypt on a megabyte of input is a denial of service
_admin_cache = {'mtime': None, 'data': None}
login_failures = SlidingWindow(_env_int('SSAI_LOGIN_MAX_FAILURES', 5), 300)          # per address
login_failures_all = SlidingWindow(_env_int('SSAI_LOGIN_MAX_FAILURES_ALL', 40), 300)  # everyone together


def admin_path():
    import ssai_config
    return os.path.join(ssai_config.INSTANCE_DIR, 'admin.json')


def load_admin():
    """{'password_hash', 'version'} from instance/admin.json, or None when no admin password has been set."""
    path = admin_path()
    try:
        mtime = os.stat(path).st_mtime_ns
    except OSError:
        _admin_cache.update(mtime=None, data=None)
        return None
    if _admin_cache['mtime'] == mtime:
        return _admin_cache['data']
    data = None
    try:
        with open(path) as f:
            raw = json.load(f)
        ph = raw.get('password_hash')
        if isinstance(ph, str) and ph:
            data = {'password_hash': ph, 'version': hashlib.sha256(ph.encode()).hexdigest()[:16]}
    except (OSError, ValueError, AttributeError):
        data = None
    _admin_cache.update(mtime=mtime, data=data)
    return data


def password_problem(pw):
    """Why this password is not acceptable, or None."""
    if not isinstance(pw, str) or len(pw) < MIN_PASSWORD_LEN:
        return f'use at least {MIN_PASSWORD_LEN} characters'
    if len(pw) > MAX_PASSWORD_LEN:
        return f'use at most {MAX_PASSWORD_LEN} characters'
    if len(set(pw)) < 5:
        return 'use a less repetitive password'
    return None


def set_admin_password(pw, path=None):
    """Store the scrypt hash (owner-only, atomic). Every existing session ends because the password version changes."""
    problem = password_problem(pw)
    if problem:
        raise ValueError(problem)
    import tempfile
    path = path or admin_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix='.admin-')
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump({'password_hash': generate_password_hash(pw), 'updated': int(time.time())}, f)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    _admin_cache.update(mtime=None, data=None)


def verify_password(pw):
    cfg = load_admin()
    if cfg is None or not isinstance(pw, str) or len(pw) > MAX_PASSWORD_LEN:
        return False
    return check_password_hash(cfg['password_hash'], pw)


def start_session():
    cfg = load_admin()
    session.clear()
    session['adm'] = True
    session['iat'] = int(time.time())
    session['pwv'] = cfg['version'] if cfg else ''
    session['csrf'] = secrets.token_urlsafe(32)
    session.permanent = True


def start_sso_session(subject):
    """A session for a person the identity provider signed in (see sso.py). `subject` is the admin-list entry that
    matched; the session lasts only while that entry stays on the list."""
    session.clear()
    session['adm'] = True
    session['iat'] = int(time.time())
    session['sso'] = subject
    session['csrf'] = secrets.token_urlsafe(32)
    session.permanent = True


def end_session():
    session.clear()


def session_admin():
    """True for a live, current admin session (not expired; a password session also has the right password version, an
    SSO session is still on the admin list). Never true for a key or a node."""
    if not session.get('adm'):
        return False
    subject = session.get('sso')
    try:
        limit = sso_session_seconds() if subject else SESSION_MAX_AGE
        # the session is older than its allowed life (written as "not younger" so a garbled timestamp also counts as expired)
        if not time.time() - float(session.get('iat', 0)) < limit:
            return False
    except (TypeError, ValueError):
        return False
    if subject:
        import sso
        return sso.is_admin_subject(subject)       # removed from the list, or SSO switched off: the session ends now
    if sso_password_disabled():
        return False
    cfg = load_admin()
    return cfg is not None and session.get('pwv') == cfg['version']


def sso_password_disabled():
    import sso
    return sso.only()


def sso_session_seconds():
    """An SSO session is short (default 2 hours, SSAI_SSO_SESSION_MINUTES): the session cookie is stateless, so this is how
    soon a person the identity provider has disabled, or a stolen cookie, stops working. Signing in again is silent while
    the provider's own session is alive."""
    import sso
    return sso.session_minutes() * 60


def csrf_token():
    return session.get('csrf', '') if session_admin() else ''


def _csrf_ok():
    sent = request.headers.get('X-CSRF-Token', '')
    want = session.get('csrf', '')
    return bool(sent and want and hmac.compare_digest(sent.encode(), want.encode()))

