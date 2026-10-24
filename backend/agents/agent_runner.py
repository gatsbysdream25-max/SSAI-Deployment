#!/usr/bin/env python3
"""
SwarmSentinel Agent Runner
Runs all scanning sub-agents as background threads, each registering with
the backend API, sending heartbeats, and submitting threats they find.

Words used in this file:
  agent      a small watcher thread (log reader, port monitor, feed fetcher ...); each reports problems to the hub as "threats"
  hub        the web app (backend/app.py); agents talk to it only through its API
  panel      the set of AI models asked to judge one finding;  voice = one model on the panel
  quorum     how many models actually answered, stated honestly in every verdict (fewer than 3 = "degraded")
  fallback   the stand-in panel used when the normal panel gives no answer; its verdicts are marked as such
  flow       the timed list of steps one finding went through (finding_flow.py), saved with its verdict
  recall     reusing an earlier verdict for the same indicator instead of asking the models again (recall.py)
  lineage    a fingerprint of which models and code produced a verdict (lineage.py)
SwarmConsensusAgent (near the end of the agents) is the one that drives the AI panel; docs/code-map.md lists the rest.
"""
import threading
import time
import shutil
import subprocess
import requests
import logging
import os
import re
import socket
import csv
import json
import sys
from collections import deque, OrderedDict
from datetime import datetime, timedelta, timezone

# agent_runner.py runs as a standalone script from backend/agents/, so its
# own directory (not backend/) is what's on sys.path by default — reach up
# one level to import the shared config module.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
import ssai_config
import quarantine_dropbox
import agent_catalog
import recall
import finding_flow
import injection_guard
import local_evidence
import intel
import redact
import state_store
import lineage
import redteam
ssai_config.ensure_dirs()

try:
    from dotenv import load_dotenv as _load_dotenv
except ImportError:
    _load_dotenv = None

def _detect_local_subnet():
    """Best-effort /24 guess from this host's own outbound-facing IP (same
    UDP-connect trick used in app.py's _never_block_ips() — no packet is
    actually sent, just forces the OS to pick a local interface)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(('10.255.255.255', 1))
            octets = s.getsockname()[0].split('.')
        return '.'.join(octets[:3]) + '.0/24'
    except OSError:
        return '192.168.0.0/24'  # last-resort fallback, not this box's real LAN

SCAN_SUBNET = os.environ.get('SCAN_SUBNET', '').strip() or _detect_local_subnet()

# Generic defaults for a fresh install; SSAI_ALLOWED_PORTS/SSAI_WATCHED_SERVICES
# extend rather than replace, so a user adds their own without losing the base set.
_DEFAULT_ALLOWED_PORTS = {22, 53, 80, 443, 5000}
ALLOWED_PORTS = _DEFAULT_ALLOWED_PORTS | {
    int(p) for p in os.environ.get('SSAI_ALLOWED_PORTS', '').split(',') if p.strip().isdigit()
}

_DEFAULT_WATCHED_SERVICES = ['swarmsentinel', 'ollama', 'ssh']
WATCHED_SERVICES = _DEFAULT_WATCHED_SERVICES + [
    s.strip() for s in os.environ.get('SSAI_WATCHED_SERVICES', '').split(',') if s.strip()
]

API = os.environ.get('SSAI_API', 'http://127.0.0.1:5000/api')
API_KEY = os.environ.get('SSAI_API_KEY', '')
HOSTNAME = socket.gethostname()
# 'hub' runs everything and hosts the dashboard; 'node' is an extra machine that runs host sensors and reports to a
# hub (SSAI_API points at it). NODE_ID names the machine in the hub's dashboard (default: its hostname).
ROLE = agent_catalog.role()
NODE_ID = (os.environ.get('SSAI_NODE_ID') or HOSTNAME)[:80]


def _agent_id(name):
    """How the hub identifies an agent. A node's agents are qualified with the node so that two machines running
    the same agent do not overwrite one row; the hub's own agents keep their plain names."""
    return name if ROLE != 'node' else f'{name}@{NODE_ID}'
OLLAMA = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434")
HERMES = os.environ.get("HERMES_URL", OLLAMA)
HERMES_MODEL = os.environ.get('HERMES_MODEL', 'hermes3')
WATCHTOWER = os.environ.get("WATCHTOWER_URL", OLLAMA)
WATCHTOWER_MODEL = os.environ.get('WATCHTOWER_MODEL', 'mistral')
OLLAMA_MODEL = os.environ.get('OLLAMA_MODEL', 'llama3')

# FIX (2026-08-18, deploy two): shared session across all agent threads instead of
# every requests.get/post/put opening a fresh connection — reuses TCP/TLS handshakes
# via urllib3's connection pool, which matters here since 16 threads are constantly
# making short-lived calls to the same handful of hosts (local API, Ollama/Hermes/
# Watchtower, Pi-hole). Safe to share across threads: no per-call mutation of
# session-level state (headers/auth are passed per-call, not via SESSION.headers).
SESSION = requests.Session()

def _build_log_handlers(path):
    """Console always; a size-rotating log file when it can be opened. An unwritable log (permissions, full
    disk) must never stop the runner from starting, and the file must not grow without bound."""
    handlers = [logging.StreamHandler()]
    try:
        import logsafe
        handlers.append(logsafe.SecureRotatingFileHandler(path, maxBytes=20 * 1024 * 1024, backupCount=5))
    except OSError as e:
        print(f'WARNING: cannot open {path} ({e}); logging to the console only', file=sys.stderr)
    return handlers


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(name)s] %(levelname)s %(message)s',
    handlers=_build_log_handlers(ssai_config.LOG_PATH),
)
redact.install_log_redaction()      # no API key or token may reach agents.log or the journal

def _refresh_credentials():
    """Pick up a changed hub address or credential from the environment (after .env was re-read). A node that is
    re-enrolled, or whose credential was replaced, starts using the new one within a cycle, with no restart."""
    global API, API_KEY
    API = os.environ.get('SSAI_API', API)
    API_KEY = os.environ.get('SSAI_API_KEY', '')


def _headers():
    h = {'Content-Type': 'application/json'}
    if API_KEY:
        h['X-API-Key'] = API_KEY
    return h

def _api_get(url, **kw):
    """GET on the hub's own API. Reads are protected since the 2026-10-18 lockdown (anonymous gets 401), so every call carries the
    runner's key. Before this the consensus agent's fetches all returned 401 and it silently judged nothing."""
    kw.setdefault('headers', _headers())
    return SESSION.get(url, **kw)


_api_warn_last = {}

def _warn_api(what, exc):
    """Log an API/system call failure at most once per 5 min per call type (agents call these constantly)."""
    key = what.split(' ')[0]
    now = time.time()
    if now - _api_warn_last.get(key, 0) >= 300:
        _api_warn_last[key] = now
        logging.getLogger('agent_runner').warning(f'call failed ({what}): {exc}')

def _note_auth(what, resp):
    """A 401/403 from the hub means this machine's credential is wrong or was revoked: say so (rate-limited)."""
    if resp is not None and getattr(resp, 'status_code', 200) in (401, 403):
        _warn_api('credential', RuntimeError(
            f'hub answered HTTP {resp.status_code} to {what}: this machine\'s credential was rejected '
            '(revoked, wrong, or the agent id is not allowed). Ask the hub admin for an enrolment code and re-run '
            'deploy/install.sh --role node --enroll-code CODE --hub-url URL'))


def register(name, role, description, agent_type='scanner'):
    """Tell the hub this agent exists (name, role, host) so it appears on the dashboard. A failure is only logged,
    never fatal."""
    try:
        r = SESSION.post(f'{API}/agents/register', json={
            'agentId': _agent_id(name), 'name': _agent_id(name), 'role': role,
            'description': description, 'type': agent_type,
            'hostname': HOSTNAME, 'platform': 'linux',
        }, headers=_headers(), timeout=5)
        _note_auth(f'register {name}', r)
    except Exception as e:
        _warn_api(f'register {name}', e)

def heartbeat(name, status='active', scan_count=None, threat_count=None, last_scan=None,
              provider_health=None):
    """Send the hub a 'still alive' ping with the agent's counters; without regular heartbeats the dashboard would
    show the agent as dead. Optional fields are only sent when given."""
    payload = {'agentId': _agent_id(name), 'name': _agent_id(name), 'status': status, 'hostname': HOSTNAME}
    if scan_count is not None:
        payload['scan_count'] = scan_count
    if threat_count is not None:
        payload['threat_count'] = threat_count
    if last_scan is not None:
        payload['last_scan'] = last_scan
    if provider_health is not None:
        payload['provider_health'] = provider_health
    try:
        r = SESSION.post(f'{API}/agents/heartbeat', json=payload, headers=_headers(), timeout=5)
        _note_auth(f'heartbeat {name}', r)
    except Exception as e:
        _warn_api(f'heartbeat {name}', e)


from agent_util import (_BoundedDict, _BoundedSet, _IFACE_RE, _MAC_RE, _PRIV_NETS, _SYSLOG_HOST_RE, _is_private_ip,   # noqa: F401
                        mask_private_ip, sanitize_log_line)

# FIX (2026-08-19): allowlist for known-normal ports (e.g. a smart TV's local
# Google Cast API), scoped to (threat_type, port) rather than a specific
# device — mask_private_ip() below collapses every LAN IP to the same
# "192.168.xxx.xxx" string on this /24 network, so per-host targeting isn't
# possible with the data actually stored anywhere. See app.py's /api/allowlist
# docstring for the full reasoning; this is a disclosed trade-off, not an
# oversight. Managed via the dashboard's "Allowlist port" button / the
# /api/allowlist API, stored at the path below, hot-reloaded on mtime change
# so a new entry takes effect without restarting the agent process.
_ALLOWLIST_PATH = ssai_config.ALLOWLIST_PATH
_allowlist_cache = {'mtime': None, 'entries': set()}

def _load_allowlist():
    """Return the set of allowed (threat type, port) pairs, re-reading the file only when it changed on disk. If the
    file cannot be read or parsed, keep using the last good list."""
    try:
        mtime = os.path.getmtime(_ALLOWLIST_PATH)
    except OSError:
        return set()
    if mtime != _allowlist_cache['mtime']:
        try:
            with open(_ALLOWLIST_PATH) as f:
                entries = json.load(f)
            _allowlist_cache['entries'] = {(e['type'], e['port']) for e in entries}
            _allowlist_cache['mtime'] = mtime
        except (OSError, ValueError, KeyError):
            pass
    return _allowlist_cache['entries']

def _is_allowlisted(threat_type, url):
    m = re.search(r':(\d+)$', url or '')
    if not m:
        return False
    return (threat_type, int(m.group(1))) in _load_allowlist()


# BUG FIX (2026-09-05): provider API keys activated via /setup were written
# to .env by app.py, but this process (the one that actually runs the AI
# swarm) only reads env vars once at startup via systemd's EnvironmentFile —
# a new key sat unused until the next `systemctl restart ssai-agents`. Same
# mtime-hot-reload technique as the allowlist above, applied to .env, so a
# newly-activated key goes live within one heartbeat cycle instead.
_env_reload_cache = {'mtime': None}

def _env_file_changed():
    """True once per on-disk change to .env since the last call."""
    try:
        mtime = os.path.getmtime(ssai_config.ENV_PATH)
    except OSError:
        return False
    if _env_reload_cache['mtime'] is None:
        _env_reload_cache['mtime'] = mtime
        return False
    if mtime == _env_reload_cache['mtime']:
        return False
    _env_reload_cache['mtime'] = mtime
    return True


_retry_queue = deque(maxlen=500)

def _post_threat(payload):
    return SESSION.post(f'{API}/threats/', json=payload, headers=_headers(), timeout=5)

def _flush_retry_queue():
    """Re-send findings that could not be delivered earlier (at most 20 per call so one call cannot stall the agent).
    Stops at the first network failure and puts that finding back at the front so the order is kept."""
    for _ in range(20):
        try:
            payload = _retry_queue.popleft()
        except IndexError:
            return
        try:
            r = _post_threat(payload)
        except Exception:
            _retry_queue.appendleft(payload)
            return
        if r.status_code >= 400:
            _warn_api(f'threat retry (HTTP {r.status_code})', 'server rejected a queued threat; dropped')

# The dashboard and the public ledger only ever see masked addresses. The real one is stored in an admin-only field so
# an operator can find out which device a masked address was. Set SSAI_STORE_REAL_ADDRESSES=0 to keep nothing.
_STORE_REAL_ADDRESSES = os.environ.get('SSAI_STORE_REAL_ADDRESSES', '1').strip().lower() not in ('0', 'false', 'no', 'off')


def submit_threat(url, threat_type, severity, description, detected_by):
    """Send one finding to the hub with LAN addresses masked (skipped if allowlisted). If the hub is unreachable the
    finding is queued in memory and retried on a later successful submit, so a restart or network blip does not
    lose it."""
    if _is_allowlisted(threat_type, url):
        return
    real_url = url or ''
    url = mask_private_ip(real_url)
    description = mask_private_ip(description or '')
    payload = {
        'url': url, 'type': threat_type, 'severity': severity,
        'description': description, 'detected_by': detected_by, 'node_id': NODE_ID,
    }
    if url != real_url and _STORE_REAL_ADDRESSES:
        payload['real_url'] = real_url
    try:
        r = _post_threat(payload)
        if r.status_code >= 400:
            logging.getLogger(detected_by).error(
                f'THREAT submit failed [{r.status_code}]: {threat_type}: {url}')
        else:
            logging.getLogger(detected_by).warning(f'THREAT [{severity.upper()}] {threat_type}: {url}')
            if _retry_queue:
                _flush_retry_queue()
    except Exception as e:
        # API unreachable (restart, network blip): keep the threat and retry on the next successful submit
        _retry_queue.append(payload)
        _warn_api(f'threat submit ({detected_by}; {len(_retry_queue)} queued)', e)


def _rotated(agent, path):
    """Reset a tailing agent's offset if `path` was rotated or truncated since the last read.
    Without this, after logrotate the stale byte offset exceeds the new file's size and the
    agent reads nothing until the new file outgrows it."""
    try:
        st = os.stat(path)
    except OSError:
        return False
    prev_ino = getattr(agent, '_last_ino', None)
    agent._last_ino = st.st_ino
    if prev_ino is not None and (prev_ino != st.st_ino or st.st_size < agent._last_pos):
        agent.log.info(f'{path} rotated/truncated - reading from the start of the new file')
        agent._last_pos = 0
        return True
    return False


# Resume points (2026-10-09, Local Shared State Plan). A tailing agent used to start at the END of its log on every
# restart, so whatever was written while the agents were down (a deploy, a reboot, a crash) was never read: a brute
# force during a restart went unseen. Now the offset is kept in the per-machine state store and a restart carries on
# from it. Bounded: a backlog bigger than SSAI_LOG_CATCHUP_MAX_MB (default 20) is skipped (start at the end, as
# before) and said so, rather than flooding the hub with a week of old lines.
_CATCHUP_MAX = int(float(os.environ.get('SSAI_LOG_CATCHUP_MAX_MB', '20')) * 1024 * 1024)


def _resume_offset(agent, path):
    """Where a tailing agent should start reading `path`: the saved offset if it is the same file and the gap is
    reasonable, else the current end of the file. Sets agent._last_pos / agent._last_ino."""
    try:
        st = os.stat(path)
    except OSError:
        agent._last_pos = 0
        return 0
    saved = state_store.store().get(agent.name_id, 'tail:' + path) or {}
    pos, ino = saved.get('pos'), saved.get('ino')
    agent._last_ino = st.st_ino
    if isinstance(pos, int) and ino == st.st_ino and 0 <= pos <= st.st_size:
        if st.st_size - pos <= _CATCHUP_MAX:
            if st.st_size > pos:
                agent.log.info(f'{path}: resuming where the last run stopped ({st.st_size - pos} bytes to catch up)')
            agent._last_pos = pos
            return pos
        agent.log.warning(f'{path}: {st.st_size - pos} bytes written since the last run, more than '
                          f'SSAI_LOG_CATCHUP_MAX_MB; skipping to the end')
    agent._last_pos = st.st_size
    return st.st_size


def _save_offset(agent, path):
    """Persist the tail position when it moved (one small upsert per scan at most)."""
    cur = (getattr(agent, '_last_pos', None), getattr(agent, '_last_ino', None))
    if cur[0] is None or getattr(agent, '_saved_tail', None) == cur:
        return
    if state_store.store().put(agent.name_id, 'tail:' + path, {'pos': cur[0], 'ino': cur[1]}):
        agent._saved_tail = cur


def _interval_scale():
    """SSAI_INTERVAL_SCALE (default 1) multiplies every agent's interval. A sandbox sets e.g. 0.2 so its drills
    (backend/tools/sandbox_drills.py) finish in minutes; production leaves it alone. Clamped to 0.01..10."""
    try:
        return min(10.0, max(0.01, float(os.environ.get('SSAI_INTERVAL_SCALE', '1'))))
    except ValueError:
        return 1.0


def _scaled(seconds):
    """The scaled interval; scaling never takes it below 5 s (an interval already shorter is left as it is)."""
    return max(seconds * _interval_scale(), min(seconds, 5.0))


class BaseAgent(threading.Thread):
    name_id = 'BaseAgent'
    role = 'scanner'
    description = 'Base agent'
    interval = 60

    def __init__(self):
        super().__init__(daemon=True, name=self.name_id)
        self.log = logging.getLogger(self.name_id)
        self._stop_evt = threading.Event()   # NOT `_stop`: that shadows a private method of threading.Thread
        self._scans = 0
        self._found = 0
        self._last_scan = None

    def stop(self):
        """Ask the agent to finish its current scan and exit (used when an operator switches it off)."""
        self._stop_evt.set()

    def setup(self):
        pass

    def scan(self):
        pass

    def _submit(self, *args, **kwargs):
        """Wrapper around submit_threat that increments the found counter."""
        submit_threat(*args, **kwargs)
        self._found += 1

    def run(self):
        """Thread entry point: register with the hub, run setup() once, then loop (heartbeat, scan(), wait) until
        stop() is called. An error in one scan is logged and the loop carries on."""
        register(self.name_id, self.role, self.description)
        self.log.info(f'Started — interval {self.interval}s')
        self.setup()
        while not self._stop_evt.is_set():
            try:
                self._last_scan = datetime.now(timezone.utc).isoformat()
                heartbeat(self.name_id, scan_count=self._scans, threat_count=self._found,
                          last_scan=self._last_scan)
                self.scan()
                self._scans += 1
            except Exception as e:
                self.log.error(f'Scan error: {e}')
            self._stop_evt.wait(_scaled(self.interval))


# ── 1. Network Scanner ────────────────────────────────────────────────────────
class NetworkScanAgent(BaseAgent):
    name_id = 'NetworkScanAgent'
    role = 'network_scanner'
    description = 'Periodic nmap LAN scan — detects new hosts and open ports'
    interval = 600  # 10 min

    SUSPICIOUS_PORTS = {21, 23, 445, 3389, 4444, 5900, 6667, 8080, 8443, 31337}

    def setup(self):
        """Warn early if the scan range looks like Docker's private bridge network, because nmap would then only see
        this container and not the real LAN."""
        # Best-effort heads-up, not a hard gate: SCAN_SUBNET wasn't overridden
        # and auto-detection landed in Docker's typical default-bridge range
        # (172.17-172.31.x.x) — nmap will still run, it'll just only ever see
        # the container's own isolated network, not the real LAN. The
        # linux-host compose override fixes this; bridge mode (Docker
        # Desktop default on Windows/Mac) can't expose the host LAN this way.
        if not os.environ.get('SCAN_SUBNET', '').strip():
            octets = SCAN_SUBNET.split('.')
            if len(octets) == 4 and octets[0] == '172' and octets[1].isdigit() and 17 <= int(octets[1]) <= 31:
                self.log.warning(
                    f'Scanning {SCAN_SUBNET} — this looks like an isolated Docker '
                    'bridge network, not your real LAN. Results will be limited to '
                    'this container until run with the linux-host compose override.'
                )

    def scan(self):
        """Run nmap against the LAN and report any open port listed in SUSPICIOUS_PORTS (ports commonly used by
        remote-control tools and malware)."""
        try:
# -sV: also identify the service on each port; --open: list open ports only; -T4: faster timing.
# The 240 s limit stops a hung scan from blocking the agent (its interval is 600 s).
            result = subprocess.run(
                ['nmap', '-sV', '--open', '-T4', '-p', '21,22,23,25,80,443,445,3389,4444,5900,6667,8080,8443,31337',
                 SCAN_SUBNET],
                capture_output=True, text=True, timeout=240
            )
            lines = result.stdout
            current_host = None
            for line in lines.splitlines():
                if line.startswith('Nmap scan report for'):
                    current_host = line.split()[-1].strip('()')
                if '/tcp' in line and 'open' in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        port = int(parts[0].split('/')[0])
                        service = parts[2] if len(parts) > 2 else 'unknown'
                        if port in self.SUSPICIOUS_PORTS and current_host:
                            self._submit(
                                url=f'{current_host}:{port}',
                                threat_type='suspicious-port',
                                severity='medium',
                                description=f'Suspicious port {port} ({service}) open on {current_host}',
                                detected_by=self.name_id,
                            )
        except FileNotFoundError:
            self.log.warning('nmap not found — skipping')
        except Exception as e:
            self.log.error(f'nmap error: {e}')


# ── 2. Auth Log Agent ─────────────────────────────────────────────────────────
class AuthLogAgent(BaseAgent):
    name_id = 'AuthLogAgent'
    role = 'log_monitor'
    description = 'Watches /var/log/auth.log for brute force and failed logins'
    interval = 30

    # Distributed ("low-and-slow") brute force: many addresses, each staying under the per-address threshold of 5.
    # Found by the sandbox drills on 2026-10-10 (24 failures from 6 addresses went unseen). One finding when the whole
    # host sees SPREAD_MIN_FAILS failures from SPREAD_MIN_IPS or more addresses within SPREAD_WINDOW seconds; at most
    # one per SPREAD_COOLDOWN, under one stable identity, so an internet-facing SSH port gives one row with sightings.
    SPREAD_WINDOW = 600
    SPREAD_MIN_FAILS = 20
    SPREAD_MIN_IPS = 5
    SPREAD_COOLDOWN = 3600

    def setup(self):
        self._seen = _BoundedSet(10000)
        self._fail_counts = _BoundedDict(10000)
        self._recent_fails = deque()
        self._last_spread_alert = float('-inf')
        _resume_offset(self, '/var/log/auth.log')

    def _note_spread(self, ip, now=None):
        """Record one failed login and raise a single 'distributed brute force' finding when many different addresses
        together cross the thresholds in a short window (attackers spread attempts out to stay under the per-
        address limit)."""
        now = time.time() if now is None else now
        recent = self._recent_fails
        recent.append((now, ip))
        while recent and now - recent[0][0] > self.SPREAD_WINDOW:
            recent.popleft()
        if len(recent) < self.SPREAD_MIN_FAILS or now - self._last_spread_alert < self.SPREAD_COOLDOWN:
            return
        ips = {i for _, i in recent}
        if len(ips) < self.SPREAD_MIN_IPS:
            return
        self._last_spread_alert = now
        self._submit(
            url='ssh://distributed',
            threat_type='distributed-brute-force',
            severity='high',
            description=(f'Distributed SSH brute force: {len(recent)} failed logins from {len(ips)} addresses in '
                         f'{self.SPREAD_WINDOW // 60} min, each below the per-address alarm (e.g. '
                         f'{", ".join(sorted(ips)[:5])})'),
            detected_by=self.name_id,
        )

    def scan(self):
        """Read the new lines of /var/log/auth.log: count failed logins per address (alert at 5, 20 and 50) and report
        the first successful SSH login from each address and user."""
        log_path = '/var/log/auth.log'
        if not os.path.exists(log_path):
            return
        _rotated(self, log_path)
        try:
            with open(log_path, 'r', errors='ignore') as f:
                f.seek(self._last_pos)
                new_lines = f.readlines()
                self._last_pos = f.tell()
            for line in new_lines:
                if 'Failed password' in line or 'Invalid user' in line:
                    ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
                    ip = ip_match.group(1) if ip_match else 'unknown'
                    self._fail_counts[ip] = self._fail_counts.get(ip, 0) + 1
                    self._note_spread(ip)
# alert only when the count reaches exactly 5, 20 or 50, so one address does not raise a new finding on every failed attempt (high from 20)
                    if self._fail_counts[ip] in (5, 20, 50):
                        sev = 'high' if self._fail_counts[ip] >= 20 else 'medium'
                        self._submit(
                            url=ip,
                            threat_type='brute-force',
                            severity=sev,
                            description=f'SSH brute force from {ip} — {self._fail_counts[ip]} failed attempts',
                            detected_by=self.name_id,
                        )
                if 'Accepted publickey' in line or 'Accepted password' in line:
                    ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
                    user_match = re.search(r'for (\S+) from', line)
                    ip = ip_match.group(1) if ip_match else 'unknown'
                    user = user_match.group(1) if user_match else 'unknown'
                    key = f'{ip}:{user}'
                    _local_node_ip = os.environ.get('NODE1_IP', '')
                    if key not in self._seen and ip not in ('127.0.0.1', _local_node_ip):
                        self._seen.add(key)
                        self._submit(
                            url=ip,
                            threat_type='ssh-login',
                            severity='low',
                            description=f'SSH login from {ip}',
                            detected_by=self.name_id,
                        )
            _save_offset(self, log_path)
        except PermissionError:
            self.log.warning('No permission to read auth.log — try running as root')


# ── 3. Syslog Agent ───────────────────────────────────────────────────────────
class SyslogAgent(BaseAgent):
    name_id = 'SyslogAgent'
    role = 'log_monitor'
    description = 'Tails /var/log/syslog for anomalies and intrusion indicators'
    interval = 45

    PATTERNS = [
        (r'kernel.*segfault', 'segfault', 'medium'),
        (r'OUT-OF-MEMORY|oom.kill', 'oom-kill', 'medium'),
        (r'POSSIBLE BREAK-IN ATTEMPT', 'intrusion-attempt', 'high'),
        (r'refused connect from', 'refused-connection', 'low'),
        (r'UFW BLOCK', 'firewall-block', 'low'),
        (r'SYN flooding', 'syn-flood', 'high'),
        (r'martian source', 'martian-packet', 'medium'),
    ]

    def setup(self):
        _resume_offset(self, '/var/log/syslog')

    def scan(self):
        """Read the new lines of /var/log/syslog and report the first pattern in PATTERNS that matches each line.
        Firewall blocks are only reported when they are inbound (public source to private destination)."""
        log_path = '/var/log/syslog'
        if not os.path.exists(log_path):
            return
        _rotated(self, log_path)
        try:
            with open(log_path, 'r', errors='ignore') as f:
                f.seek(self._last_pos)
                lines = f.readlines()
                self._last_pos = f.tell()
            for line in lines:
                for pattern, threat_type, severity in self.PATTERNS:
                    if re.search(pattern, line, re.IGNORECASE):
                        # UFW BLOCK lines fire constantly for routine outbound egress
                        # (our own traffic to the internet getting blocked by egress
                        # rules) — that's not threat intel. Only flag *inbound* blocks:
                        # an external host (SRC not private) hitting our LAN (DST private).
                        if threat_type == 'firewall-block':
                            src_m = re.search(r'SRC=(\d+\.\d+\.\d+\.\d+)', line)
                            dst_m = re.search(r'DST=(\d+\.\d+\.\d+\.\d+)', line)
                            src_ip = src_m.group(1) if src_m else None
                            dst_ip = dst_m.group(1) if dst_m else None
                            inbound = (dst_ip and _is_private_ip(dst_ip)
                                       and src_ip and not _is_private_ip(src_ip))
                            if not inbound:
                                break
                            src = src_ip
                        else:
                            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                            src = ip_match.group(1) if ip_match else 'syslog'
                        self._submit(
                            url=src,
                            threat_type=threat_type,
                            severity=severity,
                            description=sanitize_log_line(line)[:200],
                            detected_by=self.name_id,
                        )
                        break
            _save_offset(self, log_path)
        except PermissionError:
            self.log.warning('No permission to read syslog')


# ── 4. Pi-hole DNS Agent ──────────────────────────────────────────────────────
class PiHoleAgent(BaseAgent):
    name_id = 'PiHoleAgent'
    role = 'dns_monitor'
    description = 'Monitors Pi-hole DNS activity — blocked domains and query anomalies'
    interval = 120

    PIHOLE   = os.environ.get('PIHOLE_IP', '')
    PASSWORD = os.environ.get('PIHOLE_PASSWORD', '')
    # Per-domain reports are opt-in: on a working Pi-hole they are mostly ad/tracker blocks (not
    # threats), would flood the dashboard, and threat entries are published to the public GitHub ledger.
    REPORT_DOMAINS = os.environ.get('PIHOLE_REPORT_DOMAINS', '').lower() in ('1', 'true', 'yes')
    MIN_QUERIES = 500  # don't judge percent-blocked on a handful of queries
    # A working Pi-hole routinely blocks 30-50% (ads/telemetry); only a much higher share is unusual.
    BLOCK_ALERT_PCT = float(os.environ.get('PIHOLE_BLOCK_ALERT_PCT') or 60)

    def setup(self):
        """Create the memory used to avoid repeat reports and the private HTTP session used to talk to Pi-hole."""
        # FIX: added _seen_domains to deduplicate recentBlocked — without this the same
        # blocked domain is re-submitted as a threat every 120s indefinitely.
        self._seen_domains = _BoundedSet(10000)
        self._sid = None
        self._sid_expires = 0
        self._dns_cursor = None
        self._dns_seen = _BoundedDict(10000)
        self._warned_config = False
        self._warned_auth = False
        self._connected = False
        # Dedicated session that never stores cookies: Pi-hole v6 sets a `sid` cookie at login and
        # then prefers it over the ?sid= parameter (rejecting it without a CSRF token -> 401). The
        # shared SESSION would carry that cookie into every later request.
        from http.cookiejar import DefaultCookiePolicy
        self._http = requests.Session()
        self._http.cookies.set_policy(DefaultCookiePolicy(allowed_domains=[]))

    def _login(self):
        """Pi-hole v6 uses session-based auth: POST /api/auth -> {session: {sid, validity}}."""
        r = self._http.post(f'http://{self.PIHOLE}/api/auth', json={'password': self.PASSWORD}, timeout=8)
        r.raise_for_status()
        sess = r.json().get('session', {})
        if not sess.get('valid'):
            raise RuntimeError(sess.get('message', 'login rejected'))
        self._sid = sess.get('sid')
# renew 30 s before Pi-hole's stated expiry (default 300 s) so a request never uses a session that just ran out; at least 30 s
        self._sid_expires = time.time() + max(int(sess.get('validity', 300)) - 30, 30)

    def _get(self, path):
        """GET a Pi-hole API path and return the JSON. Logs in first when there is no valid session, and once more if
        Pi-hole answers 401 (session expired)."""
        if not self._sid or time.time() >= self._sid_expires:
            self._login()
        r = self._http.get(f'http://{self.PIHOLE}{path}', params={'sid': self._sid}, timeout=8)
        if r.status_code == 401:
            # session expired mid-flight — re-auth once and retry
            self._login()
            r = self._http.get(f'http://{self.PIHOLE}{path}', params={'sid': self._sid}, timeout=8)
        r.raise_for_status()
        return r.json()

    DNS_COOLDOWN = 6 * 3600
    _BLOCKED = ('GRAVITY', 'REGEX', 'DENYLIST', 'EXTERNAL_BLOCKED_IP', 'EXTERNAL_BLOCKED_NULL', 'EXTERNAL_BLOCKED_NXRA',
                'GRAVITY_CNAME', 'REGEX_CNAME', 'DENYLIST_CNAME', 'DBBUSY', 'SPECIAL_DOMAIN')

    def _check_dns_intel(self):
        """Raise a threat when a device looks up a domain that a threat feed lists (once per device+domain per 6 h)."""
        if not len(intel.STORE):
            return
        now = int(time.time())
        since = self._dns_cursor or now - int(self.interval) - 30       # first cycle: just the last interval
        self._dns_cursor = now
        d = self._get(f'/api/queries?from={since}&until={now}&length=1000')
        rows = d.get('queries') or []
        if int(d.get('recordsFiltered') or 0) > len(rows):
            self.log.warning(f'PiHole intel check saw {len(rows)} of {d.get("recordsFiltered")} queries this cycle (busy network)')
        for q in rows:
            domain = (q.get('domain') or '').strip().lower().rstrip('.')
            hit = intel.STORE.match_domain(domain)
            if hit is None:
                continue
            client = (q.get('client') or {}).get('ip') or 'unknown device'
            key = (client, hit['value'])
            if time.time() - self._dns_seen.get(key, 0) < self.DNS_COOLDOWN:
                continue
            self._dns_seen[key] = time.time()
            blocked = str(q.get('status') or '').upper() in self._BLOCKED
            self._submit(
                url=domain,
                threat_type='intel-match',
                severity='low' if blocked else intel.severity_for(hit),
                description=(f"{client} looked up {domain}, which {hit['source']} lists as {hit['malware']} "
                             f"({hit['threat'].replace('_', ' ')})" + (' - Pi-hole blocked the lookup' if blocked else '')),
                detected_by=self.name_id,
            )

    def scan(self):
        """Check Pi-hole: warn once if it is not configured; report an unusually high share of blocked queries, DNS
        lookups that match a threat feed and, if enabled, individual blocked domains."""
        if not self.PIHOLE or not self.PASSWORD:
            if not self._warned_config:
                missing = [k for k, v in (('PIHOLE_IP', self.PIHOLE), ('PIHOLE_PASSWORD', self.PASSWORD)) if not v]
                self.log.warning(
                    f'PiHoleAgent disabled — missing {", ".join(missing)} in the service environment '
                    '(set both in .env; PIHOLE_PASSWORD is a Pi-hole v6 password or app password)')
                self._warned_config = True
            return
        try:
            d = self._get('/api/stats/summary')
            qs = d.get('queries') or {}
            total = int(qs.get('total') or 0)
            pct = float(qs.get('percent_blocked') or 0)
            if not self._connected:
                self._connected = True
                self.log.info(f'PiHoleAgent connected to {self.PIHOLE}: {total} queries today, {pct:.1f}% blocked')
            if total >= self.MIN_QUERIES and pct > self.BLOCK_ALERT_PCT:
                self._submit(
                    url=f'pihole://{self.PIHOLE}',
                    threat_type='dns-anomaly',
                    severity='medium',
                    description=f'Pi-hole blocking {pct:.1f}% of DNS queries today ({total} queries) — elevated malicious domain activity',
                    detected_by=self.name_id,
                )
            try:
                self._check_dns_intel()
            except Exception as e:                       # an intel-matching hiccup must not stop the other Pi-hole checks
                _warn_api(f'pihole dns-intel {self.PIHOLE}', e)
            if self.REPORT_DOMAINS:
                qd = self._get('/api/queries?status=BLOCKED&length=10')
                for q in (qd.get('queries') or [])[:10]:
                    domain = (q.get('domain') or '').strip()
                    if domain and domain not in self._seen_domains:
                        self._seen_domains.add(domain)
                        self._submit(
                            url=domain,
                            threat_type='malicious-domain',
                            severity='info',
                            description=f'Pi-hole blocked domain: {domain}',
                            detected_by=self.name_id,
                        )
        except Exception as e:
            _warn_api(f'pihole {self.PIHOLE}', e)


# ── 5. Port Monitor Agent ─────────────────────────────────────────────────────
class PortMonitorAgent(BaseAgent):
    name_id = 'PortMonitorAgent'
    role = 'port_monitor'
    description = 'Monitors local listening ports for unexpected services'
    interval = 120

    ALLOWED = ALLOWED_PORTS

    def setup(self):
        self._known = _BoundedSet(10000)
        self._pending = set()

    def scan(self):
        """List listening TCP ports with `ss` and report one that is not in the allowed list only after it is still
        there on the next scan (this filters out short-lived ports)."""
        try:
            r = subprocess.run(['ss', '-tlnp'], capture_output=True, text=True, timeout=10)
            current = set()
            for line in r.stdout.splitlines()[1:]:
# in `ss` output the local address looks like 0.0.0.0:22 followed by a space; capture the port number
                m = re.search(r':(\d+)\s', line)
                if m:
                    current.add(int(m.group(1)))

            candidates = {p for p in current if p not in self.ALLOWED and p not in self._known}

            # FIX (2026-09-09): most "new" ports here are ephemeral one-shot binds
            # (a dev server or debug socket grabbing a random free port for a few
            # seconds) rather than persistent services — each pick is a different
            # random port, so the old immediate-flag logic never got to dedup and
            # flooded the threat table with thousands of one-off rows for ports
            # that were already gone by the next scan. Require a port to still be
            # listening on the *next* scan (interval seconds later) before it's
            # reported — a genuinely persistent unexpected listener survives that;
            # a transient ephemeral bind doesn't.
            confirmed = candidates & self._pending
            for port in confirmed:
                self._known.add(port)
                self._submit(
                    url=f'localhost:{port}',
                    threat_type='unexpected-listener',
                    severity='medium',
                    description=f'New unexpected listening port detected: {port}',
                    detected_by=self.name_id,
                )
            self._pending = candidates - confirmed
        except Exception as e:
            self.log.error(f'Port scan error: {e}')


# ── 6. Process Monitor Agent ──────────────────────────────────────────────────
class ProcessMonitorAgent(BaseAgent):
    name_id = 'ProcessMonitorAgent'
    role = 'process_monitor'
    description = 'Monitors running processes for crypto miners, reverse shells, and suspicious activity'
    interval = 90

    # Match on the program name and on real reverse-shell/miner indicators, not on substrings of the whole
    # `ps` line: a bare "python -c" is what every admin one-liner looks like, and "ncat" appears inside
    # ordinary words. (2026-10-10: an operator's own `bash -c "... python -c ..."` raised a CRITICAL "C2" finding.)
    MINERS = {'cryptominer', 'xmrig', 'minerd', 'cgminer', 'ccminer', 'cpuminer', 'nbminer', 'phoenixminer'}
    NETCATS = {'nc', 'ncat', 'netcat', 'nc.traditional', 'nc.openbsd'}
    INTERPRETERS = re.compile(r'^(python[\d.]*|perl|ruby|php|node|lua)$')
    EXEC_FLAGS = {'-c', '-e', '-r', '-E'}
    # code that opens a socket and wires it to a shell - what an interpreter reverse shell actually contains
    REVSHELL_CODE = re.compile(r'(/dev/tcp/|pty\.spawn|os\.dup2|fsockopen|socket\.socket|TCPSocket|IO\.popen|'
                               r'socket\s*\(\s*S\b|\bnc\s+-[a-z]*e\b)', re.I)

    @classmethod
    def classify(cls, args):
        """Return the matched indicator for a process's full command line, or None."""
        parts = args.split()
        if not parts:
            return None
        exe = parts[0].rsplit('/', 1)[-1].lower()
        if exe in cls.MINERS:
            return exe
        if exe in cls.NETCATS and any(re.fullmatch(r'-[a-zA-Z]*[ec][a-zA-Z]*', p) for p in parts[1:]):
            return 'netcat-exec'
        if '/dev/tcp/' in args and exe in ('bash', 'sh', 'zsh', 'dash', 'ksh'):
            return 'bash-devtcp'
        if cls.INTERPRETERS.match(exe) and cls.EXEC_FLAGS.intersection(parts[1:]) and cls.REVSHELL_CODE.search(args):
            return 'interpreter-revshell'
        return None

    def setup(self):
        self._flagged = _BoundedSet(10000)

    def scan(self):
        """List all running processes and report each one that classify() recognises as a miner or reverse shell, once
        per process id. Skips this process and its parent."""
        try:
            r = subprocess.run(['ps', '-eo', 'pid=,user=,args='], capture_output=True, text=True, timeout=10)
            me = {str(os.getpid()), str(os.getppid())}
            for line in r.stdout.splitlines():
# split into pid, user and the rest: the command line itself contains spaces, so only split twice
                bits = line.split(None, 2)
                if len(bits) < 3 or bits[0] in me:
                    continue
                pid, user, args = bits
                pattern = self.classify(args)
                if not pattern:
                    continue
                key = f'{pattern}:{pid}'
                if key not in self._flagged:
                    self._flagged.add(key)
                    self._submit(
                        url=f'process://{pid}',
                        threat_type='suspicious-process',
                        severity='high',
                        description=f'Suspicious process detected ({pattern}): {user} {pid} {args.strip()[:150]}',
                        detected_by=self.name_id,
                    )
        except Exception as e:
            self.log.error(f'Process monitor error: {e}')


# ── 7. Network Connection Agent ───────────────────────────────────────────────
class NetworkConnAgent(BaseAgent):
    name_id = 'NetworkConnAgent'
    role = 'connection_monitor'
    description = 'Monitors active outbound connections for C2 beaconing and data exfiltration'
    interval = 60

    SUSPICIOUS_PORTS = {4444, 4445, 31337, 6667, 6697, 1337, 8888, 9999}
    INTEL_COOLDOWN = 6 * 3600   # one report per listed endpoint per 6 h, however long the connection lasts

    def setup(self):
        self._seen = _BoundedSet(10000)
        self._intel_seen = _BoundedDict(10000)

    def _report_intel(self, hit, line):
        """Report that a live outbound connection matches a threat-feed entry, at most once per INTEL_COOLDOWN per
        endpoint, naming the process when `ss` showed it."""
        now = time.time()
        if now - self._intel_seen.get(hit['value'], 0) < self.INTEL_COOLDOWN:
            return
        self._intel_seen[hit['value']] = now
        proc = re.search(r'users:\(\("([^"]+)"', line)
        self._submit(
            url=hit['value'],
            threat_type='intel-match',
            severity=intel.severity_for(hit),
            description=(f"Live connection to {hit['value']}, which {hit['source']} lists as {hit['malware']} "
                         f"({hit['threat'].replace('_', ' ')})" + (f' - process: {proc.group(1)}' if proc else '')),
            detected_by=self.name_id,
        )

    def scan(self):
        """Look at established outbound connections to public addresses: check each against the threat feeds and flag
        connections to ports often used by malware to phone home."""
        try:
            r = subprocess.run(['ss', '-tnp', 'state', 'established'],
                               capture_output=True, text=True, timeout=10)
            for line in r.stdout.splitlines()[1:]:
                # `ss -tnp state established` prints: Recv-Q Send-Q Local:Port Peer:Port [Process]
                # (this used to read column 4 - the process column - so it never matched a single connection)
                parts = line.split()
                if len(parts) < 4:
                    continue
                remote = parts[3]
                m = re.search(r'(\d+\.\d+\.\d+\.\d+):(\d+)', remote)
                if not m:
                    continue
                ip, port = m.group(1), int(m.group(2))
                # FIX: original only filtered 192.168.x.x and 127.0.0.1, missing
                # 10.x.x.x and 172.16.x.x RFC1918 ranges.  Use shared _is_private_ip().
                if _is_private_ip(ip):
                    continue
                hit = intel.STORE.match_ip(ip, port)
                if hit is not None:
                    self._report_intel(hit, line)
                key = f'{ip}:{port}'
                if port in self.SUSPICIOUS_PORTS and key not in self._seen:
                    self._seen.add(key)
                    self._submit(
                        url=key,
                        threat_type='c2-beacon',
                        severity='high',
                        description=f'Suspicious outbound connection to {ip}:{port} — possible C2 channel',
                        detected_by=self.name_id,
                    )
        except Exception as e:
            self.log.error(f'Connection monitor error: {e}')


# ── 8. Ollama AI Analyzer Agent ───────────────────────────────────────────────
class OllamaAnalyzerAgent(BaseAgent):
    name_id = 'OllamaAnalyzerAgent'
    role = 'ai_analyzer'
    # FIX: description updated to reflect configurable model via OLLAMA_MODEL env var
    description = f'AI threat analysis via Ollama {OLLAMA_MODEL} — enriches and scores collected threats'
    interval = 300  # 5 min

    def setup(self):
        self._analyzed = _BoundedSet(10000)

    def scan(self):
        """Take up to 3 high-severity findings that have no AI analysis yet, ask the Ollama model for a short
        assessment of each and save it. A finding is only marked done once the save succeeded, so failures are
        retried next cycle."""
        try:
            r = _api_get(f'{API}/threats/?unanalyzed=true&severity=high%2B&limit=5', timeout=5)
            threats = r.json() if r.status_code == 200 else []
            batch = [t for t in threats if t.get('id') not in self._analyzed][:3]
            for threat in batch:
                prompt = (
                    'You are a cybersecurity analyst. In 2 sentences, assess this threat and recommend action: '
                    f"Type={threat.get('type')} Severity={threat.get('severity')} "
                    f"Source={threat.get('url')} Description={threat.get('description','')[:200]}"
                )
                # FIX: was hardcoded 'llama3' — now uses OLLAMA_MODEL env var (default 'llama3')
                try:
# 60 s is enough here; the slower local models below are given 150 s
                    resp = SESSION.post(f'{OLLAMA}/api/generate',
                                         json={'model': OLLAMA_MODEL, 'prompt': prompt, 'stream': False},
                                         timeout=60)
                except requests.exceptions.RequestException as e:
                    # Don't mark as analyzed on timeout/connection error — retry next cycle
                    self.log.warning(f'Ollama request failed for threat {threat["id"]}: {e}')
                    continue
                if resp.status_code == 200:
                    analysis = resp.json().get('response', '')
                    self.log.info(f'AI analysis for threat {threat["id"]}: {analysis[:100]}')
                    put = SESSION.put(f'{API}/threats/{threat["id"]}',
                                       json={'ai_analyzed': True, 'ai_verdict': {'analysis': analysis, 'model': OLLAMA_MODEL}},
                                       headers=_headers(), timeout=5)
                    # FIX: only mark analyzed once the verdict is confirmed saved —
                    # previously this was set before the HTTP call, so a timeout
                    # permanently orphaned the threat (ai_analyzed stayed False forever).
                    if put.status_code == 200:
                        self._analyzed.add(threat['id'])
                else:
                    self.log.warning(f'Ollama returned {resp.status_code} for threat {threat["id"]}')
        except Exception as e:
            self.log.warning(f'OllamaAnalyzerAgent error: {e}')


# ── 9. Hermes AI Analyzer Agent ───────────────────────────────────────────────
class HermesAnalyzerAgent(BaseAgent):
    name_id = 'HermesAnalyzerAgent'
    role = 'ai_analyzer'
    description = f'AI threat analysis via Ollama {HERMES_MODEL} — IOC extraction and remediation for medium-severity threats'
    interval = 300  # 5 min, offset from Ollama by stagger in main

    def setup(self):
        self._analyzed = _BoundedSet(10000)

    def scan(self):
        """Same job as OllamaAnalyzerAgent.scan but for medium-severity findings: ask the Hermes model to extract
        indicators (IPs, domains, hashes) and suggest one fix, then save the answer."""
        try:
            r = _api_get(f'{API}/threats/?unanalyzed=true&severity=medium&limit=5', timeout=5)
            threats = r.json() if r.status_code == 200 else []
            batch = [t for t in threats if t.get('id') not in self._analyzed][:3]
            for threat in batch:
                prompt = (
                    'You are a cybersecurity analyst specializing in threat intelligence. '
                    'For the following medium-severity threat, extract any IOCs (IPs, domains, hashes) '
                    'and provide one concrete remediation step: '
                    f"Type={threat.get('type')} Source={threat.get('url')} "
                    f"Description={threat.get('description','')[:200]}"
                )
                try:
                    # Local CPU-only inference measured at ~48s for a typical
                    # IOC-extraction response (vs. OllamaAnalyzerAgent's remote
                    # GPU-backed endpoint, which never times out at 60s) — 60s left
                    # almost no margin and caused most Hermes calls to time out and
                    # retry from scratch every cycle, wasting the work already done.
                    resp = SESSION.post(f'{HERMES}/api/generate',
                                         json={'model': HERMES_MODEL, 'prompt': prompt, 'stream': False},
                                         timeout=150)
                except requests.exceptions.RequestException as e:
                    # Don't mark as analyzed on timeout/connection error — retry next cycle
                    self.log.warning(f'Hermes request failed for threat {threat["id"]}: {e}')
                    continue
                if resp.status_code == 200:
                    analysis = resp.json().get('response', '')
                    self.log.info(f'Hermes analysis for threat {threat["id"]}: {analysis[:100]}')
                    put = SESSION.put(f'{API}/threats/{threat["id"]}',
                                       json={'ai_analyzed': True, 'ai_verdict': {'analysis': analysis, 'model': HERMES_MODEL}},
                                       headers=_headers(), timeout=5)
                    # FIX: only mark analyzed once the verdict is confirmed saved —
                    # previously this was set before the HTTP call, so a timeout
                    # permanently orphaned the threat (ai_analyzed stayed False forever).
                    if put.status_code == 200:
                        self._analyzed.add(threat['id'])
                else:
                    self.log.warning(f'Hermes returned {resp.status_code} for threat {threat["id"]}')
        except Exception as e:
            self.log.warning(f'HermesAnalyzerAgent error: {e}')


# ── 9b. Watchtower AI Analyzer Agent ────────────────────────────────────────────
class WatchtowerAnalyzerAgent(BaseAgent):
    name_id = 'WatchtowerAnalyzerAgent'
    role = 'ai_analyzer'
    description = f'AI threat analysis via Ollama {WATCHTOWER_MODEL} on watchtower — triage for low-severity threats'
    interval = 900  # 15 min (was 5): eases watchtower heat; offset from Ollama/Hermes by stagger in main

    def setup(self):
        self._analyzed = _BoundedSet(10000)

    def scan(self):
        """Same job as OllamaAnalyzerAgent.scan but for low-severity findings: ask the Watchtower model for a short
        triage note and save it."""
        try:
            r = _api_get(f'{API}/threats/?unanalyzed=true&severity=low&limit=5', timeout=5)
            threats = r.json() if r.status_code == 200 else []
            batch = [t for t in threats if t.get('id') not in self._analyzed][:3]
            for threat in batch:
                prompt = (
                    'You are a cybersecurity analyst. In 1-2 sentences, triage this low-severity '
                    'threat and note whether it warrants escalation: '
                    f"Type={threat.get('type')} Source={threat.get('url')} "
                    f"Description={threat.get('description','')[:200]}"
                )
                try:
# 150 s, as for Hermes: this model runs on a slower machine than Ollama's
                    resp = SESSION.post(f'{WATCHTOWER}/api/generate',
                                         json={'model': WATCHTOWER_MODEL, 'prompt': prompt, 'stream': False},
                                         timeout=150)
                except requests.exceptions.RequestException as e:
                    # Don't mark as analyzed on timeout/connection error — retry next cycle
                    self.log.warning(f'Watchtower request failed for threat {threat["id"]}: {e}')
                    continue
                if resp.status_code == 200:
                    analysis = resp.json().get('response', '')
                    self.log.info(f'Watchtower analysis for threat {threat["id"]}: {analysis[:100]}')
                    put = SESSION.put(f'{API}/threats/{threat["id"]}',
                                       json={'ai_analyzed': True, 'ai_verdict': {'analysis': analysis, 'model': WATCHTOWER_MODEL}},
                                       headers=_headers(), timeout=5)
                    # Only mark analyzed once the verdict is confirmed saved — mirrors
                    # the fix applied to Ollama/Hermes so timeouts don't orphan threats.
                    if put.status_code == 200:
                        self._analyzed.add(threat['id'])
                else:
                    self.log.warning(f'Watchtower returned {resp.status_code} for threat {threat["id"]}')
        except Exception as e:
            self.log.warning(f'WatchtowerAnalyzerAgent error: {e}')


# ── 9c. Swarm Consensus Agent (added 2026-08-18) ────────────────────────────────
# Escalation tier on top of the three severity-sliced analyzers above: dispatches
# MEDIUM+ threats that already have an individual verdict out to AiSwarmAnalyzer
# (backend/agents/ai_swarm_agent.py), which fans out in parallel to every AI
# provider with an active API key (Anthropic/OpenAI/Groq/Gemini/etc, plus a local
# Ollama vote) and merges them into a consensus. With no cloud keys configured yet
# this runs as a consensus-of-one (just the local model) — the ai_count/ai_sources
# fields make that honest in the UI rather than implying a full swarm vote.
import contextlib as _contextlib


@_contextlib.contextmanager
def _ollama_env(url, model):
    """Point OLLAMA_URL/OLLAMA_MODEL somewhere for the duration, then put them back EXACTLY: a variable that was not
    set before is removed again, not left as '' (an empty OLLAMA_URL is not the same as an unset one)."""
    saved = {k: os.environ.get(k) for k in ('OLLAMA_URL', 'OLLAMA_MODEL')}
    os.environ['OLLAMA_URL'], os.environ['OLLAMA_MODEL'] = url, model
    try:
        yield
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


class _ThreatEventAdapter:
    """Minimal shape AiSwarmAnalyzer.analyze() expects — not a DB model."""
    class _Sev:
        def __init__(self, raw):
            self.name = (raw or 'medium').upper()

    def __init__(self, threat):
        self.title = threat.get('description') or threat.get('type') or 'Unknown threat'
        self.category = threat.get('type')
        self.severity = self._Sev(threat.get('severity'))
        self.source = threat.get('url')
        self.detail = threat.get('description') or ''
        self.agent = threat.get('detected_by')


class SwarmConsensusAgent(BaseAgent):
    name_id = 'SwarmConsensusAgent'
    role = 'ai_swarm'
    description = 'Multi-AI consensus escalation for medium+ severity threats (new intelligence only)'
    interval = 300

    # Scope to threats created after this agent was deployed — an 85k-threat
    # backlog at [:3]/5min would take weeks to clear, and once cloud API keys
    # are added that backlog becomes real per-call spend. Deliberate backfill,
    # if ever wanted, is a separate one-off script, not this agent's job.
    DEPLOY_CUTOFF = datetime.now(timezone.utc)

    def setup(self):
        """Build the multi-AI panel (its local model is pointed at watchtower), warm the recall cache, work out where
        to resume after a restart and start tracking the panel's lineage (a record of which models and settings
        made each verdict)."""
        self._processed = _BoundedSet(10000)
        self._fail_counts: dict = {}      # threat id -> consecutive no-verdict attempts (see BUG FIX below)
        # AiSwarmAnalyzer's local-Ollama provider reads OLLAMA_URL/OLLAMA_MODEL
        # directly from the environment at construction time. pro1 already
        # carries both OllamaAnalyzerAgent and HermesAnalyzerAgent's load, so
        # point this escalation tier's local vote at watchtower instead —
        # construction resolves and caches the URL, so we only need the env
        # swapped for the moment of __init__, not for the agent's lifetime.
        with _ollama_env(WATCHTOWER, WATCHTOWER_MODEL):
            from ai_swarm_agent import AiSwarmAnalyzer
            self.swarm = AiSwarmAnalyzer()
        self.log.info(f'SwarmConsensusAgent: {self.swarm.active_count} provider(s) active')
        self.recall = recall.RecallCache()
        self._seed_recall()
        self.DEPLOY_CUTOFF = self._resume_cutoff()
        self.lineage = lineage.Tracker(state_store.store())
        self._refresh_lineage()

    # A restart used to move the cutoff to "now", so every medium+ threat that arrived while the agents were down was
    # never judged. Resume from the last cycle instead (minus a small overlap), but never further back than
    # SSAI_CONSENSUS_CATCHUP_HOURS (default 24): a long outage must not turn into a burst of paid API calls.
    def _resume_cutoff(self):
        """Work out the oldest finding time this agent should judge: the last completed cycle minus a 10 minute
        overlap, no further back than the catch-up limit, and never later than the original deploy cutoff. Falls
        back to the deploy cutoff when no cycle was saved."""
        now = datetime.now(timezone.utc)
        last = state_store.store().get(self.name_id, 'last_cycle')
        try:
            last_dt = datetime.fromisoformat(last) if last else None
        except (TypeError, ValueError):
            last_dt = None
        if last_dt is None:
            return type(self).DEPLOY_CUTOFF
        hours = float(os.environ.get('SSAI_CONSENSUS_CATCHUP_HOURS', '24'))
        cutoff = min(max(last_dt - timedelta(minutes=10), now - timedelta(hours=hours)), type(self).DEPLOY_CUTOFF)
        self.log.info(f'Resuming: threats since {cutoff.isoformat(timespec="seconds")} are in scope')
        return cutoff

    def _refresh_lineage(self):
        """Record the panel's manifest; log loudly when it changed (model swap, weights, config, code)."""
        try:
            mid, changes = self.lineage.refresh(self.swarm)
            if changes:
                self.log.warning(f'AI panel lineage {mid}: ' + '; '.join(changes))
        except Exception as e:                       # lineage must never stop the verdicts
            self.log.warning(f'lineage refresh failed: {e}')

    def _intel_state(self):
        """Which threat-intel data was loaded when a verdict was made: the last good pull of each feed."""
        st = state_store.store()
        out = {}
        for name, *_ in IntelFeedAgent.FEEDS:
            last = st.last_good_sync(name)
            if last is not None:
                out[name] = last.isoformat(timespec='seconds')
        return out

    def _seed_recall(self):
        """Warm the recall cache with recent verdicts so a restart does not re-ask the panel about known indicators."""
        try:
            r = _api_get(f'{API}/threats/recall', params={'limit': 500}, timeout=15)
            n = self.recall.seed(r.json()) if r.status_code == 200 else 0
            self.log.info(f'Recall: {n} prior verdict(s) loaded')
        except (requests.exceptions.RequestException, ValueError) as e:
            self.log.warning(f'Recall cache not warmed ({e}); it will fill as threats are analysed')

    def _recalled(self, threat):
        """A still-fresh prior consensus for this threat's indicator (memory first, then the database), or None."""
        url, cat, tid = threat.get('url'), threat.get('type'), threat.get('id')
        hit = self.recall.get(url, cat, exclude_id=tid)
        if hit is not None or recall.recall_key(url, cat) is None:
            return hit
        try:
            r = _api_get(f'{API}/threats/recall',
                            params={'url': url, 'category': cat or '', 'exclude_id': tid if tid is not None else ''},
                            timeout=5)
            body = r.json() if r.status_code == 200 else {}
        except (requests.exceptions.RequestException, ValueError):
            return None
        if not body.get('found'):
            return None
        self.recall.put(url, cat, body.get('consensus'), body.get('threat_id'), recall._epoch(body.get('timestamp')))
        return self.recall.get(url, cat, exclude_id=tid)

    STALE_AFTER_SECONDS = float(os.environ.get('SSAI_PANEL_STALE_MINUTES', '60')) * 60
    FETCH_LIMIT = 25      # findings asked of the hub per severity bucket each cycle (two buckets: high+ and medium)
    MAX_BATCH = 3         # findings judged per 5-minute cycle: each takes minutes on a CPU-only model, so more would overrun the cycle
    MAX_ATTEMPTS = 3      # tries per finding before the agent gives up on it (a person still sees it, marked unjudged)

    def _check_stale(self, waiting):
        """Audit F-10: if findings are waiting and the panel has judged none for an hour, say so LOUDLY. A panel that has quietly
        stopped (every provider failing, a stuck model) otherwise looks exactly like a quiet network. Logged at most every 30 min."""
        now = time.time()
        last = getattr(self, '_last_judged', None)
        if last is None:
            self._last_judged = last = now                  # the clock starts when the agent starts, not at the epoch
        if waiting and now - last > self.STALE_AFTER_SECONDS and now - getattr(self, '_stale_logged', 0) > 1800:
            self._stale_logged = now
            self.log.error(f'AI PANEL STALE: {waiting} finding(s) are waiting and none has been judged for '
                           f'{int((now - last) / 60)} minutes. Check the provider health table; a quiet dashboard does not mean a quiet network.')

    def _injection_note(self, event):
        """Names of any instruction-like text found in the evidence, for the flow record (None when clean). Never raises."""
        try:
            return ', '.join(injection_guard.scan(self.swarm._raw_threat_json(event))) or None
        except Exception:                                        # noqa: BLE001 -- the record is informational; the panel does its own scan
            return None

    def _check_local_evidence(self, threat, consensus, flow):
        """Attach what this network itself knows about the indicator (feed hits, a second detector) to the verdict. If the hub cannot
        be asked, say so in the flow and leave the verdict untouched: "could not check" must never read as "unverified"."""
        try:
            r = _api_get(f'{API}/threats/related', params={'url': threat.get('url') or '', 'exclude_id': threat.get('id', '')}, timeout=5)
            if r.status_code != 200:
                raise ValueError(f'HTTP {r.status_code}')
            evidence = local_evidence.assess(threat, r.json(), consensus)
        except (requests.exceptions.RequestException, ValueError) as e:
            flow.note(local_evidence=f'could not be checked ({type(e).__name__})')
            return
        local_evidence.apply(consensus, evidence)
        flow.note(local_evidence=evidence['status'])

    def reload_swarm(self):
        """Re-init providers from the current environment (called when .env
        changes on disk). Reapplies the same WATCHTOWER swap as setup() —
        without it, a reload would silently repoint the local-Ollama vote at
        OLLAMA_URL instead of WATCHTOWER."""
        try:
            with _ollama_env(WATCHTOWER, WATCHTOWER_MODEL):
                return self.swarm.reload()
        finally:
            if hasattr(self, 'lineage'):
                self._refresh_lineage()

    def scan(self):
        """One cycle: find findings the panel has not judged, judge a few of them, then report the panel's health."""
        if hasattr(self, 'lineage'):
            self._refresh_lineage()              # cheap (hashes a few small files); catches edits made between cycles
            state_store.store().put(self.name_id, 'last_cycle', datetime.now(timezone.utc).isoformat())
        try:
            batch, judgeable = self._pick_batch(self._fetch_unjudged())
            for threat, existing_verdict in batch:
                self._judge_one(threat, existing_verdict)
            self._check_stale(waiting=judgeable)
        except Exception as e:
            self.log.warning(f'SwarmConsensusAgent error: {e}')
        self._report_health()

    def _fetch_unjudged(self):
        """Ask the hub for unjudged findings of medium severity and above, newest first, de-duplicated."""
        # BUG FIX (2026-09-27): this used to request ?unanalyzed=false, which is not a real filter (the
        # route only checks for true/1/yes) -- so it silently fetched the newest 50 rows of ANY severity
        # and analysis state. Low-severity feed rows (5 URLhaus `info` items every 15 min) and already-judged
        # rows filled that window, so medium+ threats could scroll out of it and never be looked at. Ask the
        # server for exactly what we want: unanalyzed, medium-or-above, in two severity buckets so a flood of
        # one severity can't starve the other.
        threats, seen_ids = [], set()
        for sev_q in ('high+', 'medium'):
            r = _api_get(f'{API}/threats/?needs_consensus=true&severity={sev_q}&limit={self.FETCH_LIMIT}', timeout=10)
            if r.status_code != 200:
                continue
            for t in r.json():                    # dedupe defensively -- the buckets are exclusive in
                if t.get('id') not in seen_ids:    # production, but two independent fetches are still two
                    seen_ids.add(t.get('id'))       # chances for the same id to slip in twice
                    threats.append(t)
        return threats

    def _pick_batch(self, threats):
        """Choose up to MAX_BATCH findings to judge this cycle. Returns (list of (finding, earlier verdict), how many were judgeable)."""
        batch = []
        judgeable = 0                    # waiting AND in scope: older backlog rows are skipped on purpose and must not raise the alarm
        for t in threats:
            if t.get('id') in self._processed or not self._in_scope(t):
                continue
            existing = self._prior_verdict(t)
            if 'consensus' in existing:
                self._processed.add(t['id'])         # already judged: remember it so it is not fetched and checked again
                continue
            judgeable += 1
            batch.append((t, existing))
            if len(batch) >= self.MAX_BATCH:
                break
        return batch, judgeable

    def _in_scope(self, t):
        """Is this a finding this agent should judge: medium or above, with a readable time, newer than the cutoff?"""
        # No 'already analysed by a tier-one agent' requirement any more (2026-09-26). Those agents
        # (Ollama/Hermes/WatchtowerAnalyzerAgent) are optional and off by default since 9d566bcb
        # (2026-09-19), and waiting for them left every threat unjudged for a week. The panel has its
        # own local model; saving a verdict marks the threat analysed (PUT /threats/<id>).
        if t.get('severity') not in ('medium', 'high', 'critical'):
            return False
        ts = t.get('timestamp')
        if not ts:
            return False
        try:
            threat_time = datetime.fromisoformat(ts.replace('Z', '+00:00'))
            if threat_time.tzinfo is None:
                threat_time = threat_time.replace(tzinfo=timezone.utc)
        except ValueError:
            return False
        return threat_time >= self.DEPLOY_CUTOFF

    @staticmethod
    def _prior_verdict(t):
        """The AI verdict already stored on a finding (a dict, possibly empty). The hub may send it as text."""
        existing = t.get('ai_verdict')
        if isinstance(existing, str):
            try:
                existing = json.loads(existing)
            except ValueError:
                existing = {}
        return existing if isinstance(existing, dict) else {}

    def _judge_one(self, threat, existing_verdict):
        """Take one finding through the whole path: reuse or ask the panel, check it locally, verify it, score it, save it."""
        # Every step this finding goes through is timed and saved with the verdict (finding_flow.py), and the whole
        # path has a time budget so one slow model cannot hold the queue.
        flow = finding_flow.Flow(threat.get('id'))
        flow.enter('ingested', severity=threat.get('severity'), detector=threat.get('detected_by'))
        flow.enter('fingerprint_checked')
        consensus = self._recalled(threat)       # already judged? reuse it rather than ask the panel again
        flow.note(result='reused an earlier verdict for the same indicator' if consensus else 'new indicator')
        if consensus is None:
            consensus = self._ask_panel(threat, flow)
        if not consensus:
            self._count_failure(threat)
            return
        self._fail_counts.pop(threat['id'], None)
        flow.enter('verifying')
        self._check_local_evidence(threat, consensus, flow)
        if 'verification' not in consensus:          # a different model from another maker checks it before it is saved
            try:
                self.swarm.verify(_ThreatEventAdapter(threat), consensus)
            except Exception as e:                   # verify() does not raise; belt and braces
                self.log.warning(f'Verification step failed for threat {threat["id"]}: {e}')
        flow.enter('scored')
        consensus['flow'] = flow.finish(finding_flow.final_state(consensus))
        # Nest, don't overwrite — the existing {analysis, model} keys
        # are the tier-one verdict this escalation is building on top of.
        if hasattr(self, 'lineage') and 'recalled_from' not in consensus:
            self.lineage.stamp(consensus, self._intel_state())
        merged = dict(existing_verdict)
        merged['consensus'] = consensus
        self._save_verdict(threat, merged, consensus)

    def _ask_panel(self, threat, flow):
        """Screen the evidence, ask the AI panel, and note the outcome in the flow. Returns the consensus, or None when nobody answered."""
        event = _ThreatEventAdapter(threat)
        flow.enter('screened', injection=self._injection_note(event))
        flow.enter('reviewing')
        try:
            consensus = self.swarm.analyze(event, deadline=flow.deadline())
        except Exception as e:
            self.log.warning(f'Swarm analyze failed for threat {threat["id"]}: {e}')
            return None
        if consensus:
            challenge = consensus.get('challenge') or {}
            flow.note(models=len(consensus.get('ai_sources') or []), panel_mode=consensus.get('panel_mode'))
            if challenge.get('ran'):
                flow.enter('challenged', changed=len(challenge.get('changed') or []))
            else:
                flow.skip('challenged', challenge.get('why') or 'not run')
            self.recall.put(threat.get('url'), threat.get('type'), consensus, threat.get('id'))
        return consensus

    def _count_failure(self, threat):
        """The panel gave no verdict. Retry on later cycles, then give up once, loudly, and free the slot."""
        # BUG FIX (2026-09-27): `analyze()` returning nothing (both the primary AND fallback panel
        # empty -- outage, bad key, 429, exception) used to mark the threat processed on the spot:
        # permanent and silent, no log line, no retry. A run of failures also used to occupy this
        # cycle's 3 batch slots forever, starving every other threat behind them. Now: retry across
        # up to MAX_ATTEMPTS cycles (logged each time), then give up ONCE, loudly, and free the slot either way.
        tid = threat['id']
        n = self._fail_counts.get(tid, 0) + 1
        if n >= self.MAX_ATTEMPTS:
            self.log.warning(f'Threat {tid}: no AI verdict after {n} attempts '
                             f'(primary and fallback panels both empty); giving up')
            self._processed.add(tid)
            self._fail_counts.pop(tid, None)
        else:
            self._fail_counts[tid] = n
            self.log.info(f'Threat {tid}: no AI verdict this cycle (attempt {n}/{self.MAX_ATTEMPTS}); will retry')

    def _save_verdict(self, threat, merged, consensus):
        """Store the verdict on the finding. Only a saved verdict marks the finding judged, so a failed save is retried next cycle."""
        try:
            put = SESSION.put(f'{API}/threats/{threat["id"]}',
                              json={'ai_verdict': merged},
                              headers=_headers(), timeout=5)
        except requests.exceptions.RequestException as e:
            self.log.warning(f'Consensus save failed for threat {threat["id"]}: {e}')
            return
        if put.status_code == 200:
            self.log.info(f'Consensus for threat {threat["id"]}: '
                          f'{consensus.get("consensus_verdict")} '
                          f'({(consensus.get("quorum") or {}).get("label") or str(consensus.get("ai_count")) + " AI(s)"}: {consensus.get("ai_sources")})'
                          + (f' [recalled from threat {consensus["recalled_from"]}]' if 'recalled_from' in consensus else ''))
            self._processed.add(threat['id'])
            self._last_judged = time.time()

    def _report_health(self):
        """Show each provider's live/dead state on the dashboard (last success, last error), not just in debug logs."""
        try:
            heartbeat(self.name_id, provider_health=self.swarm.get_health())
            st = self.recall.stats()
            if st['hits'] or st['misses']:
                self.log.info(f"Recall: {st['hits']} reused / {st['misses']} asked the panel, {st['entries']} remembered")
        except Exception:
            # the dashboard health display is a nicety; a failure here must never stop the agent
            pass


# ── 9a. Consensus Verifier Agent ───────────────────────────────────────────────────────────────────────────────────
class ConsensusVerifierAgent(BaseAgent):
    """Works in tandem with SwarmConsensusAgent. The consensus agent verifies each new verdict as it makes it; this agent
    catches the ones that slipped through (the verifier was down or not configured at the time, older verdicts, a restart in
    between) and checks them once an independent model is available. It never changes a verdict."""
    name_id = 'ConsensusVerifierAgent'
    role = 'ai_verifier'
    description = 'Second opinion on every AI consensus from a model of a different maker (SSAI_VERIFIER_PROVIDER)'
    interval = 600
    BATCH = 2

    def setup(self):
        with _ollama_env(WATCHTOWER, WATCHTOWER_MODEL):
            from ai_swarm_agent import AiSwarmAnalyzer
            self.swarm = AiSwarmAnalyzer()
        self._tried = _BoundedSet(5000)
        self.log.info('ConsensusVerifierAgent ready')

    def reload_swarm(self):
        with _ollama_env(WATCHTOWER, WATCHTOWER_MODEL):
            return self.swarm.reload()

    def scan(self):
        """Look at the 60 newest findings and, for up to BATCH of those that have a consensus but no verification yet,
        ask a second model to verify it and save the result. Then report provider health."""
        import ai_swarm_agent
        if not ai_swarm_agent.verifier_enabled():
            return
        try:
            r = _api_get(f'{API}/threats/?limit=60', timeout=10)
            if r.status_code != 200:
                return
            done = 0
            for t in r.json():
                if done >= self.BATCH:
                    break
                verdict = t.get('ai_verdict')
                if isinstance(verdict, str):
                    try:
                        verdict = json.loads(verdict)
                    except ValueError:
                        continue
                consensus = verdict.get('consensus') if isinstance(verdict, dict) else None
                if not isinstance(consensus, dict) or 'verification' in consensus or t['id'] in self._tried:
                    continue
                self._tried.add(t['id'])
                self.swarm.verify(_ThreatEventAdapter(t), consensus)
                v = consensus.get('verification') or {}
                put = SESSION.put(f'{API}/threats/{t["id"]}', json={'ai_verdict': verdict}, headers=_headers(), timeout=5)
                self.log.info(f'Verification of threat {t["id"]}: {v.get("status")} by {v.get("verifier")} '
                              f'({"saved" if put.status_code == 200 else "not saved"})')
                done += 1
        except Exception as e:
            self.log.warning(f'ConsensusVerifierAgent error: {e}')
        try:
            heartbeat(self.name_id, provider_health=self.swarm.get_health())
        except Exception:
            # same: a failed heartbeat must not break the verifier
            pass


# ── 9b. Remediation Sweep Agent ────────────────────────────────────────────────
class RemediationSweepAgent(BaseAgent):
    """Housekeeping for the approve-first remediation queue (remediation_queue.py): a proposal an operator never
    acted on expires instead of sitting forever, and an approved block is auto-reverted once its TTL passes, so
    approving one is never a silent forever-block. Calls POST /api/remediation/sweep, which does the real work
    inside the Flask app (DB + ufw/Pi-hole access) — this agent is just the periodic trigger."""
    name_id = 'RemediationSweepAgent'
    role = 'remediation'
    description = 'Expires stale remediation proposals and auto-reverts expired approved blocks'
    interval = 900

    def scan(self):
        """Ask the hub to run its sweep (expire old proposals, undo expired blocks) and log anything it did."""
        try:
            r = SESSION.post(f'{API}/remediation/sweep', headers=_headers(), timeout=30)
        except requests.exceptions.RequestException as e:
            _warn_api('remediation sweep', e)
            return
        if r.status_code != 200:
            self.log.warning(f'remediation sweep returned HTTP {r.status_code}')
            return
        body = r.json()
        if body.get('expired') or body.get('rolled_back') or body.get('errors'):
            self.log.info(f"Remediation sweep: {body.get('expired', 0)} proposal(s) expired, "
                          f"{body.get('rolled_back', 0)} block(s) auto-reverted" +
                          (f", errors: {body['errors']}" if body.get('errors') else ''))


# ── 10. Threat Feed Agent ──────────────────────────────────────────────────────
_QUARANTINE_SEVERITY = {
    'high confidence phish': 'critical',
    'phish':                 'high',
    'malware':               'critical',
    'high confidence spam':  'medium',
    'spam':                  'low',
    'bulk':                  'low',
}


class EmailQuarantineAgent(BaseAgent):
    """Turns email-quarantine reports into Threat rows.

    No Microsoft Graph/EOP API credentials exist yet, so there's nothing to
    poll directly — reports get landed on disk via POST /api/quarantine/import
    (copy/paste from the admin portal for now) and this agent just drains
    whatever's unprocessed there each cycle. Swapping in a direct API pull
    later only means changing how the dropbox file gets populated, not this
    agent.
    """
    name_id = 'EmailQuarantineAgent'
    role = 'email_security'
    description = 'Ingests email quarantine reports (spam/phish) landed via /api/quarantine/import'
    interval = 300

    def scan(self):
        """Turn each unprocessed quarantine report in the dropbox file into a finding, then mark exactly those reports
        as processed by id."""
        # Snapshot under the shared lock, submit without holding it (submits are network calls), then mark what was
        # submitted BY ID in a second locked step. The old whole-file write-back dropped anything imported meanwhile.
        entries = quarantine_dropbox.read(ssai_config.QUARANTINE_DROPBOX_PATH)
        done = []
        for entry in entries:
            if not isinstance(entry, dict) or entry.get('processed') or not entry.get('id'):
                continue
            policy = (entry.get('policy_type') or '').strip().lower()
            severity = _QUARANTINE_SEVERITY.get(policy, 'medium')
            sender = entry.get('sender') or 'unknown sender'
            description = (
                f'Quarantined email — policy: {entry.get("policy_type") or "unknown"}, '
                f'from: {sender}, to: {entry.get("recipient") or "?"}, '
                f'subject: "{entry.get("subject") or "(no subject)"}", '
                f'received: {entry.get("received_time") or "unknown"}, '
                f'status: {entry.get("release_status") or "unknown"}'
            )
            self._submit(sender, 'email-quarantine', severity, description, self.name_id)
            done.append(entry['id'])
        if done:
            quarantine_dropbox.mark_processed(ssai_config.QUARANTINE_DROPBOX_PATH, done)


class ThreatFeedAgent(BaseAgent):
    name_id = 'ThreatFeedAgent'
    role = 'intel_collector'
    description = 'Pulls from public threat intelligence feeds (URLhaus, abuse.ch)'
    interval = 900  # 15 min

    def setup(self):
        self._seen = _BoundedSet(10000)

    def scan(self):
        """Download the public URLhaus list of recent malware URLs and report up to 5 new online ones per cycle as
        informational findings. The attempt is recorded in the state store's sync log."""
        # URLhaus's JSON API now answers 401 without an abuse.ch Auth-Key (this agent silently
        # produced nothing because of a bare `except: pass`). The public CSV export needs no key
        # and carries each URL's classification and tags. These are threat-intel listings of
        # malware hosted elsewhere, not something detected on this network, so severity is 'info'.
        if getattr(self, '_retired', False):
            return
        sync_id = state_store.store().sync_start('urlhaus-csv')
        try:
            # The shared session reuses a keep-alive connection that has been idle ~15 min, which
            # the server has usually closed ("Remote end closed connection"); one retry opens a fresh one.
            for attempt in (1, 2):
                try:
                    r = SESSION.get('https://urlhaus.abuse.ch/downloads/csv_recent/', timeout=45)
                    break
                except requests.exceptions.ConnectionError:
                    if attempt == 2:
                        raise
            if r.status_code == 410:
                # abuse.ch has retired this download for good: say so once and stop asking every cycle.
                self._retired = True
                self.log.warning('URLhaus CSV feed has been retired by abuse.ch (HTTP 410); this agent will stay idle')
                state_store.store().sync_finish(sync_id, False, r.status_code)
                return
            if r.status_code != 200:
                self.log.warning(f'URLhaus CSV feed returned HTTP {r.status_code}')
                state_store.store().sync_finish(sync_id, False, r.status_code)
                return
            submitted = 0
            for row in csv.reader(l for l in r.text.splitlines() if l and not l.startswith('#')):
# columns used from the URLhaus CSV: row[2] = URL, row[3] = status, row[6] = tags; skip short or offline rows
                if len(row) < 9 or row[3] != 'online':
                    continue
                url = row[2].strip()
                if not url or url in self._seen:
                    continue
                self._seen.add(url)
                tags = row[6] if row[6] and row[6] != 'None' else 'untagged'
                self._submit(
                    url=url,
                    threat_type='malware-url',
                    severity='info',
                    description=f'Threat intel (URLhaus): malware distribution URL [{tags}] - public feed listing, not detected on your network',
                    detected_by=self.name_id,
                )
                submitted += 1
# cap per cycle so one pull of the public list does not flood the dashboard
                if submitted >= 5:
                    break
            self.log.info(f'ThreatFeed: submitted {submitted} new URLhaus URLs')
            state_store.store().sync_finish(sync_id, True, r.status_code, submitted)
        except Exception as e:
            self.log.warning(f'ThreatFeed scan failed: {e}')
            state_store.store().sync_finish(sync_id, False, note=f'{type(e).__name__}: {e}')


# ── 10b. Intel Feed Agent ─────────────────────────────────────────────────────
class IntelFeedAgent(BaseAgent):
    name_id = 'IntelFeedAgent'
    role = 'intel_collector'
    description = 'Loads free abuse.ch indicator feeds (ThreatFox, Feodo Tracker, URLhaus) for the network agents to match against'
    interval = 1800  # 30 min: ThreatFox refreshes every 5 min, so this is polite and still current

    CACHE_PATH = os.path.join(ssai_config.INSTANCE_DIR, 'intel_cache.json')
    # (name, address, reader, format, name of the setting holding its key or None). ThreatFox needs a free abuse.ch Auth-Key.
    FEEDS = (('threatfox', intel.THREATFOX_URL, intel.parse_threatfox, 'json', 'ABUSECH_AUTH_KEY'),
             ('feodo', intel.FEODO_URL, intel.parse_feodo, 'json', None))

    def setup(self):
        # A cache from the last run keeps the matchers armed through restarts and feed outages.
        n = intel.STORE.load(self.CACHE_PATH)
        self.log.info(f'IntelFeed: {n} indicator(s) restored from cache')

    # Every pull is written to the sync log (state_store). A feed refreshed less than SSAI_FEED_REFRESH_MINUTES ago
    # (default 25) is not downloaded again, so restarts and crash loops do not hammer abuse.ch; the cache restored in
    # setup() already holds that data.
    REFRESH_SECONDS = float(os.environ.get('SSAI_FEED_REFRESH_MINUTES', '25')) * 60

    def _say_once(self, message):
        """Log a notice the first time only, so a feed that is switched off does not repeat itself every cycle."""
        told = self.__dict__.setdefault('_told', set())
        if message not in told:
            told.add(message)
            self.log.info(f'IntelFeed: {message}')

    def scan(self):
        """Download each indicator feed that is due for a refresh into the in-memory intel store, drop expired entries
        and save the on-disk cache if anything new loaded."""
        loaded, ok = 0, False
        st = state_store.store()
        for name, url, parse, fmt, key_setting in self.FEEDS:
            if not st.due(name, self.REFRESH_SECONDS):
                continue
            key = os.environ.get(key_setting, '').strip() if key_setting else ''
            if key_setting and not key:
                self._say_once(f'{name} is off: it needs a free abuse.ch Auth-Key (get one at https://auth.abuse.ch and set {key_setting} in .env)')
                continue
            sync_id = st.sync_start(name)
            try:
                headers = {'User-Agent': 'SwarmSentinel-intel'}
                if key:
                    headers['Auth-Key'] = key
                    r = requests.post(url, json={'query': 'get_iocs', 'days': 1}, timeout=90, headers=headers)
                else:
                    r = requests.get(url, timeout=90, headers=headers)   # fresh connection: cycles are 30 min apart
                if r.status_code != 200:
                    self.log.warning(f'IntelFeed: {name} returned HTTP {r.status_code}')
                    st.sync_finish(sync_id, False, r.status_code)
                    continue
                n = intel.STORE.add_many(parse(r.text if fmt == 'text' else r.json()))
                loaded += n
                ok = ok or n > 0        # an empty or garbled 200 is not a refresh
                st.sync_finish(sync_id, n > 0, r.status_code, n, None if n > 0 else 'empty or unparseable response')
            except (requests.exceptions.RequestException, ValueError) as e:
                _warn_api(f'intel feed {name}', e)
                st.sync_finish(sync_id, False, note=f'{type(e).__name__}: {e}')
        expired = intel.STORE.prune()
        if ok:
            try:
                intel.STORE.save(self.CACHE_PATH)
            except OSError as e:
                _warn_api('intel cache save', e)
        st = intel.STORE.stats()
        self.log.info(f'IntelFeed: {loaded} listed this cycle, {st["entries"]} in the store {st["by_kind"]}, {expired} expired')


# ── 11. Service Watcher Agent ─────────────────────────────────────────────────
class ServiceWatchAgent(BaseAgent):
    name_id = 'ServiceWatchAgent'
    role = 'service_monitor'
    description = 'Monitors critical systemd services for unexpected stops or failures'
    interval = 60

    WATCHED = WATCHED_SERVICES

    def setup(self):
        self._states = {}
        self._told_no_systemd = False

    def scan(self):
        """Ask systemd whether each watched service is active and report one that was active on the previous scan and
        is not now."""
        if shutil.which('systemctl') is None:
            # A container or a non-systemd machine has no services to watch: say so once instead of failing every minute.
            if not self._told_no_systemd:
                self._told_no_systemd = True
                self.log.info('ServiceWatchAgent: no systemctl here (container or non-systemd system), so there are no services to watch')
            return
        for svc in self.WATCHED:
            try:
                r = subprocess.run(['systemctl', 'is-active', svc],
                                   capture_output=True, text=True, timeout=5)
                state = r.stdout.strip()
                prev = self._states.get(svc)
                self._states[svc] = state
                if prev and prev == 'active' and state != 'active':
                    self._submit(
                        url=f'service://{svc}',
                        threat_type='service-failure',
                        severity='high',
                        description=f'Critical service {svc} changed state: {prev} → {state}',
                        detected_by=self.name_id,
                    )
            except Exception as e:
                _warn_api(f'service check {svc}', e)


# ── 12. Disk/File Integrity Agent ─────────────────────────────────────────────
class FileIntegrityAgent(BaseAgent):
    name_id = 'FileIntegrityAgent'
    role = 'file_integrity'
    description = 'Checks for unexpected modifications to critical system files'
    interval = 300

    WATCH_PATHS = ['/etc/passwd', '/etc/shadow', '/etc/sudoers', '/etc/ssh/sshd_config',
                   os.path.join(ssai_config.BACKEND_DIR, 'app.py')]

    # Baseline survives restarts, so changes made while the agent was down (e.g. a code
    # deploy to app.py, or an edit during an ssai-agents restart) are still reported once.
    BASELINE_PATH = os.path.join(ssai_config.BACKEND_DIR, 'instance', 'file_integrity_baseline.json')

    def _load_baseline(self):
        """Read the saved file fingerprints from disk. Returns (fingerprints by path, set of paths known to be
        missing). A missing or unreadable file gives empty results, which just means the files are baselined again."""
        try:
            with open(self.BASELINE_PATH) as f:
                raw = json.load(f)
            sigs = {p: tuple(v) for p, v in raw.get('sigs', {}).items()
                    if isinstance(v, list) and len(v) == 6}
            return sigs, set(raw.get('gone', []))
        except FileNotFoundError:
            return {}, set()
        except (OSError, ValueError, AttributeError) as e:
            self.log.warning(f'FileIntegrity: baseline file unreadable, re-baselining: {e}')
            return {}, set()

    def _save_baseline(self):
        """Write the fingerprints to disk through a temporary file and a rename, so a crash mid-write cannot leave a
        half-written baseline. The file is readable only by its owner."""
        try:
            os.makedirs(os.path.dirname(self.BASELINE_PATH), exist_ok=True)
            tmp = self.BASELINE_PATH + '.tmp'
            with open(tmp, 'w') as f:
                json.dump({'sigs': {p: list(sig) for p, sig in self._sigs.items()},
                           'gone': sorted(self._gone)}, f)
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.BASELINE_PATH)
        except OSError as e:
            _warn_api('file-integrity baseline save', e)

    @staticmethod
    def _signature(st):
        # mtime alone misses permission/owner changes, size changes with a restored mtime, and file swaps
        return (st.st_mtime_ns, st.st_size, st.st_ino, st.st_mode, st.st_uid, st.st_gid)

    @staticmethod
    def _changed_fields(old, new):
        names = ('mtime', 'size', 'inode', 'mode', 'owner', 'group')
        return [n for n, a, b in zip(names, old, new) if a != b]

    def setup(self):
        """Load the saved baseline, and fingerprint the watched files not yet in it, so scan() has something to
        compare against."""
        saved_sigs, saved_gone = self._load_baseline()
        self._sigs = {}
        self._from_disk = set()
        self._gone = {p for p in saved_gone if p in self.WATCH_PATHS}
        for p in self.WATCH_PATHS:
            if p in saved_sigs:
                # seed with the *saved* signature; the first scan compares the live file against it
                self._sigs[p] = saved_sigs[p]
                self._from_disk.add(p)
                continue
            try:
                self._sigs[p] = self._signature(os.stat(p))
            except OSError as e:
                if p not in self._gone:
                    self.log.warning(f'FileIntegrity: cannot baseline {p}: {e}')
        self._save_baseline()

    def scan(self):
        """Compare each watched file's current fingerprint with its baseline and report files that were deleted,
        recreated or modified; save the new baseline when anything changed."""
        dirty = False
        for p in self.WATCH_PATHS:
            after_downtime = ' while the agent was not running' if p in self._from_disk else ''
            self._from_disk.discard(p)
            try:
                sig = self._signature(os.stat(p))
            except FileNotFoundError:
                if p in self._sigs:
                    del self._sigs[p]
                    self._gone.add(p)
                    dirty = True
                    self._submit(
                        url=p,
                        threat_type='file-modification',
                        severity='high',
                        description=f'Critical file deleted or moved{after_downtime}: {p}',
                        detected_by=self.name_id,
                    )
                continue
            except OSError as e:
                _warn_api(f'file-integrity {p}', e)
                continue
            old = self._sigs.get(p)
            self._sigs[p] = sig
            if old is None:
                if p in self._gone:
                    self._gone.discard(p)
                    dirty = True
                    self._submit(
                        url=p,
                        threat_type='file-modification',
                        severity='medium',
                        description=f'Critical file recreated after deletion: {p}',
                        detected_by=self.name_id,
                    )
                else:
                    dirty = True  # first sighting of a previously-unbaselined path
                continue
            if sig != old:
                dirty = True
                self._submit(
                    url=p,
                    threat_type='file-modification',
                    severity='medium',
                    description=f'Critical file modified{after_downtime}: {p} ({", ".join(self._changed_fields(old, sig))} changed)',
                    detected_by=self.name_id,
                )
        if dirty:
            self._save_baseline()


# ── 13. Disk Space Agent ──────────────────────────────────────────────────────
class DiskSpaceAgent(BaseAgent):
    name_id = 'DiskSpaceAgent'
    role = 'resource_monitor'
    description = 'Monitors disk usage — full disks hide logs and enable attacks'
    interval = 300

    def scan(self):
        """Run `df` and report any filesystem that is 90% full or more (high severity from 95%). A full disk stops
        logging, which lets an attacker hide."""
        try:
            r = subprocess.run(['df', '-h', ssai_config.DATA_DIR, '/'],
                               capture_output=True, text=True, timeout=10)
            for line in r.stdout.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 5:
# df columns: Filesystem Size Used Avail Use% Mounted-on, so parts[4] is a value like '93%'
                    pct = int(parts[4].rstrip('%'))
                    mount = parts[5] if len(parts) > 5 else parts[0]
                    if pct >= 90:
                        self._submit(
                            url=f'disk://{mount}',
                            threat_type='disk-full',
                            severity='high' if pct >= 95 else 'medium',
                            description=f'Disk {mount} is {pct}% full — log hiding risk',
                            detected_by=self.name_id,
                        )
        except Exception as e:
            self.log.error(f'Disk check error: {e}')


# ── 14. Browser Extension Agent (heartbeat proxy) ─────────────────────────────
class BrowserExtAgent(BaseAgent):
    name_id = 'BrowserExtAgent'
    role = 'browser_proxy'
    description = 'Proxy agent representing Chrome/Firefox SwarmSentinel Shield extensions'
    interval = 30

    def scan(self):
        pass  # Just heartbeats — real scanning done by extensions


# ── 16. Red-team agent ────────────────────────────────────────────────────────
class RedTeamAgent(BaseAgent):
    """Attacks SSAI's own pipeline on a schedule (redteam.py): leakage through the cloud gate, consensus
    manipulation, prompt injection, excessive agency. Offline and side-effect free, so it is safe always-on.
    Every run is appended to instance/redteam_audit.jsonl; a probe that NEWLY fails raises a high finding through the
    same path as a live threat (one finding per failure, not one per run; a fixed probe that breaks again re-alerts)."""
    name_id = 'RedTeamAgent'
    role = 'red_team'
    description = 'Continuously probes SSAI itself: data leakage, consensus spoofing, prompt injection, excessive agency'
    interval = int(float(os.environ.get('SSAI_REDTEAM_INTERVAL_HOURS', '6')) * 3600)

    def scan(self):
        """Run all red-team probes, write the audit record and raise a finding only for a probe that newly fails (it
        logs when a failing probe passes again)."""
        results = redteam.run_all()
        failed = [r for r in results if r['status'] == redteam.FAIL]
        run = {'ts': datetime.now(timezone.utc).isoformat(timespec='seconds'), 'node': NODE_ID,
               'code_version': lineage.code_version(), 'passed': sum(r['status'] == redteam.PASS for r in results),
               'failed': len(failed), 'skipped': sum(r['status'] == redteam.SKIP for r in results), 'results': results}
        try:
            redteam.write_audit(run)
        except OSError as e:
            self.log.error(f'red-team audit log not writable: {e}')
        st = state_store.store()
        for r in results:
            before = st.get(self.name_id, 'last:' + r['probe'])
            if r['status'] == redteam.FAIL and before != redteam.FAIL:
                self._submit(
                    url=f"redteam://{r['probe']}",
                    threat_type='redteam-probe-failed',
                    severity='high',
                    description=f"Red-team probe failed ({r['category']}): {r['probe']}: {r['detail']}",
                    detected_by=self.name_id,
                )
            elif r['status'] == redteam.PASS and before == redteam.FAIL:
                self.log.info(f"red-team probe {r['probe']} passes again")
            st.put(self.name_id, 'last:' + r['probe'], r['status'])
        self.log.info(f"Red team: {run['passed']} passed, {run['failed']} failed, {run['skipped']} skipped"
                      + (f" -- FAILED: {', '.join(r['probe'] for r in failed)}" if failed else ''))


# ── Main ──────────────────────────────────────────────────────────────────────
AGENTS = [
    NetworkScanAgent,
    AuthLogAgent,
    SyslogAgent,
    PiHoleAgent,
    PortMonitorAgent,
    ProcessMonitorAgent,
    NetworkConnAgent,
    OllamaAnalyzerAgent,
    HermesAnalyzerAgent,
    WatchtowerAnalyzerAgent,
    SwarmConsensusAgent,
    ConsensusVerifierAgent,
    RemediationSweepAgent,
    ThreatFeedAgent,
    IntelFeedAgent,
    ServiceWatchAgent,
    FileIntegrityAgent,
    DiskSpaceAgent,
    BrowserExtAgent,
    EmailQuarantineAgent,
    RedTeamAgent,
]

def _note_disabled(AgentClass, log):
    """List a switched-off agent in the hub's menu as an option. Hub-only agents on a node are not options there
    (a node runs host sensors only), so they are not registered and do not clutter the hub with rows per machine."""
    name = AgentClass.name_id
    if ROLE == 'node' and name in agent_catalog.HUB_ONLY:
        return False
    register(name, AgentClass.role, AgentClass.description)
    heartbeat(name, status='disabled')
    log.info(f'{name} is off by default (optional agent) — switch it on in Settings to run it')
    return True


def _sync_agents(by_name, running, log):
    """Bring the running agents in line with the catalog + operator switches. Returns (started, stopped)."""
    wanted = {n for n in by_name if agent_catalog.agent_enabled(n)}
    to_start, to_stop = agent_catalog.plan_reconcile({n: t.is_alive() for n, t in running.items()}, wanted)
    for name in to_stop:
        agent = running.pop(name)
        agent.stop()
        agent.join(timeout=10)
        if agent.is_alive():
            log.warning(f'{name} did not stop within 10s (finishing a scan); it will exit on its own')
        heartbeat(name, status='disabled')
        log.info(f'{name} switched off')
    for name in to_start:
        agent = by_name[name]()
        agent.start()
        running[name] = agent
        log.info(f'{name} started')
        time.sleep(0.5)
    return to_start, to_stop


if __name__ == '__main__':
    log = logging.getLogger('runner')
    by_name = {c.name_id: c for c in AGENTS}
    log.info(f'SwarmSentinel Agent Runner starting — {len(AGENTS)} agents in the catalog')

    running = {}
    for AgentClass in AGENTS:            # start order = roster order
        name = AgentClass.name_id
        if agent_catalog.agent_enabled(name):
            agent = AgentClass()
            agent.start()
            running[name] = agent
            time.sleep(0.5)
        else:
            _note_disabled(AgentClass, log)

    _env_file_changed()  # baseline mtime — startup already read .env once via EnvironmentFile

    log.info('All enabled agents running. Ctrl+C to stop.')
    try:
        while True:
            time.sleep(30)
            _sync_agents(by_name, running, log)          # live on/off from the menu, no restart needed
            alive = sum(1 for t in running.values() if t.is_alive())
            log.info(f'Heartbeat: {alive}/{len(running)} agents alive')
            swarm_agent = running.get('SwarmConsensusAgent')
            if _env_file_changed():          # on every machine: a node has no AI panel but does have a credential
                if _load_dotenv is not None:
                    _load_dotenv(ssai_config.ENV_PATH, override=True)
                _refresh_credentials()
                if swarm_agent is not None:
                    count = swarm_agent.reload_swarm()
                    verifier_agent = running.get('ConsensusVerifierAgent')
                    if verifier_agent is not None:
                        verifier_agent.reload_swarm()
                    log.info(f'.env changed on disk — AI swarm reloaded, {count} provider(s) active')
                else:
                    log.info('.env changed on disk — credentials reloaded')
    except KeyboardInterrupt:
        log.info('Shutting down...')
