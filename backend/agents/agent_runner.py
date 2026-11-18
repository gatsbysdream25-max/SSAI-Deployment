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
import hashlib
import ipaddress
import json
import sys
from collections import Counter, deque, OrderedDict
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
import change_evidence
import live_checks
import model_config
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
    actually sent, just forces the OS to pick a local interface).

    IPv4 on purpose (2026-11-18): an IPv6 home network is one /64, 18 billion billion addresses, which no scan can cover.
    IPv6 devices are still seen where they show up: SSH and firewall logs, outbound connections, the Pi-hole and the
    neighbour table (`ip neigh` lists IPv6 neighbours too)."""
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


_version_cache = []

def _my_version():
    """Which SwarmSentinel version this machine runs, for the hub's fleet list. Read once: it cannot change while we run."""
    if not _version_cache:
        from lineage import code_version
        _version_cache.append(code_version())
    return _version_cache[0]


def register(name, role, description, agent_type='scanner'):
    """Tell the hub this agent exists (name, role, host) so it appears on the dashboard. A failure is only logged,
    never fatal."""
    try:
        r = SESSION.post(f'{API}/agents/register', json={
            'agentId': _agent_id(name), 'name': _agent_id(name), 'role': role,
            'description': description, 'type': agent_type,
            'hostname': HOSTNAME, 'platform': 'linux', 'version': _my_version(),
        }, headers=_headers(), timeout=5)
        _note_auth(f'register {name}', r)
    except Exception as e:
        _warn_api(f'register {name}', e)

def heartbeat(name, status='active', scan_count=None, threat_count=None, last_scan=None,
              provider_health=None):
    """Send the hub a 'still alive' ping with the agent's counters; without regular heartbeats the dashboard would
    show the agent as dead. Optional fields are only sent when given."""
    payload = {'agentId': _agent_id(name), 'name': _agent_id(name), 'status': status, 'hostname': HOSTNAME,
               'version': _my_version()}
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
                        find_ip, find_ip_port, mask_private_ip, normalise_ip, sanitize_log_line, split_host_port,
                        ssh_failure, ssh_source)


def _span(seconds):
    """A time window in words: 600 -> '10 min', 3600 -> '1 hour', 21600 -> '6 hours'."""
    if seconds < 3600:
        return f'{seconds // 60} min'
    hours = seconds // 3600
    return '1 hour' if hours == 1 else f'{hours} hours'


def _is_loopback_bind(addr):
    """Is an `ss` local address (127.0.0.53%lo, [::1], *, 0.0.0.0, 192.0.2.5) reachable from this machine only?"""
    host = addr.strip('[]').split('%', 1)[0]
    if host.startswith('::ffff:'):
        host = host[7:]
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False                           # '*' and anything unreadable count as reachable: report rather than miss


def _cmdline_of(pid):
    """A process's command line from /proc, or '' when it cannot be read."""
    try:
        with open(f'/proc/{pid}/cmdline', 'rb') as f:
            return f.read().replace(b'\0', b' ').decode('utf-8', 'replace').strip()
    except OSError:
        return ''

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
    # Found by the sandbox drills on 2026-10-10 (24 failures from 6 addresses went unseen); widened 2026-11-15 to slower
    # campaigns. Each rule is (window in seconds, failures, different addresses): the whole host crossing ANY rule raises
    # one finding. ACCOUNT_RULE catches many addresses guessing ONE account. All rules share one cooldown, so an
    # internet-facing SSH port gives one row with sightings, not a flood.
    SPREAD_RULES = ((600, 20, 5), (3600, 12, 4), (86400, 30, 5))
    ACCOUNT_RULE = (6 * 3600, 10, 3)
    SPREAD_COOLDOWN = 3600
    SPREAD_KEEP = 50000                    # most failures remembered for the 24-hour rule
    # kept for older callers and tests: the first (fastest) rule
    SPREAD_WINDOW, SPREAD_MIN_FAILS, SPREAD_MIN_IPS = SPREAD_RULES[0]

    # Per-address counts forget failures older than FAIL_MEMORY, so an address that tried 4 times last month does not
    # trip the alarm with one typo today. At most FAIL_KEEP timestamps per address.
    FAIL_MEMORY = 48 * 3600
    FAIL_KEEP = 60
    SUCCESS_AFTER = 5                      # a login after this many failures from the same address is a critical finding

    # One address doing most of the guessing is a plain brute force (it has its own alarm), not a distributed one: the
    # distributed rules only count when no single address made more than SPREAD_MAX_SHARE of the failures in the window.
    SPREAD_MAX_SHARE = 0.5

    # Very slow guessing (2026-11-18, beta record Part C9): one try every 13 hours never reaches 5 inside 48 hours. A
    # second, longer memory raises one medium 'slow-brute-force' finding per address when SLOW_FAILS failures fall on at
    # least SLOW_DAYS different days within SLOW_MEMORY. No automatic action is tied to it; a person decides.
    SLOW_MEMORY = 14 * 86400
    SLOW_FAILS = 6
    SLOW_DAYS = 3
    SLOW_KEEP = 60

    # sudo (2026-11-18, Part C5): a person failing sudo's password check SUDO_FAILS times within SUDO_WINDOW, or
    # someone not allowed to use sudo trying it, is a medium finding about this machine; once per user per SUDO_COOLDOWN.
    SUDO_FAILS = 3
    SUDO_WINDOW = 3600
    SUDO_COOLDOWN = 3600

    _FAILED_USER = re.compile(r'(?:Failed \S+ for (?:invalid user )?|Invalid user )(\S*) from')
    # sudo's own summary line, with "sudo" in the program position right after the time and host name, so an sshd line
    # carrying these words in a user name is never read as a sudo failure. Classic ("Nov 18 10:00:00 host") and ISO stamps.
    _SUDO_TRIES = re.compile(r'^(?:[A-Z][a-z]{2} +\d{1,2} \d\d:\d\d:\d\d|\d{4}-\d\d-\d\dT\S+) \S+ sudo(?:\[\d+\])?: +([\w.@-]+) : '
                             r'(?:(\d+) incorrect password attempts?|user NOT in sudoers) ;')
    SLOW_SAVE_MAX = 5000                   # addresses kept in the saved slow-guessing memory

    def setup(self):
        self._seen = _BoundedSet(10000)
        self._fail_times = _BoundedDict(10000)
        self._bf_success = _BoundedSet(10000)
        self._recent_fails = deque(maxlen=self.SPREAD_KEEP)
        self._last_spread_alert = float('-inf')
        _resume_offset(self, '/var/log/auth.log')
        self._load_slow()

    def _load_slow(self):
        """The slow-guessing memory spans 14 days, so it is saved (state_store) and read back after a restart."""
        try:
            saved = state_store.store().get(self.name_id, 'slow-fails') or {}
            now = time.time()
            for ip, times in (saved.get('times') or {}).items():
                kept = [float(t) for t in times if now - float(t) <= self.SLOW_MEMORY][-self.SLOW_KEEP:]
                if kept and normalise_ip(ip) == ip:
                    self._slow_times[ip] = deque(kept, maxlen=self.SLOW_KEEP)
            for ip in saved.get('told') or ():
                if normalise_ip(ip) == ip:
                    self._slow_told.add(ip)
        except Exception as e:                          # noqa: BLE001 -- a bad saved state only costs the memory
            self.log.warning(f'slow-guessing memory not restored: {e}')

    def _save_slow(self):
        if not self.__dict__.get('_slow_dirty'):
            return
        self._slow_dirty = False
        now = time.time()
        times = {ip: [t for t in ts if now - t <= self.SLOW_MEMORY] for ip, ts in list(self._slow_times.items())}
        times = dict(list((ip, ts) for ip, ts in times.items() if ts)[-self.SLOW_SAVE_MAX:])
        told = [ip for ip in times if ip in self._slow_told]
        try:
            state_store.store().put(self.name_id, 'slow-fails', {'times': times, 'told': told})
        except Exception as e:                          # noqa: BLE001
            self.log.warning(f'slow-guessing memory not saved: {e}')

    _MEMORY = {'_counted_conn': lambda: _BoundedSet(20000), '_slow_times': lambda: _BoundedDict(10000),
               '_slow_told': lambda: _BoundedSet(10000), '_sudo_fails': lambda: _BoundedDict(1000),
               '_sudo_told': lambda: _BoundedDict(1000), '_pw_times': lambda: _BoundedDict(10000)}

    def __getattr__(self, name):
        """The memories added 2026-11-18 are made on first use, so an agent built without setup() (as tests do) has them."""
        make = AuthLogAgent._MEMORY.get(name)
        if make is None:
            raise AttributeError(name)
        value = make()
        setattr(self, name, value)
        return value

    def _note_failure(self, ip, now=None):
        """Remember one failed login from `ip` and return how many it has made in the last FAIL_MEMORY seconds."""
        now = time.time() if now is None else now
        times = self._fail_times.get(ip)
        if times is None:
            times = deque(maxlen=self.FAIL_KEEP)
            self._fail_times[ip] = times
        while times and now - times[0] > self.FAIL_MEMORY:
            times.popleft()
        times.append(now)
        return len(times)

    def _recent_failures(self, ip, now=None):
        now = time.time() if now is None else now
        return sum(1 for t in self._fail_times.get(ip) or () if now - t <= self.FAIL_MEMORY)

    def _note_spread(self, ip, now=None, user=None):
        """Record one failed login and raise a single 'distributed brute force' finding when many different addresses
        together cross one of SPREAD_RULES, or guess one account (ACCOUNT_RULE). Attackers spread attempts out to stay
        under the per-address limit."""
        now = time.time() if now is None else now
        recent = self._recent_fails
        recent.append((now, ip, user))
        longest = max(w for w, _, _ in self.SPREAD_RULES + (self.ACCOUNT_RULE,))
        while recent and now - recent[0][0] > longest:
            recent.popleft()
        if now - self._last_spread_alert < self.SPREAD_COOLDOWN:
            return
        found = self._spread_match(now, user)
        if found is None:
            return
        self._last_spread_alert = now
        count, ips, window, who = found
        self._submit(
            url='ssh://distributed',
            threat_type='distributed-brute-force',
            severity='high',
            description=(f'Distributed SSH brute force{who}: {count} failed logins from {len(ips)} addresses in '
                         f'{_span(window)}, each below the per-address alarm (e.g. {", ".join(sorted(ips)[:5])})'),
            detected_by=self.name_id,
        )

    def _spread_match(self, now, user):
        """The first rule the recent failures cross, as (failures, addresses, window seconds, ' against account X' or ''),
        or None."""
        for window, min_fails, min_ips in self.SPREAD_RULES:
            inside = [i for _, i, *_ in self.recent_window(now, window)]
            ips = set(inside)
            if len(inside) >= min_fails and len(ips) >= min_ips and self._spread_evenly(inside):
                return len(inside), ips, window, ''
        window, min_fails, min_ips = self.ACCOUNT_RULE
        if user and user != 'unknown':
            mine = [e[1] for e in self.recent_window(now, window) if len(e) > 2 and e[2] == user]
            ips = set(mine)
            if len(mine) >= min_fails and len(ips) >= min_ips and self._spread_evenly(mine):
                return len(mine), ips, window, f' against the account {user}'
        return None

    def _spread_evenly(self, addresses):
        """No single address made more than SPREAD_MAX_SHARE of these failures (Part C4: one noisy attacker plus a few
        stray tries is not a distributed attack)."""
        if not addresses:
            return False
        top = Counter(addresses).most_common(1)[0][1]
        return top <= self.SPREAD_MAX_SHARE * len(addresses)

    def _note_slow(self, ip, now=None):
        """The long memory for very slow guessing: one medium 'slow-brute-force' per address when SLOW_FAILS failures
        fall on SLOW_DAYS+ different days within SLOW_MEMORY, and the address never reached the 48-hour alarm."""
        if ip == 'unknown' or _is_private_ip(ip):
            return                                   # a person on the home network mistyping over two weeks is not this
        now = time.time() if now is None else now
        times = self._slow_times.get(ip)
        if times is None:
            times = deque(maxlen=self.SLOW_KEEP)
            self._slow_times[ip] = times
        while times and now - times[0] > self.SLOW_MEMORY:
            times.popleft()
        times.append(now)
        self._slow_dirty = True
        if ip in self._slow_told or len(times) < self.SLOW_FAILS:
            return
        days = {int(t // 86400) for t in times}
        if len(days) < self.SLOW_DAYS or self._recent_failures(ip, now) >= 5:
            return                                   # a burst, which the 48-hour alarm already reports
        self._slow_told.add(ip)
        self._submit(
            url=ip,
            threat_type='slow-brute-force',
            severity='medium',
            description=(f'Slow SSH guessing from {ip}: {len(times)} failed logins spread over {len(days)} days in the '
                         f'last {self.SLOW_MEMORY // 86400} days, too far apart for the 48-hour alarm'),
            detected_by=self.name_id,
        )

    def _note_sudo(self, line, now=None):
        """sudo's own summary lines: 'alice : 3 incorrect password attempts ; ...' and 'bob : user NOT in sudoers ; ...'."""
        m = self._SUDO_TRIES.search(line)
        if not m:
            return
        now = time.time() if now is None else now
        user, tries = m.group(1), m.group(2)
        if tries is None:
            why = f'{user} tried to use sudo but is not allowed to'
        else:
            times = [t for t in self._sudo_fails.get(user) or [] if now - t <= self.SUDO_WINDOW]
            times += [now] * int(tries)
            self._sudo_fails[user] = times[-50:]
            if len(times) < self.SUDO_FAILS:
                return
            why = f'{user} gave a wrong sudo password {len(times)} times in the last hour'
        last = self._sudo_told.get(user)
        if last is not None and now - last < self.SUDO_COOLDOWN:
            return
        self._sudo_told[user] = now
        self._submit(
            url=f'sudo://{user}',
            threat_type='sudo-failure',
            severity='medium',
            description=f'sudo on this machine: {why} (someone may be trying to get administrator rights)',
            detected_by=self.name_id,
        )

    def _count_failure(self, ip, user, now=None, password=True):
        """Count one failed SSH login from `ip`: per-address alarm at 5, 20 and 50 within 48 hours, the distributed
        rules and the slow-guessing memory. Only password guesses (`password`) count toward "a login after failures":
        an admin whose key agent offers several keys, or who closes a prompt, must not look like a guessed password."""
        if password:
            t = time.time() if now is None else now
            pw = self._pw_times.get(ip)
            if pw is None:
                pw = deque(maxlen=self.FAIL_KEEP)
                self._pw_times[ip] = pw
            while pw and t - pw[0] > self.FAIL_MEMORY:
                pw.popleft()
            pw.append(t)
        count = self._note_failure(ip, now)
        self._note_spread(ip, now, user)
        self._note_slow(ip, now)
        # alert only when the count reaches exactly 5, 20 or 50, so one address does not raise a new finding on every
        # failed attempt (high from 20)
        if count in (5, 20, 50):
            self._submit(
                url=ip,
                threat_type='brute-force',
                severity='high' if count >= 20 else 'medium',
                description=f'SSH brute force from {ip} — {count} failed attempts in the last 48 hours',
                detected_by=self.name_id,
            )

    def recent_window(self, now, window):
        """The remembered failures from the last `window` seconds, newest last."""
        out = []
        for entry in reversed(self._recent_fails):
            if now - entry[0] > window:
                break
            out.append(entry)
        out.reverse()
        return out

    def _login_after_failures(self, ip, user, now=None):
        """A successful login from an address that just failed SUCCESS_AFTER+ times: the guess probably worked. Critical,
        once per address and user, never for this machine itself (loopback)."""
        if ip == 'unknown' or ip.startswith('127.') or ip == '::1':
            return
        t = time.time() if now is None else now
        fails = sum(1 for x in self._pw_times.get(ip) or () if t - x <= self.FAIL_MEMORY)     # password guesses only
        key = f'{ip}:{user}'
        if fails < self.SUCCESS_AFTER or key in self._bf_success:
            return
        self._bf_success.add(key)
        self._submit(
            url=ip,
            threat_type='brute-force-success',
            severity='critical',
            description=(f'Successful SSH login as {user} from {ip} after {fails} failed attempts from that address '
                         'in the last 48 hours: the password may have been guessed'),
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
                self.handle_line(line)
            _save_offset(self, log_path)
            self._save_slow()
        except PermissionError:
            self.log.warning('No permission to read auth.log — try running as root')

    def handle_line(self, line, now=None):
        """Act on one auth.log line: a failed login (per-address alarm at 5, 20 and 50 within 48 hours, plus the distributed
        rules) or a successful one (first login per address and user; critical when it follows 5+ failures)."""
        # Note: sshd writes BOTH "Invalid user" and "Failed password" for one attempt at an account that does not exist, so
        # such an attempt counts twice. Kept on purpose (owner decision, 2026-11-16): guessing names that do not exist is
        # worth the extra weight. tools/test_slow_bruteforce.py pins it.
        if self._SUDO_TRIES.search(line):
            self._note_sudo(line, now)
            return
        # Any failed method (password, publickey, keyboard-interactive ...) and, since 2026-11-18 (Part C5), a connection
        # that gave up or hit the attempt limit before logging in: the only trace a key-only attacker leaves. A gave-up
        # line counts once per connection, and not at all when that connection's failures were already counted.
        failure = ssh_failure(line)
        if failure is not None:
            ip = failure['ip'] or 'unknown'            # IPv4 or IPv6 (2026-11-18); ::ffff:a.b.c.d counts as a.b.c.d
            conn = f'{ip}|{failure["port"]}' if failure['port'] and ip != 'unknown' else None
            if failure['kind'] == 'gave-up':
                if ip == 'unknown' or conn in self._counted_conn:
                    return
                user = None
            else:
                user_match = self._FAILED_USER.search(line)
                user = user_match.group(1) if user_match else None
            if conn:
                self._counted_conn.add(conn)
            self._count_failure(ip, user, now, password=failure['password'])
            return
        if 'Accepted publickey' in line or 'Accepted password' in line or 'Accepted keyboard-interactive' in line:
            user_match = re.search(r'for (\S+) from', line)
            ip = ssh_source(line) or 'unknown'
            user = user_match.group(1) if user_match else 'unknown'
            self._login_after_failures(ip, user, now)
            key = f'{ip}:{user}'
            _local_node_ip = os.environ.get('NODE1_IP', '')
            if key not in self._seen and ip not in ('127.0.0.1', '::1', _local_node_ip):
                self._seen.add(key)
                self._submit(
                    url=ip,
                    threat_type='ssh-login',
                    severity='low',
                    description=f'SSH login from {ip}',
                    detected_by=self.name_id,
                )


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
                self.handle_line(line)
            _save_offset(self, log_path)
        except PermissionError:
            self.log.warning('No permission to read syslog')

    def handle_line(self, line):
        """Report the first pattern in PATTERNS that matches one syslog line (firewall blocks only when inbound)."""
        for pattern, threat_type, severity in self.PATTERNS:
            if not re.search(pattern, line, re.IGNORECASE):
                continue
            # UFW BLOCK lines fire constantly for routine outbound egress (our own traffic to the internet getting blocked by
            # egress rules): that's not threat intel. Only flag *inbound* blocks from an external host (SRC not private).
            # Inbound means: the destination is on our network (IPv4 behind NAT), or the packet came IN on an interface and
            # was going nowhere else (IN=eth0 OUT=), which is how an IPv6 packet to this host's own public address looks:
            # IPv6 has no NAT, so its DST is rarely private. Addresses are IPv4 or IPv6 (2026-11-18).
            if threat_type == 'firewall-block':
                src_m = re.search(r'SRC=(\S+)', line)
                dst_m = re.search(r'DST=(\S+)', line)
                src_ip = find_ip(src_m.group(1)) if src_m else None
                dst_ip = find_ip(dst_m.group(1)) if dst_m else None
                to_this_host = bool(re.search(r'\bIN=\S+', line)) and bool(re.search(r'\bOUT=(\s|$)', line))
                inbound = (src_ip and not _is_private_ip(src_ip)
                           and ((dst_ip and _is_private_ip(dst_ip)) or to_this_host))
                if not inbound:
                    return
                src = src_ip
            else:
                src = find_ip(line) or 'syslog'
            self._submit(
                url=src,
                threat_type=threat_type,
                severity=severity,
                description=sanitize_log_line(line)[:200],
                detected_by=self.name_id,
            )
            return


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
    SHELLS = {'bash', 'sh', 'zsh', 'dash', 'ksh', 'ash'}
    WRAPPERS = {'busybox', 'toybox'}                  # one binary that runs many tools: `busybox nc -e /bin/sh ...`
    AWKS = {'awk', 'gawk', 'mawk', 'nawk'}
    INTERPRETERS = re.compile(r'^(python[\d.]*|perl|ruby|php[\d.]*|node|lua[\d.]*)$')
    EXEC_FLAGS = {'-c', '-e', '-r', '-E'}
    # code that opens a socket and wires it to a shell - what an interpreter reverse shell actually contains
    REVSHELL_CODE = re.compile(r'(/dev/tcp/|/dev/udp/|pty\.spawn|os\.dup2|fsockopen|socket\.socket|TCPSocket|IO\.popen|'
                               r'socket\s*\(\s*S\b|\bnc\s+-[a-z]*e\b|IO::Socket|Socket::INET|proc_open|child_process|'
                               r'net\.(Socket|connect|createConnection)|require\(\s*.net.\s*\)|socket\.tcp\s*\(|'
                               r'subprocess\.(call|Popen|run)\s*\(\s*\[?\s*["\']/bin/(ba)?sh)', re.I)
    NETCAT_LONG_EXEC = re.compile(r'^--(exec|sh-exec|lua-exec)(=|$)')
    BARE_IP_URL = re.compile(r'\b(?:https?|ftp)://(?:(?!127\.)\d{1,3}(?:\.\d{1,3}){3}|\[(?!::1\])[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*'
                             r'(?:%25[\w.-]+)?\])(?::\d+)?/')      # IPv4, or IPv6 in brackets (not loopback)
    TEMP_DIRS = ('/tmp/', '/var/tmp/', '/dev/shm/')
    # a hidden folder or file under a temp directory (/tmp/.x/run, /dev/shm/.cache.sh). AppImages mount at /tmp/.mount_*,
    # which is normal, so that one prefix is left out.
    HIDDEN_TEMP = re.compile(r'^(?:/tmp|/var/tmp|/dev/shm)(?:/[^/\s]+)*?/\.(?!mount_)[^/\s]+')
    MINER_ARGS = re.compile(r'(stratum\+(tcp|ssl|tls)://|(^|\s)--donate-level\b|(^|\s)(--algo[= ]|-a\s+)'
                            r'(rx/|randomx|cn/|cryptonight|kawpow|ethash|etchash|autolykos|ghostrider|argon2))', re.I)
    CPU_HOT = 0.9                     # share of one core counted as "pinned"
    CPU_HOT_SECONDS = 600             # pinned this long, from a temp directory: report it

    @classmethod
    def classify(cls, args):
        """Return the matched indicator for a process's full command line, or None."""
        parts = args.split()
        if not parts:
            return None
        exe = parts[0].rsplit('/', 1)[-1].lower()
        if exe in cls.MINERS:
            return exe
        if exe in cls.WRAPPERS and len(parts) > 1:
            inner = cls.classify(' '.join(parts[1:]))
            return f'{exe}-{inner}' if inner else None
        if exe in cls.NETCATS and any(re.fullmatch(r'-[a-zA-Z]*[ec][a-zA-Z]*', p) or cls.NETCAT_LONG_EXEC.match(p)
                                      for p in parts[1:]):
            return 'netcat-exec'
        if exe == 'socat' and re.search(r'(^|[\s,!])(exec|system):', args, re.I):
            return 'socat-exec'
        if exe in cls.AWKS and re.search(r'/inet/(tcp|udp)/', args):
            return 'awk-inet'
        if exe == 'openssl' and 's_client' in parts and '-quiet' in parts and find_ip_port(args):
            return 'openssl-shell'
        if exe in cls.SHELLS:
            if re.search(r'/dev/(tcp|udp)/', args):
                return 'bash-devtcp'
            if 'mkfifo' in args and re.search(r'\b(nc|ncat|netcat|telnet|socat)\b|openssl\s+s_client', args):
                return 'fifo-shell'
        if cls._is_dropper(args):
            return 'ip-dropper'
        if cls.MINER_ARGS.search(args):
            return 'miner-args'
        if cls.INTERPRETERS.match(exe) and cls.EXEC_FLAGS.intersection(parts[1:]) and cls.REVSHELL_CODE.search(args):
            return 'interpreter-revshell'
        if cls._runs_from_hidden_temp(exe, parts):
            return 'hidden-temp-program'
        return None

    @classmethod
    def _is_dropper(cls, args):
        """A download from a bare IP address that is then run: piped into a shell, made executable, or saved to a temp
        directory. (Real software downloads use names, not raw addresses.)"""
        if not re.search(r'\b(curl|wget|fetch|tftp)\b', args) or not cls.BARE_IP_URL.search(args):
            return False
        return bool(re.search(r'\|\s*(sudo\s+)?(ba|z|da|k)?sh\b|chmod\s+(\+x|[0-7]*7[0-7]*)\b|'
                              r'(-O|-o|--output(-document)?)\s*=?\s*(/tmp|/var/tmp|/dev/shm)/', args))

    @classmethod
    def _runs_from_hidden_temp(cls, exe, parts):
        """The program itself, or the script an interpreter/shell is running, sits in a hidden folder under a temp directory."""
        if cls.HIDDEN_TEMP.match(parts[0]):
            return True
        if cls.INTERPRETERS.match(exe) or exe in cls.SHELLS:
            script = next((p for p in parts[1:] if not p.startswith('-')), '')
            return bool(cls.HIDDEN_TEMP.match(script))
        return False

    @classmethod
    def hidden_temp_by_path(cls, pid, args, readlink=os.readlink):
        """The same hidden-temp rule, from what the kernel says (2026-11-18, beta record Part C6): a program started by a
        relative name ('./.x/run' or '.x/run' from inside /tmp) is matched by its real file (/proc/<pid>/exe), and a
        relative script given to a shell or interpreter is matched after joining it to the process's working folder.
        Unreadable /proc entries (another user's process when not root) give False."""
        parts = args.split()
        if not parts:
            return False
        try:
            if cls.HIDDEN_TEMP.match(readlink(f'/proc/{pid}/exe').replace(' (deleted)', '')):
                return True
        except OSError:
            pass
        exe = parts[0].rsplit('/', 1)[-1].lower()
        candidates = [] if parts[0].startswith('/') else [parts[0]]
        if cls.INTERPRETERS.match(exe) or exe in cls.SHELLS:
            script = next((p for p in parts[1:] if not p.startswith('-')), '')
            if script and not script.startswith('/'):
                candidates.append(script)
        if not candidates:
            return False
        try:
            cwd = readlink(f'/proc/{pid}/cwd').replace(' (deleted)', '')
        except OSError:
            return False
        return any(cls.HIDDEN_TEMP.match(os.path.normpath(os.path.join(cwd, c))) for c in candidates)

    @staticmethod
    def impersonates_kernel(pid, ppid, args):
        """A process that names itself like a kernel thread ("[kworker/0:1]") but is not one: real kernel threads are
        children of kthreadd (process 2), or kthreadd itself."""
        name = args.strip()
        return name.startswith('[') and name.endswith(']') and pid != '2' and ppid not in ('0', '2')

    def setup(self):
        self._flagged = _BoundedSet(10000)
        self._cpu = {}                    # pid -> (cpu seconds, wall time, pinned since or None)

    def cpu_pinned(self, pid, cpu_seconds, now):
        """Track one process's CPU use between scans; True once it has used CPU_HOT of a core for CPU_HOT_SECONDS."""
        prev = self._cpu.get(pid)
        if prev is None or now <= prev[1] or cpu_seconds < prev[0]:
            self._cpu[pid] = (cpu_seconds, now, None)
            return False
        share = (cpu_seconds - prev[0]) / (now - prev[1])
        since = (prev[2] if prev[2] is not None else prev[1]) if share >= self.CPU_HOT else None
        self._cpu[pid] = (cpu_seconds, now, since)
        return since is not None and now - since >= self.CPU_HOT_SECONDS

    @staticmethod
    def program_path(pid, args):
        """Where the program file is: the kernel's link when readable (root), else the command's first word if absolute."""
        try:
            return os.readlink(f'/proc/{pid}/exe').replace(' (deleted)', '')
        except OSError:
            first = args.split()[0] if args.split() else ''
            return first if first.startswith('/') else ''

    def scan(self):
        """List all running processes and report each one that classify() recognises (miner, reverse shell, dropper ...),
        a fake kernel thread, or a program from a temp directory pinning a CPU core for 10+ minutes. Once per process id.
        Skips this process and its parent."""
        try:
            r = subprocess.run(['ps', '-eo', 'pid=,ppid=,user=,times=,args='], capture_output=True, text=True, timeout=10)
            me = {str(os.getpid()), str(os.getppid())}
            now = time.monotonic()
            alive = set()
            for line in r.stdout.splitlines():
# split into pid, ppid, user, cpu seconds and the rest: the command line itself contains spaces, so only split four times
                bits = line.split(None, 4)
                if len(bits) < 5 or bits[0] in me:
                    continue
                pid, ppid, user, cpu, args = bits
                alive.add(pid)
                pattern = self.classify(args)
                if not pattern and self.impersonates_kernel(pid, ppid, args):
                    pattern = 'fake-kernel-thread'
                if not pattern and self.hidden_temp_by_path(pid, args):
                    pattern = 'hidden-temp-program'
                if not pattern and cpu.isdigit() and self.cpu_pinned(pid, int(cpu), now):
                    path = self.program_path(pid, args)
                    if path.startswith(self.TEMP_DIRS):
                        pattern = 'cpu-hog-from-temp'
                if pattern:
                    self._report(pattern, pid, user, args)
            for gone in set(self._cpu) - alive:
                del self._cpu[gone]
        except Exception as e:
            self.log.error(f'Process monitor error: {e}')

    def _report(self, pattern, pid, user, args):
        key = f'{pattern}:{pid}'
        if key in self._flagged:
            return
        self._flagged.add(key)
        self._submit(
            url=f'process://{pid}',
            threat_type='suspicious-process',
            severity='high',
            description=f'Suspicious process detected ({pattern}): {user} {pid} {args.strip()[:150]}',
            detected_by=self.name_id,
        )


# ── 7. Socket Watch Agent (listening ports + outbound connections) ────────────
class SocketWatchAgent(BaseAgent):
    """One look at this host's sockets per cycle: new unexpected listening ports, and established outbound
    connections (threat-feed matches and ports malware phones home on). It replaces the separate port and
    connection monitors, which both ran `ss` on their own timers."""
    name_id = 'SocketWatchAgent'
    role = 'socket_monitor'
    description = 'Monitors listening ports and outbound connections for unexpected services, C2 beaconing and threat-feed matches'
    interval = 60
    LISTENER_EVERY = 2   # listeners are checked every 2nd cycle (120 s), connections every cycle (60 s)

    ALLOWED = ALLOWED_PORTS
    # classic reverse-shell/IRC ports, plus mining-pool ports malware connects out to (3333, 14433, 14444, 45560, 45700)
    SUSPICIOUS_PORTS = {4444, 4445, 31337, 6667, 6697, 1337, 8888, 9999, 3333, 14433, 14444, 45560, 45700}
    # A listener only on loopback is reachable from this machine alone, so it is reported only when its owner is one of
    # these (or runs from a temp directory, or looks like a reverse shell). Not used: a "hidden folder" rule on the
    # program's path, because VS Code (~/.vscode-server) and Ollama (~/.ollama) live in hidden folders.
    UNEXPECTED_OWNERS = (ProcessMonitorAgent.NETCATS | ProcessMonitorAgent.SHELLS | ProcessMonitorAgent.WRAPPERS
                         | ProcessMonitorAgent.AWKS | ProcessMonitorAgent.MINERS | {'socat', 'perl', 'ruby', 'php', 'lua', 'openssl'})
    INTEL_COOLDOWN = 6 * 3600   # one report per listed endpoint per 6 h, however long the connection lasts

    def setup(self):
        self._known = _BoundedSet(10000)
        self._pending = set()
        self._seen = _BoundedSet(10000)
        self._intel_seen = _BoundedDict(10000)
        self._cycle = 0

    def scan(self):
        """Check connections every cycle and listening ports every LISTENER_EVERY-th cycle."""
        self._scan_connections()
        if self._cycle % self.LISTENER_EVERY == 0:
            self._scan_listeners()
        self._cycle += 1

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

    def _scan_connections(self):
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
                host, port = split_host_port(parts[3])            # 203.0.113.5:443 or [2001:db8::5]:443
                ip = find_ip(host) if host else None
                if ip is None:
                    continue
                # FIX: original only filtered 192.168.x.x and 127.0.0.1, missing
                # 10.x.x.x and 172.16.x.x RFC1918 ranges.  Use shared _is_private_ip().
                if _is_private_ip(ip):
                    continue
                hit = intel.STORE.match_ip(ip, port)
                if hit is not None:
                    self._report_intel(hit, line)
                key = f'[{ip}]:{port}' if ':' in ip else f'{ip}:{port}'
                if port in self.SUSPICIOUS_PORTS and key not in self._seen:
                    self._seen.add(key)
                    self._submit(
                        url=key,
                        threat_type='c2-beacon',
                        severity='high',
                        description=f'Suspicious outbound connection to {key} — possible C2 channel',
                        detected_by=self.name_id,
                    )
        except Exception as e:
            self.log.error(f'Connection monitor error: {e}')

    def _scan_listeners(self):
        """List listening TCP ports with `ss` and report one that is not in the allowed list only after it is still
        there on the next scan (this filters out short-lived ports)."""
        try:
            r = subprocess.run(['ss', '-tlnp'], capture_output=True, text=True, timeout=10)
            listeners = self.listeners(r.stdout)
            current = {p for p, info in listeners.items() if info['exposed'] or info['odd_owner']}

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
                info = listeners[port]
                where = 'reachable from the network' if info['exposed'] else 'on this machine only'
                owner = f', program: {", ".join(sorted(info["owners"]))}' if info['owners'] else ''
                self._submit(
                    url=f'localhost:{port}',
                    threat_type='unexpected-listener',
                    severity='medium',
                    description=f'New unexpected listening port detected: {port} ({where}{owner})',
                    detected_by=self.name_id,
                )
            self._pending = candidates - confirmed
        except Exception as e:
            self.log.error(f'Port scan error: {e}')

    @classmethod
    def listeners(cls, ss_output, program_path=None, cmdline=None):
        """Parse `ss -tlnp`: port -> {'exposed': bound beyond loopback, 'owners': program names, 'odd_owner': an owner a
        loopback listener should not have}. `program_path`/`cmdline` look up a pid (tests pass fakes)."""
        program_path = program_path or (lambda pid: ProcessMonitorAgent.program_path(pid, ''))
        cmdline = cmdline or _cmdline_of
        out = {}
        for line in ss_output.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 4:
                continue
            addr, sep, port = parts[3].rpartition(':')
            if not sep or not port.isdigit():
                continue
            info = out.setdefault(int(port), {'exposed': False, 'owners': set(), 'odd_owner': False})
            if not _is_loopback_bind(addr):
                info['exposed'] = True
            for name, pid in re.findall(r'\("([^"]+)",pid=(\d+)', line):
                info['owners'].add(name)
                if (name.lower() in cls.UNEXPECTED_OWNERS
                        or program_path(pid).startswith(ProcessMonitorAgent.TEMP_DIRS)
                        or ProcessMonitorAgent.classify(cmdline(pid) or name)):
                    info['odd_owner'] = True
        return out


# ── 8. Local AI Analyzer Agent (Ollama; high / medium / low severity tiers) ───
def _prompt_high(t):
    return ('You are a cybersecurity analyst. In 2 sentences, assess this threat and recommend action: '
            f"Type={t.get('type')} Severity={t.get('severity')} "
            f"Source={t.get('url')} Description={t.get('description','')[:200]}")


def _prompt_medium(t):
    return ('You are a cybersecurity analyst specializing in threat intelligence. '
            'For the following medium-severity threat, extract any IOCs (IPs, domains, hashes) '
            'and provide one concrete remediation step: '
            f"Type={t.get('type')} Source={t.get('url')} "
            f"Description={t.get('description','')[:200]}")


def _prompt_low(t):
    return ('You are a cybersecurity analyst. In 1-2 sentences, triage this low-severity '
            'threat and note whether it warrants escalation: '
            f"Type={t.get('type')} Source={t.get('url')} "
            f"Description={t.get('description','')[:200]}")


class LocalAnalyzerAgent(BaseAgent):
    """Asks a local Ollama model for a short assessment of threats that have no AI analysis yet. One agent serves three
    severity tiers, each with its own model and host (the three it replaces were separate threads with the same loop).
    A threat is only marked done once its verdict is saved, so failures are retried the next time its tier is due."""
    name_id = 'LocalAnalyzerAgent'
    role = 'ai_analyzer'
    description = (f'AI threat analysis via Ollama: {OLLAMA_MODEL} (high severity), {HERMES_MODEL} (medium), '
                   f'{WATCHTOWER_MODEL} (low)')
    interval = 300  # 5 min; a tier with a longer `every` is skipped on the cycles in between

    # timeout: the high tier answers from a GPU-backed endpoint in well under 60 s; local CPU-only models measured at
    # ~48 s for an IOC-extraction answer, so 60 s left no margin and most calls timed out and restarted every cycle.
    # every: the low tier runs every 15 min (was 5) to ease the heat on the slower machine that hosts it.
    TIERS = (
        {'label': 'Ollama', 'query': 'severity=high%2B', 'host': OLLAMA, 'model': OLLAMA_MODEL,
         'timeout': 60, 'every': 300, 'prompt': _prompt_high},
        {'label': 'Hermes', 'query': 'severity=medium', 'host': HERMES, 'model': HERMES_MODEL,
         'timeout': 150, 'every': 300, 'prompt': _prompt_medium},
        {'label': 'Watchtower', 'query': 'severity=low', 'host': WATCHTOWER, 'model': WATCHTOWER_MODEL,
         'timeout': 150, 'every': 900, 'prompt': _prompt_low},
    )

    def setup(self):
        self._analyzed = _BoundedSet(10000)
        self._next_due = {}

    def scan(self):
        """Run each tier that is due: take up to 3 unanalyzed threats of its severity, ask its model and save the answer."""
        now = time.monotonic()
        for tier in self.TIERS:
            if now < self._next_due.get(tier['label'], 0):
                continue
            self._next_due[tier['label']] = now + tier['every'] - 5   # 5 s slack so a tier is not skipped by timer jitter
            self._scan_tier(tier)

    def _scan_tier(self, tier):
        label = tier['label']
        try:
            r = _api_get(f"{API}/threats/?unanalyzed=true&{tier['query']}&limit=5", timeout=5)
            threats = r.json() if r.status_code == 200 else []
            batch = [t for t in threats if t.get('id') not in self._analyzed][:3]
            for threat in batch:
                try:
                    resp = SESSION.post(f"{tier['host']}/api/generate",
                                         json={'model': tier['model'], 'prompt': tier['prompt'](threat), 'stream': False,
                                               'keep_alive': model_config.ollama_keep_alive()},
                                         timeout=tier['timeout'])
                except requests.exceptions.RequestException as e:
                    # Don't mark as analyzed on timeout/connection error — retry next cycle
                    self.log.warning(f'{label} request failed for threat {threat["id"]}: {e}')
                    continue
                if resp.status_code == 200:
                    analysis = resp.json().get('response', '')
                    self.log.info(f'{label} analysis for threat {threat["id"]}: {analysis[:100]}')
                    put = SESSION.put(f'{API}/threats/{threat["id"]}',
                                       json={'ai_analyzed': True, 'ai_verdict': {'analysis': analysis, 'model': tier['model']}},
                                       headers=_headers(), timeout=5)
                    # Only mark analyzed once the verdict is confirmed saved: setting it before the HTTP call let a
                    # timeout orphan the threat for good (ai_analyzed stayed False).
                    if put.status_code == 200:
                        self._analyzed.add(threat['id'])
                else:
                    self.log.warning(f'{label} returned {resp.status_code} for threat {threat["id"]}')
        except Exception as e:
            self.log.warning(f'LocalAnalyzerAgent {label} tier error: {e}')


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
            related = r.json()
        except (requests.exceptions.RequestException, ValueError) as e:
            flow.note(local_evidence=f'could not be checked ({type(e).__name__})')
            return
        direct = live_checks.check(threat)                 # read-only look at this machine now; never raises
        evidence = local_evidence.assess(threat, related, consensus, direct=direct)
        local_evidence.apply(consensus, evidence)
        flow.note(local_evidence=evidence['status'], direct_check=direct['result'])

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


# ── 10. Email quarantine ──────────────────────────────────────────────────
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


# ── 12. Host Health Agent (services, disk space, critical files) ───────────────
class HostHealthAgent(BaseAgent):
    """The host's own state in one pass: critical systemd services, disk space and critical-file integrity. It
    replaces three agents that each woke on their own timer for a few milliseconds of work. Each check keeps its own
    cadence (services every cycle, disk and files every 5 minutes)."""
    name_id = 'HostHealthAgent'
    role = 'host_health'
    description = 'Monitors critical services, disk space and critical system files'
    interval = 60
    SLOW_EVERY = 300   # seconds between the disk and file checks

    WATCHED = WATCHED_SERVICES

    WATCH_PATHS = ['/etc/passwd', '/etc/group', '/etc/shadow', '/etc/sudoers', '/etc/ssh/sshd_config',
                   os.path.join(ssai_config.BACKEND_DIR, 'app.py')]
    HASH_MAX_BYTES = 32 * 1024 * 1024
    # Logs that can explain an account-file change (change_evidence.py); only their last LOG_TAIL_BYTES are read.
    EVIDENCE_LOGS = ('/var/log/auth.log', '/var/log/dpkg.log', '/var/log/apt/history.log')
    LOG_TAIL_BYTES = 512 * 1024

    # Baseline survives restarts, so changes made while the agent was down (e.g. a code
    # deploy to app.py, or an edit during an ssai-agents restart) are still reported once.
    BASELINE_PATH = os.path.join(ssai_config.BACKEND_DIR, 'instance', 'file_integrity_baseline.json')

    # Persistence locations (2026-11-18, beta record Part C3): places an intruder writes to come back after a reboot or
    # log-in. Each entry is (file or folder, severity). A folder is watched for files added, changed or removed; a file
    # that does not exist yet (ld.so.preload, a person's authorized_keys) is reported when it appears. A location seen
    # for the first time is recorded silently, so a fresh install or a new home folder does not raise a flood.
    PERSIST_FILES = (('/etc/ld.so.preload', 'high'), ('/etc/crontab', 'medium'), ('/etc/environment', 'medium'),
                     ('/etc/profile', 'medium'), ('/etc/bash.bashrc', 'medium'), ('/etc/rc.local', 'medium'))
    PERSIST_DIRS = (('/etc/sudoers.d', 'high'), ('/etc/pam.d', 'high'), ('/var/spool/cron/crontabs', 'medium'),
                    ('/etc/cron.d', 'medium'), ('/etc/cron.hourly', 'medium'), ('/etc/cron.daily', 'medium'),
                    ('/etc/cron.weekly', 'medium'), ('/etc/cron.monthly', 'medium'), ('/etc/systemd/system', 'medium'),
                    ('/etc/profile.d', 'medium'), ('/etc/update-motd.d', 'medium'))
    # Inside each person's home folder (and /root). A person editing their own shell start-up file is ordinary, so
    # those are low; a new login key is high.
    HOME_FILES = (('.ssh/authorized_keys', 'high'), ('.ssh/authorized_keys2', 'high'), ('.bashrc', 'low'),
                  ('.profile', 'low'), ('.bash_profile', 'low'), ('.bash_login', 'low'), ('.zshrc', 'low'))
    HOME_DIRS = (('.config/autostart', 'medium'), ('.config/systemd/user', 'medium'))
    # A change here is never put down to a package install: packages do not ship these.
    NEVER_PACKAGE = ('/etc/ld.so.preload', '/var/spool/cron/crontabs', '/.ssh/')
    PERSIST_MAX_FILES = 3000
    PERSIST_DEPTH = 2                      # /etc/systemd/system/<x>.wants/<unit>

    def _load_baseline(self):
        """Read the saved file fingerprints from disk. Returns (fingerprints by path, set of paths known to be
        missing). A missing or unreadable file gives empty results, which just means the files are baselined again."""
        try:
            with open(self.BASELINE_PATH) as f:
                raw = json.load(f)
            sigs = {p: tuple(v) for p, v in raw.get('sigs', {}).items()
                    if isinstance(v, list) and len(v) == 6}
            # Content hashes and account snapshots were added 2026-11-15; a baseline from before has neither, and the
            # first check then falls back to comparing size, time, owner and mode, exactly as before.
            self._hashes = {p: h for p, h in (raw.get('hashes') or {}).items() if isinstance(h, str)}
            self._snaps = {p: s for p, s in (raw.get('snaps') or {}).items() if isinstance(s, dict)}
            persist = raw.get('persist') or {}
            self._p_state = {p: (tuple(v[0]), v[1]) for p, v in (persist.get('files') or {}).items()
                             if isinstance(v, list) and len(v) == 2 and isinstance(v[0], list) and len(v[0]) == 6}
            self._p_locs = {loc for loc in persist.get('locations') or () if isinstance(loc, str)}
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
                           'gone': sorted(self._gone),
                           'hashes': {p: h for p, h in self._hashes.items() if h},
                           'snaps': self._snaps,
                           'persist': {'files': {p: [list(sig), h] for p, (sig, h) in self._p_state.items()},
                                       'locations': sorted(self._p_locs)}}, f)
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
        self._states = {}
        self._told_no_systemd = False
        self._slow_due = 0.0
        self._hashes, self._snaps = {}, {}
        self._p_state, self._p_locs = {}, set()
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
                continue
            self._remember_content(p)
        self._save_baseline()

    def _content_hash(self, p):
        """SHA-256 of the file's contents, or None when it cannot be read (no permission, too big, gone)."""
        try:
            if os.path.getsize(p) > self.HASH_MAX_BYTES:
                return None
            h = hashlib.sha256()
            with open(p, 'rb') as f:
                for block in iter(lambda: f.read(1 << 16), b''):
                    h.update(block)
            return h.hexdigest()
        except OSError:
            return None

    def _remember_content(self, p, digest=None):
        """Store the file's hash, and for an account file a snapshot (never password hashes) to compare the next change with."""
        self._hashes[p] = digest if digest is not None else self._content_hash(p)
        if p in change_evidence.ACCOUNT_FILES:
            text = self._read_text(p)
            snap = change_evidence.snapshot(p, text) if text is not None else None
            if snap is not None:
                self._snaps[p] = snap
            else:
                self._snaps.pop(p, None)

    @staticmethod
    def _read_text(p):
        try:
            with open(p, 'r', errors='replace') as f:
                return f.read()
        except OSError:
            return None

    def _evidence_lines(self):
        """The recent lines of the logs that can explain an account change. A missing or unreadable log is skipped."""
        lines = []
        for log_path in self.EVIDENCE_LOGS:
            try:
                with open(log_path, 'rb') as f:
                    f.seek(0, os.SEEK_END)
                    f.seek(max(0, f.tell() - self.LOG_TAIL_BYTES))
                    lines += f.read().decode('utf-8', 'replace').splitlines()
            except OSError:
                continue
        return lines

    def _content_change(self, p, st, old, sig, digest):
        """A watched file's contents changed. Returns (severity, description) to report, or None when change_evidence proves
        the change harmless (a package install adding a system account, for example)."""
        if old[0] == sig[0] and old[1] == sig[1]:
            return 'high', (f'Contents of {p} changed although its size and modification time were restored '
                            '(a typical sign of tampering)')
        if p in change_evidence.ACCOUNT_FILES:
            when = datetime.fromtimestamp(st.st_mtime).astimezone()          # local time, like syslog's own stamps
            verdict = change_evidence.assess(p, None, self._read_text(p) or '', self._evidence_lines(), when,
                                             passwd_text=self._read_text('/etc/passwd'),
                                             group_text=self._read_text('/etc/group'),
                                             old_snapshot=self._snaps.get(p))
            if verdict['harmless']:
                self.log.info(f'FileIntegrity: {p} changed, not reported: {verdict["reason"]} ({", ".join(verdict["changes"])})')
                return None
            detail = f'{verdict["reason"]}' + (f'; changes: {", ".join(verdict["changes"][:6])}' if verdict['changes'] else '')
            return 'medium', f'Contents of {p} changed: {detail}'
        return 'medium', f'Contents of {p} changed'

    def scan(self):
        """Check services every cycle; check disk space and critical files every SLOW_EVERY seconds. A failure in one
        check is logged and does not stop the others."""
        checks = [('service', self._check_services)]
        now = time.monotonic()
        if now >= self._slow_due:
            self._slow_due = now + self.SLOW_EVERY - 5
            checks += [('disk', self._check_disk), ('file-integrity', self._check_files),
                       ('persistence', self._check_persistence)]
        for label, check in checks:
            try:
                check()
            except Exception as e:
                self.log.error(f'{label} check error: {e}')

    def _check_files(self):
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
            if old is not None:
                if self._compare(p, old, sig, after_downtime):
                    dirty = True
                continue
            dirty = True                       # first sighting of this path, or it came back after being deleted
            if p in self._gone:
                self._gone.discard(p)
                self._submit(
                    url=p,
                    threat_type='file-modification',
                    severity='medium',
                    description=f'Critical file recreated after deletion: {p}',
                    detected_by=self.name_id,
                )
            self._remember_content(p)
        if dirty:
            self._save_baseline()

    def _compare(self, p, old, sig, after_downtime=''):
        """Compare one watched file with its baseline and report what matters. Returns True when the baseline changed.

          * mode or owner changed           -> always reported (high)
          * contents changed (SHA-256)      -> reported, high when size and time were put back; an account file is skipped
                                               only when change_evidence proves the change harmless
          * only the time or inode changed  -> silent (`touch`, or a rewrite with identical contents)
          * no stored hash (a baseline from before hashes, or an unreadable file) -> any change of size, time, inode,
                                               mode or owner is reported, as before hashes existed."""
        st = None
        try:
            st = os.stat(p)
        except OSError:
            pass
        old_hash = self._hashes.get(p)
        new_hash = self._content_hash(p)
        fields = self._changed_fields(old, sig)
        owner_or_mode = [f for f in fields if f in ('mode', 'owner', 'group')]
        report = None
        if owner_or_mode:
            what = ', '.join(owner_or_mode) + (' and contents' if old_hash and new_hash and old_hash != new_hash else '')
            report = ('high', f'Critical file {p}: {what} changed{after_downtime}')
        elif old_hash and new_hash:
            if new_hash != old_hash and st is not None:
                report = self._content_change(p, st, old, sig, new_hash)
                if report is not None and after_downtime:
                    report = (report[0], report[1] + after_downtime)
        elif sig != old:
            report = ('medium', f'Critical file modified{after_downtime}: {p} ({", ".join(fields)} changed)')
        if report is not None:
            self._submit(url=p, threat_type='file-modification', severity=report[0], description=report[1],
                         detected_by=self.name_id)
        changed = sig != old or new_hash != old_hash
        if changed:
            self._remember_content(p, new_hash)
        return changed

    # ── persistence locations ──

    @staticmethod
    def _homes():
        """/root and the home folder of each person who can log in (uid 1000 or more, a real shell)."""
        homes = ['/root']
        try:
            with open('/etc/passwd', errors='replace') as f:
                for line in f:
                    parts = line.rstrip('\n').split(':')
                    if len(parts) < 7 or not parts[2].isdigit() or int(parts[2]) <= change_evidence.SYSTEM_ID_MAX:
                        continue
                    if parts[6] in change_evidence.NOLOGIN_SHELLS or not parts[5].startswith('/'):
                        continue
                    if parts[5] not in homes:
                        homes.append(parts[5])
        except OSError:
            pass
        return homes

    def _persist_locations(self):
        """[(location, severity, is_folder)] for this machine right now."""
        locs = [(p, sev, False) for p, sev in self.PERSIST_FILES] + [(p, sev, True) for p, sev in self.PERSIST_DIRS]
        for home in self._homes():
            locs += [(os.path.join(home, rel), sev, False) for rel, sev in self.HOME_FILES]
            locs += [(os.path.join(home, rel), sev, True) for rel, sev in self.HOME_DIRS]
        return locs

    def _files_under(self, folder, depth=None):
        """Regular files and links under `folder`, at most PERSIST_DEPTH levels down. A folder that is missing or cannot
        be read gives nothing."""
        depth = self.PERSIST_DEPTH if depth is None else depth
        out = []
        try:
            entries = sorted(os.scandir(folder), key=lambda e: e.name)
        except OSError:
            return out
        for e in entries:
            try:
                if e.is_dir(follow_symlinks=False):
                    if depth > 1:
                        out += self._files_under(e.path, depth - 1)
                elif e.is_file() or e.is_symlink():
                    out.append(e.path)
            except OSError:
                continue
        return out

    def _persist_sig(self, p):
        """(signature, content hash) of one file, or None when it is gone or cannot be read. A link is described by
        itself (lstat) plus where it points, so pointing an enabled unit somewhere else counts as a change."""
        try:
            st = os.lstat(p)
        except OSError:
            return None
        if os.path.islink(p):
            try:
                return self._signature(st), 'link:' + os.readlink(p)
            except OSError:
                return None
        return self._signature(st), self._content_hash(p)

    def _package_owns(self, p):
        """True when the package manager owns `p` (or, for a link, the file it points to)."""
        target = os.path.realpath(p) if os.path.islink(p) else p
        if shutil.which('dpkg-query') is None:
            return False
        try:
            r = subprocess.run(['dpkg-query', '-S', target], capture_output=True, text=True, timeout=5)
            return r.returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    @staticmethod
    def _ctime(p):
        """When the file was last written or put in place. Not the modification time: dpkg keeps the time from the
        package archive, so a file installed today can carry a date months old."""
        try:
            return os.lstat(p).st_ctime
        except OSError:
            return None

    def _package_explains(self, p, changed_at):
        """A package install or upgrade ran within change_evidence.WINDOW of the change (`changed_at`, the file's ctime),
        and the file is the package's own. Never for NEVER_PACKAGE locations."""
        if any(mark in p for mark in self.NEVER_PACKAGE):
            return False
        when = datetime.fromtimestamp(changed_at).astimezone()
        try:
            ran = change_evidence.evidence(self._evidence_lines(), when, {})['package']
        except Exception:
            return False
        return bool(ran) and self._package_owns(p)

    def _check_persistence(self):
        """Report files added, changed or removed in the persistence locations. Only the location's own severity is
        used, raised to high for a mode or owner change of a medium one."""
        locations = self._persist_locations()
        before = dict(self._p_state)
        seen_files = set()
        reports = []
        new_locs = []
        capped = False
        for loc, sev, is_folder in locations:
            files = self._files_under(loc) if is_folder else ([loc] if os.path.lexists(loc) else [])
            first_time = loc not in self._p_locs
            if first_time:
                new_locs.append(loc)
            for p in files:
                if len(seen_files) >= self.PERSIST_MAX_FILES:
                    capped = True
                    break
                seen_files.add(p)
                now_sig = self._persist_sig(p)
                if now_sig is None:
                    continue                                # unreadable just now: keep what was known
                old = self._p_state.get(p)
                self._p_state[p] = now_sig
                if first_time:
                    continue
                if old is None:
                    reports.append((p, sev, f'New file in a start-up location ({loc}): {p}', self._ctime(p)))
                    continue
                fields = self._changed_fields(old[0], now_sig[0])
                owner_or_mode = [f for f in fields if f in ('mode', 'owner', 'group')]
                if owner_or_mode:
                    reports.append((p, 'high' if sev == 'medium' else sev,
                                    f'Start-up file {p}: {", ".join(owner_or_mode)} changed', None))
                elif old[1] and now_sig[1]:
                    if old[1] != now_sig[1]:
                        reports.append((p, sev, f'Start-up file changed: {p}', self._ctime(p)))
                elif 'mtime' in fields or 'size' in fields:          # no hash to compare (too big or unreadable)
                    reports.append((p, sev, f'Start-up file modified: {p} ({", ".join(fields)} changed)',
                                    self._ctime(p)))
        severity_of = {loc: sev for loc, sev, _ in locations}
        for p in [] if capped else [p for p in self._p_state if p not in seen_files]:
            matches = [loc for loc in severity_of if p == loc or p.startswith(loc.rstrip('/') + '/')]
            loc = max(matches, key=len) if matches else None
            if loc is None or loc in new_locs:
                continue                                    # its home folder went away, or not watched any more
            del self._p_state[p]
            sev = severity_of[loc]
            reports.append((p, 'medium' if sev == 'high' else sev, f'File removed from a start-up location ({loc}): {p}',
                            None))
        self._p_locs |= set(new_locs)
        for p, sev, text, mtime in reports:
            if mtime is not None and self._package_explains(p, mtime):
                self.log.info(f'FileIntegrity: {p} changed during a package install and belongs to a package; not reported')
                continue
            self._submit(url=p, threat_type='persistence-change', severity=sev, description=text,
                         detected_by=self.name_id)
        if reports or new_locs or self._p_state != before:
            self._save_baseline()

    def _check_services(self):
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

    def _check_disk(self):
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
    ProcessMonitorAgent,
    SocketWatchAgent,
    HostHealthAgent,
    LocalAnalyzerAgent,
    SwarmConsensusAgent,
    ConsensusVerifierAgent,
    RemediationSweepAgent,
    IntelFeedAgent,
    EmailQuarantineAgent,
    RedTeamAgent,
]

def _note_disabled(AgentClass, log):
    """List a switched-off agent in the hub's menu as an option. Hub-only agents on a node are not options there
    (a node runs host sensors only), so they are not registered and do not clutter the hub with rows per machine."""
    name = AgentClass.name_id
    if ROLE == 'node' and name in agent_catalog.HUB_ONLY:
        return False
    unmet = agent_catalog.unmet_requirement(name)
    if unmet and name not in agent_catalog.load_overrides():
        # Nothing here for it to watch (no Pi-hole, no nmap): not an option either, and it starts by itself when that changes.
        log.info(f'{name} not started: {unmet}')
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
