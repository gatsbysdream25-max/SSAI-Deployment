"""Recall: reuse what the swarm has already concluded instead of re-analysing (and re-documenting) it.

Every AI verdict costs provider quota and time, and the same indicator shows up again and again: the same URL
in two feeds, the same IP in the firewall log and the DNS log, a re-sighting after a restart. `RecallCache`
remembers the consensus for an indicator so the analyzers can copy it (marked `recalled_from`) instead of asking
the panel again.

What counts as "the same indicator":
  * a public URL / IP / domain is judged on its own, so its key is just the canonical indicator;
  * an internal address, host:port endpoint or anything else is only meaningful with its context, so its key
    also carries the threat category ("suspicious-port|10.0.0.5:8080");
  * a masked indicator ("192.168.xxx.xxx") identifies nothing, so it has no key and is never recalled.

A verdict is remembered only for as long as it is likely to stay true: a malicious verdict for a week, a
suspicious or benign one for hours (sites get compromised, hosts get cleaned up). Nothing here calls a network
or the database, so it is cheap to test and safe to call from any agent thread.
"""
import ipaddress
import json
import os
import re
import copy
import threading
import time
from collections import OrderedDict
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit

VERDICTS = ('malicious', 'suspicious', 'benign')
_LOCAL_SUFFIXES = ('.local', '.lan', '.home', '.internal', '.localdomain', '.intranet', '.corp', '.home.arpa')
_MASKED = re.compile(r'(\d\.x{2,}|x{2,}\.\d|x{2,}\.x{2,})', re.I)
_DOMAIN = re.compile(r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$')
_HOSTPORT = re.compile(r'^(?P<host>[^\s:/]+):(?P<port>\d{1,5})$')
_DEFAULT_PORTS = {'http': 80, 'https': 443, 'ftp': 21}
MAX_INDICATOR_LEN = 2048


def _env_seconds(name, default):
    try:
        return max(0, int(os.environ.get(name, default)))
    except ValueError:
        return default


def ttl_seconds(verdict):
    """How long a verdict stays reusable. Env-tunable: RECALL_TTL_MALICIOUS / _SUSPICIOUS / _BENIGN (seconds)."""
    v = (verdict or '').lower()
    if v == 'malicious':
        return _env_seconds('RECALL_TTL_MALICIOUS', 7 * 86400)
    if v == 'suspicious':
        return _env_seconds('RECALL_TTL_SUSPICIOUS', 6 * 3600)
    if v == 'benign':
        return _env_seconds('RECALL_TTL_BENIGN', 12 * 3600)
    return 0


def _is_public_host(host):
    """True for a public IP or a dotted domain that is not obviously local."""
    try:
        return ipaddress.ip_address(host).is_global
    except ValueError:
        pass
    h = host.lower()
    return bool(_DOMAIN.match(h)) and not h.endswith(_LOCAL_SUFFIXES)


def normalize_indicator(raw):
    """Canonical form of an indicator, or None if it is empty, oversized or masked.

    Returns {'kind': 'url'|'ip'|'domain'|'endpoint'|'other', 'key': str, 'public': bool}."""
    if not isinstance(raw, str):
        return None
    s = raw.strip()
    if not s or len(s) > MAX_INDICATOR_LEN or _MASKED.search(s):
        return None

    if '://' in s:
        try:
            parts = urlsplit(s)
            host = (parts.hostname or '').lower()
            port = parts.port
        except ValueError:
            return None
        if not host:
            return None
        scheme = parts.scheme.lower()
        netloc = f'[{host}]' if ':' in host else host          # IPv6 literal
        if port and port != _DEFAULT_PORTS.get(scheme):
            netloc += f':{port}'
        path = parts.path or '/'                                # credentials and #fragment are dropped on purpose
        key = urlunsplit((scheme, netloc, path, parts.query, ''))
        public = scheme in ('http', 'https', 'ftp') and _is_public_host(host)
        return {'kind': 'url', 'key': key, 'public': public}

    try:
        ip = ipaddress.ip_address(s)
        return {'kind': 'ip', 'key': str(ip), 'public': ip.is_global}
    except ValueError:
        pass

    m = _HOSTPORT.match(s)
    if m and 0 < int(m.group('port')) < 65536:
        host = m.group('host').lower()
        try:
            host = str(ipaddress.ip_address(host))
        except ValueError:
            pass
        return {'kind': 'endpoint', 'key': f"{host}:{int(m.group('port'))}", 'public': False}

    if _DOMAIN.match(s.lower()):
        return {'kind': 'domain', 'key': s.lower(), 'public': _is_public_host(s)}
    return {'kind': 'other', 'key': s, 'public': False}


def recall_key(indicator, category=None):
    """The cache key for (indicator, category), or None when the indicator cannot be matched safely."""
    n = normalize_indicator(indicator)
    if n is None:
        return None
    if n['public'] and n['kind'] in ('url', 'ip', 'domain'):
        return n['key']
    return f"{(category or '').strip().lower()}|{n['key']}"


def is_scoped(indicator):
    """True when the indicator's verdict only holds within its threat category (see the module docstring)."""
    n = normalize_indicator(indicator)
    return n is not None and not (n['public'] and n['kind'] in ('url', 'ip', 'domain'))


def candidate_urls(indicator):
    """Spellings of one indicator as it may be stored in the database (for an exact-match SQL lookup)."""
    n = normalize_indicator(indicator)
    if n is None:
        return []
    out = [indicator.strip(), n['key']]
    if n['kind'] == 'url':
        if n['key'].endswith('/') and n['key'].count('/') == 3:
            out.append(n['key'][:-1])                           # https://a.com/ <-> https://a.com
    return list(dict.fromkeys(out))


def reusable_consensus(consensus):
    """True when a stored consensus is a real, complete answer worth copying."""
    if not isinstance(consensus, dict):
        return False
    if (consensus.get('consensus_verdict') or '').lower() not in VERDICTS:
        return False
    if consensus.get('error'):
        return False
    if 'recalled_from' in consensus:      # a copy is not evidence: reusing copies would keep a verdict alive forever
        return False
    quorum = consensus.get('quorum')
    if isinstance(quorum, dict) and quorum.get('complete') is False:
        return False                      # part of the panel did not answer: one model's thin verdict must not be replayed for days
    if consensus.get('panel_mode') == 'fallback':
        return False
    verification = consensus.get('verification')
    if isinstance(verification, dict) and verification.get('status') == 'disputed':
        return False                      # another maker's model disagreed: ask the panel again rather than replay it
    try:
        return int(consensus.get('ai_count') or 0) >= 1
    except (TypeError, ValueError):
        return False


def _epoch(ts):
    """Seconds since the epoch for an ISO timestamp (naive is read as UTC), or None."""
    if isinstance(ts, (int, float)):
        return float(ts)
    if not isinstance(ts, str) or not ts:
        return None
    try:
        d = datetime.fromisoformat(ts.replace('Z', '+00:00'))
    except ValueError:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d.timestamp()


def consensus_of(threat):
    """The consensus dict inside a threat's ai_verdict (a JSON string or dict), or None."""
    if not isinstance(threat, dict):
        return None
    v = threat.get('ai_verdict')
    if isinstance(v, str):
        try:
            v = json.loads(v)
        except ValueError:
            return None
    c = v.get('consensus') if isinstance(v, dict) else None
    return c if reusable_consensus(c) else None


def mark_recalled(consensus, entry, now=None):
    """A copy of a remembered consensus, labelled so nobody mistakes it for a fresh panel run."""
    out = copy.deepcopy(consensus)           # a deep copy: labels added later (local proof, flow) must not leak back into the cache
    out['recalled_from'] = entry.get('threat_id')
    out['recalled_age_s'] = max(0, int((now if now is not None else time.time()) - entry['at']))
    return out


class RecallCache:
    """Bounded, thread-safe, least-recently-used memory of consensus verdicts, keyed by `recall_key`."""

    def __init__(self, max_entries=5000, clock=time.time):
        self._max = max(1, int(max_entries))
        self._clock = clock
        self._lock = threading.Lock()
        self._data = OrderedDict()
        self.hits = self.misses = self.expired = 0

    def __len__(self):
        with self._lock:
            return len(self._data)

    def put(self, indicator, category, consensus, threat_id=None, at=None):
        """Remember a consensus. Returns True if stored (skips unmatchable indicators and unusable answers)."""
        key = recall_key(indicator, category)
        if key is None or not reusable_consensus(consensus):
            return False
        at = self._clock() if at is None else at
        with self._lock:
            old = self._data.get(key)
            if old is not None and old['at'] > at:              # never replace a newer answer with an older one
                return True
            self._data[key] = {'consensus': consensus, 'threat_id': threat_id, 'at': at}
            self._data.move_to_end(key)
            while len(self._data) > self._max:
                self._data.popitem(last=False)
        return True

    def get(self, indicator, category=None, exclude_id=None):
        """A remembered consensus (labelled `recalled_from`) that is still fresh, else None."""
        key = recall_key(indicator, category)
        if key is None:
            return None
        now = self._clock()
        with self._lock:
            e = self._data.get(key)
            if e is None or (exclude_id is not None and e['threat_id'] == exclude_id):
                self.misses += 1
                return None
            if now - e['at'] > ttl_seconds(e['consensus'].get('consensus_verdict')):
                del self._data[key]
                self.expired += 1
                self.misses += 1
                return None
            self._data.move_to_end(key)
            self.hits += 1
            entry = dict(e)
        return mark_recalled(entry['consensus'], entry, now)

    def seed(self, threats):
        """Load prior verdicts from threat dicts (as the API returns them). Returns how many were remembered."""
        n = 0
        for t in threats or []:
            if not isinstance(t, dict):
                continue
            c = consensus_of(t)
            at = _epoch(t.get('timestamp'))
            if c is not None and at is not None and self.put(t.get('url'), t.get('type'), c, t.get('id'), at):
                n += 1
        return n

    def stats(self):
        with self._lock:
            total = self.hits + self.misses
            return {'entries': len(self._data), 'hits': self.hits, 'misses': self.misses,
                    'expired': self.expired, 'hit_rate': round(self.hits / total, 3) if total else 0.0}
