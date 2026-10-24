"""Local indicator store fed by free threat-intelligence feeds, matched against what this network actually does.

The feeds list thousands of indicators that have nothing to do with this network. Reporting them as threats would
bury the dashboard (and the public ledger), so they are kept here instead, and a threat is raised only when a
device on this network contacts a listed indicator: a connection to a known botnet C2, or a DNS lookup of a
malware-delivery domain. Only abuse.ch feeds are used (ThreatFox, Feodo Tracker and the URLhaus host file: CC0,
no key, commercial use allowed), which keeps the product clear of non-commercial feed licences.

The store is thread-safe, bounded, expires entries that stop being listed, and survives restarts via an
atomically-written cache file, so a feed outage never leaves the matchers blind.
"""
import ipaddress
import json
import os
import re
import tempfile
import threading
import time
from collections import OrderedDict

# abuse.ch retired the keyless ThreatFox export and the URLhaus downloads (HTTP 410, 2026-10). ThreatFox now answers only
# with a free Auth-Key (https://auth.abuse.ch), sent in the Auth-Key header. Feodo Tracker still needs no key.
THREATFOX_URL = 'https://threatfox-api.abuse.ch/api/v1/'
FEODO_URL = 'https://feodotracker.abuse.ch/downloads/ipblocklist.json'
# URLhaus's host file (domains that serve malware themselves, not shared file hosts) is gone. Its keyed API lists every host,
# including Discord and Dropbox, so it must not be wired in without a filter for shared hosts first.

MIN_CONFIDENCE = 75
DEFAULT_TTL = 14 * 86400
MAX_ENTRIES = 200_000
_DOMAIN = re.compile(r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$')
# Popular domains that must never match even if a feed lists them by mistake (extendable via INTEL_ALLOWLIST).
_BUILTIN_ALLOW = frozenset({
    'google.com', 'googleapis.com', 'gstatic.com', 'microsoft.com', 'windows.com', 'live.com', 'office.com',
    'apple.com', 'icloud.com', 'amazon.com', 'amazonaws.com', 'cloudflare.com', 'github.com', 'githubusercontent.com',
    'mozilla.org', 'ubuntu.com', 'debian.org', 'pi-hole.net', 'abuse.ch', 'youtube.com', 'facebook.com',
    # Microsoft sign-in (Entra ID). Blocking these locks every Microsoft 365 user out, including the approvers who
    # decide SSAI's remediation proposals from Teams (red-team finding 2026-10-09). Identity endpoints only: content
    # hosts such as sharepoint.com / windows.net stay matchable because malware is hosted there.
    'microsoftonline.com', 'msauth.net', 'msftauth.net', 'office365.com',
})


def _allowlist():
    extra = {d.strip().lower() for d in os.environ.get('INTEL_ALLOWLIST', '').split(',') if d.strip()}
    return _BUILTIN_ALLOW | extra


def public_ip(value):
    """The canonical text of a public IP, or None (private, loopback, multicast, malformed...)."""
    try:
        ip = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None
    return str(ip) if ip.is_global else None


def clean_domain(value):
    """A lower-case hostname with at least two labels, or None."""
    if not isinstance(value, str):
        return None
    d = value.strip().lower().rstrip('.')
    if not d or len(d) > 253 or not _DOMAIN.match(d):
        return None
    return d


def _ancestors(domain):
    parts = domain.split('.')
    return ['.'.join(parts[i:]) for i in range(len(parts) - 1)]      # never the bare TLD


def parse_threatfox(data, min_confidence=MIN_CONFIDENCE):
    """ThreatFox `export/json/recent` -> [(kind, value, entry)]. Keeps public ip:port endpoints and domains that
    a device could actually contact; hashes and URLs cannot be matched against connections or DNS."""
    out = []
    if not isinstance(data, dict):
        return out
    for rows in data.values():
        for r in rows if isinstance(rows, list) else []:
            if not isinstance(r, dict):
                continue
            try:
                conf = int(r.get('confidence_level') or 0)
            except (TypeError, ValueError):
                continue
            if conf < min_confidence:
                continue
            kind, val = r.get('ioc_type'), r.get('ioc_value') or r.get('ioc')     # the keyed API calls the value "ioc"
            entry = {'source': 'threatfox', 'malware': str(r.get('malware_printable') or r.get('malware') or 'unknown')[:60],
                     'threat': str(r.get('threat_type') or 'unknown')[:40], 'confidence': conf}
            if kind == 'ip:port' and isinstance(val, str) and ':' in val:
                host, _, port = val.rpartition(':')
                ip = public_ip(host)
                if ip and port.isdigit() and 0 < int(port) < 65536:
                    out.append(('endpoint', f'{ip}:{int(port)}', entry))
            elif kind == 'domain':
                d = clean_domain(val)
                if d:
                    out.append(('domain', d, entry))
    return out


def parse_feodo(data):
    """Feodo Tracker `ipblocklist.json` -> [(kind, value, entry)]. A listed C2 address is bad on any port."""
    out = []
    for r in data if isinstance(data, list) else []:
        if not isinstance(r, dict):
            continue
        ip = public_ip(r.get('ip_address'))
        if ip:
            out.append(('ip', ip, {'source': 'feodo', 'malware': str(r.get('malware') or 'unknown')[:60],
                                   'threat': 'botnet_cc', 'confidence': 100}))
    return out


def parse_urlhaus_hosts(text):
    """URLhaus `downloads/hostfile/` (hosts-file lines "127.0.0.1<TAB>domain") -> [(kind, value, entry)]."""
    out = []
    for line in text.splitlines() if isinstance(text, str) else []:
        line = line.split('#', 1)[0].split()
        if len(line) < 2:
            continue
        d = clean_domain(line[1])
        if d:
            out.append(('domain', d, {'source': 'urlhaus', 'malware': 'malware download site',
                                      'threat': 'payload_delivery', 'confidence': 100}))
    return out


def severity_for(entry):
    """A device talking to a live command-and-control server is worse than one resolving a delivery domain."""
    return 'high' if (entry or {}).get('threat') == 'botnet_cc' else 'medium'


class IntelStore:
    def __init__(self, ttl=DEFAULT_TTL, max_entries=MAX_ENTRIES, clock=time.time):
        self._ttl, self._max, self._clock = ttl, max(1, int(max_entries)), clock
        self._lock = threading.Lock()
        self._data = OrderedDict()                                   # (kind, value) -> entry, oldest listing first
        self.updated = None                                          # epoch of the last successful feed load

    def __len__(self):
        with self._lock:
            return len(self._data)

    def add_many(self, items):
        """Add or refresh (kind, value, entry) tuples; refreshing keeps first_seen. Returns how many were listed."""
        now = self._clock()
        n = 0
        with self._lock:
            for kind, value, entry in items:
                if kind not in ('ip', 'endpoint', 'domain') or not value:
                    continue
                key = (kind, value)
                old = self._data.get(key)
                e = dict(entry)
                e['first_seen'] = old['first_seen'] if old else now
                e['seen'] = now
                self._data[key] = e
                self._data.move_to_end(key)
                n += 1
            while len(self._data) > self._max:
                self._data.popitem(last=False)
            if n:
                self.updated = now
        return n

    def _live(self, key):
        e = self._data.get(key)
        if e is None:
            return None
        if self._clock() - e['seen'] > self._ttl:
            return None
        return e

    def match_ip(self, ip, port=None):
        """The listing for a remote address (any-port listing first, then the exact ip:port), or None."""
        ip = public_ip(ip)
        if ip is None:
            return None
        endpoint = None
        if port is not None:
            try:
                endpoint = f'{ip}:{int(port)}'
            except (TypeError, ValueError):
                endpoint = None
        with self._lock:
            e = self._live(('ip', ip))
            if e is not None:
                return dict(e, value=ip)
            e = self._live(('endpoint', endpoint)) if endpoint else None
            return dict(e, value=endpoint) if e is not None else None

    def endpoints_for(self, ip):
        """Every listed ip:port endpoint on this address (a ThreatFox listing is per service, not per host)."""
        ip = public_ip(ip)
        if ip is None:
            return []
        prefix = f'{ip}:'
        with self._lock:
            return [dict(e, value=v) for (k, v), e in self._data.items()
                    if k == 'endpoint' and v.startswith(prefix) and self._live((k, v)) is not None]

    def match_domain(self, domain):
        """The listing for a DNS name: an exact match or a subdomain of a listed name; None for allowlisted names."""
        d = clean_domain(domain)
        if d is None:
            return None
        chain = _ancestors(d)
        allow = _allowlist()
        if any(a in allow for a in chain):
            return None
        with self._lock:
            for a in chain:
                e = self._live(('domain', a))
                if e is not None:
                    return dict(e, value=a)
        return None

    def prune(self):
        """Drop entries no feed has listed within the TTL. Returns how many were removed."""
        cutoff = self._clock() - self._ttl
        with self._lock:
            stale = [k for k, e in self._data.items() if e['seen'] < cutoff]
            for k in stale:
                del self._data[k]
        return len(stale)

    def stats(self):
        with self._lock:
            kinds = {}
            for (k, _v) in self._data:
                kinds[k] = kinds.get(k, 0) + 1
            return {'entries': len(self._data), 'by_kind': kinds, 'updated': self.updated}

    def save(self, path):
        """Write the store atomically (owner-only) so a crash never leaves a half-written cache."""
        with self._lock:
            payload = {'version': 1, 'updated': self.updated,
                       'entries': [[k, v, e] for (k, v), e in self._data.items()]}
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path) or '.', prefix='.intel-')
        try:
            with os.fdopen(fd, 'w') as f:
                json.dump(payload, f, separators=(',', ':'))
            os.chmod(tmp, 0o644)          # public feed data; the web app reads it to show listings in Identify
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def load(self, path):
        """Restore a saved store; a missing or corrupt file just means an empty store. Returns entries loaded."""
        try:
            with open(path) as f:
                payload = json.load(f)
            rows = payload['entries']
            updated = payload.get('updated')
        except (OSError, ValueError, KeyError, TypeError):
            return 0
        n = 0
        with self._lock:
            for row in rows if isinstance(rows, list) else []:
                try:
                    kind, value, e = row
                    if kind in ('ip', 'endpoint', 'domain') and isinstance(value, str) and isinstance(e, dict) \
                            and isinstance(e.get('seen'), (int, float)) and isinstance(e.get('first_seen'), (int, float)):
                        self._data[(kind, value)] = e
                        n += 1
                except (TypeError, ValueError):
                    continue
            while len(self._data) > self._max:
                self._data.popitem(last=False)
            if isinstance(updated, (int, float)):
                self.updated = updated
        return n


STORE = IntelStore()                       # shared by the feed agent and the matchers inside the agent-runner process
