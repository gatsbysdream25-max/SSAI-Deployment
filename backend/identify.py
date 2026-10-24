"""Admin IP identification: what an address actually IS.

  * public IP   -> who owns the network (RDAP registry), reverse DNS, whether a threat feed lists it, and what this
                   installation has already seen from it;
  * LAN IP      -> which device it is: MAC and vendor (Pi-hole's device table, the ARP table, the IEEE vendor list),
                   whether the MAC is a randomized "private" one, hostnames, DNS activity, and (on request only) which
                   common ports are open;
  * domain      -> the addresses it resolves to, feed listings, history.

Everything that leaves this host or touches a device is deliberately narrow: registry lookups go to one fixed public
RDAP service and only for public addresses; the port check only ever targets private addresses and only when the
admin asks. Text that comes from outside (DNS names, registry records, device names) is attacker-influenceable, so
it is stripped of control characters and length-limited here, and the dashboard escapes it again on display.
Personal names in registry records (technical/administrative contacts) are never surfaced, only the registrant
organisation and the role-based abuse address.

The module is pure: every network/OS touch is a callable in `Deps`, so tests run with fakes.
"""
import ipaddress
import re
import socket
import subprocess
import threading
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, wait
from types import SimpleNamespace
from urllib.parse import urlsplit

import requests

RDAP_URL = 'https://rdap.org/ip/{ip}'
OUI_PATHS = ('/usr/share/ieee-data/oui.txt', '/var/lib/ieee-data/oui.txt', '/usr/share/misc/oui.txt')
COMMON_PORTS = (21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 515, 554, 631, 1883, 3389, 5000, 5900,
                8000, 8080, 8081, 8443, 9100, 32400)
SECTION_TIMEOUT = 9
_CTRL = re.compile(r'[\x00-\x1f\x7f-\x9f  ]')
_MASKED = re.compile(r'(\d\.x{2,}|x{2,}\.\d|x{2,}\.x{2,})', re.I)
_pool = ThreadPoolExecutor(max_workers=12, thread_name_prefix='identify')
_scan_pool = ThreadPoolExecutor(max_workers=24, thread_name_prefix='portcheck')   # separate: scan jobs run inside _pool


def clean(value, limit=200):
    """Untrusted text -> a short single-line string with no control characters (or None)."""
    if value is None:
        return None
    s = _CTRL.sub(' ', str(value)).strip()
    return s[:limit] if s else None


def scope_of(ip):
    # special first: Python reports some multicast ranges as is_global, which must never reach a registry lookup
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        return 'special'
    return 'public' if ip.is_global else 'lan'


def extract_host(raw):
    """('ip'|'domain', value) for a threat's address field, or None if there is nothing identifiable in it."""
    if not isinstance(raw, str) or not raw.strip() or _MASKED.search(raw):
        return None
    s = raw.strip()
    if '://' in s:
        try:
            host = urlsplit(s).hostname or ''
        except ValueError:
            return None
    else:
        host = re.split(r'[/?#]', s, 1)[0]
        if host.count(':') == 1:
            host = host.split(':')[0]
        host = host.strip('[]')
    host = host.lower().rstrip('.')
    if not host:
        return None
    try:
        return 'ip', str(ipaddress.ip_address(host))
    except ValueError:
        pass
    if re.match(r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$', host) and len(host) <= 253:
        return 'domain', host
    return None


# ── registry (RDAP) ──────────────────────────────────────────────────────────

def _vcard(entity):
    out = {}
    card = entity.get('vcardArray')
    rows = card[1] if isinstance(card, list) and len(card) > 1 and isinstance(card[1], list) else []
    for row in rows:
        if isinstance(row, list) and len(row) >= 4 and isinstance(row[0], str):
            out.setdefault(row[0], []).append(row[3])
    return out


def _as_list(v):
    return v if isinstance(v, list) else []


def _entities(entities):
    for e in _as_list(entities):
        if isinstance(e, dict):
            yield e
            yield from _entities(e.get('entities'))


def parse_rdap(js):
    """The useful, safe subset of an RDAP IP-network record."""
    if not isinstance(js, dict):
        return {}
    cidrs = []
    for c in _as_list(js.get('cidr0_cidrs')):
        if isinstance(c, dict):
            pre = c.get('v4prefix') or c.get('v6prefix')
            if pre and c.get('length') is not None:
                cidrs.append(f"{pre}/{c['length']}")
    org = abuse = None
    for e in _entities(js.get('entities')):
        roles = [r for r in _as_list(e.get('roles')) if isinstance(r, str)]
        card = _vcard(e)
        if 'abuse' in roles and abuse is None and card.get('email'):
            abuse = clean(card['email'][0], 120)
        if 'registrant' in roles and org is None and card.get('fn'):
            if 'individual' not in [str(k).lower() for k in card.get('kind', [])]:
                org = clean(card['fn'][0], 120)
    events = {clean(ev.get('eventAction'), 30): clean(ev.get('eventDate'), 30)
              for ev in _as_list(js.get('events')) if isinstance(ev, dict)}
    return {k: v for k, v in {
        'name': clean(js.get('name'), 80), 'handle': clean(js.get('handle'), 80), 'country': clean(js.get('country'), 4),
        'type': clean(js.get('type'), 40), 'range': ' - '.join(x for x in (clean(js.get('startAddress'), 45), clean(js.get('endAddress'), 45)) if x) or None,
        'cidr': ', '.join(cidrs[:4]) or None, 'organization': org, 'abuse_contact': abuse,
        'registered': events.get('registration'), 'last_changed': events.get('last changed'),
    }.items() if v}


class _TtlCache:
    def __init__(self, ttl=86400, max_entries=512, clock=time.time):
        self.ttl, self.max, self.clock = ttl, max_entries, clock
        self._d, self._lock = OrderedDict(), threading.Lock()

    def get(self, key):
        with self._lock:
            hit = self._d.get(key)
            if hit and self.clock() - hit[0] <= self.ttl:
                return hit[1]
            self._d.pop(key, None)
            return None

    def put(self, key, value):
        with self._lock:
            self._d[key] = (self.clock(), value)
            self._d.move_to_end(key)
            while len(self._d) > self.max:
                self._d.popitem(last=False)


_rdap_cache = _TtlCache()


def fetch_rdap(ip, get=requests.get):
    """Registry record for a PUBLIC address (cached 24h). Only ever contacts the fixed RDAP service."""
    cached = _rdap_cache.get(ip)
    if cached is not None:
        return cached
    if not ipaddress.ip_address(ip).is_global:
        raise ValueError('registry lookups are for public addresses only')
    r = get(RDAP_URL.format(ip=ip), headers={'Accept': 'application/rdap+json'}, timeout=8)
    if r.status_code != 200:
        raise RuntimeError(f'registry answered HTTP {r.status_code}')
    parsed = parse_rdap(r.json())
    if not parsed:
        raise RuntimeError('registry returned no usable record')
    _rdap_cache.put(ip, parsed)
    return parsed


# ── DNS / device data ────────────────────────────────────────────────────────

def reverse_dns(ip, resolver=socket.gethostbyaddr):
    try:
        return clean(resolver(ip)[0], 253)
    except (OSError, IndexError):
        return None


def resolve_forward(domain, resolver=socket.getaddrinfo):
    try:
        return sorted({ai[4][0] for ai in resolver(domain, None)})[:10]
    except (OSError, UnicodeError):
        return []


def read_arp(ip, run=subprocess.run):
    """{'mac', 'state'} from the neighbour table; one ping wakes a device that has aged out of it."""
    def look():
        r = run(['ip', 'neigh', 'show', ip], capture_output=True, text=True, timeout=5)
        m = re.search(r'lladdr ([0-9a-f:]{17})\s*(\w+)?', r.stdout or '', re.I)
        return {'mac': m.group(1).lower(), 'state': (m.group(2) or '').lower()} if m else None
    try:
        found = look()
        if found is None:
            run(['ping', '-c', '1', '-W', '1', ip], capture_output=True, text=True, timeout=5)
            found = look()
    except (OSError, subprocess.TimeoutExpired):               # no `ip`/`ping` binary, or it hung: the other sources still count
        return None
    return found


_oui = {'loaded': False, 'map': {}}


def oui_vendor(mac, paths=OUI_PATHS):
    """Vendor for a globally-assigned MAC from the IEEE registry file, if the system has it."""
    if not _oui['loaded']:
        for p in paths:
            try:
                with open(p, encoding='utf-8', errors='replace') as f:
                    for line in f:
                        m = re.match(r'^\s*([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2})\s+\(hex\)\s+(.+)$', line)
                        if m:
                            _oui['map'][m.group(1).replace('-', '')] = m.group(2).strip()
            except OSError:
                continue
        _oui['loaded'] = True
    return clean(_oui['map'].get(mac.replace(':', '').upper()[:6]), 100)


def mac_flags(mac):
    first = int(mac[:2], 16)
    return {'randomized': bool(first & 2), 'multicast': bool(first & 1)}


def pihole_device(ip, pihole):
    """The Pi-hole network-table entry for this IP (it tracks MAC, vendor, hostnames and DNS activity), or None."""
    data = pihole.get_json('/api/network/devices')
    for dev in data.get('devices') or []:
        for entry in dev.get('ips') or []:
            if entry.get('ip') == ip:
                names = sorted({clean(e.get('name'), 100) for e in dev.get('ips') or [] if e.get('name')} - {None})
                return {'mac': clean(dev.get('hwaddr'), 17), 'vendor': clean(dev.get('macVendor'), 100), 'names': names,
                        'first_seen': dev.get('firstSeen'), 'last_query': dev.get('lastQuery'),
                        'dns_queries': dev.get('numQueries')}
    return None


def scan_ports(ip, ports=COMMON_PORTS, timeout=0.5, connect=socket.create_connection):
    """Open TCP ports among a short common list. Private addresses only; the caller must have checked."""
    if ipaddress.ip_address(ip).is_global:
        raise ValueError('port checks are limited to private addresses')

    def one(port):
        """Try one TCP port; return its details if something answers, None if it is closed."""
        try:
            connect((ip, port), timeout=timeout).close()
        except OSError:
            return None
        try:
            svc = socket.getservbyport(port)
        except OSError:
            svc = None
        return {'port': port, 'service': svc}
    return [r for r in _scan_pool.map(one, ports) if r]


def merge_device(pihole, arp, oui=oui_vendor):
    """One device record from whatever sources knew the address (Pi-hole preferred, ARP as the fallback)."""
    dev = dict(pihole or {})
    sources = ['Pi-hole'] if pihole else []
    if arp:
        sources.append('ARP')
        dev.setdefault('mac', arp['mac'])
    mac = dev.get('mac')
    if mac and re.match(r'^[0-9a-f]{2}(:[0-9a-f]{2}){5}$', mac, re.I):
        mac = dev['mac'] = mac.lower()
        flags = mac_flags(mac)
        dev['randomized_mac'] = flags['randomized']
        if not dev.get('vendor') and not flags['randomized']:
            dev['vendor'] = oui(mac)
    else:
        dev.pop('mac', None)
    dev['sources'] = sources
    return dev if (dev.get('mac') or pihole) else {}


# ── assembling the answer ────────────────────────────────────────────────────

class Deps(SimpleNamespace):
    """Injectable side effects: rdap(ip), rdns(ip), device(ip), scan(ip), intel(kind, value), history(kind, value),
    forward(domain). Missing ones default to 'not available'."""


def _section(fn, *args):
    try:
        return {'ok': True, 'data': fn(*args)}
    except Exception as e:                                              # one failing source must not sink the answer
        return {'ok': False, 'error': clean(f'{type(e).__name__}: {e}', 160)}


def _collect(jobs, deadline=None):
    futures = {name: _pool.submit(_section, *job) for name, job in jobs.items()}
    wait(list(futures.values()), timeout=deadline or SECTION_TIMEOUT)
    out = {}
    for name, f in futures.items():
        out[name] = f.result() if f.done() else {'ok': False, 'error': 'timed out'}
    return out


def headline(r):
    """Write a one-line plain-English summary of what is known about an IP address (who owns it, what device it is,
    whether a feed lists it)."""
    bits = []
    if r['scope'] == 'public':
        reg = r.get('registry') or {}
        who = reg.get('organization') or reg.get('name')
        if who:
            bits.append(who + (f" ({reg['country']})" if reg.get('country') else ''))
        if r.get('reverse_dns'):
            bits.append(f"reverse DNS {r['reverse_dns']}")
    elif r['scope'] == 'lan':
        d = r.get('device') or {}
        if d.get('vendor'):
            bits.append(f"{d['vendor']} device")
        elif d.get('randomized_mac'):
            bits.append('device using a randomized (private) MAC, typical of a phone or laptop')
        elif d.get('mac'):
            bits.append('device with an unregistered vendor')
        else:
            bits.append('a device on your network that is not in the ARP or Pi-hole tables right now')
        if d.get('names'):
            bits.append(f"named {', '.join(d['names'][:2])}")
        elif r.get('reverse_dns'):
            bits.append(f"named {r['reverse_dns']}")
    else:
        bits.append('not a routable address (loopback, link-local, multicast or reserved)')
    for hit in r.get('intel') or []:
        bits.append(f"LISTED by {hit['source']} as {hit['malware']} ({hit['threat'].replace('_', ' ')})")
        break
    h = (r.get('history') or {})
    if h.get('count'):
        bits.append(f"{h['count']} threat record(s) here")
    return '; '.join(bits) or 'no information found'


def identify_ip(ip_text, deps, ports=False):
    """Gather what is known about an IP address (reverse DNS, registry, LAN device, open ports, feed hits, history) and
    add a one-line headline. Raises ValueError for text that is not an IP."""
    ip = ipaddress.ip_address(str(ip_text).strip())                     # ValueError -> caller answers 400
    scope = scope_of(ip)
    value = str(ip)
    res = {'ip': value, 'scope': scope, 'errors': {}}
    jobs = {}
    if scope in ('public', 'lan'):
        jobs['reverse_dns'] = (reverse_dns, value) if not getattr(deps, 'rdns', None) else (deps.rdns, value)
    if scope == 'public' and getattr(deps, 'rdap', None):
        jobs['registry'] = (deps.rdap, value)
    if scope == 'lan':
        if getattr(deps, 'device', None):
            jobs['device'] = (deps.device, value)
        if ports and getattr(deps, 'scan', None):
            jobs['open_ports'] = (deps.scan, value)
    if getattr(deps, 'intel', None):
        jobs['intel'] = (deps.intel, 'ip', value)
    if getattr(deps, 'history', None):
        jobs['history'] = (deps.history, 'ip', value)
    for name, sec in _collect(jobs).items():
        if sec['ok']:
            res[name] = sec['data']
        else:
            res['errors'][name] = sec['error']
    res['headline'] = headline(res)
    return res


def identify_domain(domain, deps):
    """Gather what is known about a domain (where it resolves, threat feed hits, past findings) in parallel and add a
    one-line headline."""
    d = clean(domain, 253).lower()
    res = {'domain': d, 'scope': 'domain', 'errors': {}}
    jobs = {}
    if getattr(deps, 'forward', None):
        jobs['resolves_to'] = (deps.forward, d)
    if getattr(deps, 'intel', None):
        jobs['intel'] = (deps.intel, 'domain', d)
    if getattr(deps, 'history', None):
        jobs['history'] = (deps.history, 'domain', d)
    for name, sec in _collect(jobs).items():
        if sec['ok']:
            res[name] = sec['data']
        else:
            res['errors'][name] = sec['error']
    bits = []
    if res.get('resolves_to'):
        bits.append('resolves to ' + ', '.join(res['resolves_to'][:3]))
    for hit in res.get('intel') or []:
        bits.append(f"LISTED by {hit['source']} as {hit['malware']} ({hit['threat'].replace('_', ' ')})")
        break
    if (res.get('history') or {}).get('count'):
        bits.append(f"{res['history']['count']} threat record(s) here")
    res['headline'] = '; '.join(bits) or 'no information found'
    return res


def default_deps(pihole=None, history=None, intel_lookup=None):
    """The real thing: RDAP, resolver, ARP/Pi-hole/OUI, port check. The app supplies history and intel lookups."""
    def device(ip):
        p = None
        if pihole is not None:
            try:
                p = pihole_device(ip, pihole)
            except Exception:                                           # Pi-hole down/unconfigured: ARP may still know it
                p = None
        return merge_device(p, read_arp(ip))
    return Deps(rdap=fetch_rdap, rdns=reverse_dns, device=device, scan=scan_ports, forward=resolve_forward,
                history=history, intel=intel_lookup)


