"""Pure helpers the agents share (agent_util.py): hide private addresses, scrub log lines, cap memory use.

Nothing here talks to the hub, a model or the network, so each piece can be read and tested on its own.

  mask_private_ip      "10.1.2.3" -> "10.1.xxx.xxx", "fd12:3456::5" -> "fd12:3456:xxxx::" (shape kept, machine not named)
  find_ip / find_ips / find_ip_port / ssh_source / split_host_port / normalise_ip
                       read IPv4 and IPv6 addresses out of log lines and `ss` output (one reader for every agent)
  sanitize_log_line    drop the hostname, MAC addresses and interface names from a syslog line
  _BoundedSet / _BoundedDict   a set / dict that forgets its oldest entries, so a long-running agent cannot grow without limit
"""
import re
from collections import OrderedDict, deque

import ipaddress as _ipmod
# Addresses inside the organisation (never "the internet"): RFC 1918, loopback, link-local, carrier-grade NAT / Tailscale
# (100.64.0.0/10), and the IPv6 equivalents: loopback ::1, unique-local fc00::/7 (fd..), link-local fe80::/10. IPv6 added
# 2026-11-18; before that every local IPv6 address counted as public.
_PRIV_NETS = [_ipmod.ip_network(n) for n in
              ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', '169.254.0.0/16', '100.64.0.0/10',
               '::1/128', 'fc00::/7', 'fe80::/10']]

# ── reading addresses out of text (IPv4 and IPv6) ────────────────────────────
# A loose candidate pattern; every candidate is then checked by the ipaddress module, so times (12:34:56), MAC addresses and
# version strings are never taken for addresses. IPv6 may be written bare (2001:db8::5), in brackets ([2001:db8::5]:22), with
# a zone (fe80::1%eth0) or as an IPv4-mapped address (::ffff:203.0.113.5, read as the IPv4 address it wraps).
_V4_PAT = r'\d{1,3}(?:\.\d{1,3}){3}'
_V6_PAT = r'(?:[0-9A-Fa-f]{0,4}:){2,7}(?:' + _V4_PAT + r'|[0-9A-Fa-f]{0,4})'
_ADDR_RE = re.compile(r'(?<![\w:.])(?:\[(?P<b6>' + _V6_PAT + r')(?:%[\w.-]+)?\](?::(?P<bport>\d{1,5}))?'
                      r'|(?P<v6>' + _V6_PAT + r')(?:%[\w.-]+)?'
                      r'|(?P<v4>' + _V4_PAT + r')(?::(?P<port>\d{1,5}))?)(?![\w:])')
_V6_ANYWHERE = re.compile(r'(?<![\w:.])' + _V6_PAT + r'(?:%[\w.-]+)?(?![\w:])')


def normalise_ip(text):
    """'2001:DB8:0::5' -> '2001:db8::5', '::ffff:203.0.113.5' -> '203.0.113.5', '[fe80::1%eth0]' -> 'fe80::1'; None when the
    text is not one address. The unspecified address (0.0.0.0, ::) is nobody's source, so it is None too."""
    if text is None:
        return None
    t = str(text).strip().strip('[]').split('%', 1)[0]
    try:
        addr = _ipmod.ip_address(t)
    except ValueError:
        return None
    if getattr(addr, 'ipv4_mapped', None) is not None:
        addr = addr.ipv4_mapped
    if addr.is_unspecified:
        return None
    return str(addr)


def find_ips(text):
    """Every address in `text`, in order, as (address, port or None). A port is read only where it cannot be confused with the
    address: after an IPv4 address (203.0.113.5:22) or a bracketed IPv6 one ([2001:db8::5]:22)."""
    out = []
    for m in _ADDR_RE.finditer(str(text or '')):
        ip = normalise_ip(m.group('b6') or m.group('v6') or m.group('v4'))
        if ip is None:
            continue
        port = m.group('bport') or m.group('port')
        out.append((ip, int(port) if port and int(port) <= 65535 else None))
    return out


def find_ip(text):
    """The first address in `text`, or None."""
    found = find_ips(text)
    return found[0][0] if found else None


def find_ip_port(text):
    """The first address that comes with a port, as (address, port), or None."""
    return next(((ip, port) for ip, port in find_ips(text) if port is not None), None)


_SSH_FROM = re.compile(r'\bfrom (\S+) port \d+')
_ANY_FROM = re.compile(r'\bfrom (\S+)')


def ssh_source(line):
    """The remote address of an sshd log line ("... from 203.0.113.5 port 4242 ssh2", or IPv6), or None. The LAST
    "from <address> port <n>" wins: sshd writes it at the end, while the user name before it is chosen by whoever connects."""
    for pattern in (_SSH_FROM, _ANY_FROM):
        for token in reversed(pattern.findall(str(line or ''))):
            ip = normalise_ip(token)
            if ip is not None:
                return ip
    return None


# One reader for "an SSH login failed" (2026-11-18), shared by AuthLogAgent and the direct checks so both count the same
# lines. Everything before the address is chosen by whoever connects (a user name may hold spaces and fake addresses), so
# the address and port are always the LAST "<address> port <n>" on the line.
_SSH_FAILED = re.compile(r'\bFailed (password|keyboard-interactive/pam|publickey|none|hostbased) for ')
_SSH_GAVE_UP = re.compile(
    r'\bsshd(?:-session)?(?:\[\d+\])?: (?:'
    r'(?:Connection closed by|Disconnected from|Disconnecting) (?:authenticating|invalid) user (?P<u1>.*) (?P<a1>\S+) port (?P<p1>\d+)'
    r'(?::| \[preauth\]|$)'
    r'|error: maximum authentication attempts exceeded for (?:invalid user )?(?P<u2>.*) from (?P<a2>\S+) port (?P<p2>\d+) ssh2)')
_SSH_PORT = re.compile(r'\bport (\d+)')
_PASSWORD_KINDS = {'password', 'keyboard-interactive/pam', 'invalid-user'}


def ssh_failure(line):
    """A failed SSH login on this auth.log line, as {'ip', 'port', 'kind'}, or None.

    kind: 'password' / 'keyboard-interactive/pam' / 'publickey' / 'none' / 'hostbased' (a "Failed <method>" line),
    'invalid-user' (sshd's "Invalid user" line; with the "Failed" line that follows, an unknown name counts twice, on purpose),
    or 'gave-up' (the connection was closed before logging in, or hit the attempt limit: the only trace a key-only attacker
    leaves). 'password' says whether it is a guess at a password (those alone can lead to "the password may have been guessed").
    ip is None when sshd's line has no readable address."""
    text = str(line or '')
    # The gave-up lines first: their wording starts right after sshd's own tag, so a user name holding "Failed password for"
    # or "Invalid user" cannot turn one into a password failure with a planted address.
    g = _SSH_GAVE_UP.search(text)
    if g:
        token, port = (g.group('a1'), g.group('p1')) if g.group('a1') is not None else (g.group('a2'), g.group('p2'))
        return {'ip': normalise_ip(token), 'port': port, 'kind': 'gave-up', 'password': False}
    m = _SSH_FAILED.search(text)
    if m or 'Invalid user ' in text:
        ports = _SSH_PORT.findall(text)
        kind = m.group(1) if m else 'invalid-user'
        return {'ip': ssh_source(text), 'port': ports[-1] if ports else None, 'kind': kind,
                'password': kind in _PASSWORD_KINDS}
    return None


def split_host_port(endpoint):
    """An `ss` address column -> (host, port): '203.0.113.5:443', '[2001:db8::5]:443', '*:22', '[::ffff:203.0.113.5]:80' and
    the bracket-less IPv6 form older ss versions print ('2001:db8::5:443': the port is after the last colon). The host keeps
    its written form ('*', '0.0.0.0', '[::]' -> '::'); (None, None) when there is no port."""
    host, sep, port = str(endpoint or '').rpartition(':')
    if not sep or not port.isdigit():
        return None, None
    return host.strip('[]').split('%', 1)[0], int(port)


def _is_private_ip(ip_str):
    """True for an address inside the organisation (_PRIV_NETS, IPv4 and IPv6), IPv4-mapped forms included."""
    ip = normalise_ip(ip_str)
    if ip is None:
        return False
    addr = _ipmod.ip_address(ip)
    return any(addr.version == net.version and addr in net for net in _PRIV_NETS)


def _mask_v6(addr):
    """fd12:3456:789a::5 -> fd12:3456:xxxx:: (the network's first two groups stay; the device does not)."""
    groups = addr.exploded.split(':')
    return f'{int(groups[0], 16):x}:{int(groups[1], 16):x}:xxxx::'


def mask_private_ip(text):
    """Replace addresses inside the organisation with a masked form: 10.1.2.3 -> 10.1.xxx.xxx, fd12:3456::5 -> fd12:3456:xxxx::.
    Public addresses stay readable. IPv6 loopback (::1) stays as it is: it names no device."""
    if not text:
        return text

    def _sub6(match):
        raw = match.group(0)
        try:
            addr = _ipmod.ip_address(raw.split('%', 1)[0])
        except ValueError:
            return raw
        if addr.ipv4_mapped is not None or addr.is_loopback:
            return raw                                   # a mapped IPv4 address is masked by the IPv4 pass below
        if any(addr.version == net.version and addr in net for net in _PRIV_NETS):
            return _mask_v6(addr)
        return raw

    def _sub(match):
        """Mask one matched IPv4 address, but only if it is a private (home or office network) address; public ones stay
        readable."""
        try:
            addr = _ipmod.ip_address(match.group(0))
            if any(addr.version == net.version and addr in net for net in _PRIV_NETS):
                octets = match.group(0).split('.')
                return f'{octets[0]}.{octets[1]}.xxx.xxx'
        except ValueError:
            pass
        return match.group(0)
    text = _V6_ANYWHERE.sub(_sub6, text)
    return re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', _sub, text)

# FIX: removed re.DOTALL — the flag is meaningless here (no '.' in pattern) and was misleading.
# FIX: the original regex '^(\S+)\s+\S+(\s+)' only matched the first whitespace-delimited token
# as group 1 (e.g., "May" from "May 24 00:01:23 hostname sshd:") which is wrong — syslog
# timestamps are 3 tokens.  Corrected pattern captures the full 3-token timestamp as group 1
# and the whitespace after the hostname as group 2, so r'\1\2' strips only the hostname.
_SYSLOG_HOST_RE = re.compile(r'^((?:\S+\s+){2}\S+)\s+\S+(\s+)')
_MAC_RE          = re.compile(r'\bMAC=[\da-fA-F:]+', re.IGNORECASE)
_IFACE_RE        = re.compile(r'\b(?:IN|OUT)=\S*', re.IGNORECASE)

def sanitize_log_line(line):
    """Strip hostname token, MAC addresses, and interface names from syslog lines."""
    line = _SYSLOG_HOST_RE.sub(r'\1\2', line)
    line = _MAC_RE.sub('MAC=<redacted>', line)
    line = _IFACE_RE.sub('', line)
    return line.strip()

class _BoundedSet:
    """Set capped at maxlen entries — oldest insertions are evicted first (FIFO).

    Long-running agents use plain sets to dedupe repeat events (seen IPs, blocked
    domains, analyzed threat ids, ...). Left uncapped these grow for the lifetime
    of the process — weeks/months of uptime — and leak memory. Eviction here just
    means an old entry could be re-reported once after falling out of the window,
    which is harmless for these dedup use-cases.
    """
    __slots__ = ('_set', '_order', '_maxlen')

    def __init__(self, maxlen=10000):
        self._set = set()
        self._order = deque()
        self._maxlen = maxlen

    def __contains__(self, item):
        return item in self._set

    def __len__(self):
        return len(self._set)

    def add(self, item):
        if item in self._set:
            return
        self._set.add(item)
        self._order.append(item)
        if len(self._set) > self._maxlen:
            self._set.discard(self._order.popleft())


class _BoundedDict(OrderedDict):
    """Dict capped at maxlen entries — oldest-inserted keys evicted first (FIFO).

    Same rationale as _BoundedSet (e.g. AuthLogAgent._fail_times keyed by source IP).
    """

    def __init__(self, maxlen=10000):
        super().__init__()
        self._maxlen = maxlen

    def __setitem__(self, key, value):
        super().__setitem__(key, value)
        if len(self) > self._maxlen:
            self.popitem(last=False)
