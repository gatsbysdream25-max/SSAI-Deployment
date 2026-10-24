"""Pure helpers the agents share (agent_util.py): hide private addresses, scrub log lines, cap memory use.

Nothing here talks to the hub, a model or the network, so each piece can be read and tested on its own.

  mask_private_ip      "10.1.2.3" -> "10.1.xxx.xxx" (so a finding keeps the shape of an address without naming a machine)
  sanitize_log_line    drop the hostname, MAC addresses and interface names from a syslog line
  _BoundedSet / _BoundedDict   a set / dict that forgets its oldest entries, so a long-running agent cannot grow without limit
"""
import re
from collections import OrderedDict, deque

import ipaddress as _ipmod
_PRIV_NETS = [_ipmod.ip_network(n) for n in
              ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8']]

def _is_private_ip(ip_str):
    """Return True if ip_str is an RFC1918/loopback address."""
    try:
        addr = _ipmod.ip_address(ip_str)
        return any(addr in net for net in _PRIV_NETS)
    except ValueError:
        return False

def mask_private_ip(text):
    """Replace private RFC1918 IPs with masked form (x.x.xxx.xxx)."""
    if not text:
        return text
    def _sub(match):
        """Mask one matched IP address, but only if it is a private (home or office network) address; public ones stay
        readable."""
        try:
            addr = _ipmod.ip_address(match.group(0))
            if any(addr in net for net in _PRIV_NETS):
                octets = match.group(0).split('.')
                return f'{octets[0]}.{octets[1]}.xxx.xxx'
        except ValueError:
            pass
        return match.group(0)
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

    Same rationale as _BoundedSet (e.g. AuthLogAgent._fail_counts keyed by source IP).
    """

    def __init__(self, maxlen=10000):
        super().__init__()
        self._maxlen = maxlen

    def __setitem__(self, key, value):
        super().__setitem__(key, value)
        if len(self) > self._maxlen:
            self.popitem(last=False)
