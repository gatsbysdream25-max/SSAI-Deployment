"""Remediation behind the dashboard's Block button: decide what a threat's indicator IS, then act on it honestly.

  * a public IP  -> firewall rules on THIS host, both directions (a malware server is something we connect *out* to,
                    so an inbound-only rule does nothing), inserted at the top because ufw is first-match and
                    the standing "allow ssh from anywhere" rule would otherwise let a blocked address straight in;
  * a domain     -> Pi-hole deny list, which stops every device that uses that Pi-hole from resolving it. A firewall
                    cannot block a name, so a domain threat used to fail with "no valid source IP".
  * anything else (masked LAN address, unsupported scheme, protected domain) -> a clear refusal that says why.

Every action, success or failure, is appended to an audit log, and every block has an unblock, because the cost of a
wrong block (a legitimate site or device cut off) must be one click to undo. Nothing here touches Flask, so it is
testable with fakes; the app passes the real subprocess/requests in.
"""
import ipaddress
import json
import logging
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from urllib.parse import urlsplit

import requests

from agents import intel

UFW = '/usr/sbin/ufw'
_MASKED = re.compile(r'(\d\.x{2,}|x{2,}\.\d|x{2,}\.x{2,})', re.I)
_WEB_SCHEMES = ('http', 'https', 'ftp')


class TargetError(ValueError):
    """The threat's indicator cannot (or must not) be blocked; the message is shown to the operator."""


class RemediationError(RuntimeError):
    """The action was attempted and failed; the message is shown to the operator."""


def classify_target(raw):
    """What to block for a threat's url field: {'kind': 'ip'|'domain', 'value': str}. Raises TargetError."""
    if not isinstance(raw, str) or not raw.strip():
        raise TargetError('this threat has no address to block')
    s = raw.strip()
    if _MASKED.search(s):
        raise TargetError('the address is masked (e.g. 192.168.xxx.xxx), so SwarmSentinel cannot tell which device it is '
                          'and will not guess; block it on the router or firewall that can see the real address')
    if '://' in s:
        try:
            parts = urlsplit(s)
            host = parts.hostname or ''
        except ValueError:
            raise TargetError('the address is not a valid URL') from None
        if parts.scheme.lower() not in _WEB_SCHEMES:
            raise TargetError(f'"{parts.scheme}://" addresses are internal monitors, not something that can be blocked')
    else:
        host = re.split(r'[/?#]', s, 1)[0]
        if host.count(':') == 1:                                   # host:port (a bare IPv6 literal has several colons)
            host = host.split(':')[0]
        host = host.strip('[]')
    host = host.strip().lower().rstrip('.')
    if not host:
        raise TargetError('no host found in this address')

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        if getattr(ip, 'ipv4_mapped', None) is not None:
            ip = ip.ipv4_mapped                     # ::ffff:192.168.1.5 is 192.168.1.5; judge (and block) the address it wraps
        if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local or ip.is_reserved:
            raise TargetError(f'{ip} is not a blockable address')
        return {'kind': 'ip', 'value': str(ip)}

    domain = intel.clean_domain(host)
    if domain is None:
        raise TargetError(f'"{host[:60]}" is not an IP address or a domain name')
    if any(a in intel._allowlist() for a in intel._ancestors(domain)):
        raise TargetError(f'{domain} is a protected domain (widely used legitimate service); it will not be blocked. '
                          'Add to INTEL_ALLOWLIST in .env to extend this list')
    return {'kind': 'domain', 'value': domain}


# ── firewall (ufw) ───────────────────────────────────────────────────────────

def _ufw_command(args):
    """ufw needs root: call it directly when we are root (containers, the agent runner), otherwise through sudo."""
    if not sys.platform.startswith('linux'):
        raise RemediationError('firewall blocking is only supported on Linux hosts; block this address on your router or firewall')
    ufw = shutil.which('ufw') or UFW
    return ([ufw] if os.geteuid() == 0 else ['sudo', '-n', ufw]) + args


def _ufw(args, run):
    try:
        r = run(_ufw_command(args), capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise RemediationError(f'could not run ufw: {e}') from e
    return r


def firewall_block(ip, run=subprocess.run):
    """Deny traffic to and from `ip` on this host, above every allow rule. Idempotent."""
    st = _ufw(['status'], run)
    if st.returncode != 0:
        message = (st.stderr or st.stdout).strip()
        if 'password is required' in message or 'a terminal is required' in message:
            # The installer writes the sudo rule only when ufw already exists, so ufw installed afterwards is not covered yet.
            raise RemediationError('this account is not yet allowed to run ufw: re-run deploy/install.sh as root (it adds the rule once ufw is installed)')
        if 'command not found' in message or 'No such file' in message:
            raise RemediationError('ufw is not installed on this host, so there is nothing to block with '
                                   '(Debian/Ubuntu: sudo apt install ufw, then re-run deploy/install.sh as root so this account may use it)')
        raise RemediationError(f'ufw is not usable: {message[:200]}')
    if 'status: active' not in st.stdout.lower():
        raise RemediationError('the firewall (ufw) is switched off on this host, so a rule would not be enforced; enable it first')
    done = []
    for rule in (['deny', 'from', ip], ['deny', 'out', 'to', ip]):
        r = _ufw(['insert', '1'] + rule, run)
        if r.returncode != 0 and 'invalid position' in (r.stderr + r.stdout).lower():
            r = _ufw(rule, run)                                    # empty rule set: nothing to insert above
        if r.returncode != 0:
            for undo in done:                                      # never leave half a block behind
                _ufw(['delete'] + undo, run)
            raise RemediationError(f'ufw refused the rule: {(r.stderr or r.stdout).strip()[:200]}')
        done.append(rule)
    return 'this host only: inbound and outbound traffic with %s is denied' % ip


def firewall_unblock(ip, run=subprocess.run):
    for rule in (['deny', 'from', ip], ['deny', 'out', 'to', ip]):
        r = _ufw(['delete'] + rule, run)
        if r.returncode != 0:
            raise RemediationError(f'ufw could not remove the rule: {(r.stderr or r.stdout).strip()[:200]}')
    return 'firewall rules for %s removed' % ip


# ── Pi-hole deny list ────────────────────────────────────────────────────────

class PiHole:
    """The few Pi-hole v6 calls remediation needs. A dedicated cookie-less session (the `sid` cookie makes Pi-hole
    reject the ?sid= parameter), and a logout after every action so we never hold one of its limited seats."""

    def __init__(self, host=None, password=None, http=None):
        self.host = host if host is not None else os.environ.get('PIHOLE_IP', '')
        self.password = password if password is not None else os.environ.get('PIHOLE_PASSWORD', '')
        if http is None:
            from http.cookiejar import DefaultCookiePolicy
            http = requests.Session()
            http.cookies.set_policy(DefaultCookiePolicy(allowed_domains=[]))
        self.http = http

    def _call(self, method, path, **kw):
        """Log in to Pi-hole, make one request, and log out again, returning the response.
        Raises RemediationError if Pi-hole is not configured, rejects the login, or cannot be reached.
        """
        if not self.host or not self.password:
            raise RemediationError('Pi-hole is not configured (set PIHOLE_IP and PIHOLE_PASSWORD in .env), so a domain cannot be blocked')
        base = f'http://{self.host}'
        try:
            login = self.http.post(f'{base}/api/auth', json={'password': self.password}, timeout=8)
            sess = (login.json() or {}).get('session', {}) if login.status_code == 200 else {}
            if not sess.get('valid'):
                raise RemediationError(f'Pi-hole rejected the login (HTTP {login.status_code}); check PIHOLE_PASSWORD')
            sid = sess['sid']
            try:
                return self.http.request(method, f'{base}{path}', params={'sid': sid}, timeout=10, **kw)
            finally:
                try:
                    self.http.delete(f'{base}/api/auth', params={'sid': sid}, timeout=5)
                except requests.exceptions.RequestException:
                    pass
        except (requests.exceptions.RequestException, ValueError) as e:
            raise RemediationError(f'could not reach Pi-hole at {self.host}: {e}') from e

    def get_json(self, path):
        r = self._call('GET', path)
        if r.status_code != 200:
            raise RemediationError(f'Pi-hole answered HTTP {r.status_code} for {path}')
        return r.json()

    def deny(self, domain, comment):
        r = self._call('POST', '/api/domains/deny/exact',
                       json={'domain': domain, 'comment': comment[:200], 'groups': [0], 'enabled': True})
        if r.status_code == 201:
            return
        if r.status_code == 400 and 'already present' in r.text:   # someone (or an earlier click) already blocked it
            return
        raise RemediationError(f'Pi-hole refused the domain (HTTP {r.status_code}): {r.text[:160]}')

    def undeny(self, domain):
        r = self._call('DELETE', f'/api/domains/deny/exact/{domain}')
        if r.status_code not in (204, 404):                        # 404: already gone
            raise RemediationError(f'Pi-hole could not remove the domain (HTTP {r.status_code}): {r.text[:160]}')


def block(target, threat_id, pihole=None, run=subprocess.run):
    """Apply the block for a classify_target() result. Returns a one-line description of what changed and its scope."""
    if target['kind'] == 'ip':
        return firewall_block(target['value'], run)
    (pihole or PiHole()).deny(target['value'], f'SwarmSentinel threat #{threat_id}')
    return ('every device that uses this Pi-hole can no longer resolve %s (exact name; a device using a different '
            'DNS server is not covered)' % target['value'])


def unblock(target, pihole=None, run=subprocess.run):
    if target['kind'] == 'ip':
        return firewall_unblock(target['value'], run)
    (pihole or PiHole()).undeny(target['value'])
    return '%s removed from the Pi-hole deny list' % target['value']


# ── audit ────────────────────────────────────────────────────────────────────

def audit(path, **event):
    """Append one JSON line (time, action, target, result...). Never raises: a full disk must not stop an UNBLOCK or an expiry.
    A failure is logged loudly, because a missing audit line is itself something an operator must hear about."""
    event['time'] = datetime.now(timezone.utc).isoformat(timespec='seconds')
    try:
        import logsafe
        logsafe.append_line(path, json.dumps(event, separators=(',', ':')))
    except OSError as exc:
        logging.getLogger('remediation').error(f'AUDIT LINE NOT WRITTEN ({event.get("action")}): {exc}')
    return event


def audit_before_acting(path, **event):
    """Write the audit line for an action BEFORE doing it, and raise RemediationError if it cannot be written. Approving a block
    changes the firewall, so no record means no block (audit F-14). Unblocking and expiry use plain audit(): undoing a block
    must never be held up by a full disk."""
    event['time'] = datetime.now(timezone.utc).isoformat(timespec='seconds')
    try:
        import logsafe
        logsafe.append_line(path, json.dumps(event, separators=(',', ':')))
    except OSError as exc:
        raise RemediationError(f'the audit log could not be written, so nothing was blocked ({exc.__class__.__name__}); fix the disk or permissions and try again')
    return event


