"""The gate between SwarmSentinel and anything in the cloud (Copilot lane), 2026-09-23.

Nothing may be sent to Copilot (or any cloud service) except through sanitize_for_cloud(). Network facts (internal
IPs, hostnames, MACs, ports, topology, DNS logs, syslog, payloads) stay on this network; only a sanitized verdict
may leave.

    sanitize_for_cloud(payload) -> dict

  1. Allow-list, deny by default. Only severity, threat_type, timestamp and sanitized_summary can pass, each checked
     for shape. Every other field is dropped, whatever it is called.
  2. Redact what is left. Credentials (known API-key formats, auth headers, passwords in URLs, sshpass / sudo -S,
     anything named like a password, token or key), IPv4 / IPv6 addresses, MAC addresses, internal hostnames and
     domains, e-mail addresses and user home paths become stable tokens (SECRET_1, IP_1, HOST_1, MAC_1 ...): the
     same value always gets the same token, so an analysis still reads sensibly. The token map lives in memory
     only and is never sent or logged. File hashes and other indicators are left alone.
  3. Log what crossed (the redacted result and counts, never an original value) to an append-only local audit log.
  4. Return the result.

Fails closed: any error, an unwritable audit log, or a leftover address after redaction returns {} (nothing is
sent) and says why in the log. Callers must treat {} as "do not send".
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import socket
import threading
from datetime import datetime, timezone
from typing import Dict, List, Optional

log = logging.getLogger("ssai.sanitizer")

ALLOWED_FIELDS = ("severity", "threat_type", "timestamp", "sanitized_summary")
SEVERITIES = ("critical", "high", "medium", "low", "info")
MAX_SUMMARY = 500
MAX_TOKENS = 100_000                      # bound on the in-memory map; see _TokenMap

# ── what counts as internal ────────────────────────────────────────────────
_INTERNAL_SUFFIXES = ("local", "lan", "internal", "home", "corp", "localdomain", "intranet", "private", "arpa")

# IPv4 address: four groups of 1-3 digits separated by dots. Groups may also be x's, so masked forms like 192.168.xxx.xxx match.
_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}|x{1,3})(?:\.(?:\d{1,3}|x{1,3})){3}(?![\w])", re.I)     # also 192.168.xxx.xxx
# IPv6 address: 3 to 8 groups of hex digits separated by colons (empty groups allowed, as in ::1).
_IPV6 = re.compile(r"(?<![\w:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![\w:])", re.I)
# MAC address (hardware address of a network card): six pairs of hex digits separated by ':' or '-', or the Cisco style of three groups of four digits separated by dots.
_MAC = re.compile(r"(?<![0-9a-f])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![0-9a-f])|(?<![0-9a-f])(?:[0-9a-f]{4}\.){2}[0-9a-f]{4}(?![0-9a-f])", re.I)
# E-mail address: name, '@', then a domain with at least one dot. Skips text already turned into a SECRET_n token (a password inside a URL).
_EMAIL = re.compile(r"(?<![\w.+-])(?!SECRET_\d+@)[\w.+-]+@[\w-]+(?:\.[\w-]+)+")   # not a password token from a URL
# A user's home folder on Linux (/home/), Mac (/Users/) or Windows (a drive letter then Users); the second group is the account name that gets replaced.
_HOME_PATH = re.compile(r"(/home/|/Users/|[A-Za-z]:\\Users\\)([^/\\\s\"']+)")
# A `ps aux` line (ProcessMonitorAgent findings): USER PID %CPU %MEM VSZ RSS ... The first column is a user name.
_PS_USER = re.compile(r"(?m)(^|:\s*)([A-Za-z_][\w.-]{0,31}\$?)(\s+\d+\s+\d+(?:\.\d+)?\s+\d+(?:\.\d+)?\s+\d+\s+\d+\s)")
# A user name written into a log line (audit F-08). Covers the phrasing the auth log and sudo use:
#   "Failed password for bob from ...", "session opened for user bob", "user=bob", "logname=bob",
#   "sudo:  bob : TTY=pts/0 ; ...". A name is only found after one of these cues, so ordinary words are left alone.
#   "Invalid user admin" is deliberately NOT here: that name is whatever an attacker typed, and it is evidence.
_LOG_USER = re.compile(
    r"(?i)(\b(?:(?:failed|accepted)\s+\w+\s+for\s+(?!invalid\s+user\b)|for\s+user\s+|"
    r"(?:r?user(?:name)?|logname|acct)\s*[=:]\s*)|\bsudo:\s+)([A-Za-z_][\w.-]{0,31}\$?)(?=\s|$|[,;:)\]\"'])")
_SYSTEM_ACCOUNTS = ("root", "nobody", "daemon", "unknown", "none", "null")
# Threat reports write dots as [.] (.) {.} [dot] or (dot) so links cannot be clicked; this matches those so they can be turned back into real dots before looking for addresses.
_DEFANG = re.compile(r"\s?(?:\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\))\s?", re.I)   # threat-report "defanged" dots
# A host or domain name that ends in a private-network suffix such as .local or .corp (the list is _INTERNAL_SUFFIXES), e.g. printer.home.lan.
_DOTTED_NAME = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?:%s)\b" % "|".join(_INTERNAL_SUFFIXES), re.I)

# ── credentials (2026-09-26) ────────────────────────────────────────────────
# Process command lines and log lines can carry them (sshpass -p, echo pw | sudo -S, API keys in env or flags). They
# become SECRET_n. Deliberately NOT a generic "long random string" rule: file hashes are evidence the analysis needs.
_SECRET_WORDS = (r"pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key"
                 r"|client[_-]?secret|credentials?|auth(?:orization)?|session[_-]?id|cookie")
# The value part of a credential: a double-quoted string, a single-quoted string, or a run of characters up to the next space, quote or separator. Ignores values already replaced by SECRET_n.
_SECRET_VALUE = r"(?!SECRET_\d)(?:\"[^\"]*\"|'[^']*'|[^\s\"'&;,|]+)"
_SECRET_FORMATS = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)"      # PEM private key (may be cut off)
    r"|\b(?:sk-(?:ant-|or-v1-|proj-)?[A-Za-z0-9_-]{20,}"                                 # OpenAI / Anthropic / OpenRouter
    r"|gsk_[A-Za-z0-9]{20,}|hf_[A-Za-z0-9]{30,}|AIza[0-9A-Za-z_-]{35}"                   # Groq / Hugging Face / Google
    r"|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|xox[abprs]-[A-Za-z0-9-]{10,}"  # GitHub / Slack
    r"|AKIA[0-9A-Z]{16}|cfut_[A-Za-z0-9_-]{30,}"                                         # AWS key id / Cloudflare token
    r"|eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})",                 # JWT
    re.S)
# A password inside a URL, as in scheme://user:PASSWORD@host. Groups: the part before the password, the password, the '@'.
_URL_PASSWORD = re.compile(r"(\b[a-z][a-z0-9+.-]*://[^\s:/@]+:)([^\s@/]+)(@)", re.I)
# The password given on an `sshpass -p` command line.
_SSHPASS = re.compile(r"(\bsshpass\s+-p\s*)(" + _SECRET_VALUE + ")")
# A password piped into sudo, as in `echo PASSWORD | sudo -S ...` (-S makes sudo read the password from standard input).
_SUDO_S = re.compile(r"(\becho\s+)(" + _SECRET_VALUE + r")(\s*\|\s*sudo\b[^|\n]*?\s-S\b)")
# The token after 'Bearer' or 'Basic' in an Authorization header. It must be 12+ characters and contain a digit, so ordinary words after 'basic' are left alone.
_AUTH_HEADER = re.compile(r"(?i)(\b(?:bearer|basic)\s+)((?=[A-Za-z0-9._~+/=-]*\d)[A-Za-z0-9._~+/=-]{12,})")
# Any name containing a secret-sounding word (password, token, api_key ...) followed by '=' or ':' and a value, e.g. password=hunter2 or "api_key": "abc". Only the value is replaced.
_KEY_VALUE = re.compile(r"(?i)((?<![\w-])[\w.-]*(?:" + _SECRET_WORDS + r")[\w.-]*[\"']?\s*[=:]\s*)(" + _SECRET_VALUE + ")")
# A command-line flag containing a secret-sounding word followed by its value, e.g. --password hunter2 or -token abc. Only the value is replaced.
_FLAG_VALUE = re.compile(r"(?i)((?<![\w-])--?[\w-]*(?:" + _SECRET_WORDS + r")[\w-]*\s+)(?!-)(" + _SECRET_VALUE + ")")


def _private_names() -> List[str]:
    """Names that must never leave: this machine's own name, SSAI_PRIVATE_NAMES (the ledger uses the same list) and
    SSAI_INTERNAL_DOMAINS (your own domain, e.g. corp.example.com)."""
    names = set()
    try:
        names.add(socket.gethostname().split(".")[0])
    except OSError:
        pass
    for var in ("SSAI_PRIVATE_NAMES", "SSAI_INTERNAL_DOMAINS", "NODE_ID"):
        names.update(n.strip() for n in os.environ.get(var, "").split(",") if n.strip())
    return sorted((n for n in names if len(n) >= 3), key=len, reverse=True)


class _TokenMap:
    """value -> stable token, in memory only. Case-insensitive. Never persisted, sent or logged."""

    def __init__(self):
        self._lock = threading.Lock()
        self._map: Dict[tuple, str] = {}
        self._count: Dict[str, int] = {}

    def token(self, kind: str, value: str) -> str:
        """Return the placeholder (like IP_1) for this value, creating the next number for that kind the first time it is seen.
        The same value always gets the same placeholder, so an analysis still makes sense.
        """
        key = (kind, value.strip().lower())
        with self._lock:
            if key not in self._map:
                if len(self._map) >= MAX_TOKENS:          # bounded: start over rather than grow without limit
                    self._map.clear()
                    self._count.clear()
                self._count[kind] = self._count.get(kind, 0) + 1
                self._map[key] = f"{kind}_{self._count[kind]}"
            return self._map[key]


_TOKENS = _TokenMap()


class Redactor:
    """Applies the redaction rules to one string and counts what it replaced (counts only, never values)."""

    def __init__(self, tokens: _TokenMap = _TOKENS, extra_names: Optional[List[str]] = None, keep_public_ips: bool = False):
        self.keep_public_ips = keep_public_ips      # the public ledger shows attacker addresses; the cloud gate never does
        self.tokens = tokens
        self.names = sorted(set(_private_names()) | {n for n in (extra_names or []) if len(n) >= 3}, key=len, reverse=True)
        self.counts: Dict[str, int] = {}

    def _sub(self, kind: str, match: "re.Match") -> str:
        self.counts[kind] = self.counts.get(kind, 0) + 1
        return self.tokens.token(kind, match.group(0))

    def _secret_in(self, match: "re.Match", group_number: int = 2) -> str:
        """Replace one group of the match (the credential itself) with a token; keep the rest, e.g. the key name and
        separator."""
        self.counts["SECRET"] = self.counts.get("SECRET", 0) + 1
        whole = match.group(0)
        offset = match.start(0)                        # where the whole match begins; group positions are measured from the text start
        secret_begins = match.start(group_number) - offset
        secret_ends = match.end(group_number) - offset
        token = self.tokens.token("SECRET", match.group(group_number))
        return whole[:secret_begins] + token + whole[secret_ends:]

    def _home(self, match: "re.Match") -> str:
        self.counts["USER"] = self.counts.get("USER", 0) + 1
        return match.group(1) + self.tokens.token("USER", match.group(2))

    def _log_user(self, match: "re.Match") -> str:
        user = match.group(2)
        if user.lower() in _SYSTEM_ACCOUNTS or re.fullmatch(r"USER_\d+", user):   # system accounts identify no one; already a token
            return match.group(0)
        self.counts["USER"] = self.counts.get("USER", 0) + 1
        return match.group(1) + self.tokens.token("USER", user)

    def _address(self, match: "re.Match") -> str:
        """An IPv4 address becomes a token, except (ledger mode) one that is a public internet address."""
        if self.keep_public_ips and ("x" in match.group(0).lower() or is_public_address(match.group(0))):
            return match.group(0)
        return self._sub("IP", match)

    def _ps_user(self, match: "re.Match") -> str:
        user = match.group(2)
        if user in ("root", "nobody", "daemon"):              # system accounts identify no one
            return match.group(0)
        self.counts["USER"] = self.counts.get("USER", 0) + 1
        return match.group(1) + self.tokens.token("USER", user) + match.group(3)

    def _ipv6(self, match: "re.Match") -> str:
        """Replace an IPv6 address with a token, unless it is not really an address or (ledger mode) is a public one."""
        address = match.group(0)
        try:
            ipaddress.IPv6Address(address)
        except ValueError:
            return address                                       # not an address (a time like 12:30:45 has too few groups)
        if self.keep_public_ips and is_public_address(address):
            return address
        return self._sub("IP", match)

    def redact(self, text: str) -> str:
        """Return `text` with every secret, address, name and account replaced by a placeholder token.
        The order matters: credentials go first so later rules cannot split them up.
        """
        cleaned = _DEFANG.sub(".", str(text))   # 192[.]168[.]0[.]5 and box(.)corp(.)local are still addresses (red team, 2026-10-09)
        cleaned = _SECRET_FORMATS.sub(lambda match: self._sub("SECRET", match), cleaned)     # credentials first, before anything
        for rx in (_URL_PASSWORD, _SSHPASS, _SUDO_S, _AUTH_HEADER, _KEY_VALUE, _FLAG_VALUE):   # splits them up
            cleaned = rx.sub(self._secret_in, cleaned)
        cleaned = _EMAIL.sub(lambda match: self._sub("EMAIL", match), cleaned)
        cleaned = _HOME_PATH.sub(self._home, cleaned)
        cleaned = _PS_USER.sub(self._ps_user, cleaned)
        cleaned = _LOG_USER.sub(self._log_user, cleaned)
        cleaned = _MAC.sub(lambda match: self._sub("MAC", match), cleaned)
        cleaned = _IPV6.sub(self._ipv6, cleaned)
        cleaned = _IPV4.sub(self._address, cleaned)
        cleaned = _DOTTED_NAME.sub(lambda match: self._sub("HOST", match), cleaned)
        for name in self.names:                            # this network's own names, whole words, any case
            cleaned = re.sub(r"(?<![\w-])%s(?![\w-])" % re.escape(name), lambda match: self._sub("HOST", match), cleaned, flags=re.I)
        return cleaned

    @staticmethod
    def private_leftovers(text: str) -> bool:
        """Ledger mode defence in depth: does a MAC, a private/internal address or a known key format survive? (Public
        addresses are meant to stay.)"""
        if _MAC.search(text) or _SECRET_FORMATS.search(text):
            return True
        return (any("x" not in m.group(0).lower() and not is_public_address(m.group(0)) for m in _IPV4.finditer(text))
                or any(_valid_v6(m.group(0)) and not is_public_address(m.group(0)) for m in _IPV6.finditer(text)))

    @staticmethod
    def leftovers(text: str) -> bool:
        """Defence in depth: does anything that looks like an address, MAC or known key format survive?"""
        if _MAC.search(text) or _IPV4.search(text) or _SECRET_FORMATS.search(text):
            return True
        return any(_valid_v6(m.group(0)) for m in _IPV6.finditer(text))


# Example addresses (RFC 5737 / 3849) are never inside anyone's network; the ledger keeps them like any other public address.
_DOCUMENTATION_NETS = tuple(ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"))


def is_public_address(value: str) -> bool:
    """True only for an address on the public internet. Private, loopback, link-local, Tailscale/CGNAT (100.64/10), documentation
    ranges and anything that is not a valid address (192.168.xxx.xxx) count as NOT public, so they are masked."""
    try:
        ip = ipaddress.ip_address(value.strip("[]"))
    except ValueError:
        return False
    return ip.is_global or any(ip.version == n.version and ip in n for n in _DOCUMENTATION_NETS)


def _valid_v6(s: str) -> bool:
    try:
        ipaddress.IPv6Address(s)
        return True
    except ValueError:
        return False


# ── audit log ───────────────────────────────────────────────────────────────
def audit_path() -> str:
    try:
        import ssai_config
        return os.path.join(ssai_config.INSTANCE_DIR, "cloud_audit.jsonl")
    except ImportError:
        return os.path.join(os.path.dirname(os.path.abspath(__file__)), "instance", "cloud_audit.jsonl")


def _audit(entry: dict, path: Optional[str] = None) -> None:
    """Append one line. Append-only: opened for append, never rewritten. Raises if it cannot write (caller fails closed)."""
    path = path or audit_path()
    import logsafe
    logsafe.append_line(path, json.dumps(entry, sort_keys=True))


# ── the gate ────────────────────────────────────────────────────────────────
def _destination(d):
    """Normalise the destination label: a short id or a sorted list of ids. Never raises."""
    try:
        if d is None:
            return None
        if isinstance(d, (list, tuple, set)):
            ids = sorted({str(x)[:64] for x in d if x})
            return ids or None
        return str(d)[:64] or None
    except Exception:                                             # noqa: BLE001
        return None



def _timestamp(v) -> Optional[str]:
    """Convert a date (datetime object or ISO text, with or without a zone) to UTC text like 2026-10-22T14:03:00Z, or
    None if it cannot be read."""
    if isinstance(v, datetime):
        dt = v
    else:
        try:
            dt = datetime.fromisoformat(str(v).strip().replace("Z", "+00:00"))
        except ValueError:
            return None
    dt = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sanitize_for_cloud(payload, *, audit_file: Optional[str] = None, extra_names: Optional[List[str]] = None,
                       tokens: _TokenMap = _TOKENS, destination=None) -> dict:
    """Return the sanitized copy of `payload` that may be sent to the cloud, or {} if anything goes wrong (do not send).

    destination: who it is for (a provider id from config/provider_approvals.json, or a list of them). It is written
    to the audit log, so the log shows not just WHAT crossed but to WHOM: the evidence for the "data submitted" row
    of the shared-responsibility table (docs/third-party-ai/README.md)."""
    dest = _destination(destination)
    try:
        if not isinstance(payload, dict):
            raise TypeError("payload must be a dict")
        red = Redactor(tokens, extra_names)
        out: dict = {}

        sev = str(payload.get("severity", "")).strip().lower()
        if sev in SEVERITIES:
            out["severity"] = sev

        tt = str(payload.get("threat_type", "")).strip().lower()
        if re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", tt):
            out["threat_type"] = red.redact(tt)

        if "timestamp" in payload:
            ts = _timestamp(payload["timestamp"])
            if ts:
                out["timestamp"] = ts

        summary = payload.get("sanitized_summary")
        if isinstance(summary, str) and summary.strip():
            out["sanitized_summary"] = red.redact(summary.strip()[:2000])[:MAX_SUMMARY]

        if any(Redactor.leftovers(v) for v in out.values() if isinstance(v, str)):
            raise ValueError("an address survived redaction")

        dropped = sorted(k for k in payload if k not in out)      # names only, never values
        _audit({"ts": datetime.now(timezone.utc).isoformat(), "sent": out, "dropped_fields": dropped,
                "redactions": red.counts, "ok": True, **({"to": dest} if dest else {})}, audit_file)
        return out
    except Exception as exc:                                      # noqa: BLE001 -- fail closed, whatever went wrong
        log.warning("sanitize_for_cloud dropped a payload: %s: %s", type(exc).__name__, exc)
        try:
            _audit({"ts": datetime.now(timezone.utc).isoformat(), "sent": None, "ok": False,
                    "reason": type(exc).__name__, **({"to": dest} if dest else {})}, audit_file)
        except Exception as audit_exc:                            # noqa: BLE001 -- the payload is already refused; all we can do is say the record is missing
            log.error("cloud audit entry for a REFUSED payload could not be written (%s); the refusal itself still holds",
                      type(audit_exc).__name__)
        return {}
