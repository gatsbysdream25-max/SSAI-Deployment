"""Direct checks: before anything acts on a finding, look again at the machine itself (2026-11-15 sync, rebuilt 2026-11-16).

A finding is a report from the past. The AI panel judges the report, not the machine. These checks ask the machine, now:

    suspicious-process          is that process id still running with the same command line?
    unexpected-listener,
    suspicious-port (this host) is the port still listening?
    c2-beacon, intel-match(ip)  is the connection to that address still open?
    brute-force, distributed-*  does auth.log show failed logins from that address in the last 48 hours?
    brute-force-success         does auth.log show a login from that address after failures?
    intel-match, malicious-domain, malware-url
                                does a loaded threat feed still list the indicator?

Each answer is one of:
    confirmed       the machine shows it now
    not-confirmed   the check ran and did NOT see it (the process is gone, the port is closed ...)
    inconclusive    no check exists for this kind, the finding came from another machine, or the check could not run

Everything here is READ-ONLY: it lists processes and sockets and reads logs; it never changes, stops or blocks anything.
`check()` never raises: any error is "inconclusive", which means "a person decides", never "act".
"""
from __future__ import annotations

import os
import re
import socket
import subprocess
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

CONFIRMED, NOT_CONFIRMED, INCONCLUSIVE = "confirmed", "not-confirmed", "inconclusive"
AUTH_LOG = "/var/log/auth.log"
AUTH_WINDOW = timedelta(hours=48)
AUTH_TAIL_BYTES = 4 * 1024 * 1024


def _sibling(name: str):
    """Import a module from this folder whether we were loaded as `agents.live_checks` (web app) or `live_checks` (agents)."""
    import importlib
    try:
        return importlib.import_module(f"agents.{name}")
    except ImportError:
        return importlib.import_module(name)


def _addr():
    """agent_util: the one IPv4 + IPv6 address reader every agent uses (find_ip, find_ip_port, ssh_source, split_host_port)."""
    return _sibling("agent_util")


def _show(ip: str, port=None) -> str:
    """203.0.113.5:22, [2001:db8::5]:22, or the bare address."""
    if port is None:
        return ip
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


def _result(result: str, check: str, detail: str) -> dict:
    return {"result": result, "check": check, "detail": detail[:300],
            "at": datetime.now(timezone.utc).isoformat(timespec="seconds")}


def _this_machine() -> set:
    names = {socket.gethostname().lower()}
    if os.environ.get("SSAI_NODE_ID"):
        names.add(os.environ["SSAI_NODE_ID"].lower())
    return names


def is_local(threat: dict) -> bool:
    """Did THIS machine report the finding? Another machine's processes, ports and logs cannot be checked from here."""
    if "@" in str(threat.get("detected_by") or ""):
        return False                                         # the hub adds '@<node>' to every node's submission
    node = str(threat.get("node_id") or "").lower()
    return node == "" or node in _this_machine()


def _indicator(threat: dict) -> str:
    """The real indicator: the stored real address when the url is masked (192.168.xxx.xxx), otherwise the url."""
    return str(threat.get("real_source") or threat.get("real_url") or threat.get("url") or "")


# ── the individual checks (each takes injectable readers so tests never touch the real machine) ──

def process_running(threat: dict, read_cmdline: Callable[[str], Optional[str]]) -> dict:
    m = re.match(r"process://(\d+)", str(threat.get("url") or ""))
    if not m:
        return _result(INCONCLUSIVE, "process", "the finding names no process id")
    pid = m.group(1)
    current = read_cmdline(pid)
    if current is None:
        return _result(NOT_CONFIRMED, "process", f"process {pid} is no longer running")
    # the agent stored "... ({pattern}): {user} {pid} {command line[:150]}"
    desc = str(threat.get("description") or "")
    reported = desc.split(f" {pid} ", 1)[1].strip() if f" {pid} " in desc else ""
    if not reported:
        return _result(INCONCLUSIVE, "process", f"process {pid} runs, but the finding does not say which command line it had")
    if " ".join(current.split())[:150] == " ".join(reported.split())[:150]:
        return _result(CONFIRMED, "process", f"process {pid} is still running the same command line")
    return _result(NOT_CONFIRMED, "process", f"process id {pid} now belongs to a different program (the original ended)")


def port_listening(threat: dict, ss: Callable[[list], str]) -> dict:
    m = re.search(r":(\d{1,5})\b", str(threat.get("url") or ""))
    if not m:
        return _result(INCONCLUSIVE, "port", "the finding names no port")
    port = m.group(1)
    out = ss(["ss", "-tln"])
    if any(re.search(rf":{port}\s", line) for line in out.splitlines()[1:]):
        return _result(CONFIRMED, "port", f"port {port} is listening now")
    return _result(NOT_CONFIRMED, "port", f"nothing is listening on port {port} now")


def connection_open(threat: dict, ss: Callable[[list], str]) -> dict:
    ind = _indicator(threat)
    au = _addr()
    ip, port = au.find_ip_port(ind) or (au.find_ip(ind), None)          # IPv4 or IPv6 (2026-11-18)
    if not ip:
        return _result(INCONCLUSIVE, "connection", "the finding names no address")
    out = ss(["ss", "-tn", "state", "established"])
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 4:
            continue
        host, peer_port = au.split_host_port(parts[3])
        if host and au.normalise_ip(host) == ip and (port is None or peer_port == port):
            return _result(CONFIRMED, "connection", f"a connection to {_show(ip, port)} is open now")
    return _result(NOT_CONFIRMED, "connection", f"no open connection to {_show(ip, port)} now")


def _auth_lines(read_tail: Callable[[str, int], Optional[str]]) -> Optional[list]:
    text = read_tail(AUTH_LOG, AUTH_TAIL_BYTES)
    return None if text is None else text.splitlines()


def _recent(line: str, now: datetime) -> bool:
    when = _sibling("change_evidence").line_time(line, now)   # same timestamp reader (ISO, dpkg and classic syslog stamps)
    return when is not None and now - when <= AUTH_WINDOW


def failed_login_count(ip: Optional[str], read_tail=None, now: Optional[datetime] = None) -> Optional[int]:
    """How many failed logins auth.log shows in the last 48 hours (from `ip`, or in total when ip is None); None when it
    cannot be read. The finding's own text is never trusted for this number (a merged finding keeps its first count)."""
    lines = _auth_lines(read_tail or _read_tail)
    if lines is None:
        return None
    now = now or datetime.now().astimezone()
    source = _addr().ssh_source
    return sum(1 for ln in lines if ("Failed password" in ln or "Invalid user" in ln) and _recent(ln, now)
               and (ip is None or source(ln) == ip))


def failed_logins(threat: dict, read_tail, now: datetime) -> dict:
    ind = _indicator(threat)
    ip = _addr().find_ip(ind)
    count = failed_login_count(ip, read_tail, now)
    if count is None:
        return _result(INCONCLUSIVE, "auth-log", "auth.log could not be read here")
    fails = range(count)
    if fails:
        who = f"from {ip}" if ip else "in total"
        return _result(CONFIRMED, "auth-log", f"{len(fails)} failed logins {who} in the last 48 hours")
    return _result(NOT_CONFIRMED, "auth-log", "no failed logins" + (f" from {ip}" if ip else "") + " in the last 48 hours")


def login_after_failures(threat: dict, read_tail, now: datetime) -> dict:
    lines = _auth_lines(read_tail)
    if lines is None:
        return _result(INCONCLUSIVE, "auth-log", "auth.log could not be read here")
    ind = _indicator(threat)
    au = _addr()
    ip, fails = au.find_ip(ind), 0
    if not ip:
        return _result(INCONCLUSIVE, "auth-log", "the finding names no address")
    for ln in lines:
        if au.ssh_source(ln) != ip or not _recent(ln, now):
            continue
        if "Failed password" in ln or "Invalid user" in ln:
            fails += 1
        elif "Accepted " in ln and fails >= 1:
            return _result(CONFIRMED, "auth-log", f"a login from {ip} followed {fails} failed attempts")
    return _result(NOT_CONFIRMED, "auth-log", f"auth.log shows no login from {ip} after failed attempts in the last 48 hours")


def feed_listed(threat: dict, store) -> dict:
    if store is None or not getattr(store, "stats", None) or not store.stats().get("entries"):
        return _result(INCONCLUSIVE, "threat-feed", "no threat feed is loaded on this machine")
    ind = _indicator(threat)
    au = _addr()
    with_port, bare = au.find_ip_port(ind), au.find_ip(ind)
    if with_port:
        hit = store.match_ip(with_port[0], with_port[1])
    elif bare:
        hit = store.match_ip(bare)
    else:
        host = re.sub(r"^[a-z]+://", "", ind, flags=re.I).split("/", 1)[0].split(":", 1)[0]
        domain = _sibling("intel").clean_domain(host)
        hit = store.match_domain(domain) if domain else None
    if hit:
        return _result(CONFIRMED, "threat-feed", f"{hit.get('source', 'a feed')} lists {hit.get('value', ind)} now")
    return _result(NOT_CONFIRMED, "threat-feed", "no loaded threat feed lists this indicator now")


# ── the dispatcher ───────────────────────────────────────────────────────────

def _read_cmdline(pid: str) -> Optional[str]:
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            return f.read().replace(b"\0", b" ").decode("utf-8", "replace").strip()
    except FileNotFoundError:
        return None
    except OSError:
        raise


def _ss(args: list) -> str:
    return subprocess.run(args, capture_output=True, text=True, timeout=10, check=True).stdout


def _read_tail(path: str, size: int) -> Optional[str]:
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            f.seek(max(0, f.tell() - size))
            return f.read().decode("utf-8", "replace")
    except OSError:
        return None


def _default_store():
    """The agents' feed store when it is loaded (agent process); otherwise a fresh copy read from the IntelFeedAgent's cache file,
    because the web app process never downloads feeds itself."""
    try:
        intel = _sibling("intel")
        if intel.STORE.stats().get("entries"):
            return intel.STORE
        import ssai_config
        store = intel.IntelStore()
        store.load(os.path.join(ssai_config.INSTANCE_DIR, "intel_cache.json"))
        return store
    except Exception:                                       # noqa: BLE001
        return None


def check(threat: dict, *, read_cmdline=None, ss=None, read_tail=None, store=None, now: Optional[datetime] = None) -> dict:
    """Run the direct check that fits this finding. Returns {'result', 'check', 'detail', 'at'}. Never raises."""
    try:
        t = dict(threat or {})
        kind = str(t.get("type") or "").strip().lower()
        now = now or datetime.now().astimezone()
        read_cmdline, ss, read_tail = read_cmdline or _read_cmdline, ss or _ss, read_tail or _read_tail
        if kind in ("intel-match", "malicious-domain", "malware-url"):
            feed = feed_listed(t, store if store is not None else _default_store())
            if kind != "intel-match" or feed["result"] == CONFIRMED or not is_local(t):
                return feed
        if not is_local(t):
            return _result(INCONCLUSIVE, "none", "the finding came from another machine; its processes, ports and logs "
                                                 "cannot be checked from here")
        if kind == "suspicious-process":
            return process_running(t, read_cmdline)
        if kind in ("unexpected-listener",) or (kind == "suspicious-port" and str(t.get("url") or "").startswith("localhost:")):
            return port_listening(t, ss)
        if kind in ("c2-beacon", "intel-match"):
            return connection_open(t, ss)
        if kind in ("brute-force", "distributed-brute-force"):
            return failed_logins(t, read_tail, now)
        if kind == "brute-force-success":
            return login_after_failures(t, read_tail, now)
        return _result(INCONCLUSIVE, "none", f"there is no direct check for '{kind or 'unknown'}' findings")
    except Exception as exc:                                # noqa: BLE001 -- a failed check must never become "act"
        return _result(INCONCLUSIVE, "error", f"the check could not run ({type(exc).__name__})")
