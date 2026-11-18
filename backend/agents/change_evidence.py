"""Was a change to a protected account file harmless? Only with proof (2026-11-15 sync, rebuilt on the home build 2026-11-16).

HostHealthAgent watches /etc/passwd, /etc/group and /etc/shadow. Package installs legitimately add system accounts to them (for
example `apt install postgresql` adds a `postgres` user), and before this module every such install raised a "critical file
modified" finding that taught people to ignore the alert. This module lets the file check stay quiet ONLY when it can prove the
change is harmless:

  * every change is the creation of a system account (uid/gid below 1000) that cannot log in (nologin/false shell, locked or
    absent password) or of that account's own group, AND
  * the logs show why it happened at that moment: a package-manager run (dpkg/apt), or a real person's sudo command within minutes.

Everything else still alerts, and says what changed: a new account that can log in, a new member of sudo/adm/root/shadow/docker
(and the other admin groups), a password change, a deleted user, a changed uid/shell/home, a mode or owner change (handled by the
caller), an account-tool log line this module does not recognise, and any error inside the check itself. When in doubt, alert.

Snapshots never contain password hashes: for /etc/shadow only a short digest of the password field and whether it is locked.
The functions here read nothing from disk on their own; the caller passes file text and log lines, so the tests need no root.
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timedelta, timezone
from typing import Dict, Iterable, List, Optional, Tuple

ACCOUNT_FILES = ("/etc/passwd", "/etc/group", "/etc/shadow")
SYSTEM_ID_MAX = 999                     # Debian/Ubuntu: system uids/gids are 100-999, people start at 1000
NOLOGIN_SHELLS = {"/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false", "/bin/sync"}
PRIVILEGED_GROUPS = {"sudo", "adm", "root", "shadow", "docker", "wheel", "admin", "lxd", "disk", "libvirt", "kvm", "systemd-journal"}
WINDOW = timedelta(minutes=10)          # how close the explaining log line must be to the change
ACCOUNT_TOOLS = ("useradd", "groupadd", "usermod", "userdel", "groupdel", "groupmod", "gpasswd", "passwd", "chpasswd",
                 "chage", "adduser", "addgroup", "deluser", "delgroup", "newusers", "vipw", "vigr", "chsh", "chfn")

# Account-tool lines this module understands. Anything else from those tools means "we cannot explain it": alert.
_KNOWN_TOOL_LINES = (
    re.compile(r"\b(useradd|adduser)\[\d+\]: new user: name=([\w.-]+), UID=(\d+), GID=(\d+), home=\S*, shell=(\S+)"),
    re.compile(r"\b(groupadd|addgroup|useradd)\[\d+\]: (new group|group added to /etc/(group|gshadow)): name=([\w.-]+)"),
    re.compile(r"\b(useradd|groupadd)\[\d+\]: new group: name=([\w.-]+), GID=(\d+)"),
)


# ── snapshots ────────────────────────────────────────────────────────────────

def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:16]


def snapshot(path: str, text: str) -> Optional[dict]:
    """A comparable summary of an account file, or None for a file this module does not understand."""
    if path not in ACCOUNT_FILES:
        return None
    out: Dict[str, dict] = {}
    for line in (text or "").splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        f = line.split(":")
        if path == "/etc/passwd" and len(f) >= 7:
            out[f[0]] = {"uid": _int(f[2]), "gid": _int(f[3]), "home": f[5], "shell": f[6].strip()}
        elif path == "/etc/group" and len(f) >= 4:
            out[f[0]] = {"gid": _int(f[2]), "members": sorted(m for m in f[3].strip().split(",") if m)}
        elif path == "/etc/shadow" and len(f) >= 2:
            pw = f[1]
            out[f[0]] = {"pw": _digest(pw), "locked": pw.startswith(("!", "*")), "empty": pw == ""}
    return out


def _int(v: str) -> int:
    try:
        return int(v)
    except ValueError:
        return -1


# ── what changed ─────────────────────────────────────────────────────────────

def diff(path: str, old: dict, new: dict) -> List[Tuple[str, str, dict]]:
    """List of (kind, name, details) changes between two snapshots of the same file."""
    events: List[Tuple[str, str, dict]] = []
    for name in sorted(set(old) | set(new)):
        a, b = old.get(name), new.get(name)
        if a is None:
            events.append(("added", name, b))
        elif b is None:
            events.append(("removed", name, a))
        elif a != b:
            if path == "/etc/group" and a.get("gid") == b.get("gid"):
                for m in sorted(set(b["members"]) - set(a["members"])):
                    events.append(("member-added", name, {"member": m, "gid": b["gid"]}))
                for m in sorted(set(a["members"]) - set(b["members"])):
                    events.append(("member-removed", name, {"member": m}))
            elif path == "/etc/shadow" and a.get("pw") != b.get("pw"):
                events.append(("password-changed", name, b))
            else:
                events.append(("changed", name, {"before": a, "after": b}))
    return events


# ── log evidence ─────────────────────────────────────────────────────────────

_SYSLOG_TS = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2}) (\d{2}):(\d{2}):(\d{2})\s")
_ISO_TS = re.compile(r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.\d+)?(Z|[+-]\d{2}:?\d{2})?")
_MONTHS = {m: i for i, m in enumerate(("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1)}


def line_time(line: str, now: datetime) -> Optional[datetime]:
    """When a log line was written (UTC), from an ISO, dpkg or classic syslog timestamp; None if it has none."""
    m = _ISO_TS.match(line)
    if m:
        tz = m.group(3)
        try:
            stamp = datetime.fromisoformat(f"{m.group(1)}T{m.group(2)}")
        except ValueError:
            return None
        if tz in (None, ""):
            return stamp.replace(tzinfo=now.tzinfo or timezone.utc)
        if tz == "Z":
            return stamp.replace(tzinfo=timezone.utc)
        sign = 1 if tz[0] == "+" else -1
        digits = tz[1:].replace(":", "")
        return (stamp.replace(tzinfo=timezone.utc)
                - sign * timedelta(hours=int(digits[:2]), minutes=int(digits[2:])))
    m = _SYSLOG_TS.match(line)
    if m:
        month = _MONTHS.get(m.group(1))
        if month is None:
            return None
        year = now.year - (1 if month > now.month else 0)          # December lines read in January
        try:
            return datetime(year, month, int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(5)),
                            tzinfo=now.tzinfo or timezone.utc)
        except ValueError:
            return None
    return None


_PKG = re.compile(r"(\bstatus (installed|half-configured|unpacked)\b|\b(configure|install|upgrade|remove) \S+:\S+|^Start-Date:|"
                  r"\bCommandline: (apt|apt-get|aptitude|dpkg)\b)")
_SUDO = re.compile(r"\bsudo(?:\[\d+\])?:\s+([\w.-]+) : .*COMMAND=")


def _tool_of(line: str) -> Optional[str]:
    m = re.search(r"\b(" + "|".join(ACCOUNT_TOOLS) + r")\[\d+\]:", line)
    return m.group(1) if m else None


def evidence(lines: Iterable[str], change_time: datetime, people: Dict[str, int]) -> dict:
    """What the logs say happened around `change_time`: {'package': bool, 'sudo_by': [users], 'unknown': [lines],
    'tool_lines': [lines]}. `people` maps user name -> uid (from /etc/passwd) so a sudo by a real person (uid >= 1000) counts."""
    out = {"package": False, "sudo_by": [], "unknown": [], "tool_lines": []}
    for raw in lines:
        line = raw.rstrip("\n")
        when = line_time(line, change_time)
        if when is None or abs(when - change_time) > WINDOW:
            continue
        if _PKG.search(line):
            out["package"] = True
            continue
        m = _SUDO.search(line)
        if m:
            user = m.group(1)
            if people.get(user, -1) > SYSTEM_ID_MAX and when <= change_time + timedelta(minutes=1):
                out["sudo_by"].append(user)
            continue
        if _tool_of(line):
            out["tool_lines"].append(line)
            if not any(p.search(line) for p in _KNOWN_TOOL_LINES):
                out["unknown"].append(line)
    return out


# ── the decision ─────────────────────────────────────────────────────────────

def _harmless_event(path: str, kind: str, name: str, info: dict, passwd_new: dict, group_new: dict) -> Tuple[bool, str]:
    """Is ONE change, on its own, the kind that can be harmless? (The caller still needs log evidence.)"""
    if kind == "added" and path == "/etc/passwd":
        if info.get("uid", -1) < 0 or info["uid"] > SYSTEM_ID_MAX:
            return False, f"new account {name} is a person's account (uid {info.get('uid')})"
        if info.get("uid") == 0:
            return False, f"new account {name} has uid 0 (root)"
        if info.get("shell") not in NOLOGIN_SHELLS:
            return False, f"new account {name} can log in (shell {info.get('shell')})"
        return True, ""
    if kind == "added" and path == "/etc/shadow":
        if info.get("empty"):
            return False, f"new account {name} has an EMPTY password (anyone can log in)"
        if not info.get("locked"):
            return False, f"new account {name} has a password set"
        acct = passwd_new.get(name)
        if acct is not None and acct.get("shell") not in NOLOGIN_SHELLS:
            return False, f"new account {name} can log in (shell {acct.get('shell')})"
        return True, ""
    if kind == "added" and path == "/etc/group":
        if name in PRIVILEGED_GROUPS:
            return False, f"privileged group {name} was created"
        if info.get("gid", -1) < 0 or info["gid"] > SYSTEM_ID_MAX or info["gid"] == 0:
            return False, f"new group {name} is not a system group (gid {info.get('gid')})"
        for m in info.get("members", []):
            if passwd_new.get(m, {}).get("uid", 0) > SYSTEM_ID_MAX:
                return False, f"new group {name} contains the person {m}"
        return True, ""
    if kind == "member-added":
        if name in PRIVILEGED_GROUPS:
            return False, f"{info.get('member')} was added to the privileged group {name}"
        member = passwd_new.get(info.get("member", ""), {})
        if member.get("uid", 1000) > SYSTEM_ID_MAX or member.get("shell") not in NOLOGIN_SHELLS:
            return False, f"{info.get('member')} (an account that can log in) was added to group {name}"
        return True, ""
    if kind == "removed":
        return False, f"{'user' if path != '/etc/group' else 'group'} {name} was deleted"
    if kind == "password-changed":
        return False, f"the password of {name} was changed"
    if kind == "member-removed":
        return False, f"{info.get('member')} was removed from group {name}"
    return False, f"{name} was changed ({kind})"


def assess(path: str, old_text: Optional[str], new_text: str, log_lines: Iterable[str], change_time: datetime,
           passwd_text: Optional[str] = None, group_text: Optional[str] = None, old_snapshot: Optional[dict] = None) -> dict:
    """Decide whether a content change to `path` may be skipped. Never raises.

    Returns {'harmless': bool, 'reason': plain words, 'changes': [short descriptions]}. `old_snapshot` (stored by the caller)
    is used when the previous text is not available. `passwd_text`/`group_text` are the CURRENT files, used to judge accounts
    named in another file."""
    try:
        return _assess(path, old_text, new_text, list(log_lines), change_time, passwd_text, group_text, old_snapshot)
    except Exception as exc:                                      # noqa: BLE001 -- an error in the check must mean "alert"
        return {"harmless": False, "reason": f"the change check failed ({type(exc).__name__}), so it is reported", "changes": []}


def _assess(path, old_text, new_text, log_lines, change_time, passwd_text, group_text, old_snapshot) -> dict:
    if path not in ACCOUNT_FILES:
        return {"harmless": False, "reason": "not an account file: every content change is reported", "changes": []}
    old = old_snapshot if old_snapshot is not None else (snapshot(path, old_text) if old_text is not None else None)
    if old is None:
        return {"harmless": False, "reason": "no earlier copy to compare with", "changes": []}
    new = snapshot(path, new_text)
    events = diff(path, old, new)
    changes = [f"{k} {n}" + (f" ({i.get('member')})" if k.startswith("member") else "") for k, n, i in events]
    if not events:
        # The bytes changed but nothing account-related did (comments, ordering, whitespace): we cannot explain a change we
        # cannot see, so it is still reported.
        return {"harmless": False, "reason": "the file changed but no account changed (comments or order?)", "changes": []}
    passwd_new = snapshot("/etc/passwd", passwd_text) if passwd_text is not None else (new if path == "/etc/passwd" else {})
    group_new = snapshot("/etc/group", group_text) if group_text is not None else (new if path == "/etc/group" else {})
    for kind, name, info in events:
        ok, why = _harmless_event(path, kind, name, info, passwd_new or {}, group_new or {})
        if not ok:
            return {"harmless": False, "reason": why, "changes": changes}
    people = {u: a.get("uid", -1) for u, a in (passwd_new or {}).items()}
    ev = evidence(log_lines, change_time, people)
    if ev["unknown"]:
        return {"harmless": False, "reason": f"an account-tool log line was not recognised: {ev['unknown'][0][:160]}",
                "changes": changes}
    if ev["package"]:
        return {"harmless": True, "reason": "system account(s) created during a package-manager run", "changes": changes}
    if ev["sudo_by"]:
        return {"harmless": True, "reason": f"system account(s) created within minutes of a sudo by {ev['sudo_by'][0]}",
                "changes": changes}
    return {"harmless": False, "reason": "no package-manager run or person's sudo explains this change", "changes": changes}
