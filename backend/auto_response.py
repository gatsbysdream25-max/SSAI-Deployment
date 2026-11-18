"""Automatic response: a few narrow actions SSAI may take ON ITS OWN, only after a person switches them on (2026-11-15 sync).

    block-attacker-ip   block an address that failed 20+ logins here in the last 48 hours (auth.log is counted, not the finding)
    block-bad-ip        block an address a loaded threat feed lists
    block-bad-domain    block a domain a loaded threat feed lists (Pi-hole)
    freeze-process      pause (SIGSTOP) a miner or reverse-shell process owned by a person's account, so a person can look

Invariants (each has a test in tools/test_auto_response.py):
  * the master switch and all four actions are OFF by default; DRY RUN is ON by default and only the JSON value `false` turns
    it off. A missing, unreadable or broken policy file means: everything off, dry run on.
  * only a signed-in person (never an API key) changes the policy, presses Undo or Terminate (routes/auto_response.py).
  * every automatic action writes its audit line BEFORE acting; if that line cannot be written, nothing happens.
  * never an address inside the organisation, the hub itself or the never-block list; never a finding reported by another
    machine; never a process that does not belong to a person's account (uid 1000 or above), nor SSAI's own process.
  * at most HOURLY_CAP (10) automatic actions per hour, counting these AND the autonomy grants' automatic approvals. A live
    action that hits the cap engages break-glass (break_glass.py), which stops every automatic action until a person releases it.
  * never a program on the never-pause list (DEFAULT_NEVER_PAUSE plus SSAI_NEVER_PAUSE).
  * a direct check of the machine (agents/live_checks.py) must confirm the finding at that moment.
  * the ACTION-RISK POLICY (action_risk.py, Week 2) decides by severity: when a finding arrives only LOW findings may be acted
    on; MEDIUM waits for the AI panel's verdict (on_verdict) and needs full consensus (2+ independent model families, judged
    from the hub's own registry); HIGH and CRITICAL always go to a person, except the consensus-gated PAUSE of a miner or
    reverse shell, which is off by default and can only be switched on once an alert channel has been tested.
  * every block ends after its time limit (default 24 h) unless a person ends it earlier (Undo). A PAUSE never ends by itself:
    it stays paused until a person chooses Resume (Undo), Terminate or Keep paused, so a timer never lets an attacker back in.
  * every live automatic action raises an alert (alerts.py).

Dry run records "would have" rows (with the same checks) and touches nothing.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import signal
from datetime import datetime, timedelta, timezone
from typing import Optional

log = logging.getLogger("auto_response")

ACTIONS = ("block-attacker-ip", "block-bad-ip", "block-bad-domain", "freeze-process")
HOURLY_CAP = 10
ATTACKER_MIN_FAILS = 20
DEFAULT_HOURS = 24
MAX_HOURS = 24 * 7
PERSON_UID_MIN = 1000
NOBODY_UIDS = {65534, 4294967295}

MINER_PATTERNS = {"cryptominer", "xmrig", "minerd", "cgminer", "ccminer", "cpuminer", "nbminer", "phoenixminer", "miner-args"}
SHELL_PATTERNS = {"netcat-exec", "bash-devtcp", "interpreter-revshell", "socat-exec", "awk-inet", "openssl-shell", "fifo-shell"}


# ── policy ───────────────────────────────────────────────────────────────────

def policy_path() -> str:
    import ssai_config
    return os.path.join(ssai_config.INSTANCE_DIR, "auto_response.json")


def defaults() -> dict:
    import action_risk
    return {"enabled": False, "dry_run": True,
            "actions": {a: {"enabled": False, "hours": DEFAULT_HOURS} for a in ACTIONS},
            "consensus": dict(action_risk.DEFAULT_STANDARD), "consensus_pause": False}


def _hours(v) -> int:
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return DEFAULT_HOURS
    return int(v) if 1 <= v <= MAX_HOURS else DEFAULT_HOURS


def normalise(raw) -> dict:
    """A safe policy from whatever was stored or sent: switches are on only when literally `true`; dry run is off only when
    literally `false`."""
    pol = defaults()
    if not isinstance(raw, dict):
        return pol
    pol["enabled"] = raw.get("enabled") is True
    pol["dry_run"] = raw.get("dry_run") is not False
    acts = raw.get("actions") if isinstance(raw.get("actions"), dict) else {}
    for a in ACTIONS:
        one = acts.get(a) if isinstance(acts.get(a), dict) else {}
        pol["actions"][a] = {"enabled": one.get("enabled") is True, "hours": _hours(one.get("hours", DEFAULT_HOURS))}
    import action_risk
    pol["consensus"] = action_risk.standard(raw.get("consensus"))      # SSAI's floors: 2 families, confidence 80
    pol["consensus_pause"] = raw.get("consensus_pause") is True
    return pol


def load_policy(path: Optional[str] = None) -> dict:
    try:
        with open(path or policy_path(), encoding="utf-8") as f:
            return normalise(json.load(f))
    except (OSError, ValueError):
        return defaults()


def save_policy(raw, who: str, audit_path: str, path: Optional[str] = None) -> dict:
    """Store a new policy (owner-only file, atomic rename). The change is audited BEFORE it is written."""
    import alerts
    import remediation
    pol = normalise(raw)
    if pol["consensus_pause"] and not alerts.a_channel_works():
        raise ActionError("the consensus-gated pause can only be switched on after a test alert has been sent and acknowledged "
                          "(Alerts, on this page)")
    remediation.audit_before_acting(audit_path, action="auto-response-policy", by=who, policy=pol)
    path = path or policy_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(pol, f, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    return pol


# ── what a finding asks for ──────────────────────────────────────────────────

def _pattern_of(description: str) -> str:
    """The rule name ProcessMonitorAgent put in brackets: 'Suspicious process detected (xmrig): ...' -> 'xmrig'."""
    import re
    m = re.search(r"\(([\w./+-]+)\)", description or "")
    p = m.group(1) if m else ""
    for wrapper in ("busybox-", "toybox-"):
        if p.startswith(wrapper):
            p = p[len(wrapper):]
    return p


def wanted_action(threat_type: str, url: str, description: str) -> Optional[str]:
    t = (threat_type or "").lower()
    if t == "brute-force":
        return "block-attacker-ip"
    if t in ("intel-match", "malicious-domain", "malware-url"):
        import remediation
        try:
            kind = remediation.classify_target(url)["kind"]
        except remediation.TargetError:
            return None
        return "block-bad-ip" if kind == "ip" else "block-bad-domain"
    if t == "suspicious-process":
        p = _pattern_of(description)
        if p in MINER_PATTERNS or p in SHELL_PATTERNS:
            return "freeze-process"
    return None


# ── counting ─────────────────────────────────────────────────────────────────

def actions_last_hour(now: Optional[datetime] = None) -> int:
    """Automatic actions in the last hour, counting this module's rows (live or would-have) AND the autonomy grants' automatic
    approvals, so the two systems share one cap."""
    from models import AutoAction, PendingRemediation
    now = now or datetime.now(timezone.utc)
    since = now - timedelta(hours=1)
    mine = AutoAction.query.filter(AutoAction.created_at >= since,
                                   AutoAction.status.in_(("would-have", "done", "undone", "expired", "terminated"))).count()
    grants = PendingRemediation.query.filter(PendingRemediation.decided_by.like("auto:%"),
                                             PendingRemediation.decided_at >= since).count()
    return mine + grants


# ── processes ────────────────────────────────────────────────────────────────

def _proc_uid(pid: str) -> Optional[int]:
    try:
        with open(f"/proc/{pid}/status", encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.startswith("Uid:"):
                    return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        return None
    return None


def _proc_state(pid: str) -> Optional[str]:
    """The one-letter state from /proc/<pid>/stat ('T' = stopped), or None."""
    try:
        with open(f"/proc/{pid}/stat", encoding="utf-8", errors="replace") as f:
            return f.read().rsplit(")", 1)[1].split()[0]
    except (OSError, IndexError):
        return None


def _sha(text: str) -> str:
    return hashlib.sha256(" ".join((text or "").split()).encode("utf-8", "replace")).hexdigest()


class Deps:
    """Everything that touches the real machine, in one place so tests replace all of it."""

    def __init__(self, block=None, unblock=None, kill=None, check=None, read_cmdline=None, proc_uid=None, fail_count=None,
                 never_block=None, own_pids=None, never_pause=None, proc_state=None):
        import remediation
        from agents import live_checks
        self.block = block or remediation.block
        self.unblock = unblock or remediation.unblock
        self.kill = kill or os.kill
        self.check = check or live_checks.check
        self.read_cmdline = read_cmdline or live_checks._read_cmdline
        self.proc_uid = proc_uid or _proc_uid
        self.fail_count = fail_count or live_checks.failed_login_count
        self.never_block = never_block if never_block is not None else _never_block_ips()
        self.own_pids = own_pids if own_pids is not None else {str(os.getpid()), str(os.getppid())}
        self.never_pause = never_pause if never_pause is not None else never_pause_names()
        self.proc_state = proc_state or _proc_state


# Programs SSAI never pauses on its own, matched by program name (Week 1 allowlist, 2026-11-17). A process wearing one of
# these names is still reported and still goes to a person; it is only the AUTOMATIC pause that is withheld, because pausing
# a real database or the model server would cause an outage. SSAI_NEVER_PAUSE (comma-separated names) adds to the list.
DEFAULT_NEVER_PAUSE = ("postgres", "mysqld", "mariadbd", "mongod", "redis-server", "ollama", "sshd", "systemd", "dockerd",
                       "containerd")


def never_pause_names() -> set:
    names = set(DEFAULT_NEVER_PAUSE)
    names.update(n.strip().lower() for n in (os.environ.get("SSAI_NEVER_PAUSE") or "").split(",") if n.strip())
    return names


def protected_program(command: str, names) -> Optional[str]:
    """The program's name when it is on the never-pause list, else None."""
    parts = (command or "").split()
    if not parts:
        return None
    prog = os.path.basename(parts[0]).lower()
    return prog if prog in names else None


def _never_block_ips():
    try:
        from app import _never_block_ips as nb
        return nb()
    except Exception:                                      # noqa: BLE001
        return {"127.0.0.1"}


# ── the decision ─────────────────────────────────────────────────────────────

def on_finding(threat, who_kind: str, audit_path: str, deps: Optional[Deps] = None, policy: Optional[dict] = None,
               now: Optional[datetime] = None, description: Optional[str] = None):
    """Called after a finding is stored or repeated. `description` is the newest report's wording when a repeat was merged
    into an older row (whose stored text is not changed). Returns the AutoAction row written, or None. Never raises."""
    try:
        policy = policy if policy is not None else load_policy()
        if not policy["enabled"]:
            return None                                    # the default: one small file read, nothing else
        import break_glass
        if break_glass.engaged():
            return None                                    # break-glass: nothing automatic, not even dry-run rows
        return _decide(threat, who_kind, audit_path, deps or Deps(), policy, now or datetime.now(timezone.utc),
                       description or threat.description)
    except Exception as exc:                               # noqa: BLE001 -- a response failing must never break ingest
        log.warning(f"automatic response skipped for finding {getattr(threat, 'id', '?')}: {type(exc).__name__}: {exc}")
        return None


def on_verdict(threat, consensus, audit_path: str, deps: Optional[Deps] = None, policy: Optional[dict] = None,
               now: Optional[datetime] = None, voters: Optional[dict] = None):
    """Called after the AI panel's verdict is saved on a finding. MEDIUM findings may be acted on here with full consensus;
    HIGH and CRITICAL only through the consensus-gated pause. Every other rule of _decide still applies. Never raises."""
    try:
        policy = policy if policy is not None else load_policy()
        if not policy["enabled"] or not isinstance(consensus, dict):
            return None
        import action_risk
        import alerts
        import break_glass
        if break_glass.engaged():
            return None
        description = threat.description
        action = wanted_action(threat.type, threat.real_source or threat.url, description)
        if action is None:
            return None
        from models import PendingRemediation
        if action != "freeze-process" and PendingRemediation.query.filter(
                PendingRemediation.threat_id == threat.id, PendingRemediation.status.in_(("approved", "approving"))).first():
            return None                                    # a permission already approved this block: never two blocks, two timers
        sev = action_risk.stricter(threat.severity, consensus.get("consensus_severity"))
        ok, why, gate = action_risk.after_verdict(sev, action, consensus, policy.get("consensus"),
                                                  policy.get("consensus_pause") is True, alerts.a_channel_works(), voters)
        if not ok:
            log.info(f"no automatic {action} for finding {threat.id} after the verdict: {why}")
            return None
        families = sorted(action_risk.agreeing_families(consensus, voters)) if gate != "low" else []
        return _decide(threat, "verdict", audit_path, deps or Deps(), policy, now or datetime.now(timezone.utc), description,
                       stage=gate, families=families)
    except Exception as exc:                               # noqa: BLE001 -- a response failing must never break the verdict save
        log.warning(f"automatic response after the verdict skipped for finding {getattr(threat, 'id', '?')}: "
                    f"{type(exc).__name__}: {exc}")
        return None


def _program(command: Optional[str]) -> str:
    parts = (command or "").split()
    return os.path.basename(parts[0])[:60] if parts else "?"


def _decide(threat, who_kind, audit_path, deps: Deps, policy: dict, now: datetime, description: str, stage: str = "arrival",
            families=()):
    from agents import live_checks
    import remediation
    import remediation_queue
    from models import AutoAction, db

    if who_kind == "node" or not live_checks.is_local({"detected_by": threat.detected_by, "node_id": threat.node_id}):
        return None                                        # another machine's finding: never acted on from here
    if (threat.status or "active") != "active":
        return None
    action = wanted_action(threat.type, threat.real_source or threat.url, description)
    if action is None:
        return None
    if stage == "consensus-pause":
        if action != "freeze-process" or policy.get("consensus_pause") is not True:
            return None                                    # its own switch (plus the master switch) governs it
    elif not policy["actions"][action]["enabled"]:
        return None
    if stage == "arrival":
        import action_risk
        ok, why = action_risk.at_arrival(threat.severity)
        if not ok:
            log.debug(f"no automatic {action} on arrival of finding {threat.id}: {why}")
            return None
    hours = policy["actions"][action]["hours"]

    # the target, and the places SSAI must never touch
    if action == "freeze-process":
        import re
        m = re.match(r"process://(\d+)$", threat.url or "")
        if not m:
            return None
        kind, target = "process", m.group(1)
        if target in deps.own_pids:
            return None
        uid = deps.proc_uid(target)
        if uid is None or uid < PERSON_UID_MIN or uid in NOBODY_UIDS:
            log.info(f"not pausing process {target}: it does not belong to a person's account (uid {uid})")
            return None
    else:
        try:
            tgt = remediation.classify_target(threat.real_source or threat.url)
        except remediation.TargetError:
            return None
        kind, target = tgt["kind"], tgt["value"]
        if kind == "ip" and (remediation_queue.internal_address(target) or target in deps.never_block):
            return None

    # the machine must confirm it NOW
    facts = {"id": threat.id, "type": threat.type, "url": threat.url, "description": description,
             "detected_by": threat.detected_by, "node_id": threat.node_id, "real_source": threat.real_source}
    direct = deps.check(facts)
    if direct.get("result") != "confirmed":
        return None
    if action == "block-attacker-ip":
        fails = deps.fail_count(target)
        if fails is None or fails < ATTACKER_MIN_FAILS:
            return None
    command = deps.read_cmdline(target) if kind == "process" else None
    if kind == "process" and not command:
        return None
    if kind == "process":
        protected = protected_program(command, deps.never_pause)
        if protected:
            log.info(f"not pausing process {target}: '{protected}' is on the never-pause list, so a person decides")
            return None

    # once per target while an earlier action still holds, and never more than the hourly cap
    if AutoAction.query.filter_by(action=action, target=target, status="done").first() is not None:
        return None                                        # already blocked or paused
    if AutoAction.query.filter_by(action=action, target=target, status="would-have").filter(
            AutoAction.created_at >= now - timedelta(hours=1)).first() is not None:
        return None                                        # dry run: one "would have" row per target an hour, not one per sighting
    if actions_last_hour(now) >= HOURLY_CAP:
        log.warning(f"automatic response cap reached ({HOURLY_CAP} an hour): {action} {target} left for a person")
        if not policy["dry_run"]:                          # a live action hit the cap: stop everything until a person looks
            import break_glass
            break_glass.trip_on_cap(audit_path, HOURLY_CAP)
        return None

    reason = f"{threat.type} finding {threat.id}: {direct.get('detail', '')}"[:400]
    if stage in ("consensus", "consensus-pause"):
        reason = f"{reason} [{stage}: {len(families)} independent model families agreed: {', '.join(families)}]"[:500]
    if policy["dry_run"]:
        remediation.audit_before_acting(audit_path, action=action, stage="would-have", target=target, threat=threat.id,
                                        by="auto-response (dry run)", reason=reason)
        row = AutoAction(threat_id=threat.id, action=action, kind=kind, target=target, dry_run=True, status="would-have",
                         detail=f"dry run: would have {'paused' if kind == 'process' else 'blocked'} {target}"
                                f"{' until a person decides' if kind == 'process' else f' for {hours} h'}. {reason}")
        db.session.add(row)
        db.session.commit()
        return row

    # live: record first, then act
    remediation.audit_before_acting(audit_path, action=action, stage="intent", target=target, threat=threat.id,
                                    by="auto-response", hours=hours, reason=reason)
    row = AutoAction(threat_id=threat.id, action=action, kind=kind, target=target, dry_run=False, status="failed",
                     command_sha=_sha(command) if command else None,
                     expires_at=None if kind == "process" else now + timedelta(hours=hours))   # a pause waits for a person
    try:
        if kind == "process":
            if deps.read_cmdline(target) != command:            # the process changed between the check and now
                raise RuntimeError("the process ended or changed just before pausing it")
            deps.kill(int(target), signal.SIGSTOP)
            row.detail = f"paused process {target} ({command[:150]}). {reason}"
        else:
            out = deps.block({"kind": kind, "value": target}, threat.id)
            row.detail = f"{out}. {reason}"
        row.status = "done"
    except Exception as exc:                                    # noqa: BLE001 -- reported on the row and in the audit
        row.detail = f"could not {'pause' if kind == 'process' else 'block'} {target}: {type(exc).__name__}: {exc}"[:500]
        row.expires_at = None
        # Part C bug (15 Nov): a pause was logged "failed" although the process had really stopped, and a failed row has no
        # Undo, so nobody could resume it from the dashboard. If the SAME program is now stopped, record it as paused.
        try:
            if kind == "process" and deps.proc_state(target) == "T" and deps.read_cmdline(target) == command:
                row.status = "done"
                row.detail = (f"paused process {target} ({command[:150]}): the pause call reported {type(exc).__name__}, "
                              f"but the process is stopped, so it is recorded as paused and can be resumed. {reason}")[:500]
        except Exception:                                       # noqa: BLE001 -- stays "failed"
            pass
    db.session.add(row)
    db.session.commit()
    remediation.audit(audit_path, action=action, stage="result", target=target, threat=threat.id, ok=row.status == "done",
                      auto_action=row.id, detail=row.detail, by="auto-response", gate=stage)
    if row.status == "done":
        import alerts
        what = f"paused program '{_program(command)}'" if kind == "process" else f"blocked {kind} {target}"
        title = ("Consensus-gated pause: " if stage == "consensus-pause" else "Automatic action: ") + what
        alerts.raise_alert("consensus-pause" if stage == "consensus-pause" else "auto-action", title,
                           f"finding {threat.id} ({threat.type}); gate: {stage}"
                           + (f"; families agreeing: {', '.join(families)}" if families else "")
                           + ("; it stays paused until a person chooses Resume, Terminate or Keep paused" if kind == "process" else ""),
                           finding=threat.id, action=action, auto_action=row.id,
                           level="critical" if stage == "consensus-pause" else "high")
    return row


# ── ending an action: Undo, Terminate, expiry ────────────────────────────────

class ActionError(ValueError):
    """Shown to the person who asked."""


def _same_process(row, deps: Deps) -> bool:
    current = deps.read_cmdline(row.target)
    return bool(current) and _sha(current) == row.command_sha


def undo(row_id: int, who: str, audit_path: str, deps: Optional[Deps] = None, now: Optional[datetime] = None):
    """A person ends an automatic block or pause early (unblock / SIGCONT)."""
    from models import AutoAction, db
    import remediation
    deps = deps or Deps()
    row = AutoAction.query.get(row_id)
    if row is None:
        raise ActionError("no such automatic action")
    if row.status != "done":
        raise ActionError(f"this action is {row.status}; only an active block or pause can be undone")
    remediation.audit_before_acting(audit_path, action="auto-undo", auto_action=row.id, target=row.target, by=who)
    _end(row, deps, "undone", who, now)
    db.session.commit()
    remediation.audit(audit_path, action="auto-undo", auto_action=row.id, target=row.target, ok=True, detail=row.detail, by=who)
    return row


def terminate(row_id: int, who: str, audit_path: str, deps: Optional[Deps] = None, now: Optional[datetime] = None):
    """A person ends a PAUSED program for good (SIGKILL), after checking it is still the same program."""
    from models import AutoAction, db
    import remediation
    deps = deps or Deps()
    row = AutoAction.query.get(row_id)
    if row is None:
        raise ActionError("no such automatic action")
    if row.kind != "process" or row.status != "done":
        raise ActionError("only a program that is still paused can be ended")
    if not _same_process(row, deps):
        raise ActionError("that process id now belongs to a different program (or none): nothing was ended")
    remediation.audit_before_acting(audit_path, action="auto-terminate", auto_action=row.id, target=row.target, by=who)
    deps.kill(int(row.target), signal.SIGKILL)
    row.status, row.ended_at, row.ended_by = "terminated", now or datetime.now(timezone.utc), who[:100]
    db.session.commit()
    remediation.audit(audit_path, action="auto-terminate", auto_action=row.id, target=row.target, ok=True, by=who)
    return row


def keep_paused(row_id: int, who: str, audit_path: str, now: Optional[datetime] = None):
    """A person has looked at a paused program and leaves it paused. Recorded; nothing is signalled."""
    from models import AutoAction, db
    import remediation
    row = AutoAction.query.get(row_id)
    if row is None:
        raise ActionError("no such automatic action")
    if row.kind != "process" or row.status != "done":
        raise ActionError("only a program that is still paused can be kept paused")
    remediation.audit_before_acting(audit_path, action="auto-keep-paused", auto_action=row.id, target=row.target, by=who)
    stamp = (now or datetime.now(timezone.utc)).strftime("%Y-%m-%d %H:%M UTC")
    row.detail = f"{row.detail or ''} | kept paused by {who[:60]} at {stamp}".strip(" |")[:1000]
    db.session.commit()
    return row


def _end(row, deps: Deps, status: str, who: str, now=None):
    """Lift a block or resume a paused process. A process that is gone or changed is only marked, never signalled."""
    if row.kind == "process":
        if _same_process(row, deps):
            deps.kill(int(row.target), signal.SIGCONT)
            row.detail = f"{row.detail or ''} | resumed".strip(" |")
        else:
            row.detail = f"{row.detail or ''} | process gone or changed: nothing resumed".strip(" |")
    else:
        deps.unblock({"kind": row.kind, "value": row.target})
    row.status, row.ended_at, row.ended_by = status, now or datetime.now(timezone.utc), who[:100]


def sweep(audit_path: str, deps: Optional[Deps] = None, now: Optional[datetime] = None) -> dict:
    """End every live BLOCK whose time limit has passed (a pause is never resumed by a timer). Undoing is never held up by
    the audit log (plain audit)."""
    from models import AutoAction, db
    import remediation
    now = now or datetime.now(timezone.utc)
    due = AutoAction.query.filter(AutoAction.status == "done", AutoAction.expires_at.isnot(None),
                                  AutoAction.expires_at < now, AutoAction.kind != "process").all()   # a pause waits for a person
    if not due:
        return {"expired": 0, "errors": []}
    deps = deps or Deps()
    expired, errors = 0, []
    for row in due:
        import alerts
        try:
            _end(row, deps, "expired", "time limit", now)
            expired += 1
            remediation.audit(audit_path, action="auto-expire", auto_action=row.id, target=row.target, ok=True, by="sweep")
            alerts.undo_succeeded(f"auto:{row.id}")
        except Exception as exc:                            # noqa: BLE001 -- tried again on the next sweep
            errors.append(f"{row.action} {row.target} (#{row.id}): {exc}")
            remediation.audit(audit_path, action="auto-expire", auto_action=row.id, target=row.target, ok=False,
                              error=str(exc)[:200], by="sweep")
            alerts.undo_failed(f"auto:{row.id}", f"{row.kind} {row.target}", f"{type(exc).__name__}: {exc}",
                               finding=row.threat_id)       # a person is told after a few failures in a row
    db.session.commit()
    return {"expired": expired, "errors": errors}
