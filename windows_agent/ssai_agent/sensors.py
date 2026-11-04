"""The things the Windows agent watches. Each sensor looks at one part of the PC and returns a list of Findings.

A sensor never talks to the hub: it only asks Windows a question (through `run` or `powershell`, which tests replace with
canned answers) and decides whether the answer is a problem. agent.py sends what the sensors find.

Windows tools are asked in PowerShell wherever possible, because netstat and netsh print words in the PC's own language
and PowerShell objects do not.
"""
import hashlib
import json
import os
import re
import shutil
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone

from . import util

EVENT_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


@dataclass
class Finding:
    url: str              # what the finding is about: an address, a program, a drive
    threat_type: str      # a short label the dashboard groups by, e.g. 'brute-force'
    severity: str         # low, medium or high
    description: str      # one plain sentence; never contains a command line, which can hold passwords
    key: str              # same problem = same key, so it is not re-sent every minute


class Sensor:
    agent_name = "WinSensor"
    role = "scanner"
    description = ""
    interval = 60         # seconds between looks

    def __init__(self, state, run=util.run_command, powershell=util.run_powershell):
        self.state = state
        self.run = run
        self.powershell = powershell
        self.problem = ""     # why this sensor is blind right now, in plain words; '' when it can see

    def scan(self):
        """Look once; return a list of Findings (empty when all is well)."""
        raise NotImplementedError


def powershell_objects(text):
    """PowerShell's ConvertTo-Json gives one object for one result and a list for several. Always return a list."""
    try:
        data = json.loads(text)
    except ValueError:
        return []
    if isinstance(data, dict):
        return [data]
    return data if isinstance(data, list) else []


# ── Sign-ins ──────────────────────────────────────────────────────────────────────────────────────────────────────────
@dataclass
class SignIn:
    record_id: int
    account: str
    address: str          # where the attempt came from; '' when it was typed at this PC


def parse_sign_ins(xml_text):
    """Turn the Security log's XML (several <Event> elements, no single root) into SignIn records."""
    try:
        root = ET.fromstring("<Events>" + re.sub(r"<\?xml[^>]*\?>", "", xml_text) + "</Events>")
    except ET.ParseError:
        return []
    records = []
    for event in root.iter(EVENT_NS + "Event"):
        record = event.find(f"{EVENT_NS}System/{EVENT_NS}EventRecordID")
        data = {d.get("Name"): (d.text or "") for d in event.iter(EVENT_NS + "Data")}
        address = data.get("IpAddress", "").strip()
        if address in ("-", "::1", "127.0.0.1"):
            address = ""
        if record is not None and record.text and record.text.isdigit():
            records.append(SignIn(int(record.text), data.get("TargetUserName", "?"), address))
    return records


class LoginSensor(Sensor):
    agent_name = "WinLoginAgent"
    role = "auth_monitor"
    description = "Watches Windows sign-ins: bursts of failed passwords and Remote Desktop logins from the internet"
    interval = 60
    FAILURES_BEFORE_ALERT = 5          # fewer than this in one look is an ordinary typo

    FAILED = "*[System[(EventID=4625)]]"
    REMOTE_DESKTOP = "*[System[(EventID=4624)]] and *[EventData[Data[@Name='LogonType']='10']]"

    def __init__(self, state, can_read_log=None, **kwargs):
        super().__init__(state, **kwargs)
        self.can_read_log = can_read_log or (lambda: util.command_succeeds(["wevtutil", "qe", "Security", "/c:1", "/f:text"]))

    def scan(self):
        # Windows only lets Administrators and SYSTEM read the Security log. Say so instead of quietly seeing nothing.
        self.problem = "" if self.can_read_log() else \
            "cannot read the Windows Security log; run the agent as SYSTEM or Administrator (the installer does this)"
        if self.problem:
            return []
        return self._failed_password_bursts() + self._internet_remote_logins()

    def _new_sign_ins(self, query, fact_name):
        """Sign-ins logged since the last look. The very first look only notes where the log ends, so an old log is
        not reported as if it had just happened."""
        output = self.run(["wevtutil", "qe", "Security", f"/q:{query}", "/c:200", "/rd:true", "/f:xml"])
        records = parse_sign_ins(output)
        last_seen = self.state.get(fact_name)
        self.state.put(fact_name, max([r.record_id for r in records] + [last_seen or 0]))
        if last_seen is None:
            return []
        return [r for r in records if r.record_id > last_seen]

    def _failed_password_bursts(self):
        by_source = {}
        for sign_in in self._new_sign_ins(self.FAILED, "last_failed_record"):
            by_source.setdefault(sign_in.address or "this PC", []).append(sign_in)
        findings = []
        for source, attempts in by_source.items():
            if len(attempts) < self.FAILURES_BEFORE_ALERT:
                continue
            accounts = sorted({a.account for a in attempts})[:3]
            severity = "high" if len(attempts) >= 20 else ("low" if source == "this PC" else "medium")
            findings.append(Finding(
                url=source, threat_type="brute-force", severity=severity,
                description=f"{len(attempts)} failed Windows sign-ins from {source} (accounts tried: {', '.join(accounts)})",
                key=f"brute:{source}"))
        return findings

    def _internet_remote_logins(self):
        findings = []
        for sign_in in self._new_sign_ins(self.REMOTE_DESKTOP, "last_rdp_record"):
            if sign_in.address and not util.is_private_address(sign_in.address):
                findings.append(Finding(
                    url=sign_in.address, threat_type="remote-login", severity="medium",
                    description=f"Remote Desktop sign-in to account {sign_in.account} from the internet address {sign_in.address}",
                    key=f"rdp:{sign_in.address}:{sign_in.account}"))
        return findings


# ── Listening ports ───────────────────────────────────────────────────────────────────────────────────────────────────
class PortSensor(Sensor):
    agent_name = "WinPortAgent"
    role = "port_monitor"
    description = "Watches for new programs that start accepting connections from the network"
    interval = 120

    # Ordinary Windows services; and the 49152+ range Windows hands out to short-lived RPC connections.
    NORMAL_PORTS = {135, 139, 445, 5040, 7680}
    DYNAMIC_FROM = 49152
    LISTENERS = ("Get-NetTCPConnection -State Listen | ForEach-Object { [pscustomobject]@{ Address = $_.LocalAddress; "
                 "Port = $_.LocalPort; Program = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName } } "
                 "| ConvertTo-Json -Compress")

    def _allowed_ports(self):
        extra = {int(p) for p in os.environ.get("SSAI_ALLOWED_PORTS", "").replace(" ", "").split(",") if p.isdigit()}
        return self.NORMAL_PORTS | extra

    def _reachable_from_network(self):
        """Port -> program, for every listener that other machines could connect to (not 127.0.0.1 / ::1 only)."""
        found = {}
        for item in powershell_objects(self.powershell(self.LISTENERS)):
            port = item.get("Port")
            if isinstance(port, int) and item.get("Address") not in ("127.0.0.1", "::1") and port < self.DYNAMIC_FROM:
                found[port] = item.get("Program") or "an unknown program"
        return found

    def scan(self):
        current = self._reachable_from_network()
        known = self.state.get("known_ports")
        if known is None:                                  # first look: everything already listening is 'normal'
            self.state.put("known_ports", sorted(current))
            return []
        new = set(current) - set(known) - self._allowed_ports()
        pending = set(self.state.get("pending_ports", []))
        confirmed = new & pending                          # still there on the next look: not a one-second flicker
        self.state.put("pending_ports", sorted(new - confirmed))
        self.state.put("known_ports", sorted(set(known) | confirmed))
        return [Finding(url=f"localhost:{port}", threat_type="unexpected-listener", severity="medium",
                        description=f"New unexpected listening port detected: {port} ({current[port]})",
                        key=f"port:{port}") for port in sorted(confirmed)]


# ── Running programs ──────────────────────────────────────────────────────────────────────────────────────────────────
MINER_NAMES = {"xmrig.exe", "minerd.exe", "cpuminer.exe", "nbminer.exe", "t-rex.exe", "phoenixminer.exe", "lolminer.exe"}
HACKING_TOOL_NAMES = {"mimikatz.exe", "lazagne.exe", "ncat.exe", "nc.exe", "nc64.exe", "pwdump.exe"}

# Ways malware and "paste this into Run" tricks start on Windows. Matched against the lower-cased command line.
COMMAND_RULES = [
    ("PowerShell running a hidden encoded command", re.compile(r"powershell.*\s-e(?:nc\w*|c)?\s+[a-z0-9+/=]{20,}"), "medium"),
    ("PowerShell downloading and running code",
     re.compile(r"(?:iex|invoke-expression).*(?:downloadstring|invoke-webrequest|iwr|irm|invoke-restmethod)"
                r"|(?:downloadstring|iwr|irm|invoke-webrequest|invoke-restmethod).*\|\s*(?:iex|invoke-expression)"), "high"),
    ("mshta opening a web page", re.compile(r"mshta(?:\.exe)?\s.*https?://"), "high"),
    ("certutil downloading a file", re.compile(r"certutil.*-urlcache"), "high"),
    ("regsvr32 loading a remote script", re.compile(r"regsvr32.*(?:/i:|scrobj).*https?://"), "high"),
    ("rundll32 running JavaScript", re.compile(r"rundll32.*javascript:"), "high"),
    ("bitsadmin copying a file from the web", re.compile(r"bitsadmin.*/transfer"), "medium"),
]


def rule_for_process(name, command_line):
    """(label, severity) of the first rule this program breaks, or None."""
    lowered_name = (name or "").lower()
    if lowered_name in MINER_NAMES:
        return "a crypto-currency miner", "high"
    if lowered_name in HACKING_TOOL_NAMES:
        return "a password-stealing or remote-shell tool", "high"
    lowered_command = (command_line or "").lower()
    for label, pattern, severity in COMMAND_RULES:
        if pattern.search(lowered_command):
            return label, severity
    return None


class ProcessSensor(Sensor):
    agent_name = "WinProcessAgent"
    role = "process_monitor"
    description = "Watches running programs for miners, hacking tools and the command tricks malware uses to start"
    interval = 90
    PROCESSES = "Get-CimInstance Win32_Process | Select-Object ProcessId,Name,CommandLine | ConvertTo-Json -Compress"

    def scan(self):
        findings = []
        for item in powershell_objects(self.powershell(self.PROCESSES)):
            name, command_line = item.get("Name") or "", item.get("CommandLine") or ""
            rule = rule_for_process(name, command_line)
            if rule:
                label, severity = rule
                fingerprint = hashlib.sha1(command_line.encode("utf-8", "replace")).hexdigest()[:10]
                findings.append(Finding(
                    url=f"{name} (process {item.get('ProcessId')})", threat_type="suspicious-process", severity=severity,
                    description=f"{name} is {label}",           # the command line is deliberately not copied: it can hold passwords
                    key=f"proc:{name.lower()}:{label}:{fingerprint}"))
        return findings


# ── Windows protection settings ───────────────────────────────────────────────────────────────────────────────────────
# ── Event logs ────────────────────────────────────────────────────────────────────────────────────────────────────────
@dataclass
class LogEvent:
    record_id: int
    event_id: int
    provider: str
    time: object          # when it happened (a UTC datetime), or None if the log gave no readable time
    data: dict            # the event's named <Data> items
    fields: list          # every <Data> text in order; some events (the blue-screen one) have unnamed items only
    pid: int = 0          # the process that wrote the event (0 if the log did not say)


def parse_event_time(text):
    """'2026-11-01T16:31:36.3720000Z' -> a UTC datetime; anything else -> None."""
    try:
        return datetime.strptime(text[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def parse_events(xml_text):
    """Turn `wevtutil qe ... /f:xml` output (several <Event> elements, no single root) into LogEvent records."""
    try:
        root = ET.fromstring("<Events>" + re.sub(r"<\?xml[^>]*\?>", "", xml_text) + "</Events>")
    except ET.ParseError:
        return []
    events = []
    for event in root.iter(EVENT_NS + "Event"):
        system = event.find(EVENT_NS + "System")
        if system is None:
            continue
        record, event_id = system.find(EVENT_NS + "EventRecordID"), system.find(EVENT_NS + "EventID")
        provider, created = system.find(EVENT_NS + "Provider"), system.find(EVENT_NS + "TimeCreated")
        if record is None or not (record.text or "").isdigit() or event_id is None or not (event_id.text or "").isdigit():
            continue
        items = list(event.iter(EVENT_NS + "Data"))
        execution = system.find(EVENT_NS + "Execution")
        pid = execution.get("ProcessID", "") if execution is not None else ""
        events.append(LogEvent(
            record_id=int(record.text), event_id=int(event_id.text),
            provider=provider.get("Name", "") if provider is not None else "",
            time=parse_event_time(created.get("SystemTime", "")) if created is not None else None,
            data={d.get("Name"): (d.text or "") for d in items if d.get("Name")},
            fields=[d.text or "" for d in items], pid=int(pid) if pid.isdigit() else 0))
    return events


class EventLogSensor(Sensor):
    """Shared by the sensors that read Windows event logs: ask wevtutil, keep only what is new since the last look."""

    def new_events(self, log, xpath, fact_name, count=200):
        """Events in `log` matching `xpath`, newest record numbers only. The very first look only notes where the log
        ends, so an old log is not reported as if it had just happened."""
        events = parse_events(self.run(["wevtutil", "qe", log, f"/q:{xpath}", f"/c:{count}", "/rd:true", "/f:xml"]))
        last_seen = self.state.get(fact_name)
        self.state.put(fact_name, max([e.record_id for e in events] + [last_seen or 0]))
        if last_seen is None:
            return []
        return [e for e in events if e.record_id > last_seen]


def _event_query(provider, *event_ids):
    ids = " or ".join(f"EventID={i}" for i in event_ids)
    return f"*[System[Provider[@Name='{provider}'] and ({ids})]]"


class EventSensor(EventLogSensor):
    agent_name = "WinEventAgent"
    role = "event_monitor"
    description = ("Watches the Windows event logs for new services, new accounts, changes to the Administrators group, "
                   "cleared logs and PowerShell scripts Windows itself flags as suspicious")
    interval = 120

    SERVICE_INSTALLED = ("System", _event_query("Service Control Manager", 7045))
    SYSTEM_LOG_CLEARED = ("System", _event_query("Microsoft-Windows-Eventlog", 104))
    SECURITY_LOG_CLEARED = ("Security", _event_query("Microsoft-Windows-Eventlog", 1102))
    ACCOUNT_CREATED = ("Security", _event_query("Microsoft-Windows-Security-Auditing", 4720))
    GROUP_MEMBER_ADDED = ("Security", _event_query("Microsoft-Windows-Security-Auditing", 4732))
    TASK_CREATED = ("Security", _event_query("Microsoft-Windows-Security-Auditing", 4698))
    SCRIPT_FLAGGED = ("Microsoft-Windows-PowerShell/Operational", "*[System[(EventID=4104) and (Level=3)]]")

    ADMINISTRATORS_SID = "S-1-5-32-544"
    # A service that starts from a user's folder, a temp folder or a script host is how malware often sets itself up.
    RISKY_SERVICE_PATH = re.compile(r"\\users\\|\\temp\\|\\appdata\\|powershell|%comspec%|cmd(?:\.exe)?\s|mshta|wscript|cscript", re.I)
    OWN_PATH = re.compile(r"^\"?(?:[a-z]:\\windows\\|[a-z]:\\program files)", re.I)

    def __init__(self, state, can_read_log=None, **kwargs):
        super().__init__(state, **kwargs)
        self.can_read_log = can_read_log or (lambda: util.command_succeeds(["wevtutil", "qe", "Security", "/c:1", "/f:text"]))

    def scan(self):
        security = self.can_read_log()
        self.problem = "" if security else \
            "cannot read the Windows Security log, so account, group and task changes are not seen; run the agent as SYSTEM or Administrator"
        findings = self._services() + self._cleared_logs(security) + self._scripts()
        if security:
            findings += self._accounts() + self._admin_group() + self._tasks()
        return findings

    def _look(self, query, fact):
        return self.new_events(query[0], query[1], fact)

    def _services(self):
        findings = []
        for event in self._look(self.SERVICE_INSTALLED, "last_service_record"):
            name, path = event.data.get("ServiceName", "?"), event.data.get("ImagePath", "")
            risky = bool(self.RISKY_SERVICE_PATH.search(path))
            severity = "high" if risky else ("low" if self.OWN_PATH.search(path) else "medium")
            # The path is deliberately not copied into the finding: a service's command line can hold secrets.
            findings.append(Finding(
                url=f"service {name}", threat_type="new-service", severity=severity,
                description=f"A new Windows service was installed: {name}"
                            + (" (it starts from a user folder, a temp folder or a script program)" if risky else ""),
                key=f"svc:{event.record_id}"))
        return findings

    def _cleared_logs(self, security):
        findings = []
        for label, query, fact in (("System", self.SYSTEM_LOG_CLEARED, "last_system_clear_record"),
                                   ("Security", self.SECURITY_LOG_CLEARED, "last_security_clear_record")):
            if label == "Security" and not security:
                continue
            for event in self._look(query, fact):
                findings.append(Finding(
                    url=f"{label} event log", threat_type="log-cleared", severity="high",
                    description=f"The Windows {label} event log was cleared (this is how an intruder hides what they did)",
                    key=f"clear:{label}:{event.record_id}"))
        return findings

    def _accounts(self):
        return [Finding(url=f"account {e.data.get('TargetUserName', '?')}", threat_type="new-account", severity="medium",
                        description=f"A new local Windows account was created: {e.data.get('TargetUserName', '?')}",
                        key=f"acct:{e.record_id}")
                for e in self._look(self.ACCOUNT_CREATED, "last_account_record")]

    def _admin_group(self):
        findings = []
        for event in self._look(self.GROUP_MEMBER_ADDED, "last_group_record"):
            if event.data.get("TargetSid") != self.ADMINISTRATORS_SID:
                continue
            findings.append(Finding(
                url="Administrators group", threat_type="admin-change", severity="high",
                description=f"An account ({event.data.get('MemberSid', '?')}) was added to the local Administrators group "
                            f"by {event.data.get('SubjectUserName', '?')}",
                key=f"admin:{event.record_id}"))
        return findings

    def _tasks(self):
        findings = []
        for event in self._look(self.TASK_CREATED, "last_task_record"):
            name = event.data.get("TaskName", "?")
            if name.lower().startswith("\\microsoft\\"):
                continue                                    # Windows' own tasks are created all the time
            findings.append(Finding(url=f"task {name}", threat_type="new-scheduled-task", severity="low",
                                    description=f"A new scheduled task was created: {name}", key=f"task:{event.record_id}"))
        return findings

    def _scripts(self):
        flagged = self._look(self.SCRIPT_FLAGGED, "last_script_record")
        # Windows logs the generated wrapper scripts of its own modules (loaded by Get-NetTCPConnection and the like) at the
        # same warning level as a suspicious script. Those from PowerShell this agent started are its own questions, not a threat.
        own = util.own_child_pids()
        flagged = [e for e in flagged if not (e.pid and e.pid in own)]
        if not flagged:
            return []
        # Only the count: the script text itself can hold passwords and is never copied.
        return [Finding(url="PowerShell", threat_type="suspicious-script", severity="medium",
                        description=f"Windows flagged {len(flagged)} PowerShell script(s) as suspicious",
                        key=f"ps:{max(e.record_id for e in flagged)}")]


# ── Windows Defender ──────────────────────────────────────────────────────────────────────────────────────────────────
class DefenderSensor(Sensor):
    agent_name = "WinDefenderAgent"
    role = "malware_monitor"
    description = ("Reports what Windows Defender finds, whether Defender, its ransomware and attack-surface protections and "
                   "the firewall are on, and whether its definitions are up to date")
    interval = 300
    DEFENDER = ("Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureAge "
                "| ConvertTo-Json -Compress")
    FIREWALL = "Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json -Compress"
    STALE_SIGNATURE_DAYS = 7

    DETECTIONS = ("$threats = @{}; Get-MpThreat | ForEach-Object { $threats[[string]$_.ThreatID] = $_ }; "
                  "Get-MpThreatDetection | ForEach-Object { [pscustomobject]@{ Id = [string]$_.DetectionID; "
                  "Threat = $threats[[string]$_.ThreatID].ThreatName; Severity = $threats[[string]$_.ThreatID].SeverityID; "
                  "Resource = (@($_.Resources) | Select-Object -First 1) } } | ConvertTo-Json -Compress")
    POSTURE = ("$s = Get-MpComputerStatus; $p = Get-MpPreference; [pscustomobject]@{ Active = $s.AntivirusEnabled; "
               "FolderAccess = [int]$p.EnableControlledFolderAccess; AsrRules = @($p.AttackSurfaceReductionRules_Ids).Count } "
               "| ConvertTo-Json -Compress")
    SEVERITY = {1: "low", 2: "medium", 4: "high", 5: "high"}      # Defender's own scale: low, moderate, high, severe

    def scan(self):
        return self._detections() + self._posture() + self._defender_problems() + self._firewall_problems()

    def _detections(self):
        items = [i for i in powershell_objects(self.powershell(self.DETECTIONS)) if i.get("Id")]
        known = self.state.get("known_defender_detections")
        self.state.put("known_defender_detections", sorted({i["Id"] for i in items} | set(known or [])))
        if known is None:                                  # first look: what Defender already dealt with is history
            return []
        findings = []
        for item in items:
            if item["Id"] in known:
                continue
            # Only the file's name, not its folder: the folder often holds the user's name.
            filename = re.split(r"[\\/]", item.get("Resource") or "")[-1] or "a file"
            threat = item.get("Threat") or "malware"
            findings.append(Finding(
                url=filename, threat_type="malware-detected", severity=self.SEVERITY.get(item.get("Severity"), "medium"),
                description=f"Windows Defender detected {threat} in {filename}", key=f"mp:{item['Id']}"))
        return findings

    def _posture(self):
        status = (powershell_objects(self.powershell(self.POSTURE)) or [{}])[0]
        if not status.get("Active"):
            return []                    # Defender is not the active antivirus here (another product may be): say nothing
        findings = []
        if status.get("FolderAccess") == 0:
            findings.append(Finding(
                "Controlled folder access", "ransomware-protection-off", "low",
                "Windows' ransomware protection (controlled folder access) is off; turn it on in Windows Security, "
                "Virus & threat protection", "cfa-off"))
        if status.get("AsrRules") == 0:
            findings.append(Finding(
                "Attack surface reduction", "protection-off", "low",
                "No Windows attack surface reduction rules are switched on", "asr-none"))
        return findings

    def _defender_problems(self):
        status = (powershell_objects(self.powershell(self.DEFENDER)) or [{}])[0]
        if not status.get("AntivirusEnabled"):
            return []                    # Defender is not the active antivirus here (another product may be): say nothing
        findings = []
        if status.get("RealTimeProtectionEnabled") is False:
            findings.append(Finding("Windows Defender", "protection-off", "high",
                                    "Windows Defender real-time protection is switched off", "defender-realtime-off"))
        age = status.get("AntivirusSignatureAge")
        if isinstance(age, int) and age > self.STALE_SIGNATURE_DAYS:
            findings.append(Finding("Windows Defender", "protection-stale", "medium",
                                    f"Windows Defender's virus definitions are {age} days old", "defender-stale"))
        return findings

    def _firewall_problems(self):
        findings = []
        for profile in powershell_objects(self.powershell(self.FIREWALL)):
            if profile.get("Enabled") is False or profile.get("Enabled") == 0:
                name = profile.get("Name", "?")
                findings.append(Finding("Windows Firewall", "protection-off", "high",
                                        f"The Windows firewall is switched off for the {name} network profile",
                                        f"firewall-off:{name}"))
        return findings


# ── Crashes and hardware errors ───────────────────────────────────────────────────────────────────────────────────────
BUGCHECK_NAMES = {
    0x0A: "IRQL_NOT_LESS_OR_EQUAL", 0x1A: "MEMORY_MANAGEMENT", 0x1E: "KMODE_EXCEPTION_NOT_HANDLED",
    0x3B: "SYSTEM_SERVICE_EXCEPTION", 0x50: "PAGE_FAULT_IN_NONPAGED_AREA", 0x7E: "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED",
    0xD1: "DRIVER_IRQL_NOT_LESS_OR_EQUAL", 0xF7: "DRIVER_OVERRAN_STACK_BUFFER", 0x133: "DPC_WATCHDOG_VIOLATION",
    0x139: "KERNEL_SECURITY_CHECK_FAILURE", 0x124: "WHEA_UNCORRECTABLE_ERROR",
}


class StabilitySensor(EventLogSensor):
    agent_name = "WinStabilityAgent"
    role = "stability_monitor"
    description = ("Reports blue-screen crashes, unexpected shutdowns and hardware errors, warns when they repeat, "
                   "and warns when the system drive is nearly full")
    interval = 600
    LOW_PERCENT = 10
    CRITICAL_PERCENT = 5
    REPEATED_CRASHES = 3                       # this many in a day is a pattern, not bad luck
    WINDOW_SECONDS = 24 * 3600

    BUGCHECK = ("System", _event_query("Microsoft-Windows-WER-SystemErrorReporting", 1001))
    UNEXPECTED_SHUTDOWN = ("System", _event_query("Microsoft-Windows-Kernel-Power", 41))
    HARDWARE_ERROR = ("System", "*[System[Provider[@Name='Microsoft-Windows-WHEA-Logger']]]")
    FATAL_HARDWARE_IDS = (1, 18, 20)           # WHEA: fatal hardware error, fatal machine check, uncorrectable PCI Express error

    def __init__(self, state, clock=time.time, drive=None, **kwargs):
        super().__init__(state, **kwargs)
        self.clock = clock
        self.drive = drive or (os.environ.get("SystemDrive", "C:") + "\\")

    def scan(self):
        bugchecks = self._recent(self.BUGCHECK, "last_bugcheck_record")
        power_events = self._recent(self.UNEXPECTED_SHUTDOWN, "last_shutdown_record")
        return (self._crashes(bugchecks, power_events) + self._shutdowns(power_events) + self._hardware_errors()
                + self._disk_problems())

    def _recent(self, query, fact):
        """New events, or on the very first look the last day's worth: a crash just before the agent was installed is
        exactly what a person wants to hear about, unlike an old login failure."""
        first_look = self.state.get(fact) is None
        events = self.new_events(query[0], query[1], fact)
        if first_look:
            events = [e for e in parse_events(self.run(
                ["wevtutil", "qe", query[0], f"/q:{query[1]}", "/c:50", "/rd:true", "/f:xml"]))
                if e.time and self.clock() - e.time.timestamp() <= self.WINDOW_SECONDS]
        return events

    @staticmethod
    def bugcheck_code(event):
        match = re.search(r"0x([0-9a-f]+)", event.fields[0] if event.fields else "", re.I)
        return int(match.group(1), 16) if match else None

    @staticmethod
    def power_event_code(event):
        """The bug check code Kernel-Power 41 carries (it writes it in decimal); 0 or none means no crash was recorded."""
        value = event.data.get("BugcheckCode", "")
        return int(value) if value.isdigit() else 0

    def _same_crash(self, power_event, bugcheck):
        """Kernel-Power 41 and the bug check event are two records of one crash: same code, a few seconds apart."""
        if self.power_event_code(power_event) != self.bugcheck_code(bugcheck):
            return False
        if power_event.time is None or bugcheck.time is None:
            return True
        return abs((power_event.time - bugcheck.time).total_seconds()) < 600

    def _crashes(self, bugchecks, power_events):
        """Every crash once. Usually the bug check event records it, but when Windows could not write a crash dump that
        event is missing and only Kernel-Power 41 remembers the crash, so that one counts too."""
        crashes = []
        for event in bugchecks:
            crashes.append((event.record_id, self.bugcheck_code(event), f"crash:{event.record_id}"))
        for event in power_events:
            if self.power_event_code(event) and not any(self._same_crash(event, b) for b in bugchecks):
                crashes.append((event.record_id, self.power_event_code(event), f"crash-power:{event.record_id}"))
        findings = []
        for _, code, key in crashes:
            name = BUGCHECK_NAMES.get(code)
            label = f"0x{code:X}" + (f" ({name})" if name else "") if code is not None else "an unknown code"
            findings.append(Finding(url="this PC", threat_type="system-crash", severity="medium",
                                    description=f"Windows crashed with a blue screen: bug check {label}", key=key))
        if len(crashes) >= self.REPEATED_CRASHES:
            findings.append(Finding(
                url="this PC", threat_type="repeated-crashes", severity="high",
                description=f"{len(crashes)} blue-screen crashes in the last day: look for a faulty driver, memory or other hardware",
                key=f"crashes:{len(crashes)}:{max(c[0] for c in crashes)}"))
        return findings

    def _shutdowns(self, power_events):
        # Code 0 means power was cut or the PC froze, which leaves no crash record of its own.
        return [Finding(url="this PC", threat_type="unexpected-shutdown", severity="medium",
                        description="Windows restarted without shutting down cleanly (power loss, a freeze or a forced reset)",
                        key=f"shutdown:{e.record_id}")
                for e in power_events if not self.power_event_code(e)]

    def _hardware_errors(self):
        events = self._recent(self.HARDWARE_ERROR, "last_hardware_record")
        if not events:
            return []
        fatal = any(e.event_id in self.FATAL_HARDWARE_IDS for e in events)
        return [Finding(url="this PC", threat_type="hardware-error", severity="high" if fatal else "medium",
                        description=f"Windows logged {len(events)} hardware error(s) (WHEA)"
                                    + (", including an uncorrectable one" if fatal else ", all corrected"),
                        key=f"whea:{max(e.record_id for e in events)}")]

    def _disk_problems(self):
        try:
            usage = shutil.disk_usage(self.drive)
        except OSError:
            return []
        free_percent = round(100 * usage.free / usage.total) if usage.total else 100
        if free_percent >= self.LOW_PERCENT:
            return []
        severity = "high" if free_percent < self.CRITICAL_PERCENT else "medium"
        return [Finding(self.drive, "disk-low", severity, f"Drive {self.drive} has only {free_percent}% free space", "disk-low")]


def all_sensors(state):
    """Every sensor the agent runs."""
    return [LoginSensor(state), PortSensor(state), ProcessSensor(state), DefenderSensor(state), EventSensor(state),
            StabilitySensor(state)]
