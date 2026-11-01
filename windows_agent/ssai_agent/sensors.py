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
import xml.etree.ElementTree as ET
from dataclasses import dataclass

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
class SecuritySensor(Sensor):
    agent_name = "WinSecurityAgent"
    role = "config_monitor"
    description = "Checks that Windows Defender and the Windows firewall are switched on and up to date"
    interval = 600
    DEFENDER = ("Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureAge "
                "| ConvertTo-Json -Compress")
    FIREWALL = "Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json -Compress"
    STALE_SIGNATURE_DAYS = 7

    def scan(self):
        return self._defender_problems() + self._firewall_problems()

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


class DiskSensor(Sensor):
    agent_name = "WinDiskAgent"
    role = "disk_monitor"
    description = "Warns when the system drive is nearly full"
    interval = 900
    LOW_PERCENT = 10
    CRITICAL_PERCENT = 5

    def __init__(self, state, drive=None, **kwargs):
        super().__init__(state, **kwargs)
        self.drive = drive or (os.environ.get("SystemDrive", "C:") + "\\")

    def scan(self):
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
    return [LoginSensor(state), PortSensor(state), ProcessSensor(state), SecuritySensor(state), DiskSensor(state)]
