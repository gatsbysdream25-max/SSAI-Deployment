"""Agent catalog: which agents exist, which run by default, and the operator's on/off choices.

The defaults live here, in one place shared by the agent runner and the settings menu. Operator choices are
stored in backend/instance/agents.json and take effect without a restart: the runner reconciles every ~30 s.

Principle (2026-09-19): an agent that costs real resources (CPU on a local LLM, paid or quota-limited APIs) and
has not shown it earns them is OFF by default and offered in the menu as an opt-in; cheap detectors stay on.
"""
import json
import os
import shutil
from datetime import datetime, timezone
from typing import Dict, Optional

def _instance_file(name):
    """A state file under the instance directory that ssai_config points at (the persistent data volume in Docker,
    the install directory on a normal host). Located via the code's own position only as a last resort."""
    try:
        import ssai_config
        return os.path.join(ssai_config.INSTANCE_DIR, name)
    except ImportError:
        return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "instance", name)


_PATH = _instance_file("agents.json")
_cache: Dict[str, object] = {"mtime": None, "data": {}}

# tier: core (cheap detector) | ai (uses the AI panel) | intel (public threat data) | optional (off by default)
CATALOG: Dict[str, dict] = {
    "NetworkScanAgent":     {"tier": "core", "default_on": True,
                             "notes": "nmap sweep of the LAN every 10 minutes: new hosts and risky open ports."},
    "AuthLogAgent":         {"tier": "core", "default_on": True,
                             "notes": "Watches auth.log for brute force and logins. The most productive detector so far."},
    "SyslogAgent":          {"tier": "core", "default_on": True,
                             "notes": "Tails syslog for out-of-memory kills, segfaults, break-in attempts and inbound firewall blocks. "
                                      "Rarely fires (0 findings in 30 days) but costs almost nothing."},
    "PiHoleAgent":          {"tier": "core", "default_on": True,
                             "notes": "DNS view from Pi-hole: unusual blocking rates. Needs PIHOLE_IP and PIHOLE_PASSWORD, otherwise it stays idle."},
    "ProcessMonitorAgent":  {"tier": "core", "default_on": True,
                             "notes": "Suspicious processes such as reverse shells and miners."},
    "EmailQuarantineAgent": {"tier": "core", "default_on": True,
                             "notes": "Ingests the phishing-quarantine drop box."},
    "SocketWatchAgent":     {"tier": "core", "default_on": True,
                             "notes": "Listening ports and live outbound connections on this host: new unexpected listeners, connections to "
                                      "ports malware uses, and connections to anything the threat feeds list."},
    "HostHealthAgent":      {"tier": "core", "default_on": True,
                             "notes": "Critical systemd services stopping, full disks and changes to critical system files, in one pass. "
                                      "The service check is skipped on a machine without systemd."},
    "IntelFeedAgent":       {"tier": "intel", "default_on": True,
                             "notes": "Loads free abuse.ch feeds (ThreatFox, Feodo Tracker: CC0, no key) into a local store; the connection and DNS "
                                      "agents raise a threat only when a device on your network touches a listed indicator."},
    "SwarmConsensusAgent":  {"tier": "ai", "default_on": True,
                             "notes": "Multi-AI verdicts for medium-and-above threats, using the AI providers that are switched on."},
    "ConsensusVerifierAgent": {"tier": "ai", "default_on": True,
                             "notes": "Second opinion on every AI verdict from a model of a different maker than the voters, so a consensus is "
                                      "never one family agreeing with itself. Set SSAI_VERIFIER_PROVIDER to reserve a model for it."},
    "RemediationSweepAgent": {"tier": "core", "default_on": True,
                             "notes": "Expires unapproved remediation proposals and auto-reverts an approved block once its TTL passes."},
    "RedTeamAgent":         {"tier": "core", "default_on": True,
                             "notes": "Attacks SSAI itself every 6 hours (data leaks through the cloud gate, a spoofed AI voice, prompt "
                                      "injection, AI-triggered actions) using the real code with fake data: no network, no changes. "
                                      "A probe that starts failing raises a high finding. Results: instance/redteam_audit.jsonl."},
    "LocalAnalyzerAgent":   {"tier": "optional", "default_on": False,
                             "notes": "Local-LLM analysis of high, medium and low severity threats through Ollama (one agent; each tier has its "
                                      "own model, set in Settings). Off by default: the local models tried so far score poorly "
                                      "(30% false alarms on medium, near-zero accuracy on low). Useful for air-gapped installs."},
}

# Agents merged into others or removed (2026-11-03). Their dashboard rows are deleted when the hub starts, so the count
# shows only agents that exist. A machine still running an old build re-registers them, and they go again at the next start.
RETIRED = frozenset({
    "PortMonitorAgent", "NetworkConnAgent", "ServiceWatchAgent", "DiskSpaceAgent", "FileIntegrityAgent",
    "OllamaAnalyzerAgent", "HermesAnalyzerAgent", "WatchtowerAnalyzerAgent", "ThreatFeedAgent", "BrowserExtAgent",
    "WinSecurityAgent", "WinDiskAgent",
})


LEGACY_ANALYZERS = ("OllamaAnalyzerAgent", "HermesAnalyzerAgent", "WatchtowerAnalyzerAgent")


def load_overrides(path: Optional[str] = None) -> Dict[str, bool]:
    """Operator choices {agent: bool} from instance/agents.json ({} if absent or unreadable)."""
    path = path or _PATH
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return {}
    if path == _PATH and _cache["mtime"] == mtime:
        return _cache["data"]  # type: ignore[return-value]
    data: Dict[str, bool] = {}
    try:
        with open(path) as f:
            doc = json.load(f)
        for name, val in (doc.get("enabled") or {}).items():
            if isinstance(val, bool):
                data[str(name)] = val
    except (OSError, ValueError, AttributeError):
        data = {}
    # A choice made for one of the three analyzers that LocalAnalyzerAgent replaced carries over: switched on before means on now.
    if "LocalAnalyzerAgent" not in data and any(data.get(old) for old in LEGACY_ANALYZERS):
        data["LocalAnalyzerAgent"] = True
    if path == _PATH:
        _cache.update(mtime=mtime, data=data)
    return data


# Agents that watch the network or serve the whole installation rather than one machine. On a "node" (an extra machine
# reporting to a hub) they stay off unless the operator turns them on, so N machines do not run N LAN scanners, N AI
# panels or N copies of the same reference feed. Host-level sensors (logs, ports, processes, connections, file
# integrity, disk, services) and the feed store that the connection matcher needs run everywhere.
HUB_ONLY = frozenset({
    "NetworkScanAgent", "PiHoleAgent", "EmailQuarantineAgent",
    "SwarmConsensusAgent", "ConsensusVerifierAgent", "LocalAnalyzerAgent",
    "RemediationSweepAgent", "RedTeamAgent",
})


def _needs_env(*names):
    """A check that passes when every named environment variable is set."""
    def check():
        missing = [n for n in names if not os.environ.get(n, "").strip()]
        return f"{' and '.join(missing)} not set" if missing else ""
    return check


def _needs_program(program):
    """A check that passes when the program is installed."""
    def check():
        return "" if shutil.which(program) else f"{program} is not installed here"
    return check


# What a machine must have for an agent to be worth running. An agent whose need is missing stays off and is not
# offered as an option (an operator's explicit switch still wins). This is how one build runs on any network: a
# laptop with no Pi-hole never starts the Pi-hole agent, and one that later gets PIHOLE_IP/PIHOLE_PASSWORD in .env
# starts it within ~30 s. Each check returns "" when satisfied, or a short reason.
REQUIRES = {
    "PiHoleAgent": _needs_env("PIHOLE_IP", "PIHOLE_PASSWORD"),
    "NetworkScanAgent": _needs_program("nmap"),
}


def unmet_requirement(name: str) -> str:
    """Why this agent cannot usefully run on this machine ('' when it can)."""
    check = REQUIRES.get(name)
    return check() if check else ""


def role() -> str:
    """'hub' (default: runs everything, hosts the dashboard) or 'node' (host sensors only, reports to a hub)."""
    return "node" if os.environ.get("SSAI_ROLE", "hub").strip().lower() == "node" else "hub"


def agent_enabled(name: str, overrides: Optional[Dict[str, bool]] = None) -> bool:
    """Should this agent run? The operator's choice wins; then the machine's role; then whether the machine has
    what the agent needs (REQUIRES); then the catalog default; unknown agents run."""
    if overrides is None:
        overrides = load_overrides()
    if name in overrides:
        return bool(overrides[name])
    if role() == "node" and name in HUB_ONLY:
        return False
    if unmet_requirement(name):
        return False
    meta = CATALOG.get(name)
    return bool(meta["default_on"]) if meta else True


def set_agent_enabled(name: str, enabled: bool, path: Optional[str] = None) -> None:
    """Persist an operator choice (atomic write)."""
    path = path or _PATH
    try:
        with open(path) as f:
            doc = json.load(f)
        current = {k: v for k, v in (doc.get("enabled") or {}).items() if isinstance(v, bool)}
    except (OSError, ValueError, AttributeError):
        current = {}
    current[name] = bool(enabled)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"enabled": current, "updated": datetime.now(timezone.utc).isoformat()}, f, indent=1)
    os.replace(tmp, path)
    if path == _PATH:
        _cache["mtime"] = None


def plan_reconcile(running: Dict[str, bool], wanted: set):
    """running: {agent: thread_is_alive}; wanted: names that should be running.
    Returns (to_start, to_stop): start anything wanted that is not alive; stop anything alive that is not wanted."""
    to_start = sorted(n for n in wanted if not running.get(n, False))
    to_stop = sorted(n for n, alive in running.items() if alive and n not in wanted)
    return to_start, to_stop
