"""Agent catalog: which agents exist, which run by default, and the operator's on/off choices.

The defaults live here, in one place shared by the agent runner and the settings menu. Operator choices are
stored in backend/instance/agents.json and take effect without a restart: the runner reconciles every ~30 s.

Principle (2026-09-19): an agent that costs real resources (CPU on a local LLM, paid or quota-limited APIs) and
has not shown it earns them is OFF by default and offered in the menu as an opt-in; cheap detectors stay on.
"""
import json
import os
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
    "PortMonitorAgent":     {"tier": "core", "default_on": True,
                             "notes": "Listening-port changes on this host."},
    "ProcessMonitorAgent":  {"tier": "core", "default_on": True,
                             "notes": "Suspicious processes such as reverse shells and miners."},
    "NetworkConnAgent":     {"tier": "core", "default_on": True,
                             "notes": "Established outbound connections to known-bad ports."},
    "ServiceWatchAgent":    {"tier": "core", "default_on": True,
                             "notes": "Critical systemd services stopping unexpectedly."},
    "FileIntegrityAgent":   {"tier": "core", "default_on": True,
                             "notes": "Changes to critical system files, including deletions."},
    "DiskSpaceAgent":       {"tier": "core", "default_on": True,
                             "notes": "Low disk space on this host."},
    "EmailQuarantineAgent": {"tier": "core", "default_on": True,
                             "notes": "Ingests the phishing-quarantine drop box."},
    "BrowserExtAgent":      {"tier": "core", "default_on": True,
                             "notes": "Represents the browser extensions that report in."},
    "ThreatFeedAgent":      {"tier": "optional", "default_on": False,
                             "notes": "Posts a few public URLhaus listings every 15 min as 'info' rows (feed samples, not events on your "
                                      "network). Off by default: IntelFeedAgent now loads URLhaus into the local store and raises a "
                                      "threat only when a device here looks up a listed site."},
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
    "OllamaAnalyzerAgent":  {"tier": "optional", "default_on": False,
                             "notes": "Local-LLM analysis of high-severity threats. Off by default: it has analyzed 5 threats ever and the "
                                      "local models tried so far score poorly. Useful for air-gapped installs."},
    "HermesAnalyzerAgent":  {"tier": "optional", "default_on": False,
                             "notes": "Local-LLM analysis of medium threats (hermes3, about 40 s of CPU each). Off by default: 30% false alarms "
                                      "on the benchmark. Air-gapped installs only."},
    "RedTeamAgent":         {"tier": "core", "default_on": True,
                             "notes": "Attacks SSAI itself every 6 hours (data leaks through the cloud gate, a spoofed AI voice, prompt "
                                      "injection, AI-triggered actions) using the real code with fake data: no network, no changes. "
                                      "A probe that starts failing raises a high finding. Results: instance/redteam_audit.jsonl."},
    "WatchtowerAnalyzerAgent": {"tier": "optional", "default_on": False,
                             "notes": "Local-LLM triage of LOW-severity threats (mistral, about 45 s of CPU each). Off by default: near-zero "
                                      "accuracy on the benchmark, and its 37,000-row backlog can never clear."},
}


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
    if path == _PATH:
        _cache.update(mtime=mtime, data=data)
    return data


# Agents that watch the network or serve the whole installation rather than one machine. On a "node" (an extra machine
# reporting to a hub) they stay off unless the operator turns them on, so N machines do not run N LAN scanners, N AI
# panels or N copies of the same reference feed. Host-level sensors (logs, ports, processes, connections, file
# integrity, disk, services) and the feed store that the connection matcher needs run everywhere.
HUB_ONLY = frozenset({
    "NetworkScanAgent", "PiHoleAgent", "EmailQuarantineAgent", "BrowserExtAgent", "ThreatFeedAgent",
    "SwarmConsensusAgent", "ConsensusVerifierAgent", "OllamaAnalyzerAgent", "HermesAnalyzerAgent", "WatchtowerAnalyzerAgent",
    "RemediationSweepAgent", "RedTeamAgent",
})


def role() -> str:
    """'hub' (default: runs everything, hosts the dashboard) or 'node' (host sensors only, reports to a hub)."""
    return "node" if os.environ.get("SSAI_ROLE", "hub").strip().lower() == "node" else "hub"


def agent_enabled(name: str, overrides: Optional[Dict[str, bool]] = None) -> bool:
    """Should this agent run? The operator's choice wins; then the machine's role; then the catalog default;
    unknown agents run."""
    if overrides is None:
        overrides = load_overrides()
    if name in overrides:
        return bool(overrides[name])
    if role() == "node" and name in HUB_ONLY:
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
