"""What can THIS machine protect? (capability.py)

SwarmSentinel installs on anything from a 1 GB mini-PC to a 32 GB server, and what it can honestly offer depends on the machine.
This module measures the machine (probe) and turns the measurements into a plain-words level (assess), so the installer, the
dashboard and a person reading the report all say the same thing and nothing is promised that the hardware cannot deliver.

The four levels, each includes the one before:

  1  Watch      this machine only: failed logins, odd processes, open ports, file changes, disk and service health.
                Needs: Linux with systemd and about 1 GB of memory.
  2  Guard      adds the dashboard, public threat lists checked against this network's traffic, and local proof checks.
                Needs: 2 GB of memory and 2 GB of free disk. (A machine that is only a "node" reports to a hub and stays at Watch.)
  3  Panel      adds the AI panel: several AI models judge each serious finding and must agree. Needs enough models that can answer
                (cloud keys with internet, or local models) to reach the minimum number of voters (3 by default).
  4  Sovereign  the panel runs on this machine's own models, so it works with no internet and no data leaves the building.
                Needs: at least 2 local models answering, which in practice means about 8 GB of memory.

The probe sends nothing anywhere: it reads the machine and, optionally, asks the local model server what it has installed.
Pure function assess() takes plain numbers, so tests can try every kind of machine without owning one.
"""
from __future__ import annotations

import json
import os
import platform
import shutil
import urllib.request
from typing import Dict, List, Optional

LEVEL_NAMES = {0: "Unsupported", 1: "Watch", 2: "Guard", 3: "Panel", 4: "Sovereign"}
LEVEL_MEANING = {
    0: "this machine cannot run the host sensors natively",
    1: "watches this machine only",
    2: "watches this machine and the network, with a dashboard, but no AI panel yet",
    3: "full protection with an AI panel that must agree before a serious verdict",
    4: "full protection, and the AI panel runs on this machine so it works offline",
}

LEVEL_MEANING_NO_HOST = {
    2: "the dashboard and network checks work, but this machine's own logs and services are not watched here",
    3: "the AI panel is ready, but this machine's own logs and services are not watched here",
    4: "the AI panel runs on this machine's models and works offline, but its own logs and services are not watched here",
}

# Memory (GB) needed before each step; the models figure is for two 7-8 billion parameter models taking turns (one in memory at a time).
RAM_WATCH_GB, RAM_GUARD_GB, RAM_LOCAL_PANEL_GB = 1.0, 1.8, 7.5
DISK_GUARD_GB = 2.0
ONE_SMALL_MODEL_GB = 3.5            # enough for one 3-4 billion parameter model, not enough for a proper local panel

# Agents that need an outside program or a readable log; the reason is shown when they cannot work here.
_NEEDS_TOOL = {"NetworkScanAgent": "nmap"}


def probe(check_ollama_url: Optional[str] = None) -> Dict[str, object]:
    """Measure this machine. Every value is a plain number, true/false or short word; nothing leaves the machine."""
    return {
        "os": platform.system().lower(),                                  # linux | windows | darwin
        "machine": platform.machine().lower(),
        "cpu_cores": os.cpu_count() or 1,
        "ram_gb": _ram_gb(),
        "disk_free_gb": _disk_free_gb(),
        "role": os.environ.get("SSAI_ROLE", "hub").strip().lower(),
        "has_systemd": os.path.isdir("/run/systemd/system"),
        "in_container": os.path.exists("/.dockerenv"),
        "has_nmap": shutil.which("nmap") is not None,
        "logs_readable": _logs_readable(),
        "cloud_keys": _cloud_keys_present(),
        "local_models": _voting_local_models(check_ollama_url) if check_ollama_url else [],
        # Models served from another machine on the network still vote, but do not make THIS machine independent.
        "models_on_this_machine": bool(check_ollama_url) and _is_loopback(check_ollama_url),
    }


def assess(facts: Dict[str, object], min_voters: int = 3) -> Dict[str, object]:
    """Turn measurements into {level, name, summary, can, cannot, model_advice}. Never raises on missing facts."""
    f = dict(facts)
    ram, disk = float(f.get("ram_gb") or 0), float(f.get("disk_free_gb") or 0)
    can: List[str] = []
    cannot: List[Dict[str, str]] = []

    if f.get("os") != "linux":
        return _result(0, ["The dashboard and AI panel can run in Docker (see the README)."],
                       [_gap("Watching this machine's logs, processes and ports",
                             "the host sensors read Linux system files",
                             "install on a Linux machine or virtual machine, or use Docker for the hub and install a Linux node beside it")],
                       f, _model_advice(ram))
    if ram < RAM_WATCH_GB:
        cannot.append(_gap("Anything beyond the basics", f"only {ram:.1f} GB of memory", "use a machine with at least 2 GB"))
    _check_host_watching(f, can, cannot)                                     # level 1: watching this machine

    if f.get("role") == "node":
        can.append("Reports to a hub; the dashboard and AI panel run on the hub, not here")
        return _result(1, can, cannot, f, _model_advice(ram))
    if not _check_guard(f, ram, disk, can, cannot):                          # level 2: dashboard and network
        return _result(1, can, cannot, f, _model_advice(ram))
    return _result(_check_panel(f, ram, min_voters, can, cannot), can, cannot, f, _model_advice(ram))   # levels 3 and 4


def _check_host_watching(f, can, cannot) -> None:
    """Can the sensors that watch THIS machine work here? Adds what works to `can` and what does not (with the fix) to
    `cannot`."""
    in_container = f.get("in_container")
    if f.get("has_systemd"):
        can.append("Failed logins, odd processes, open ports, file changes, disk and service health on this machine")
    elif in_container:
        cannot.append(_gap("Watching the host machine's services", "this runs inside a container, which cannot see the host's services",
                           "install natively (deploy/install.sh) on the host, or add the host-mode override: "
                           "docker compose -f docker-compose.yml -f docker-compose.linux-host.yml up -d"))
    else:
        cannot.append(_gap("Starting automatically and watching services", "no systemd found",
                           "run it in Docker, or start the agents by hand with the commands in deploy/README.md"))
    if not f.get("logs_readable"):
        cannot.append(_gap("Reading login and system logs", "the logs are not readable here",
                           "mount the host's /var/log into the container (the host-mode override does this)" if in_container
                           else "run the agents as root (the installer does) or check /var/log"))


def _check_guard(f, ram, disk, can, cannot) -> bool:
    """Is there room for the dashboard and the network-wide checks? True if so (level 2 reached)."""
    if ram < RAM_GUARD_GB or disk < DISK_GUARD_GB:
        cannot.append(_gap("Dashboard and threat-list matching",
                           f"{ram:.1f} GB memory / {disk:.1f} GB free disk (needs {RAM_GUARD_GB:g} / {DISK_GUARD_GB:g})",
                           "use a larger machine as the hub, and install this one as a node that reports to it"))
        return False
    can.append("Dashboard, public threat lists matched against this network's traffic, local proof checks")
    if f.get("has_nmap"):
        can.append("A scan of the local network for new machines and risky open ports")
    else:
        cannot.append(_gap("Scanning the local network", "nmap is not installed", "sudo apt install nmap"))
    return True


def _check_panel(f, ram, min_voters, can, cannot) -> int:
    """Are there enough AI models for a panel (level 3), and do they run on this machine so it works offline (level 4)?
    Returns 2, 3 or 4."""
    local = len(f.get("local_models") or [])
    voters = len(f.get("cloud_keys") or []) + local
    if voters < min_voters:
        cannot.append(_gap("The AI panel", f"{voters} model(s) available, the panel needs {min_voters}",
                           "add free cloud keys on the /setup page, or install local models (sudo deploy/get-models.sh; offline: deploy/local-ai.sh)"))
        return 2
    can.append(f"AI panel: {voters} models available to judge serious findings")
    on_this_machine = f.get("models_on_this_machine", True)
    if local >= 2 and not on_this_machine:
        cannot.append(_gap("Working with no network", "the local models are served by another machine",
                           "install them here with sudo deploy/get-models.sh (Sovereign level)"))
    if local >= 2 and ram >= RAM_LOCAL_PANEL_GB and on_this_machine:
        can.append("Works with no internet: the panel runs on this machine's own models and no data leaves it")
        return 4
    return 3


def _model_advice(ram_gb: float) -> List[str]:
    """Which local models this much memory can run (one in memory at a time; the second loads when needed)."""
    if ram_gb >= 15:
        return ["hermes3 and mistral (about 9 GB of disk) and room for a third local model"]
    if ram_gb >= RAM_LOCAL_PANEL_GB:
        return ["hermes3 and mistral, taking turns (about 9 GB of disk)"]
    if ram_gb >= ONE_SMALL_MODEL_GB:
        return ["one small model only (3-4 billion parameters); use free cloud keys for the other voices"]
    return ["no local models: use free cloud keys for the panel, or run the panel on a bigger hub"]


def _gap(what: str, why: str, fix: str) -> Dict[str, str]:
    return {"what": what, "why": why, "fix": fix}


def _result(level, can, cannot, facts, advice) -> Dict[str, object]:
    """Build the final answer dict for the capability report: the level, what works, what does not, and a one-line
    summary."""
    # Without systemd (a plain container) the dashboard and AI panel work, but this machine's own logs and services are not watched,
    # so the "full protection" wording would overstate it.
    host_watching = bool(facts.get("has_systemd")) or level == 0
    if level >= 2 and not host_watching:
        meaning = LEVEL_MEANING_NO_HOST[level]
    elif can or level != 1:
        meaning = LEVEL_MEANING[level]
    else:
        meaning = "very little can be watched here yet (see below)"
    return {"level": level, "name": LEVEL_NAMES[level], "can": can, "cannot": cannot, "model_advice": advice,
            "host_watching": host_watching,
            "summary": f"Level {level} ({LEVEL_NAMES[level]}): {meaning}",
            "facts": {k: v for k, v in facts.items() if k not in ("cloud_keys",)} | {"cloud_keys_count": len(facts.get("cloud_keys") or [])}}


# --- measuring (kept tiny and defensive: any failure just means "unknown", never an error) ---

def _ram_gb() -> float:
    """Memory this program may use: the machine's, or the container's limit when that is smaller (a container still reads
    the host's meminfo)."""
    total = 0.0
    try:
        with open("/proc/meminfo") as fh:
            for line in fh:
                if line.startswith("MemTotal:"):
                    total = int(line.split()[1]) / 1024 / 1024                  # the file is in kB
                    break
    except (OSError, ValueError, IndexError):
        pass
    limit = _container_memory_limit_gb()
    return round(min(total, limit) if total and limit else total, 1)


def _container_memory_limit_gb() -> float:
    """The memory limit set on this container (cgroup v2, then v1), or 0 when there is none."""
    for path in ("/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"):
        try:
            with open(path) as fh:
                raw = fh.read().strip()
            if raw.isdigit() and int(raw) < 1 << 50:                           # "max" or a huge number means no limit
                return int(raw) / 1024 ** 3
        except OSError:
            continue
    return 0.0


def _disk_free_gb() -> float:
    """Free space where the data is kept (DATA_DIR: a separate volume in Docker), else where the code is."""
    for path in (os.environ.get("DATA_DIR"), os.path.dirname(os.path.abspath(__file__))):
        try:
            if path and os.path.isdir(path):
                return round(shutil.disk_usage(path).free / 1024 ** 3, 1)
        except OSError:
            continue
    return 0.0


def _logs_readable() -> bool:
    if os.name != "posix":
        return False
    return any(os.access(p, os.R_OK) for p in ("/var/log/auth.log", "/var/log/secure", "/var/log/syslog", "/var/log/messages")) \
        or shutil.which("journalctl") is not None


def _config_and_switches():
    """(provider entries, operator on/off choices) exactly as the panel reads them; ({}, {}) if the config cannot be
    read."""
    try:
        try:
            import model_config
        except ImportError:                       # imported as agents.capability by the web app
            from agents import model_config
        entries = model_config.load()
        switches_path = os.path.join(os.path.dirname(model_config.instance_path()), "ai_providers.json")
    except Exception:                             # noqa: BLE001 -- a probe must never fail because the config is odd
        return {}, {}
    try:
        with open(switches_path, encoding="utf-8") as fh:
            switches = {k: v for k, v in (json.load(fh).get("enabled") or {}).items() if isinstance(v, bool)}
    except (OSError, ValueError, AttributeError):
        switches = {}                             # no choices made yet: every provider keeps its default
    return entries, switches


def _is_on(pid: str, entry: dict, switches: Dict[str, bool]) -> bool:
    """Is this provider part of the panel? The operator's choice wins; otherwise the config's default (the same rule the
    panel uses)."""
    return switches[pid] if pid in switches else bool(entry.get("default_on"))


def voting_cloud(entries: Dict[str, dict], switches: Dict[str, bool], environ) -> List[str]:
    """Cloud providers that would really vote: switched on AND a key is set. Names only, never values."""
    return sorted(pid for pid, e in entries.items()
                  if e.get("kind") != "ollama" and e.get("key_env") and str(environ.get(e["key_env"], "")).strip()
                  and _is_on(pid, e, switches))


def voting_local(entries: Dict[str, dict], switches: Dict[str, bool], installed: List[str]) -> List[str]:
    """Local models that would really vote: described in the config, switched on, and installed. Other installed models
    do not count."""
    have = {n[:-len(":latest")] if n.endswith(":latest") else n for n in installed}
    return sorted(pid for pid, e in entries.items()
                  if e.get("kind") == "ollama" and _is_on(pid, e, switches) and str(e.get("model", "")).replace(":latest", "") in have)


def _cloud_keys_present() -> List[str]:
    entries, switches = _config_and_switches()
    return voting_cloud(entries, switches, os.environ)


def _is_loopback(url: str) -> bool:
    """True when the URL points at this very machine (localhost / 127.x / ::1)."""
    import ipaddress
    from urllib.parse import urlparse
    host = (urlparse(url).hostname or "").lower()
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _voting_local_models(base_url: str) -> List[str]:
    """The local models on that server that would really vote (see voting_local)."""
    entries, switches = _config_and_switches()
    installed = _local_models(base_url)
    return voting_local(entries, switches, installed) if entries else installed


def _local_models(base_url: str) -> List[str]:
    """Models the local Ollama server reports as installed (empty if it is not running)."""
    try:
        with urllib.request.urlopen(base_url.rstrip("/") + "/api/tags", timeout=3) as r:
            return sorted(m["name"] for m in json.load(r).get("models", []))
    except (OSError, ValueError, KeyError):
        return []


def report(check_ollama_url: Optional[str] = None, min_voters: int = 3) -> Dict[str, object]:
    return assess(probe(check_ollama_url), min_voters)


def format_text(result: Dict[str, object]) -> str:
    """The same result as a few plain lines for the installer and the terminal."""
    lines = [str(result["summary"]), ""]
    lines += [f"  can:    {c}" for c in result["can"]]
    for g in result["cannot"]:
        lines.append(f"  cannot: {g['what']}: {g['why']}.  To fix: {g['fix']}")
    lines.append("  models: " + "; ".join(result["model_advice"]))
    return "\n".join(lines)


def _load_env_file() -> None:
    """For the command line only: read KEY=VALUE lines from the install's .env so keys already set up are counted (the
    web app has them already)."""
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), ".env")
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                key, sep, value = line.strip().partition("=")
                if sep and not key.startswith("#") and key.strip():
                    os.environ.setdefault(key.strip(), value.strip().strip("'\""))
    except OSError:
        pass


if __name__ == "__main__":
    import sys
    _load_env_file()
    url = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434")
    res = report(url, int(os.environ.get("SSAI_MIN_VOTERS", "3") or 3))
    print(json.dumps(res, indent=1) if "--json" in sys.argv else format_text(res))
