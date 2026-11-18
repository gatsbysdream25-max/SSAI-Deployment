"""Small helpers the Windows agent shares: hiding private addresses, running Windows tools, reading and writing JSON.

Nothing here talks to the hub. Keeping these apart means every sensor can be tested with plain text instead of a real Windows.
"""
import ipaddress
import json
import os
import re
import subprocess
import sys
import time
from collections import deque

# Home and office address ranges. The hub and the public ledger only ever see these masked, like the Linux agents do.
# IPv6 (2026-11-18): loopback, unique-local (fd..) and link-local (fe80::) are inside the network too. Listed explicitly: Python's
# own is_private also counts documentation and other special ranges, which are not anyone's home network.
_PRIVATE_NETWORKS = [ipaddress.ip_network(n) for n in
                     ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
                      "::1/128", "fc00::/7", "fe80::/10")]
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6 = re.compile(r"(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f]{0,4})(?:%[\w.-]+)?(?![\w:])")


def is_private_address(text):
    """True for an address inside a home/office/loopback range. Anything that is not an IP address is False."""
    try:
        address = ipaddress.ip_address(text.strip().strip("[]"))
    except ValueError:
        return False
    if getattr(address, "ipv4_mapped", None) is not None:
        address = address.ipv4_mapped
    return any(address.version == network.version and address in network for network in _PRIVATE_NETWORKS)


def mask_private_ips(text):
    """Replace the last two parts of every private IPv4 address with 'xxx' (10.1.0.9 -> 10.1.xxx.xxx) and keep only the first
    two groups of a local IPv6 address (fd12:3456:789a::5 -> fd12:3456:xxxx::). Public addresses stay readable, because they are
    what an investigation needs; IPv6 loopback (::1) names no device and stays too."""
    def hide6(match):
        raw = match.group(0)
        try:
            address = ipaddress.ip_address(raw.split("%", 1)[0])
        except ValueError:
            return raw
        if address.ipv4_mapped is not None or address.is_loopback or not is_private_address(raw.split("%", 1)[0]):
            return raw                         # a mapped IPv4 address is masked by the IPv4 pass below
        groups = address.exploded.split(":")
        return f"{int(groups[0], 16):x}:{int(groups[1], 16):x}:xxxx::"

    def hide(match):
        if is_private_address(match.group(0)):
            first, second = match.group(0).split(".")[:2]
            return f"{first}.{second}.xxx.xxx"
        return match.group(0)
    return _IPV4.sub(hide, _IPV6.sub(hide6, text or ""))


# Process ids of the programs this agent started, newest last. The Windows event log says which process wrote an event, so a
# sensor can tell the agent's own PowerShell (whose generated module wrappers Windows logs as "suspicious") from anyone else's.
_own_children = deque(maxlen=4000)        # (pid, time started)
OWN_CHILD_MINUTES = 30                    # a pid is only treated as ours this long: Windows reuses process ids


def note_child(pid):
    _own_children.append((pid, time.monotonic()))


def own_child_pids():
    """Process ids of programs this agent started in the last OWN_CHILD_MINUTES minutes."""
    cutoff = time.monotonic() - OWN_CHILD_MINUTES * 60
    return {pid for pid, started in _own_children if started >= cutoff}


def run_checked(args, timeout=30):
    """Run a Windows tool and return (exit code, what it printed, what it complained about). Never raises: a missing
    tool or a timeout gives (-1, '', reason)."""
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)       # no black console window flashing up on the desktop
    try:
        with subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=flags) as proc:
            note_child(proc.pid)
            try:
                out, err = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate()
                return -1, "", "timed out"
    except (OSError, subprocess.SubprocessError) as error:
        return -1, "", str(error)
    return proc.returncode, out.decode("utf-8", errors="replace"), err.decode("utf-8", errors="replace")


def run_command(args, timeout=30):
    """Run a Windows tool and return everything it printed as text. Never raises: a missing tool, a timeout or a
    refusal gives '' so one broken sensor cannot stop the others."""
    return run_checked(args, timeout)[1]


def command_succeeds(args, timeout=30):
    """True if the tool ran and reported success (exit code 0). Used to ask 'am I allowed to read this?'."""
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        return subprocess.run(args, capture_output=True, timeout=timeout, creationflags=flags).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def run_powershell(script, timeout=45):
    """Run a PowerShell snippet and return its text. Output is forced to UTF-8 so names with accents survive."""
    wrapped = "[Console]::OutputEncoding = [Text.Encoding]::UTF8; " + script
    return run_command(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                        "-Command", wrapped], timeout)


def read_json(path, default):
    """Read a JSON file; a missing or damaged file gives the default instead of an error."""
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return default


def write_json(path, data):
    """Write JSON so a power cut mid-write cannot leave half a file: write a temp file, then swap it in."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    temp = path + ".tmp"
    with open(temp, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)
    os.replace(temp, path)


def lock_to_administrators(path):
    """On Windows, let only SYSTEM and Administrators read this file or folder (it holds the machine's hub credential).
    Elsewhere (tests) do nothing. SSAI_AGENT_NO_LOCK=1 skips it, for trying the agent without administrator rights;
    never set it on a real install."""
    if not sys.platform.startswith("win") or os.environ.get("SSAI_AGENT_NO_LOCK") == "1":
        return
    run_command(["icacls", path, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"])
