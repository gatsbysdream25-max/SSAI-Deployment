"""Small helpers the Windows agent shares: hiding private addresses, running Windows tools, reading and writing JSON.

Nothing here talks to the hub. Keeping these apart means every sensor can be tested with plain text instead of a real Windows.
"""
import ipaddress
import json
import os
import re
import subprocess
import sys

# Home and office address ranges. The hub and the public ledger only ever see these masked, like the Linux agents do.
_PRIVATE_NETWORKS = [ipaddress.ip_network(n) for n in
                     ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16")]
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def is_private_address(text):
    """True for an address inside a home/office/loopback range. Anything that is not an IP address is False."""
    try:
        address = ipaddress.ip_address(text.strip().strip("[]"))
    except ValueError:
        return False
    if address.version == 6:
        return address.is_loopback or address.is_link_local or address.is_private
    return any(address in network for network in _PRIVATE_NETWORKS)


def mask_private_ips(text):
    """Replace the last two parts of every private IPv4 address with 'xxx' (192.168.0.9 -> 192.168.xxx.xxx).
    Public addresses stay readable, because they are what an investigation needs."""
    def hide(match):
        if is_private_address(match.group(0)):
            first, second = match.group(0).split(".")[:2]
            return f"{first}.{second}.xxx.xxx"
        return match.group(0)
    return _IPV4.sub(hide, text or "")


def run_command(args, timeout=30):
    """Run a Windows tool and return everything it printed as text. Never raises: a missing tool, a timeout or a
    refusal gives '' so one broken sensor cannot stop the others."""
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)       # no black console window flashing up on the desktop
    try:
        done = subprocess.run(args, capture_output=True, timeout=timeout, creationflags=flags)
    except (OSError, subprocess.SubprocessError):
        return ""
    return done.stdout.decode("utf-8", errors="replace")


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
