"""Where the agent keeps its settings, and what they are.

One folder holds everything the agent owns: agent.json (hub address and this machine's credential), state.json (what it
has already seen) and agent.log. On Windows that is C:\\ProgramData\\SwarmSentinel; SSAI_AGENT_HOME overrides it (tests).
"""
import os
import socket
from dataclasses import dataclass

from . import util

SETTINGS_FILE = "agent.json"


def data_folder():
    """The folder the agent keeps its files in."""
    override = os.environ.get("SSAI_AGENT_HOME")
    if override:
        return override
    base = os.environ.get("ProgramData") or os.path.expanduser("~")
    return os.path.join(base, "SwarmSentinel")


@dataclass
class Settings:
    """What the agent needs to talk to its hub. 'api' ends in /api, e.g. http://hub:5000/api."""
    api: str
    node_id: str
    token: str


def settings_path():
    return os.path.join(data_folder(), SETTINGS_FILE)


def load_settings():
    """The saved settings, or None if this machine has not been enrolled yet."""
    saved = util.read_json(settings_path(), {})
    if not (saved.get("api") and saved.get("node_id") and saved.get("token")):
        return None
    return Settings(api=saved["api"], node_id=saved["node_id"], token=saved["token"])


def can_write_data_folder():
    """True if this account may create files in the agent's folder. Checked BEFORE a one-time enrollment code is used,
    because a code spent on a credential that cannot be saved is lost."""
    probe = os.path.join(data_folder(), ".write-test")
    try:
        os.makedirs(data_folder(), exist_ok=True)
        with open(probe, "w", encoding="ascii") as handle:
            handle.write("ok")
        os.remove(probe)
        return True
    except OSError:
        return False


def save_settings(settings):
    """Save the settings, THEN lock the folder so only SYSTEM and Administrators can read the credential
    (locking first would lock the writer out of its own folder)."""
    folder = data_folder()
    os.makedirs(folder, exist_ok=True)
    util.write_json(settings_path(), {"api": settings.api, "node_id": settings.node_id, "token": settings.token})
    util.lock_to_administrators(folder)


def default_node_id():
    """How this PC is named on the hub's dashboard unless the admin picks another name."""
    return socket.gethostname()
