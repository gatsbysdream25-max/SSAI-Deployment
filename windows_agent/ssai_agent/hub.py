"""Talking to the hub: enrolling, telling it the agents exist, heartbeats, and sending findings.

It speaks the same small protocol the Linux nodes use, so the hub needs nothing special for a Windows machine:
  POST /api/node/register   a single-use enrollment code -> this machine's own token (shown once)
  POST /api/agents/register, /api/agents/heartbeat   so the agents appear on the dashboard
  POST /api/threats/        one finding
All calls go through one function, `transport`, so tests can replace the network with a plain Python function.
"""
import json
import logging
import platform
import urllib.error
import urllib.request
from collections import deque

from . import __version__, util

log = logging.getLogger("hub")
TIMEOUT_SECONDS = 10


def http_transport(method, url, payload, token):
    """The real network call. Returns (status code, parsed JSON or {}). A hub that cannot be reached gives (0, {})."""
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(url, data=body, method=method)
    request.add_header("Content-Type", "application/json")
    if token:
        request.add_header("X-API-Key", token)
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as reply:
            return reply.status, _json_or_empty(reply.read())
    except urllib.error.HTTPError as error:              # the hub answered, but with a refusal (401, 429, ...)
        return error.code, _json_or_empty(error.read())
    except (urllib.error.URLError, OSError):             # the hub did not answer at all
        return 0, {}


def _json_or_empty(raw):
    try:
        return json.loads(raw.decode("utf-8"))
    except ValueError:
        return {}


def enroll(hub_url, code, node_id, hostname, transport=http_transport):
    """Trade a single-use enrollment code for this machine's own credential. Returns (settings dict, error text)."""
    base = hub_url.rstrip("/")
    status, reply = transport("POST", base + "/api/node/register",
                              {"enrollCode": code, "nodeId": node_id, "hostname": hostname, "platform": "windows"}, None)
    if status == 200 and reply.get("token"):
        return {"api": base + "/api", "node_id": reply["nodeId"], "token": reply["token"]}, ""
    if status == 0:
        return None, f"cannot reach the hub at {base}"
    return None, reply.get("error") or f"the hub refused the code (HTTP {status})"


class HubClient:
    """One machine's connection to its hub. Findings that cannot be delivered wait in a queue and are retried."""

    def __init__(self, settings, transport=http_transport):
        self.settings = settings
        self.transport = transport
        self.waiting = deque(maxlen=500)              # findings that could not be delivered yet
        self.credential_rejected = False
        self.hostname = platform.node()

    def agent_id(self, name):
        """The hub names a node's agents <agent>@<machine>; a node may only use names ending in its own."""
        return f"{name}@{self.settings.node_id}"

    def _send(self, path, payload):
        status, reply = self.transport("POST", self.settings.api + path, payload, self.settings.token)
        if status in (401, 403):
            self.credential_rejected = True
        elif status:
            self.credential_rejected = False
        return status, reply

    def register(self, name, role, description):
        self._send("/agents/register", {"agentId": self.agent_id(name), "name": self.agent_id(name), "role": role,
                                        "description": description, "type": "scanner",
                                        "hostname": self.hostname, "platform": "windows", "version": __version__})

    def heartbeat(self, name, scans, found, last_scan):
        """Tell the hub this agent is alive. Returns the hub's status code (404 means the hub forgot the agent)."""
        status, _ = self._send("/agents/heartbeat", {"agentId": self.agent_id(name), "name": self.agent_id(name), "status": "active",
                                         "hostname": self.hostname, "scan_count": scans, "threat_count": found,
                                         "last_scan": last_scan, "version": __version__})
        return status

    def send_finding(self, finding, detected_by):
        """Send one finding with private addresses masked. The real address goes in an admin-only field, as on Linux.
        If the hub does not answer the finding is kept and retried before the next one."""
        payload = {"url": util.mask_private_ips(finding.url), "type": finding.threat_type, "severity": finding.severity,
                   "description": util.mask_private_ips(finding.description), "detected_by": detected_by,
                   "node_id": self.settings.node_id}
        if payload["url"] != finding.url:
            payload["real_url"] = finding.url
        self.resend_waiting()
        if not self._deliver(payload):
            self.waiting.append(payload)

    def _deliver(self, payload):
        """True when the hub took the finding, or refused it for good (retrying a refusal would never help)."""
        status, _ = self._send("/threats/", payload)
        if status == 0 or status == 429:
            return False
        if status >= 400:
            log.error("the hub refused a finding (HTTP %s); dropped", status)
        return True

    def resend_waiting(self):
        """Try the waiting findings again, oldest first, at most 20 per call; stop at the first failure."""
        for _ in range(20):
            if not self.waiting:
                return
            payload = self.waiting.popleft()
            if not self._deliver(payload):
                self.waiting.appendleft(payload)
                return
