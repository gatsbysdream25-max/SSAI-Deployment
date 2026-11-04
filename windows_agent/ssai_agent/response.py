"""Carrying out actions a person approved on the hub, on this PC.

The agent never listens for commands. Every 30 seconds it ASKS the hub whether a person approved anything for this PC, and
runs only what is on the fixed list below. The hub sends a name and checked arguments, never a script. A PC whose agent.json
says "response": "off" (the default) never asks at all; only an administrator of this PC can change that.

Safety rules, all enforced here whatever the hub says:
  * each network change (block an address or a name, isolate the PC) is undone by this agent after its time limit, from a
    list kept on disk, so it is lifted even if the hub is gone or the agent restarts;
  * the hub, this PC's gateway and DNS servers, and every address inside the organisation are never blocked;
  * Windows' own programs, Defender and this agent are never stopped;
  * an action runs at most once (its id is written down before it starts) and not at all if it waited more than an hour.
Killing a process cannot be undone; everything else can.
"""
import ipaddress
import logging
import os
import re
import socket
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

from . import config, util

log = logging.getLogger("response")
POLL_SECONDS = 30
KEEP_HANDLED = 200
DEFAULT_TTL_HOURS = {"block-ip": 24, "block-domain": 24, "isolate-host": 1}
MAX_TTL_HOURS = {"block-ip": 24 * 7, "block-domain": 24 * 7, "isolate-host": 24}
PROTECTED_IMAGES = frozenset((
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "lsaiso.exe",
    "svchost.exe", "dwm.exe", "fontdrvhost.exe", "msmpeng.exe", "nissrv.exe", "securityhealthservice.exe", "ssai-agent.exe"))
_INTERNAL = tuple(ipaddress.ip_network(n) for n in
                  ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7", "fe80::/10"))
_IMAGE = re.compile(r"^[\w .()\-]{1,100}\.exe$", re.I)
_DOMAIN = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$")
_PROFILE = re.compile(r"^(Domain|Private|Public)\|(Allow|Block|NotConfigured)\|(Allow|Block|NotConfigured)$")


class Refused(Exception):
    """The agent will not (or could not) do this; the message goes back to the hub and the operator."""


def hosts_file():
    return os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "drivers", "etc", "hosts")


class Responder:
    def __init__(self, client, settings, path=None, run=util.run_checked, clock=time.time, hosts_path=None,
                 mode=config.response_mode):
        self.client = client
        self.settings = settings
        self.path = path or os.path.join(config.data_folder(), "response.json")
        self.run = run                          # (args, timeout) -> (exit code, stdout, stderr); tests replace it
        self.clock = clock
        self.hosts_path = hosts_path or hosts_file()
        self.mode = mode
        saved = util.read_json(self.path, {})
        self.undo = [r for r in saved.get("undo", []) if isinstance(r, dict)]
        self.handled = [i for i in saved.get("handled", []) if isinstance(i, int)]
        self.handlers = {"block-ip": self._block_ip, "block-domain": self._block_domain, "defender-scan": self._defender_scan,
                         "defender-remove": self._defender_remove, "kill-process": self._kill_process,
                         "isolate-host": self._isolate_host, "undo": self._undo_action}

    # ── bookkeeping ──
    def save(self):
        util.write_json(self.path, {"undo": self.undo, "handled": self.handled[-KEEP_HANDLED:]})

    def _ttl_seconds(self, name, hours):
        try:
            hours = float(hours)
        except (TypeError, ValueError):
            hours = DEFAULT_TTL_HOURS[name]
        return min(max(hours, 0.01), MAX_TTL_HOURS[name]) * 3600

    def _register_undo(self, record, name, hours):
        record["undo_at"] = self.clock() + self._ttl_seconds(name, hours)
        self.undo.append(record)
        self.save()                             # on disk BEFORE the change is made: a crash must never leave a block with no timer
        return record

    def _drop_undo(self, record):
        if record in self.undo:
            self.undo.remove(record)
            self.save()

    # ── the loop ──
    def tick(self):
        self.undo_due()
        if self.mode() != "approve":
            return
        for action in self.client.fetch_actions():
            if isinstance(action, dict):
                self.handle(action)

    def run_forever(self, stop_event):
        log.info("response: %s", "waiting for actions a person approves on the hub" if self.mode() == "approve"
                 else "off (this PC never asks the hub for actions)")
        while not stop_event.is_set():
            try:
                self.tick()
            except Exception as error:           # nothing here may take the agent down
                log.error("response loop failed: %s", error)
            stop_event.wait(POLL_SECONDS)

    def handle(self, action):
        aid = action.get("id")
        if not isinstance(aid, int) or isinstance(aid, bool) or aid in self.handled:
            return
        self.handled.append(aid)
        self.save()                             # written down before it runs: an action never runs twice
        name = str(action.get("action"))
        try:
            until = datetime.fromisoformat(str(action.get("valid_until")))
            if until.tzinfo is None:
                until = until.replace(tzinfo=timezone.utc)
            if until < datetime.now(timezone.utc):
                raise Refused("this action waited too long and was dropped")
            if name not in self.handlers:
                raise Refused(f"this agent does not know the action '{name}'")
            args = action.get("args") if isinstance(action.get("args"), dict) else {}
            detail, ok = self.handlers[name](aid, args, action.get("ttl_hours")), True
        except Refused as reason:
            detail, ok = str(reason), False
        except Exception as error:               # a bug here is reported, not raised
            log.exception("action %s failed", aid)
            detail, ok = f"failed: {error}", False
        log.warning("ACTION %s %s %s: %s", aid, name, "ok" if ok else "FAILED", detail)
        self.client.report_action(aid, ok, detail)

    def undo_due(self):
        for record in list(self.undo):
            if record.get("undo_at", 0) > self.clock():
                continue
            try:
                self._lift(record)
            except Refused as reason:
                log.error("could not undo action %s yet: %s", record.get("id"), reason)
                continue
            self._drop_undo(record)
            log.warning("ACTION %s %s undone: time limit reached", record.get("id"), record.get("kind"))
            self.client.report_action(record.get("id", 0), True, "time limit reached; undone", undone=True)

    # ── helpers ──
    def _ps(self, script, timeout=60):
        wrapped = ("[Console]::OutputEncoding = [Text.Encoding]::UTF8; $ErrorActionPreference = 'Stop'; "
                   "try { " + script + "; exit 0 } catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }")
        return self.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", wrapped], timeout)

    def _netsh(self, *args):
        return self.run(["netsh", "advfirewall", "firewall", *args], 30)

    @staticmethod
    def _internal(address):
        if getattr(address, "ipv4_mapped", None) is not None:
            address = address.ipv4_mapped
        return (address.is_loopback or address.is_unspecified or address.is_multicast or address.is_link_local
                or address.is_reserved or any(address.version == n.version and address in n for n in _INTERNAL))

    def _hub_addresses(self):
        host = urlsplit(self.settings.api).hostname or ""
        try:
            return {ipaddress.ip_address(host)}
        except ValueError:
            pass
        try:
            return {ipaddress.ip_address(info[4][0]) for info in socket.getaddrinfo(host, None)}
        except (OSError, ValueError):
            return set()

    def _never_block(self):
        """The hub, this PC's gateways and DNS servers. If they cannot be listed the block is refused (fail closed)."""
        code, out, err = self._ps("$a = @(); $a += Get-DnsClientServerAddress | ForEach-Object { $_.ServerAddresses }; "
                                  "$a += Get-NetRoute -ErrorAction SilentlyContinue | Where-Object { $_.DestinationPrefix -in '0.0.0.0/0','::/0' } "
                                  "| ForEach-Object { $_.NextHop }; "
                                  "$a | Where-Object { $_ } | Sort-Object -Unique")
        if code != 0:
            raise Refused("could not list this PC's DNS servers and gateway, so nothing is blocked: " + (err.strip() or "no answer")[:150])
        found = set(self._hub_addresses())
        for line in out.split():
            try:
                found.add(ipaddress.ip_address(line.strip().split("%")[0]))
            except ValueError:
                continue
        return found

    # ── block an address ──
    def _block_ip(self, aid, args, ttl):
        try:
            ip = ipaddress.ip_address(str(args.get("ip", "")).strip())
        except ValueError:
            raise Refused("not a valid IP address") from None
        if self._internal(ip):
            raise Refused(f"{ip} is inside the organisation or not routable, so it is never blocked")
        if ip in self._never_block():
            raise Refused(f"{ip} is the hub, this PC's gateway or a DNS server, so it is never blocked")
        record = self._register_undo({"id": aid, "kind": "block-ip", "ip": str(ip)}, "block-ip", ttl)
        for direction in ("out", "in"):
            code, out, err = self._netsh("add", "rule", f"name=SSAI-block-{aid}-{direction}", f"dir={direction}", "action=block",
                                         f"remoteip={ip}", "enable=yes", "profile=any")
            if code != 0:
                self._lift(record, quiet=True)
                self._drop_undo(record)
                raise Refused("Windows Firewall refused the rule: " + (out + err).strip()[:150])
        return f"blocked {ip} in both directions (lifted automatically after {self._hours(ttl, 'block-ip')} h)"

    def _hours(self, ttl, name):
        return round(self._ttl_seconds(name, ttl) / 3600, 2)

    # ── block a name ──
    def _block_domain(self, aid, args, ttl):
        domain = str(args.get("domain", "")).strip().lower().rstrip(".")
        if not _DOMAIN.match(domain) or len(domain) > 253:
            raise Refused("not a valid domain name")
        hub_name = (urlsplit(self.settings.api).hostname or "").lower()
        if hub_name == domain or hub_name.endswith("." + domain):
            raise Refused(f"{domain} covers the hub's own address ({hub_name}); blocking it would cut this PC off from the hub")
        record = self._register_undo({"id": aid, "kind": "block-domain", "domain": domain}, "block-domain", ttl)
        tag = f"# SSAI-{aid}"
        try:
            with open(self.hosts_path, encoding="utf-8", errors="replace") as handle:
                existing = handle.read()
            with open(self.hosts_path, "a", encoding="utf-8") as handle:
                handle.write(("" if existing.endswith("\n") or not existing else "\n")
                             + f"0.0.0.0 {domain} {tag}\n0.0.0.0 www.{domain} {tag}\n")
        except OSError as error:
            self._drop_undo(record)
            raise Refused(f"could not write the hosts file: {error}") from None
        self.run(["ipconfig", "/flushdns"], 15)
        return (f"{domain} and www.{domain} now resolve to 0.0.0.0 on this PC (hosts file; a browser using its own encrypted DNS "
                f"can bypass this); lifted automatically after {self._hours(ttl, 'block-domain')} h")

    # ── Defender ──
    def _defender_scan(self, aid, args, ttl):
        code, out, err = self._ps("Start-MpScan -ScanType QuickScan", 900)
        if err == "timed out":
            return "quick scan started; still running after 15 minutes (Defender keeps scanning)"
        if code != 0:
            raise Refused("Defender could not scan: " + (err.strip() or out.strip() or "no answer")[:200])
        return "Defender quick scan finished"

    def _defender_remove(self, aid, args, ttl):
        code, out, err = self._ps("$t = @(Get-MpThreat); if ($t.Count -eq 0) { 'Defender lists no active threats' } else { "
                                  "Remove-MpThreat; 'Defender is removing ' + $t.Count + ' threat(s)' }", 300)
        if code != 0:
            raise Refused("Defender could not remove threats: " + (err.strip() or out.strip() or "no answer")[:200])
        return out.strip()[:200] or "done"

    # ── stop a process ──
    def _kill_process(self, aid, args, ttl):
        try:
            pid = int(args.get("pid"))
        except (TypeError, ValueError):
            raise Refused("not a valid process id") from None
        image = str(args.get("image", "")).strip()
        if not _IMAGE.match(image):
            raise Refused("not a valid program file name")
        if pid <= 4 or pid in (os.getpid(), os.getppid()):
            raise Refused("that process id cannot be stopped")
        if image.lower() in PROTECTED_IMAGES:
            raise Refused(f"{image} is part of Windows or of SwarmSentinel's protection and is never stopped")
        code, out, err = self._ps(
            f"$p = Get-Process -Id {pid}; "
            f"if (($p.ProcessName + '.exe') -ne '{image}') {{ throw ('process {pid} is ' + $p.ProcessName + '.exe, not {image}') }}; "
            "if (-not $p.Path) { throw 'cannot read the program path, so it is not stopped' }; "
            "if ($p.Path.StartsWith($env:SystemRoot, [StringComparison]::OrdinalIgnoreCase)) { throw 'it runs from the Windows folder, so it is not stopped' }; "
            f"Stop-Process -Id {pid} -Force; 'stopped'")
        if code != 0:
            raise Refused((err.strip() or out.strip() or "no answer")[:200])
        return f"stopped {image} (process {pid}); this cannot be undone"

    # ── isolate the PC ──
    def _starts_at_boot(self):
        """True only if the agent's scheduled task starts at boot. Fails closed: if it cannot be confirmed, answer False."""
        code, out, err = self._ps("Get-ScheduledTask -TaskName 'SwarmSentinel Agent' | ForEach-Object { $_.Triggers } "
                                  "| Where-Object { $_.CimClass.CimClassName -eq 'MSFT_TaskBootTrigger' } "
                                  "| ForEach-Object { 'boot-start' }")
        return code == 0 and "boot-start" in out

    def _isolate_host(self, aid, args, ttl):
        if any(r.get("kind") == "isolate-host" for r in self.undo):
            raise Refused("this PC is already isolated")
        # Only this agent can lift the isolation. If it did not restart after a reboot the PC would stay cut off, so
        # isolation is only allowed on a PC where the agent starts by itself at boot.
        if not self._starts_at_boot():
            raise Refused("this agent is not set to start at boot, so after a restart nothing would lift the isolation; "
                          "re-run the installer with -AutoStart On first")
        host = urlsplit(self.settings.api).hostname or ""
        try:
            hub = ipaddress.ip_address(host)
        except ValueError:
            if host.lower() != "localhost":
                raise Refused("isolation needs the hub's address as an IP number (this agent was set up with the name "
                              f"'{host}'); without it the PC could not reach the hub while isolated") from None
            hub = ipaddress.ip_address("127.0.0.1")
        code, out, err = self._ps("Get-NetFirewallProfile -All | ForEach-Object { \"$($_.Name)|$($_.DefaultInboundAction)|$($_.DefaultOutboundAction)\" }")
        prior = [line.strip() for line in out.splitlines() if line.strip()]
        if code != 0 or len(prior) != 3 or not all(_PROFILE.match(line) for line in prior):
            raise Refused("could not read the firewall's current settings, so it will not change them (it could not restore them)")
        rule = f"SSAI-isolate-allow-{aid}"
        record = self._register_undo({"id": aid, "kind": "isolate-host", "prior": prior, "rule": rule}, "isolate-host", ttl)
        try:
            if not hub.is_loopback:
                code, out, err = self._netsh("add", "rule", f"name={rule}", "dir=out", "action=allow", f"remoteip={hub}",
                                             "enable=yes", "profile=any")
                if code != 0:
                    raise Refused("Windows Firewall refused the rule that keeps the hub reachable: " + (out + err).strip()[:150])
            code, out, err = self._ps("Set-NetFirewallProfile -All -DefaultInboundAction Block -DefaultOutboundAction Block")
            if code != 0:
                raise Refused("could not switch the firewall to block everything: " + (err.strip() or out.strip())[:150])
        except Refused:
            self._lift(record, quiet=True)
            self._drop_undo(record)
            raise
        return (f"PC isolated: all traffic blocked except to the hub ({hub}); restored automatically after "
                f"{self._hours(ttl, 'isolate-host')} h")

    # ── undo ──
    def _lift(self, record, quiet=False):
        """Reverse one recorded change. Raises Refused when it could not (the caller keeps the record and tries again)."""
        kind, problems = record.get("kind"), []
        if kind == "block-ip":
            for direction in ("out", "in"):
                code, out, err = self._netsh("delete", "rule", f"name=SSAI-block-{record['id']}-{direction}")
                if code != 0 and "no rules match" not in (out + err).lower():
                    problems.append((out + err).strip()[:100])
        elif kind == "block-domain":
            tag = f"# SSAI-{record['id']}"
            try:
                with open(self.hosts_path, encoding="utf-8", errors="replace") as handle:
                    lines = handle.read().splitlines()
                kept = [line for line in lines if not line.rstrip().endswith(tag)]
                if len(kept) != len(lines):
                    with open(self.hosts_path, "w", encoding="utf-8") as handle:
                        handle.write("\n".join(kept) + "\n")
                self.run(["ipconfig", "/flushdns"], 15)
            except OSError as error:
                problems.append(str(error))
        elif kind == "isolate-host":
            for line in record.get("prior", []):
                match = _PROFILE.match(line)
                if match:
                    code, out, err = self._ps(f"Set-NetFirewallProfile -Name {match.group(1)} -DefaultInboundAction "
                                              f"{match.group(2)} -DefaultOutboundAction {match.group(3)}")
                    if code != 0:
                        problems.append(err.strip()[:100])
            code, out, err = self._netsh("delete", "rule", f"name={record.get('rule', '')}")
            if code != 0 and "no rules match" not in (out + err).lower():
                problems.append((out + err).strip()[:100])
        if problems and not quiet:
            raise Refused("; ".join(p for p in problems if p) or "undo failed")

    def lift_everything(self):
        """Undo every block and isolation still waiting on a timer, now. Used before the agent is removed or stops starting
        at boot, so it never leaves the PC cut off. Returns (lifted, failed) counts."""
        lifted = failed = 0
        for record in list(self.undo):
            try:
                self._lift(record)
            except Refused as reason:
                log.error("could not undo action %s: %s", record.get("id"), reason)
                failed += 1
                continue
            self._drop_undo(record)
            lifted += 1
        return lifted, failed

    def _undo_action(self, aid, args, ttl):
        try:
            of = int(args.get("of"))
        except (TypeError, ValueError):
            raise Refused("not a valid action id") from None
        record = next((r for r in self.undo if r.get("id") == of), None)
        if record is None:
            raise Refused(f"nothing to undo for action {of} (already undone, or this agent did not run it)")
        self._lift(record)
        self._drop_undo(record)
        self.client.report_action(of, True, "undone at a person's request", undone=True)
        return f"undid action {of} ({record.get('kind')})"

    def describe(self):
        """For `ssai-agent response`: the mode and every change still waiting to be undone."""
        lines = [f"Response mode: {self.mode()}"]
        for record in self.undo:
            left = max(record.get("undo_at", 0) - self.clock(), 0) / 60
            lines.append(f"  action {record.get('id')} {record.get('kind')} will be undone in {left:.0f} min")
        return lines
