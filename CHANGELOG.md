# Changelog

## Unreleased (2026-11-04)

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
