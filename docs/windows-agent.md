# SwarmSentinel agent for Windows

A small program that watches a Windows 10/11 PC and reports to a SwarmSentinel hub. It needs no Python, no WSL and no
Docker: it is one file, `ssai-agent.exe`. The hub (the dashboard and the AI panel) runs on a Linux machine, in Docker, or
in WSL; the Windows agent is a **node** that reports to it.

## What it watches

| Agent on the dashboard | Looks at | Reports |
|---|---|---|
| `WinLoginAgent` | The Windows Security log | Bursts of failed passwords (5 or more in one minute from one place) and Remote Desktop sign-ins from internet addresses |
| `WinPortAgent` | Programs listening for network connections | A new program that starts accepting connections from the network, once it is still there on the next look. Whatever was already listening at install time counts as normal |
| `WinProcessAgent` | Running programs | Crypto miners and hacking tools by name, and the command tricks malware uses to start: hidden encoded PowerShell, `mshta` or `certutil` fetching from the web, PowerShell downloading and running code (the "paste this into Run" trick) |
| `WinDefenderAgent` | What Windows Defender finds, and Windows' protection settings | A new detection (threat name and file name only, never the folder), and, when Defender is the active antivirus, real-time protection switched off, out-of-date virus definitions, controlled folder access or attack surface reduction rules switched off (low). Also a firewall profile switched off |
| `WinEventAgent` | The System, Security and PowerShell event logs | A new service (high if it starts from a user or temp folder), a new local account, someone added to the Administrators group, a cleared event log, a new scheduled task (low; Windows' own are ignored), and PowerShell scripts Windows flags as suspicious (counted, the script text is never copied) |
| `WinStabilityAgent` | Crash and hardware-error records, and the system drive | Blue-screen crashes with the bug check name, restarts without a clean shutdown, hardware errors (WHEA), and a high finding when 3 or more crashes happen in a day. On its first look it reports the last 24 hours, because a crash just before install matters. Also less than 10% free space on the system drive |

Two notes on the event sensors. Account, group and task changes come from the Security log, which Windows only fills if
auditing is on: account and group changes are audited by default, scheduled-task creation is not (turn on "Audit Other
Object Access Events" to see it). And the agent keeps no copy of any log: it remembers only the number of the last record
it saw, so on the first look it starts from "now" (the stability sensor excepted, as above).

Rules it keeps: findings show private addresses masked (`192.168.xxx.xxx`); a command line is **never** copied into a
finding (it can hold passwords); the agent sends nothing except findings and "still alive" signals to its own hub.

The AI panel runs on the hub. A Windows PC on its own is at protection level 1 to 2 (Watch / Guard); the hub decides how
serious a finding is.

## Acting on findings (off by default)

By default the agent only watches. A PC can also carry out actions that **a signed-in person approves on the hub**; there
is no automatic mode. Turn it on per PC, in an administrator PowerShell on that PC (the hub cannot turn it on):

```powershell
& "C:\Program Files\SwarmSentinel\ssai-agent.exe" response approve     # off again: ... response off
```

The agent never listens for commands. Every 30 seconds it asks the hub whether anything was approved for it, so nothing is
opened on the PC and it works on any network. The hub sends an action name and checked arguments, never a script. The agent
runs only these:

| Action | What it does | Undone |
|---|---|---|
| `block-ip` | Windows Firewall rules `SSAI-block-<id>-in/out` for one public address | after its time limit (default 24 h, at most 7 days) |
| `defender-scan` / `defender-remove` | Defender quick scan / removal of the threats Defender lists | not needed |
| `kill-process` | stops one process, by id **and** program name | cannot be undone |
| `isolate-host` | blocks all traffic except to the hub | after its time limit (default 1 h, at most 24 h) |
| `block-domain` | `0.0.0.0` lines in the hosts file (a browser with its own encrypted DNS can bypass it) | after its time limit |

Rules the agent enforces itself: every address inside the organisation, the hub, the PC's gateway and DNS servers are never
blocked (if it cannot list them, nothing is blocked); Windows' own programs, Defender and the agent are never stopped, nor
anything running from the Windows folder; isolation needs the hub's address as an IP number or `localhost`, and refuses
if it cannot read the firewall settings it would have to put back; an action runs at most once and not at all after
an hour of waiting; every network change is undone by the agent from a list kept in `response.json`, so it is lifted even
if the hub is gone or the agent restarts (and still when the mode is switched to `off`). `ssai-agent.exe response` lists
what is waiting to be undone. Each action is recorded in `agent.log` and in the hub's audit file.

Hub side: `POST /api/nodes/<node>/actions` (a signed-in person, not an API key), `GET /api/nodes/<node>/actions`,
`POST /api/nodes/<node>/actions/<id>/undo`. There is no dashboard button for these yet.

## Install (about two minutes)

1. On the hub's **Settings** page, under *Machines*, optionally type a name for the PC and click **Create enrollment
   code**. It shows a one-time code and the Windows command.
2. On the Windows PC, open PowerShell **as administrator** and paste the Windows command. It downloads
   `ssai-agent.exe`, **checks its checksum**, installs it to `C:\Program Files\SwarmSentinel`, trades the code for this
   PC's own credential, and starts the agent.

The installer also puts a **SwarmSentinel Dashboard** icon on the Desktop and in the Start menu's app list. It opens the hub's
dashboard in your browser (the agent itself has no window). Leave either out with `-DesktopIcon Off` or `-StartMenu Off`. Windows
does not allow a program to pin itself to Start: open Start, All apps, right-click **SwarmSentinel Dashboard**, choose **Pin to Start**.
Uninstalling removes both icons.

Start at boot is a choice. The default is **on**; add `-AutoStart Off` to the command to install without it. With it off
the agent runs now but is not started after a reboot (start it with `Start-ScheduledTask -TaskName 'SwarmSentinel
Agent'`). Run the installer again with `-AutoStart On` or `-AutoStart Off` to change your mind later.

The agent runs as SYSTEM, because Windows only lets administrators and SYSTEM read the Security log. Its folder
`C:\ProgramData\SwarmSentinel` (credential, memory, log) is readable only by SYSTEM and Administrators.

## Everyday commands

```
"C:\Program Files\SwarmSentinel\ssai-agent.exe" status     # is the hub reachable, is the credential accepted
"C:\Program Files\SwarmSentinel\ssai-agent.exe" scan       # look once, print what it finds, send nothing
Get-Content C:\ProgramData\SwarmSentinel\agent.log -Tail 30   # what it has been doing
```

If `status` or the log says the **Security log cannot be read**, the agent is not running as SYSTEM or Administrator and
the sign-in sensor is blind. The installer sets this up correctly.

## Remove

```
.\install-windows-agent.ps1 -Uninstall            # stops and removes the program; keeps the credential and log
.\install-windows-agent.ps1 -Uninstall -PurgeData # removes those too
```
Then delete the machine on the hub's Settings page (or **Revoke** it, which keeps its history).

## For developers

- Source: `windows_agent/` (standard library only). `python windows_agent/main.py scan` runs it from source.
- Build the exe on Windows: `python windows_agent/build_exe.py --out C:\ssai-dist` (needs PyInstaller). Attach
  `ssai-agent.exe`, `ssai-agent.exe.sha256` and `deploy/install-windows-agent.ps1` to a release.
- Tests: `backend/tools/test_windows_agent.py`. The sensors are tested with canned Windows output, and the hub client is
  tested against the real hub routes, so the agent and the hub cannot drift apart unnoticed.
- Trying it without administrator rights: `SSAI_AGENT_HOME=<folder>` moves its files, `SSAI_AGENT_NO_LOCK=1` skips
  locking the folder, `SSAI_AGENT_INTERVAL_SCALE=0.1` makes the sensors look ten times as often. Never use
  `SSAI_AGENT_NO_LOCK` on a real install.
- Not done yet: the exe is unsigned (Windows SmartScreen may warn), and the agent does not update itself; reinstall with
  the new release to update.

## Seeing which version each machine runs

Every machine tells the hub its version each time it checks in. In **Settings, Machines** each one shows "up to date", or
"this hub expects X", or "has not reported its version yet" (an older agent). The hub only compares and shows; it never
tells a machine to update. To update a Windows PC, run the installer again from the latest release; for a Linux machine run
`deploy/update.sh` on it. That keeps a stolen dashboard login from being able to push code to your machines.
