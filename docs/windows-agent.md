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
| `WinSecurityAgent` | Windows protection settings | Defender real-time protection switched off, out-of-date virus definitions, a firewall profile switched off |
| `WinDiskAgent` | The system drive | Less than 10% free space |

Rules it keeps: findings show private addresses masked (`192.168.xxx.xxx`); a command line is **never** copied into a
finding (it can hold passwords); the agent sends nothing except findings and "still alive" signals to its own hub.

The AI panel runs on the hub. A Windows PC on its own is at protection level 1 to 2 (Watch / Guard); the hub decides how
serious a finding is.

## Install (about two minutes)

1. On the hub's **Settings** page, under *Machines*, optionally type a name for the PC and click **Create enrollment
   code**. It shows a one-time code and the Windows command.
2. On the Windows PC, open PowerShell **as administrator** and paste the Windows command. It downloads
   `ssai-agent.exe`, **checks its checksum**, installs it to `C:\Program Files\SwarmSentinel`, trades the code for this
   PC's own credential, and starts the agent.

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
