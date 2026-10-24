# SwarmSentinel sandbox

A throwaway machine for two jobs that must never run on a real install:

1. **The customer experience.** Install a release package on a fresh Ubuntu exactly as a customer would, and time it.
2. **Live red-team drills.** Stage real attacks on that machine (log lines, a fake miner, a backdoor port, a touched
   system file, a real firewall block) and check SwarmSentinel catches each one. Evasion attempts that slip through
   are reported as known gaps.

It is the first step towards a permanent sandbox that keeps attacking its own copy of SSAI and records what to
improve.

## 1. Build a release package (on any clone)

```bash
deploy/make-release.sh                     # -> dist/swarmsentinel-<version>.tar.gz and its .sha256
```

No git history, no internal plans or lab data (see `.gitattributes`), and it refuses to build if a secret-looking
file would be included.

## 2. Create the VM (Windows + VirtualBox)

```powershell
powershell -ExecutionPolicy Bypass -File deploy\sandbox\create-virtualbox-vm.ps1 -Iso C:\path\ubuntu-24.04.5-live-server-amd64.iso
```

Unattended Ubuntu Server install (10-15 minutes, headless). Networking keeps it off your LAN:

| NIC | Network | Used for |
|---|---|---|
| 1 | NAT | Internet for packages. SSH on `127.0.0.1:2222`, dashboard on `http://127.0.0.1:5080` (this PC only) |
| 2 | Host-only (`192.168.56.0/24`) | Other VirtualBox VMs (Kali, Parrot) can attack it; your real network cannot see it |

Login is SSH key only (`ssh -p 2222 ssai@127.0.0.1`); the console password is in the VM's folder
(`console-login.txt`). The account has passwordless sudo, which is fine for a throwaway sandbox and never acceptable
anywhere else.

## 3. Install the package as a customer would

```bash
scp -P 2222 dist/swarmsentinel-<version>.tar.gz deploy/sandbox/setup-sandbox.sh ssai@127.0.0.1:
ssh -p 2222 ssai@127.0.0.1 'sudo bash setup-sandbox.sh swarmsentinel-<version>.tar.gz --sha256 <hash>'
```

It checks the checksum, unpacks to `/opt/swarmsentinel/<version>`, switches the firewall on (SSH and the dashboard
allowed), runs `deploy/install.sh`, reports how long the install took, and marks the install as a sandbox
(`SSAI_SANDBOX=1`, `SSAI_INTERVAL_SCALE=0.2`: agents check five times as often).

## 4. Run the drills

```bash
sudo /opt/swarmsentinel/current/swarmsentinel-env/bin/python3 /opt/swarmsentinel/current/backend/tools/sandbox_drills.py
```

| Drill | What is staged | Expected |
|---|---|---|
| brute-force | 6 failed SSH logins from one address | caught (brute-force) |
| low-and-slow-brute-force | 4 failed logins from each of 6 addresses | evasion attempt: a miss is a known gap |
| break-in-attempt | a "POSSIBLE BREAK-IN ATTEMPT" syslog line | caught (intrusion-attempt) |
| miner-process | a process named `xmrig-ssai-drill` | caught (suspicious-process) |
| backdoor-port | a listener on port 4444 | caught (unexpected-listener) |
| file-tamper | `/etc/ssh/sshd_config` timestamp changed (contents untouched) | caught (file-modification) |
| firewall-round-trip | block the brute-force address through the API, check ufw, unblock, check | rule added then removed |
| redteam-probes | the 13 offline probes | all pass |

Addresses are from the documentation ranges (`203.0.113.0/24`, `198.51.100.0/24`). Reports go to
`backend/instance/sandbox_drills/` (`.json` + `.md`). The tool refuses to run without `SSAI_SANDBOX=1`.

## Not yet (next steps)

- Attacks from another VM on the host-only network (Kali/Parrot): port scans, real SSH brute force, beaconing.
- Live prompt-injection against the configured cloud models (needs an API key in the sandbox; costs calls).
- Run the drills on a schedule and track gaps over time (the "always-on sandbox").
