# Deploying SwarmSentinel

Everything needed to install, update and remove SwarmSentinel on a Linux machine is in this repository. No
hand-editing of unit files, no copying files over SSH.

## Requirements

- Linux with systemd (Debian, Ubuntu, Raspberry Pi OS, Fedora, ...), Python 3.10+, `python3-venv`, `git`, `curl`
- Root (`sudo`) to install services. The dashboard runs as your normal user; the agents run as root so they can read
  system logs and inspect connections.
- Optional but recommended: `ufw` (firewall blocking), `iproute2` and `ping` (device identification)

No Docker needed. A Docker image is also provided (see below).

## Install a hub (the machine that hosts the dashboard)

```bash
git clone https://github.com/gatsbysdream25-max/SSAI-Deployment.git
cd SSAI-Deployment
sudo deploy/install.sh
```

The installer creates a virtualenv, installs the dependencies, writes `.env` with freshly generated secrets (an
existing `.env` is never overwritten), installs and starts the services, and waits for the dashboard to answer.
Run it again at any time to repair or upgrade: it is idempotent. Add `--dry-run` to see what it would do.

At the end the installer prints the dashboard address, a sign-in page and a **one-time admin password, shown once and not
stored anywhere**: copy it now (change it later under Settings, or reset it with `deploy/set-password.sh`). If the machine
has a firewall (`ufw`), allow your network to reach the dashboard, for example `sudo ufw allow from 192.168.1.0/24 to any port 5000`
(use your own network). If it stops with "python3-venv is missing", run `sudo apt install python3-venv` and run it again.

Then open the URL it prints and add an AI provider key on the **/setup** page.

## Add another machine (a node)

A node runs the host-level sensors (logs, ports, processes, connections, file integrity, disk, services) and reports
to the hub. It runs no dashboard, no LAN scanner and no AI panel.

Each node gets **its own credential**. The hub's admin key never leaves the hub.

1. On the hub, create a single-use enrollment code (valid for an hour): run `deploy/new-node.sh` (add `--node-id NAME`
   to name the machine), or open **Settings -> Machines -> Create enrollment code**. Either prints the exact command.
2. On the new machine:

```bash
git clone https://github.com/gatsbysdream25-max/SSAI-Deployment.git
cd SSAI-Deployment
sudo deploy/install.sh --role node --hub-url http://HUB-ADDRESS:5000 --enroll-code XXXX-XXXX-XXXX-XXXX
```

The installer trades the code for the machine's token before it builds anything, so a wrong or expired code stops it
right away. The token is stored only as a hash on the hub and in `.env` (mode 600) on the machine. Re-running the
installer keeps the existing credential; `--re-enroll` with a new code replaces it.

What a node's credential can do: register its own agents (`<agent>@<machine>`) and report threats, which are always
stamped with that machine's name. It cannot dismiss, block, change settings, read keys or create credentials. A machine
is rate-limited on its own, and the same finding on two machines is two separate threats.

To cut a machine off, use **Settings -> Machines -> Revoke credential**: its token stops working immediately and its
history is kept. Enroll it again with a new code (bound to its name) to bring it back. Codes are single-use, and an
address that tries five wrong codes in five minutes is locked out for a while.

If the hub runs `ufw`, allow the nodes to reach it: `sudo ufw allow from <your-lan>/24 to any port 5000`.

## Operations

| Task | Command |
|---|---|
| Change or reset the admin password | `deploy/set-password.sh` (or Settings once signed in) |
| Sandbox the services with systemd (undoes itself if anything breaks) | `sudo deploy/harden.sh apply` / `revert` / `status` |
| See what old data could be removed (changes nothing) | `swarmsentinel-env/bin/python3 backend/retention.py` |
| Remove it (writes a backup first) | `backend/retention.py --apply` |
| Names never to publish in the threat ledger | `SSAI_PRIVATE_NAMES=name1,name2` in `.env` (hostnames the hub has seen are added automatically) |
| Remove private data from an existing ledger | `swarmsentinel-env/bin/python3 backend/github_reporter.py --scrub` |
| Regenerate the third-party licence list | `swarmsentinel-env/bin/python3 deploy/gen_notices.py > THIRD-PARTY-NOTICES.md` |

## Update

```bash
deploy/update.sh            # or: deploy/update.sh --check
```

It fetches, refuses if you have local edits or your history has diverged, fast-forwards, runs the new code's test
suite, and only then restarts the services and checks they are healthy. If the tests or the health check fail, the
previous version is restored automatically. Database changes are applied by the app itself on start.

For unattended updates, install with `--auto-update` (a daily systemd timer runs `deploy/update.sh`).

A hub also gets a daily **retention** timer (03:30, `ssai-retention.timer`): `backend/retention.py --apply --vacuum
--keep-backups 7` removes low-severity rows older than 30 days, info rows older than 14 days, and resolved/dismissed
medium+ rows older than a year. Active medium, high and critical findings are never removed. It writes a backup next to
the database before deleting and keeps the 7 newest. Run `backend/retention.py` alone for a dry run; install with
`--no-retention` to opt out.

## Roles

| | hub | node |
|---|---|---|
| Dashboard, API, database | yes | no |
| Host sensors (auth log, syslog, ports, processes, connections, file integrity, disk, services) | yes | yes |
| Feed store for connection matching (abuse.ch) | yes | yes |
| LAN scan, Pi-hole, email, browser extension, reference feed, AI consensus | yes | no |

Which agents run can be changed per machine in **Settings** on a hub, or in `backend/instance/agents.json`. Setting
`SSAI_ROLE=node` in `.env` is what makes a machine a node.

## Docker

```bash
docker compose up -d
```

State lives in the `ssai_data` volume (`/data`), including operator settings, so upgrading the image keeps them.
Inside a container the LAN scan and the firewall action cannot see the host network; every other agent works. For the
full feature set on a Linux host use `docker compose -f docker-compose.yml -f docker-compose.linux-host.yml up -d`.

## Uninstall

```bash
sudo deploy/uninstall.sh          # removes services and sudo rules, keeps your data
sudo deploy/uninstall.sh --purge  # also deletes the database, settings and logs (asks first)
```

## Known limits

- **The dashboard pages embed the admin API key for anyone who can open them**, so on a shared network the admin key is
  effectively readable by every machine that can reach the hub. Node credentials stop a compromised *node* from acting
  as admin, but they cannot protect the hub from a hostile *neighbour* until the dashboard has a real login. Keep the
  hub on a trusted network segment for now.
- The dashboard and the node credential travel over plain HTTP: put the hub behind a TLS reverse proxy before exposing it
  beyond your LAN (`--hub-url https://...` is supported). Set `SSAI_TRUSTED_PROXIES` to the proxy's address so rate limits
  see the real client.
- Nodes are Linux only. Windows and macOS endpoints are not supported yet (the old Windows client under
  `windows_client_incomplete/` predates enrollment codes and cannot register).
- The public threat ledger auto-push (`ssai-github`) is not installed by this script; it needs repository credentials
  and is opt-in.
