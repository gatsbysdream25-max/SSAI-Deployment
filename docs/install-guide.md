# Installing SwarmSentinel: which way, and what you get

SwarmSentinel runs on almost any machine. **How much it can protect depends on the machine**, and it tells you plainly (Settings, "Protection level", or `python3 backend/agents/capability.py`). This page helps you pick the install route first, then explains the four levels.

## 1. Pick a route

| Your machine | Use | Command |
|---|---|---|
| Ubuntu or Debian, with systemd (a PC, a server, a mini-PC, a VM) | **Native install**. Full protection. | `sudo deploy/install.sh` |
| Anything that runs Docker (Windows, Mac, any Linux) | **Docker**. Dashboard and AI panel work everywhere; watching the host itself is limited, see below. | `docker compose up -d` |
| Windows or Mac | **Docker Desktop** (above). On Windows you can also use WSL2 with Ubuntu and the native route inside it. There is no native Windows or Mac agent yet, so only the dashboard, the AI panel and the feeds run there, not the host sensors. `deploy\install-windows.ps1 -CheckOnly` checks the PC; without `-CheckOnly` and with `-Package` it sets up WSL2, Ubuntu and the installer in one go. *(WSL2 has not been tested on a real PC yet.)* | `docker compose up -d` |
| A Linux machine with Docker where you want the host watched too | **Docker, host mode** | `docker compose -f docker-compose.yml -f docker-compose.linux-host.yml up -d` |
| A small or extra machine that should report to one you already run | **Node** | `sudo deploy/install.sh --role node --hub-url http://HUB:5000 --enroll-code CODE` |
| No internet, or showing it somewhere else | **USB kit** | see [portable-and-relocation.md](portable-and-relocation.md) |

Not sure? Native on Ubuntu or Debian is the most complete; Docker is the quickest way to look at it.

**Tested.** On 2026-10-22 the installer and the whole test suite were run in clean containers of Ubuntu 22.04 (Python 3.10), Ubuntu 24.04 (3.12), Debian 12 (3.11) and Debian 13 (3.13): the install succeeded and every test passed on each. A container has no systemd, so those runs used `--no-systemd`: the step that installs and starts the services was not repeated there. It runs every day on the Ubuntu 24.04 machine that hosts this project. Other distributions are untested; the installer needs Python 3.10 or newer, `python3-venv` and (for the services) systemd.

## 2. The four levels

Each level includes the one before. The installer prints yours when it finishes, and Settings shows it any time (with what to do to reach the next one).

| Level | Name | What it does | What the machine needs |
|---|---|---|---|
| 1 | **Watch** | Watches this machine: failed logins, odd processes, open ports, file changes, disk and service health | Linux with systemd, about 1 GB of memory |
| 2 | **Guard** | Adds the dashboard, public threat lists matched against this network's traffic, local proof checks, a scan of the local network | 2 GB of memory, 2 GB free disk, `nmap` for the network scan |
| 3 | **Panel** | Adds the AI panel: several AI models judge each serious finding, and a person approves any action | Enough models to reach the minimum number of voters (3): free cloud keys on the `/setup` page, or local models |
| 4 | **Sovereign** | The panel runs on this machine's own models, so it works with no internet and no data leaves the building | Two local models on this machine: about 8 GB of memory and 9 GB of disk |

### Why a machine may sit lower than you hoped

- **Too little memory for the dashboard.** Install it as a *node* reporting to a bigger machine. It still watches itself.
- **Inside Docker.** A container cannot see the host's logs or services. The host-mode override (Linux only) mounts them; otherwise install natively. Docker's memory limit is respected: a container limited to 1 GB reports Level 1.
- **Models on another machine.** They vote, so you can reach Level 3, but the machine is not independent of the network, so it is not Sovereign. Install models here with `deploy/local-ai.sh` to get Level 4.
- **Fewer than 3 voters.** The panel refuses to call a serious verdict on less. A machine that is on its own can use `--standalone`, which accepts 2 local voters.

### Which local models fit

| Memory | Suggestion |
|---|---|
| under 4 GB | No local models. Use free cloud keys, or let a bigger hub run the panel |
| 4 to 7 GB | One small model (3 to 4 billion parameters). Use cloud keys for the other voices |
| 8 to 15 GB | `hermes3` and `mistral`, taking turns (one in memory at a time) |
| 16 GB and more | The same, with room for a third |

## 3. After installing

1. Copy the one-time admin password the installer prints, then sign in.
2. Open **Settings**. The top card says what level you reached and what would raise it.
3. Add AI keys in **Settings, AI models and API keys** (free tiers are fine), or install local models with `sudo deploy/get-models.sh`. It picks models by this machine's memory, installs Ollama if needed, downloads them and puts them on the panel. (Offline machine: `deploy/local-ai.sh` copies them from a USB kit instead.)
4. If the machine has a firewall (`ufw`), allow your network to reach the dashboard port.
5. To add another machine, use Settings, "Machines", or `deploy/new-node.sh`.

Nothing is sent to an AI provider until you add a key for it, and nothing sensitive is ever sent: every cloud call goes through the sanitizer first and fails closed. Details in [consensus-operating-guide.md](consensus-operating-guide.md); how the code is laid out in [code-map.md](code-map.md).

## Who can open the dashboard

A hub installed with `--standalone`, or inside WSL on Windows, listens on `127.0.0.1` only: just that machine can open it.
A hub that serves other machines listens on all interfaces. Override either way with `--bind ADDR`.

## Blocking bad addresses (ufw) and threat feeds

- The dashboard's "block this address" uses the Ubuntu firewall, `ufw`. The installer installs it on a hub but does **not**
  switch it on (switching it on can cut off an SSH session). Turn it on yourself with `sudo ufw enable` after allowing SSH.
  The installer pre-allows the machine's own loopback traffic (`lo`, and `loopback0` under WSL mirrored networking), so
  turning ufw on does not cut the dashboard off from its agents.
- abuse.ch retired the keyless ThreatFox and URLhaus downloads. ThreatFox now needs a free key from https://auth.abuse.ch,
  set as `ABUSECH_AUTH_KEY` in `.env`; without it that one feed stays off. Feodo Tracker needs no key. The URLhaus feeds are
  retired and the agent that used them stays idle.
