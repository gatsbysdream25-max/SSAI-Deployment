# Taking SwarmSentinel somewhere else

Two ways, depending on what you can carry.

| | **A. USB kit** | **B. Move the machine** |
|---|---|---|
| You carry | A USB stick (8 GB with one AI model, 16 GB with two) | The machine itself |
| Needs at the other end | Any Ubuntu/Debian PC (x86_64, same Python version) | Power, a network cable, a keyboard and screen for the first start |
| Your own data | Never on the stick | Stays on the machine; demo mode sets it aside |
| Internet needed | No | No |

## A. The USB kit (nothing of yours is on it)

Build it once, on a machine like the target (same CPU type, same Ubuntu release):

```
deploy/make-usb-kit.sh /media/usb --models hermes3,mistral
```

It packs the committed code only (no keys, databases or settings), the Python packages, and the local AI models you name. On the target:

```
cd /media/usb/ssai-kit-*
sudo ./INSTALL.sh --demo
```

That installs into `/opt/swarmsentinel`, creates a one-time admin password (shown once), starts the AI models on the machine itself, and adds six labelled example findings. The sixth carries text that tries to instruct the AI; watch the panel catch it and send it to a person. Nothing leaves the machine.

## B. Moving the machine

1. **Back up first** (a copy somewhere else): `deploy/backup_full.sh user@backup-host:/folder`.
   Then prove it restores: `deploy/test-restore.sh the-archive.tar.gz` rebuilds a hub from it in a throwaway container and prints how many findings and machines it found. (On 2026-10-22 this was done for the first real backup: the hub came back with all its findings, machines and the admin sign-in.)
2. **At home, before you unplug it:** `sudo deploy/demo-mode.sh on`. Your real database and settings are set aside in `_archive/demo-mode/` (readable by the owner only); the machine starts with an empty database, local AI only, no GitHub push and no cloud calls. Check the dashboard shows the examples being judged.
3. **At the new place:** plug it in. Its old fixed address will not fit the new network. At its own keyboard: `sudo deploy/set-network.sh dhcp` (or `static ADDRESS/24 GATEWAY`, using an address that is free on that network; the examples in `--help` are placeholders, not values to copy). It applies the change with an automatic undo after two minutes if you cannot reach it.
4. **Back home:** `sudo deploy/set-network.sh static <your address>/24 <your gateway>` then `sudo deploy/demo-mode.sh off`. Your data and settings return exactly as they were.

Honest limit of B: demo mode hides your real data from the dashboard and from the programs; it does not erase it. The saved copy, the nightly backups made before the switch, and the logs are still on the disk. If the person you are showing it to must not be able to reach that data at all, use the USB kit (A) on a clean machine instead.

## What the panel does with only local models

Two local models are the whole panel here, so `SSAI_MIN_VOTERS` is set to 2 (the usual minimum is 3, which a machine with no cloud voices cannot reach). Verdicts are marked as coming from two models and nothing is ever blocked without a signed-in person approving it. Each model runs one at a time, so a verdict takes a minute or two on a small CPU.
