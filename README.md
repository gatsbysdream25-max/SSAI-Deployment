# SwarmSentinel — AI Security Intelligence Platform

> **Patent Pending** · Provisional Filed 2026-02-22
> Version 0.3.0 · © 2026 SSAI-SwarmSentinel. All rights reserved.

SwarmSentinel (SSAI) is a distributed, AI-powered threat detection platform that protects users across browsers, networks, and operating systems. Every node contributes to and benefits from a collective threat intelligence database — the more nodes in the swarm, the smarter the protection gets.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [Components](#components)
- [API Reference](#api-reference)
- [Installation & Setup](#installation--setup)
- [Configuration](#configuration)
- [Security](#security)
- [Roadmap](#roadmap)
- [License & Patent](#license--patent)

---

## Overview

SwarmSentinel operates on a three-tier architecture:

```
[ Windows/Linux Client ]
         |
         | HTTPS
         v
[ ProDesk API Server (Flask) ]   <-- local threat processing
         |
         | Collective sync
         v
[ Azure VM + Cosmos DB ]         <-- global threat intelligence
```

Each node registers itself, reports threats it detects, and pulls the collective threat feed back — creating a swarm intelligence network where every device makes every other device smarter.

---

## Architecture

```
+-------------------------------------------------------------------+
|                        CLIENT LAYER                               |
|                                                                   |
|  +--------------------+   +--------------------+                 |
|  |  Chrome Extension  |   |  Firefox Extension  |                |
|  |  - Gmail scanner   |   |  - Gmail scanner    |                |
|  |  - URL analysis    |   |  - URL analysis     |                |
|  |  - Threat popup    |   |  - Threat popup     |                |
|  +--------+-----------+   +----------+----------+                |
|           +-----------+-----------+--+                           |
+------------------------|-----------+-------------------------------+
                         | HTTP/JSON
+------------------------v-------------------------------------------+
|            BACKEND API  (Local Network : <host>:5000)              |
|            Flask 3.1 + SQLAlchemy + SQLite                         |
|                                                                    |
|  POST /api/node/register       Enroll a node (single-use code)     |
|  POST /api/node/heartbeat      Keep-alive ping                     |
|  GET  /api/nodes               All registered nodes                |
|  GET/POST /api/agents/         Agent registry                      |
|  GET/POST /api/threats/        Threat feed + submission            |
|  GET  /api/threats/collective  Swarm-wide threat feed              |
|  POST /api/signal              Raw IOC signal ingestion            |
|  GET  /api/signal/feed         IOC feed with pagination            |
|  GET  /api/status/             Health and platform stats           |
|                                                                    |
|  AI Analysis: Ollama (llama3) — data never leaves your network     |
+------------------------+-------------------------------------------+
                         | Collective sync
+------------------------v-------------------------------------------+
|            CLOUD LAYER  (Azure VM)                                 |
|  - Azure Cosmos DB (MongoDB API) — collective threat database      |
|  - Safe Haven API — verified threat archive (port 5001)            |
|  - Cross-node threat correlation and enrichment                    |
+--------------------------------------------------------------------+
```

---

## Features

### Threat Detection

| Feature | Status | Description |
|---------|--------|-------------|
| Phishing email detection | **Active** | Keyword scoring, URL analysis, sender heuristics |
| Malicious URL detection | **Active** | Shortlink detection, raw-IP URLs, domain blacklist |
| Network threat scanning | **Active** | nmap + Pi-hole DNS logs + syslog anomaly detection |
| AI threat analysis | **Active** | Ollama llama3 local LLM — zero cloud dependency |
| Collective threat feed | **Active** | Cross-node shared intelligence database |
| Credential threat detection | Planned | Password leak detection, credential stuffing alerts |
| Screen reading analysis | Planned | Visual threat detection via screenshot AI analysis |
| Windows native client | Planned | Tray app with real-time system-level protection |

### Browser Extensions (Chrome + Firefox)

- Real-time Gmail scanning with inline severity badges: **HIGH** / **MEDIUM** / **LOW**
- 20+ phishing keyword patterns, shortlink URL detection, raw-IP URL scoring
- Suspicious sender heuristics — urgent language from free providers flagged
- One-click manual threat submission from any active tab
- Live API status indicator and running threat count in popup
- 30-second background heartbeat — auto-registers browser as a swarm node
- Visual threat badge injected inline on flagged Gmail messages

### Network Scanner

- Full subnet nmap scan (`192.168.0.0/24`) with service version detection (`-sV --open -T4`)
- Pi-hole DNS log analysis — blocked domains, query stats, recently blocked list
- Syslog anomaly extraction — auth failures, refused connections, intrusion indicators
- AI-generated threat report via Ollama llama3
- Markdown reports saved to `/mnt/ssd/SwarmSentinel/security/reports/YYYY-MM-DD.md`

### Backend API

- Node registration with 64-char cryptographic token issuance per device
- Agent registry with status tracking and last-seen timestamps
- Dual threat ingestion: structured (`/api/threats/`) and raw IOC signals (`/api/signal`)
- SQLite local storage with Cosmos DB sync capability
- API key authentication on all write endpoints

---

## Components

### `backend/`

| File | Purpose |
|------|---------|
| `app.py` | Flask entry point — CORS, node registration, signal endpoints, stats |
| `models/__init__.py` | SQLAlchemy models: `Threat`, `Agent`, `Node` |
| `routes/threats.py` | Threat submission, retrieval, collective feed |
| `routes/agents.py` | Agent registration and heartbeat |
| `routes/status.py` | Platform status endpoint |
| `agents/ai_analyzer.py` | Ollama llama3 integration for AI threat analysis |

### `client/browser-extension/`

One shared source, built into four packages (Chrome, Brave, Edge, Firefox) by `build.py`. Optional and **off by default**: it holds no
credential until a person enrols it with a single-use code from the dashboard, it asks the browser for access to one address (the hub),
and it reports only warning signs, never the subject, sender or text of an e-mail. See `client/browser-extension/README.md`.

| File | Purpose |
|------|---------|
| `build.py` | Builds `dist/<browser>/` and a zip per browser; refuses a source that contains a key or a hard-coded address |
| `src/background.js` | Enrolment as a node, reporting with that node's own token, heartbeat |
| `src/content-gmail.js` | Gmail part: does nothing unless turned on; scores the open message locally |
| `src/popup.html`, `src/popup.js` | The switch, the enrolment form, status (credential shown as its last 4 characters) |

### Root Scripts

| File | Purpose |
|------|---------|
| `network_scanner.py` | Standalone network scanner — nmap, Pi-hole, syslog, AI report |
| `safe_haven_api.py` | Secondary Flask API (port 5001) for verified threat archival |
| `ecosystem.config.js` | PM2 process manager configuration |

---

## API Reference

### Enroll a Node

An admin creates a single-use enrollment code (`deploy/new-node.sh`, or Settings -> Machines). The machine trades it for
its own token, which is shown once and stored only as a hash on the hub.

```http
POST /api/node/register
Content-Type: application/json

{ "enrollCode": "XXXX-XXXX-XXXX-XXXX", "nodeId": "web-1", "hostname": "web-1", "platform": "linux" }
```

**Response:** `{ "nodeId": "web-1", "token": "ssn_...", "apiBase": "http://hub:5000/api" }`. Send the token as
`X-API-Key` (or `Authorization: Bearer`) on later calls. A node token may register its own agents (`<agent>@<node>`),
send heartbeats and submit threats/signals, and nothing else. Wrong, used or expired codes all get `401`; repeated
failures from one address get `429`.

### Submit a Threat

```http
POST /api/threats/
Content-Type: application/json

{
  "url": "http://malicious-site.com/login",
  "type": "phishing",
  "severity": "high",
  "description": "Credential harvesting page mimicking bank login",
  "detected_by": "chrome-extension"
}
```

### Submit a Raw IOC Signal

Requires an enrolled node's token (`X-API-Key: ssn_...`). The node id is taken from the token, never from the body.

```http
POST /api/signal
X-API-Key: ssn_...
Content-Type: application/json

{
  "source": "http://192.168.1.99:4444",
  "type": "c2-beacon",
  "severity": "critical",
  "ttps": ["T1071", "T1566"],
  "platform": "windows"
}
```

### Get Collective Threat Feed

```http
GET /api/threats/collective
GET /api/signal/feed?limit=50
GET /api/threats/
```

### Agent Heartbeat

```http
POST /api/agents/heartbeat
Content-Type: application/json

{ "agentId": "chrome-extension", "type": "browser-agent", "status": "active" }
```

### Platform Status

```http
GET /api/status/      # threat and agent counts
GET /api/stats        # full node/agent/threat stats
GET /health           # service liveness check
```

---

## Installation & Setup

**Which route fits your machine, and what protection level you will get from it: [docs/install-guide.md](docs/install-guide.md).**

### Quickstart (Docker — recommended)

```bash
git clone https://github.com/gatsbysdream25-max/SSAI-Deployment.git
cd SSAI-Deployment
docker compose up -d
```

Open `http://localhost:5000/setup`, add at least one AI provider key, and
you're monitoring. No manual file editing — `SECRET_KEY` and `SSAI_API_KEY`
are generated automatically on first boot and persisted in a Docker volume
across restarts/upgrades.

This default mode uses bridge networking, which works identically on
Linux/Mac/Windows Docker Desktop. Two agents — the LAN network scanner and
the firewall-block action — need to see your real network to do anything
useful, which Docker's bridge networking deliberately isolates the
container from; everything else (AI threat analysis, log/file-integrity
monitoring, disk/service health) works fully in this mode.

**On a Linux host**, get those two features working too:

```bash
docker compose -f docker-compose.yml -f docker-compose.linux-host.yml up -d
```

This switches the container to host networking (Linux-only — not supported
by Docker Desktop on Mac/Windows the same way), so it sees the real LAN.

See `.env.example` for optional overrides (AI provider endpoints, allowed
ports, watched services, etc.) — none of them are required to get started.

### Manual / bare-metal Linux install (advanced)

Prefer running without Docker, or need this on the same box as an existing
non-containerized deployment? The steps below still work.

#### Prerequisites

- Python 3.10 or newer (tested on 3.10, 3.11, 3.12 and 3.13)
- Ollama with llama3: `ollama pull llama3`
- nmap: `sudo apt install nmap`
- systemd for service management

#### Backend Setup

```bash
git clone https://github.com/gatsbysdream25-max/SSAI-Deployment.git
cd SSAI-Deployment

# One command installs the virtualenv, dependencies, settings (.env with generated secrets),
# and the systemd services, then waits for the dashboard. Safe to re-run.
sudo deploy/install.sh

# Later, to update (tests the new code first, rolls back on failure):
deploy/update.sh
```

See [`deploy/README.md`](deploy/README.md) for adding more machines, unattended updates, Docker and uninstalling.

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECRET_KEY` | **Yes** | — | Flask session signing key |
| `SSAI_API_KEY` | **Yes** | — | API auth key for all write endpoints |
| `OLLAMA_URL` | No | `http://<your-ollama-host>:11434` | Ollama server endpoint |
| `OLLAMA_MODEL` | No | `llama3` | LLM model name for threat analysis |
| `PORT` | No | `5000` | API listening port |
| `SSAI_REQUIRE_PROVIDER_APPROVAL` | No | `0` | `1` keeps every cloud AI provider that is not approved in `backend/config/provider_approvals.json` out of the AI panel. Turn on for customer deployments |
| `SSAI_REDTEAM_INTERVAL_HOURS` | No | `6` | How often RedTeamAgent attacks SSAI's own pipeline |
| `SSAI_FEED_REFRESH_MINUTES` | No | `25` | A threat-intel feed refreshed more recently than this is not downloaded again (restarts don't re-pull) |
| `SSAI_LOG_CATCHUP_MAX_MB` | No | `20` | After a restart, log agents read what was written while they were down, up to this much |
| `SSAI_CONSENSUS_CATCHUP_HOURS` | No | `24` | After a restart, the AI panel judges threats from the downtime, at most this far back |
| `SSAI_STATE_DB` | No | `instance/agent_state.db` | Where the agents' local state (resume points, sync log, lineage) is kept |

### Browser extension (optional, Chrome / Brave / Edge / Firefox)

1. `python client/browser-extension/build.py` (writes `client/browser-extension/dist/`)
2. Chrome, Brave or Edge: open `chrome://extensions` (Brave: `brave://extensions`, Edge: `edge://extensions`), turn on Developer mode, **Load unpacked**, pick `dist/chrome`, `dist/brave` or `dist/edge`.
   Firefox: open `about:debugging#/runtime/this-firefox`, **Load Temporary Add-on**, pick `dist/firefox/manifest.json`.
3. Click the toolbar icon, enter your hub's address and an enrolment code from the dashboard, then tick the box to turn it on. It is off until you do.

---

## Configuration

### systemd Service (`/etc/systemd/system/swarmsentinel.service`)

```ini
[Unit]
Description=SwarmSentinel API
After=network.target

[Service]
WorkingDirectory=/mnt/ssd/SwarmSentinel/backend
ExecStart=/mnt/ssd/SwarmSentinel/swarmsentinel-env/bin/python3.12 app.py
Restart=always
RestartSec=5
EnvironmentFile=/mnt/ssd/SwarmSentinel/.env

[Install]
WantedBy=multi-user.target
```

### Scheduled Network Scanning (cron)

```bash
# Run nightly at 2:00 AM
0 2 * * * cd /mnt/ssd/SwarmSentinel && source swarmsentinel-env/bin/activate && python3 network_scanner.py >> /var/log/swarmsentinel-scan.log 2>&1
```

### Nginx Reverse Proxy (recommended for production)

```nginx
server {
    listen 80;
    server_name your-domain.com;
    location /api/ {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

---

## Security

- **Authentication**: All write endpoints require `X-API-Key` header matching `SSAI_API_KEY` env var
- **CORS**: Restricted to browser extensions, LAN (192.168.0.x), and localhost — no wildcard origins
- **AI and your data**: local models (Ollama on your network) see raw threats; cloud AI providers and the Microsoft
  Copilot lane only ever receive a sanitized copy (internal addresses, host names, user names and credentials replaced
  by tokens), every crossing is logged with its destination, and nothing is sent if sanitization fails
- **Third-party AI responsibility**: who owns what (infrastructure, the AI service, configuration, submitted data) for
  every outside AI service, the written pre-approval checklist, and the opt-in gate that enforces it:
  [`docs/third-party-ai/`](docs/third-party-ai/README.md)
- **Built-in red team**: RedTeamAgent attacks SSAI's own pipeline every 6 hours (data leakage, a spoofed AI voice,
  prompt injection, AI-triggered actions) and raises a finding when a protection breaks
- **Lineage**: every AI verdict records the exact model, provider and configuration that produced it; configuration
  changes are logged and can be rolled back (`backend/tools/lineage_cli.py`)
- **Evidence for reviewers**: `GET /api/status/governance` (admin) returns provider approvals, red-team results,
  lineage and the feed sync log in one place
- **Node Tokens**: 64-char cryptographically random hex token issued per registered device
- **No hardcoded secrets**: All sensitive values loaded from environment variables only
- **TLS**: Deploy behind nginx with Let's Encrypt for any internet-facing deployment

### Responsible Disclosure

This platform is designed exclusively for defensive security purposes.

**Email:** gatsbyssai@hotmail.com

Please do not open public GitHub issues for security vulnerabilities.

---

## Roadmap

See [CHANGELOG.md](CHANGELOG.md) for what has shipped recently, and [deploy/README.md](deploy/README.md) to install a hub
or node or build a downloadable release package.

- [ ] Windows native tray application with real-time system protection
- [ ] Screen reading / visual threat detection (screenshot AI analysis)
- [ ] Password leak detection via HIBP API integration
- [x] Cosmos DB retired: SQLite is the primary store and nodes enroll directly with the hub
- [ ] STIX/TAXII threat feed export for enterprise integration
- [ ] Web dashboard — live threat map, node grid, analytics
- [ ] Automated IOC enrichment (VirusTotal, Shodan, AbuseIPDB)
- [ ] Mobile agent (Android/iOS)
- [ ] FedRAMP compliance documentation
- [ ] Multi-tenant node tiers (Free, Pro, Enterprise)

---

## License & Patent

**Patent Pending** — Provisional application filed 2026-02-22.

All rights reserved. This software is proprietary and confidential. No part may be reproduced, distributed, transmitted, or used in any form without express written permission from the copyright holder.

**Licensing inquiries:** gatsbyssai@hotmail.com

See [`LICENSE`](LICENSE), [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md) and [`SECURITY.md`](SECURITY.md).

---

*SwarmSentinel — Protecting the swarm, one node at a time.*
