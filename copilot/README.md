# SwarmSentinel for Microsoft 365 Copilot (Copilot lane)

A **custom engine agent** built with the Microsoft 365 Agents SDK (Python). People ask it about SwarmSentinel from
Microsoft 365 Copilot Chat or Teams: "status", "threats", "critical".

It is a front door only. SwarmSentinel keeps its own models and does all the analysis. The agent reads one thing,
the hub's **sanitized brief** (`GET /api/copilot/brief`), so it never sees internal addresses, machine names,
user names, command lines or credentials. Those are replaced by tokens (IP_1, HOST_1, SECRET_1 ...) on the hub,
before anything leaves the network.

## Files

| File | What it does |
|---|---|
| `replies.py` | What the agent says (text) and which command a message is. Pure functions, no SDK, no network. |
| `cards.py` | Adaptive Cards for status, threats and alerts. Pure functions over the brief. |
| `alerts.py` | Alert subscriptions (per chat) and the poller that pushes new findings. |
| `ssai_client.py` | Fetches the brief (or the alert feed) from the hub with the Copilot key. |
| `agent.py` | Wires everything into the Agents SDK (`AgentApplication`), including proactive sends. |
| `app.py` | Starts the web server on `localhost:3978/api/messages` and the alert poller. |
| `test_replies.py`, `test_alerts.py` | Tests (no network; `test_alerts.py` needs no SDK either). |

## Commands

| Say | Answer |
|---|---|
| **status** | Card: counts for the last 24 h and what is still open |
| **threats** / **critical** / **high** | Card: the latest medium+ threats, or only that severity |
| **alerts on** | This chat gets new high and critical findings as the hub reports them |
| **alerts medium** / **alerts critical** | Same, from that level up |
| **alerts off** | Stop |
| **pending** | Cards for blocks waiting for approval, with **Approve block** / **Reject** buttons |

Alerts: the agent polls `GET /api/copilot/brief?since=<cursor>` every `SSAI_ALERT_POLL_SECONDS` (default 60). A finding
that stays open is re-reported on the hub's own schedule (critical 5 min, high 1 h, medium 6 h) and is posted again
then. At most 5 cards per chat per round; the rest become one "...and N more" card. A chat that fails 3 rounds in a
row (app removed, conversation deleted) is dropped. Subscriptions and the cursor are kept in
`SSAI_AGENT_STATE` (default `copilot/instance/state.json`, owner-only, git-ignored): it holds Teams conversation
references, which identify people.

Optional `SSAI_DASHBOARD_URL` adds an "Open SwarmSentinel" button to cards. **Leave it unset once the agent runs in
Microsoft's cloud** unless the hub has a public name: a LAN address in it (e.g. `http://192.168.x.x:5000`) would be
sent to Microsoft with every card. Everything else on a card comes from the sanitized brief.

## 1. Turn the lane on at the hub

In the hub's `.env`, set `SSAI_COPILOT_KEY` to a long random value (at least 16 characters), then restart
SwarmSentinel. Without it the lane is off: `/api/copilot/brief` only answers the admin key. The Copilot key opens that
one route and nothing else.

## 2. Run the agent locally

Needs Python 3.10+ and Node.js 22+ (for the Playground).

```
cd copilot
python -m venv .venv
.venv\Scripts\activate            # Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
copy .env.example .env            # then set SSAI_HUB_URL and SSAI_COPILOT_KEY
python test_replies.py
python app.py
```

## 3. Talk to it in the Agents Playground (no Microsoft 365 account needed)

In a second terminal:

```
npx -y -p @microsoft/teams-app-test-tool teamsapptester
```

It opens a browser chat connected to `http://127.0.0.1:3978/api/messages`. Try **status**, **threats**, **critical**.

## Later: real Copilot and Teams

Needs a Microsoft 365 tenant where you are admin (a developer sandbox, or Microsoft 365 Business Basic), with
"Upload custom apps" on in the Teams admin center, plus an Entra app registration and an Azure Bot resource. Then the
agent runs with authentication instead of anonymous mode. Plain Copilot Chat is enough for a custom engine agent: a
Microsoft 365 Copilot licence is only needed for grounding on organisational data, which this agent does not use.

## Approving blocks from Teams

When SwarmSentinel's AIs agree a target is malicious, the hub proposes a block and waits for a person. The agent shows
each proposal as a card (new ones are also posted to chats that said **alerts on**). Pressing **Approve block** or
**Reject** sends the hub **the person's own Entra token**, and the hub decides whether they may:

- signature checked against Microsoft's published keys, issuer + tenant (`SSAI_COPILOT_TENANT_ID`), audience
  (`SSAI_COPILOT_AUDIENCE`), expiry; app-only tokens refused;
- the person's object id must be in `SSAI_COPILOT_APPROVERS` (hub `.env`);
- the Copilot lane key is required as well, but it is never enough on its own (nor is the admin key), so whoever
  holds the agent's key still cannot block anything;
- 10 bad tokens from one address in 5 minutes locks that address out for a while; every attempt is written to the
  hub's `remediation_audit.jsonl` with the person's object id, and the block is undone automatically after the TTL.

Targets: a public address or domain (the attacker's) is shown on the card; a LAN address never leaves the hub (the
card says it is a device on your network).

**What is needed from the tenant** (not possible in the Agents Playground, which has no sign-in): an Entra app
registration for the agent with an exposed API (`api://.../access_as_user`), an Azure Bot with an OAuth connection for
Teams single sign-on, and the Teams app manifest's `webApplicationInfo`. Then set `SSAI_SSO_HANDLER` (the agent's
user-authorization handler name) and `MICROSOFT_APP_ID` for the agent, and the three `SSAI_COPILOT_*` approval settings
on the hub. Until then the buttons answer: "Sign-in isn't available here ... decide in the dashboard".
