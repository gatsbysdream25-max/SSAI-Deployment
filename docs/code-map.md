# Code map: where everything is and why

For someone who has never seen this project. About 90% of it is Python; the rest is a little bash (installers), HTML with some JavaScript (the dashboard) and small config files. You do not need to know anything else.

## The idea in one minute

SwarmSentinel watches a network and the machines on it. Small programs called **agents** look for trouble (a stranger trying passwords, a new open port, a phishing link). Each problem they find is stored as a **threat** (also called a *finding*). For serious ones, several **AI models** are asked to vote on whether it is really malicious; the votes are combined into one **verdict** with an honest label of how much to trust it. A **person** then approves or rejects any proposed block. Nothing is blocked without that, unless a person has granted a narrow standing permission.

```
agents find a problem  ->  hub stores it (a "threat")  ->  consensus agent asks the AI models
        ->  hub checks its own records for proof  ->  verdict saved  ->  a person approves or rejects  ->  block is applied and logged
```

Two programs run on the main machine (the **hub**): the **web app** (dashboard + API, the front door) and the **agent runner** (all the detectors and the AI panel). They talk to each other only through the web app's API.

## Where to start reading

| If you want to understand... | Read, in this order |
|---|---|
| How an AI verdict is made | `backend/agents/finding_flow.py` (the steps), `ai_swarm_agent.py` (`analyze`, then `apply_quorum_policy`), `local_evidence.py` |
| Why nothing blocks without a person | `backend/remediation_queue.py`, then `backend/auth.py` (`approving_person`) |
| What leaves the machine for the cloud | `backend/sanitizer.py` and `backend/agents/usage_caps.py` |
| How to install or move it | `deploy/README.md`, `docs/portable-and-relocation.md` |
| How to run the tests | `python backend/tools/run_all_tests.py` |

## The web app (`backend/`)

| File | What it is for |
|---|---|
| `app.py` | Starts the web server, registers the pages and API routes, serves the dashboard |
| `auth.py` | Decides who is calling (a signed-in person, a machine's key, a read-only viewer) and what they may do |
| `sso.py`, `entra.py` | Sign-in through an organisation's Microsoft account; checking who pressed Approve in Teams |
| `models/__init__.py` | The database tables (threats, machines, agents, permissions) |
| `routes/login.py` | Sign-in, single sign-on, sign-out, changing the admin password |
| `routes/nodes.py` | Machines that report to this hub: enrolment codes, heartbeats, revoking, the shared signal feed |
| `routes/allowlist.py`, `routes/quarantine.py`, `routes/settings.py` | The port allowlist, e-mail quarantine import, and the Settings page's agent switches and AI routing |
| `routes/threats.py` | Receive, list, update and report on findings |
| `routes/remediation.py` | The approve / reject / block endpoints |
| `routes/autonomy.py`, `autonomy.py` | Standing permissions: what SSAI may do without asking (none by default) |
| `routes/agents.py`, `routes/status.py`, `routes/copilot.py` | Agent status, health, and the read-only door used by Microsoft Copilot/Teams |
| `remediation.py` | Works out what a finding's indicator *is* (address, domain, file) and applies or undoes a block honestly |
| `remediation_queue.py` | Turns a trusted verdict into a **proposal**, never an action |
| `findings.py` | "Same problem seen again" memory, so repeats are counted instead of re-alerting |
| `sanitizer.py` | Replaces addresses, host names, user names and secrets with tokens before anything goes to a cloud AI |
| `identify.py` | Works out what an IP address actually is (a router, a phone, a known service) |
| `retention.py` | Removes old low-value rows, with a backup first |
| `github_reporter.py` | Publishes a masked list of threat indicators to GitHub (optional) |
| `ssai_config.py`, `envfile.py`, `logsafe.py` | File locations, safe edits of the settings file, and log protection |
| `adminctl.py` | Set or reset the admin password from the command line |
| `templates/dashboard.html` | The whole dashboard page (HTML, CSS and JavaScript in one file) |

## The agent runner (`backend/agents/`)

| File | What it is for |
|---|---|
| `agent_runner.py` | Runs every agent on a timer. Holds the detectors (network scan, log watcher, file integrity...) **and** the `SwarmConsensusAgent` that drives the AI panel |
| `agent_util.py` | Pure helpers the agents share: hide private addresses, scrub log lines, memory-capped set and dict. Split out of `agent_runner.py`. |
| `ai_swarm_agent.py` | The AI panel itself: asks each model, combines the votes, applies the quorum rules |
| `finding_flow.py` | The numbered steps one finding goes through, timed, with a time budget |
| `local_evidence.py` | Decides *verified / partial / unverified* from this network's own records (feed hit, second detector, repeat sightings) |
| `injection_guard.py` | Spots evidence text that tries to give the AI instructions |
| `verifier.py` | A model from a different maker double-checks the verdict |
| `recall.py` | Reuses an earlier verdict for the same indicator instead of asking again |
| `provider_errors.py`, `provider_check.py` | Plain-English reasons a model call failed; a health table of every provider |
| `model_config.py` | One place that says which model each provider uses (`backend/config/ai_models.json`) |
| `usage_caps.py`, `keyvault.py` | Daily/monthly limits on paid models; optional storage of keys in the operating system's vault |
| `provider_approval.py`, `lineage.py` | Records that a cloud provider was approved; a fingerprint of which models and code produced a verdict |
| `incident_report.py` | Turns a finding into a report a person can read |
| `intel.py` | Free threat-feed lists, matched against what this network does |
| `redteam.py` | Attacks SSAI's own pipeline on purpose to check it holds |
| `agent_catalog.py`, `state_store.py` | Which agents exist and are on; small shared state between agents |
| `capability.py` | Measures the machine (memory, disk, tools, models) and says which protection level it can honestly offer: Watch, Guard, Panel or Sovereign. Shown in Settings and printed by the installer. |
| `request_helpers.py` | Small functions that clean what a client sent (trim, cap the length, keep only known values) and read the clock. |
| `ai_providers.py` | One small class per kind of AI model server (local Ollama, OpenAI-style cloud APIs, Gemini, Hugging Face, Anthropic) and the check "is this endpoint on my own network". |
| `panel_rules.py` | The panel's pure rules: how a quorum is worded, the 40% cap on any one model's vote, outliers, and the challenge-round text. |
| `screenshot_ai.py` | Reads a screenshot with a local vision model; never a cloud one. |
| `redact.py` | Keeps secrets out of logs |

## Tools and tests (`backend/tools/`)

`run_all_tests.py` runs every `test_*.py` file in its own process (no secrets, no internet). `ai_benchmark.py` scores models on labelled examples; `ablation.py` decides whether a new model earns a vote; `enable_local_models.py` switches installed local models onto the panel.

## Installing, moving, backing up (`deploy/`)

`install.sh` (install or repair), `update.sh` (safe update from git), `backup_full.sh` (copy everything to another machine), `make-usb-kit.sh` + `kit/INSTALL.sh` (offline install from a stick), `local-ai.sh` (AI models on this machine), `demo-mode.sh` (clean demo and back), `set-network.sh` (change address with an automatic undo), `export_public.py` (a clean copy with no private data), `systemd/` (service templates).

## Other folders

`client/browser-extension/` (Chrome, Brave, Edge, Firefox add-on, off by default) · `copilot/` (the Microsoft Teams / Copilot agent, a separate small service) · `docs/` (guides; `consensus-operating-guide.md` explains the settings in plain words) · `docker/` (container packaging) · `threats/` (the published ledger; not code).

## Conventions

- Settings come from the `.env` file or `backend/instance/` (never from the code), and model names live only in `backend/config/ai_models.json`.
- Every new module starts with a docstring saying what it is for and which design decision it came from.
- A comment says **why**, not what; numbers have a name and a reason beside them.

## Why `agent_runner.py` is still one large file

The agent classes stay together on purpose. The service runs the file as a script, and the tests replace module-level names in it (`SESSION`, `API`, `register`, `heartbeat`) and expect every agent to see the change. Moving the agents into other files would either load a second copy of the module, with its own state, or silently stop those tests from testing anything. Splitting it safely means first putting the hub connection behind one object that agents are given, which is a separate piece of work. What was safe has been done: the pure helpers moved out (`agent_util.py`) and the longest method, `SwarmConsensusAgent.scan`, is now a short sequence of named steps.
