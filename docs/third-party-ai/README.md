# Third-party AI: shared responsibility, approvals, red team, lineage

SwarmSentinel (SSAI) does its detection and analysis on the customer's own machines. Some features hand a
**sanitized** summary to an outside AI service: the cloud voices on the AI consensus panel (Groq, Gemini, ...) and
the Microsoft 365 Copilot lane. Every such integration raises the same question: *if something goes wrong (a breach,
a bad answer, a compliance failure), who is responsible?* This folder answers it, provider by provider, and the code
enforces the answer.

| Piece | Where | What it does |
|---|---|---|
| Framework (this page) | `docs/third-party-ai/README.md` | The four layers, who owns what, and the approval process |
| One record per provider | `docs/third-party-ai/<id>.md` | The framework filled in for that provider, plus its checklist evidence |
| Approval status (machine-readable) | `backend/config/provider_approvals.json` (+ `instance/provider_approvals.json`) | `approved` / `pending` / `rejected` and the checklist, per provider |
| The gate | `backend/agents/provider_approval.py`, used by the AI panel | With `SSAI_REQUIRE_PROVIDER_APPROVAL=1`, an unapproved cloud provider never receives data |
| Process check | `backend/tools/test_provider_approvals.py` | Fails if a cloud provider is configured without an entry and a record, or is "approved" with gaps |
| Evidence of what crossed | `instance/cloud_audit.jsonl` | Every sanitized payload: what was sent, what was dropped, redaction counts, and **to whom** (`to`) |
| Red team (16th agent) | `backend/agents/redteam.py`, `RedTeamAgent` | Attacks SSAI's own pipeline every 6 h; results in `instance/redteam_audit.jsonl` |
| Lineage | `backend/agents/lineage.py`, `instance/agent_state.db` | Which model, provider and configuration produced every AI verdict; rollback with `backend/tools/lineage_cli.py` |

## The four layers

For any third-party AI provider, responsibility splits across four layers. Start every new integration from this
table, then fill in the provider column in its record.

| Layer | Who typically owns it | What to confirm before approving |
|---|---|---|
| **Infrastructure** (cloud, servers, model hosting) | Provider | Uptime SLA, the provider's own sub-processors, where data is physically processed and stored |
| **The AI service** (the model, its training, its behaviour) | Provider | Known failure modes, update/versioning cadence, the provider's incident-disclosure commitments |
| **Configuration** (how SSAI sets up and calls the service) | SSAI | Access scopes granted, what SSAI enables or disables, which SSAI data flows are wired to the service |
| **Data submitted** to the service | SSAI and the customer, jointly | What the sanitization gate strips before anything leaves the network; what the customer consents to submit |

The question to answer for every provider: which of these layers does the provider's contract actually cover, and
which default back to SSAI or the customer by omission? Gaps in that mapping are where liability surprises happen.

### What SSAI already guarantees on its side of the line

- **One door out.** Nothing leaves the network except through `sanitizer.sanitize_for_cloud()`. It is an allow-list
  (severity, threat type, timestamp, a summary), redacts internal addresses, host names, MACs, e-mail addresses, user
  names and credentials into stable tokens (`IP_1`, `HOST_1`, `SECRET_1` ...), and **fails closed**: an error, an
  address that survived, or an audit log it cannot write means nothing is sent.
- **Local models see raw data, cloud models never do.** Only an Ollama model on this network gets the unsanitized
  threat; every other provider gets the sanitized copy or nothing.
- **Every crossing is logged** (append-only, `0600`) with its destination, so the "data submitted" row is backed by
  evidence, not a promise.
- **AI never acts alone.** A verdict can only create a *proposal*. A named person approves it (dashboard or Teams,
  with their own Entra identity), every block expires, and AI proposals never target internal or VPN addresses.

## Approval process (do this before a provider is switched on)

1. **Create the record.** Copy an existing `docs/third-party-ai/<id>.md`, name it after the provider id used in
   `backend/config/ai_models.json`, and fill in the four layers.
2. **Add the entry** to `backend/config/provider_approvals.json` with `"status": "pending"` and every checklist item
   `false`. Run `backend/tools/test_provider_approvals.py`: it fails until both exist.
3. **Get the checklist confirmed in writing by the provider**, and list the evidence (contract clause, DPA, saved copy
   of the published terms with date) in the record:

   - [ ] SLA terms covering uptime, latency and support response time (`sla`)
   - [ ] Where data is processed and stored: region, sub-processors (`data_location`)
   - [ ] Retention: how long submitted data is kept, and whether it trains the provider's models (`retention_training`)
   - [ ] Audit rights: can SSAI or the customer get logs/evidence of how submitted data was handled (`audit_rights`)
   - [ ] Incident response: who notifies whom, within what time, if the provider is breached (`incident_response`)
   - [ ] Termination/exit: what happens to submitted data when the integration ends (`exit_terms`)
   - [ ] Compliance certifications relevant to the customer, e.g. SOC 2 for a bank (`certifications`)

4. **Approve.** Set each confirmed item to `true`, `"status": "approved"`, `"reviewed"` (date) and `"reviewer"`
   (role, not a personal e-mail). An entry marked approved with any item missing is treated as pending.
5. **Commit** the record and the entry together. A customer can record its own decision in
   `instance/provider_approvals.json` (same shape, only what changes; it survives updates).
6. **Enforce** on customer deployments: `SSAI_REQUIRE_PROVIDER_APPROVAL=1` in `.env`. Unapproved cloud providers
   then sit out (logged once, local models keep voting). `rejected` is always enforced.

Current state (2026-10-09): **every provider is `pending`**. No provider has confirmed the checklist in writing yet.
The gate is off by default so existing installations keep working; turn it on per customer once the providers they
use are approved.

## Red teaming

SSAI recommends blocks on network connections, so it is itself a target. Two layers:

**Always-on (RedTeamAgent, every 6 h, `SSAI_REDTEAM_INTERVAL_HOURS`).** Probes call the real code with crafted input
and nothing else: no network, no model calls, no firewall or DNS change, no database write. Safe in production.

| Category | Probes |
|---|---|
| Data leakage | 15 kinds of internal data (addresses, defanged addresses, IPv6, MACs, internal names, user names in paths and `ps` lines, e-mail, SSH/sudo passwords, API keys, bearer tokens, passwords in URLs) through the gate; unlisted fields; fail-closed behaviour; the panel's cloud copy of a realistic reverse-shell finding |
| Consensus manipulation | one spoofed voice against two honest ones; malformed or "instruction" verdict strings; a single AI trying to trigger a block proposal |
| Prompt injection | injected text stays a quoted string inside the threat's JSON slot; crafted model replies (two objects, no JSON, nested tricks) give no verdict rather than a wrong one |
| Excessive agency | no agent calls the block code or the firewall; only `approve_proposal()` blocks; AI proposals refuse LAN, CGNAT/Tailscale and IPv6-local targets; protected targets (loopback, masked LAN, internal monitors, Microsoft sign-in, GitHub) are refused |

Each run is appended to `instance/redteam_audit.jsonl`. A probe that **newly** fails raises a `high` finding
(`redteam-probe-failed`) through the same path as a live threat; it re-alerts if a fixed probe breaks again. Run it
by hand: `python3 backend/agents/redteam.py` (exit code 1 on any failure).

Its first run (2026-10-09) found and led to fixes for: defanged addresses (`192[.]168[.]1[.]30`) passing the gate;
user names in `ps aux` lines passing the gate; Microsoft sign-in domains not protected from blocking; AI proposals able
to target internal/VPN addresses.

**Before each customer deployment and after major changes (staging only).** Attacks that need real traffic, real
models or real permissions do not belong in production: evasion traffic crafted to look benign, live prompt
injection against the configured cloud models, false-positive flooding (can an attacker get SSAI to propose blocking
something legitimate?), and privilege tests of the install's sudo rules. Run them on a staging copy with
`backend/tools/ai_benchmark.py` and record the results next to the red-team audit log.

Known limits (documented, not hidden): a bare user name inside free prose ("logged in as jdoe") is not recognised as
a user name; the cloud copy still carries the attacker-controlled *text* of a threat (tokens replace internal facts,
but an injection attempt in a phishing subject line is passed to the model as data, inside its JSON slot). The
consensus rule and approve-first remediation are the defence there.

## Lineage (model and data versioning)

Every AI verdict carries a `lineage` block: the **manifest id** of the panel that produced it, the **exact model** each
answering provider used, the code version, and when each threat-intel feed was last refreshed. The manifest is a
snapshot of the whole panel (provider, model, endpoint host, local/cloud, vote weight for every member; hashes of the
model config, weights and on/off files; a copy of this installation's override files) and its id is a hash of that
content. Whenever it changes, an event is written with old id, new id and a readable list of what changed (model
swap, provider added or removed, weights or config edited, code updated), and the agent log says so.

So a wrong verdict can be traced to "Groq served `openai/gpt-oss-20b` under manifest `3f2c...`, after the weights file
changed on ...". If the cause is a provider's model update rather than SSAI's code, that is now provable.

```
python3 backend/tools/lineage_cli.py events            # what changed, when
python3 backend/tools/lineage_cli.py show <id>         # one manifest
python3 backend/tools/lineage_cli.py restore <id>      # what a rollback would write (add --apply to do it)
```

Restoring writes the snapshot of `instance/ai_models.json`, `ai_weights.json` and `ai_providers.json` back (the
current files are kept as `.bak-<timestamp>`); the agents pick the change up within a cycle.

## Records

| Provider | Kind | Status |
|---|---|---|
| [Microsoft 365 Copilot](microsoft-copilot.md) | Integration (Copilot lane) | pending |
| [Groq](groq.md) | AI panel (on by default) | pending |
| [OpenRouter](openrouter.md) | AI panel | pending |
| [Cerebras](cerebras.md) | AI panel | pending |
| [Mistral AI](mistral.md) | AI panel | pending |
| [Google Gemini](gemini.md) | AI panel | pending |
| [Hugging Face](huggingface.md) | AI panel | pending |
| [Together AI](together.md) | AI panel | pending |
| [Anthropic](anthropic.md) | AI panel | pending |
| [xAI Grok](grok.md) | AI panel | pending |
| [Moonshot Kimi](kimi.md) | AI panel | pending |
