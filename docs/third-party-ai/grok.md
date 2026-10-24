# xAI Grok API: responsibility record

Provider id: `grok` · Kind: AI consensus panel voice · Operator: xAI · **Status: pending**
(see `backend/config/provider_approvals.json`)

## What SSAI sends, and how

When this provider is switched on and has a key, it is one voice on the AI consensus panel for medium-and-above
threats. It receives only the sanitized copy of a threat built by `ai_swarm_agent._cloud_threat_json()`: category,
severity and a summary passed through `sanitizer.sanitize_for_cloud()` (internal addresses, host names, MACs,
e-mail addresses, user names and credentials replaced by tokens). Every payload is logged in
`instance/cloud_audit.jsonl` with this provider's id in `to`. It never sees the raw threat, and its answer is one
vote: it cannot decide a verdict alone, and no verdict acts without a named person's approval.

- Endpoint: `https://api.x.ai/v1`
- Model (config default): `grok-beta` (the exact model behind every answer is recorded in the verdict's `lineage`)
- Default: off (opt-in)
- Notes: Pay-per-use. Not benchmarked yet.

## The four layers

| Layer | xAI | SwarmSentinel (SSAI) | The customer |
|---|---|---|---|
| **Infrastructure** | Hosting and serving the model at the endpoint above | Its own hub and nodes | Its own network and the hub's outbound access |
| **The AI service** | Model behaviour, availability, model updates behind the model name | Choosing the model, measuring it (`tools/ai_benchmark.py`), its vote weight, the consensus rule | Whether to allow this provider at all |
| **Configuration** | API key issuance, rate limits | Endpoint, model, prompt, timeout, on/off switch, approval gate | Supplying the API key under its own account (or SSAI's), switching the provider on |
| **Data submitted** | Handling of what it receives, under its terms | The sanitization gate; evidence in `cloud_audit.jsonl` | Consent to send sanitized summaries off-network |

## Pre-approval checklist

Confirm each in writing from the provider and record the document and date. Nothing below has been confirmed yet.

| Item | Confirmed | Evidence |
|---|---|---|
| SLA: uptime, latency, support response (`sla`) | no | |
| Data location: region, sub-processors (`data_location`) | no | |
| Retention and model training (`retention_training`) | no | |
| Audit rights: logs / evidence of handling (`audit_rights`) | no | |
| Incident response: who notifies whom, how fast (`incident_response`) | no | |
| Exit terms: data after the integration ends (`exit_terms`) | no | |
| Certifications relevant to the customer, e.g. SOC 2 (`certifications`) | no | |

## Status

`pending`. With `SSAI_REQUIRE_PROVIDER_APPROVAL=1` this provider sits out of the panel until it is approved.
