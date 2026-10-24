# Microsoft 365 Copilot (Copilot lane): responsibility record

Provider id: `microsoft-copilot` · Kind: integration · Operator: Microsoft · **Status: pending**
(see `backend/config/provider_approvals.json`)

## What SSAI sends, and how

The Copilot lane is a custom engine agent (`copilot/`, Microsoft 365 Agents SDK) that people talk to from Copilot
Chat or Teams. It reads one thing from the hub: the sanitized brief (`GET /api/copilot/brief`) and, for approvals,
sanitized remediation proposals (`GET /api/copilot/remediation`). Each item passes `sanitizer.sanitize_for_cloud()`
and is written to `instance/cloud_audit.jsonl` with `"to": "microsoft-copilot"`. Counts, severities, threat types,
timestamps and redacted summaries cross; internal addresses, host names, user names, command lines, credentials,
threat URLs and real source addresses do not. A LAN target in a block proposal is shown only as "a device on your
network".

Approving or rejecting a block from Teams needs the lane key **and** the person's own Entra ID token, verified by the
hub (`backend/entra.py`) against a named approver list, and is audited.

## The four layers

| Layer | Microsoft | SwarmSentinel (SSAI) | The customer (e.g. the bank) |
|---|---|---|---|
| **Infrastructure** | Azure, Entra ID, Microsoft 365 hosting, Copilot's cloud infrastructure | Its own on-prem nodes (hub + nodes) running the local agents and AI panel | Its own network, endpoints and Microsoft 365 tenant |
| **The AI service** | Copilot's model behaviour, uptime and update cadence | The custom engine agent plugged into Copilot; the local / multi-provider consensus panel that makes the actual security judgements | Its choice to enable Copilot and which SSAI features it turns on |
| **Configuration** | Entra app registration mechanics, token issuance (OBO exchange) | How the agent is wired; the sanitization gate; what is allow-listed to cross; the approver list; the lane key | Licensing (per-user Microsoft 365 Copilot licences), which users and roles can reach the agent, tenant policies |
| **Data submitted** | Processes what reaches Copilot under its own data-handling terms | The sanitization gate is the single chokepoint; responsible for what leaves the local network (evidence: `cloud_audit.jsonl`) | The raw data generated on its network before it ever reaches SSAI or Copilot |

Key point for a customer's security team: SSAI's local data (nmap results, Pi-hole DNS logs, syslog, process lists)
never becomes Microsoft's responsibility, because it never leaves the customer's network unsanitized. Microsoft's
responsibility starts only at the data the sanitization gate actually sends, and the audit log shows exactly what
that was.

## Pre-approval checklist

Confirm each in writing from Microsoft (Product Terms, Data Protection Addendum, Microsoft 365 Copilot data-handling
documentation for the customer's tenant), and record the document and date here.

| Item | Confirmed | Evidence |
|---|---|---|
| SLA: uptime, latency, support response (`sla`) | no | |
| Data location: region, sub-processors (`data_location`) | no | |
| Retention and model training (`retention_training`) | no | |
| Audit rights: logs / evidence of handling (`audit_rights`) | no | |
| Incident response: who notifies whom, how fast (`incident_response`) | no | |
| Exit terms: data after the integration ends (`exit_terms`) | no | |
| Certifications relevant to the customer, e.g. SOC 2 (`certifications`) | no | |

Note: much of this is governed by the customer's own Microsoft 365 agreement, not SSAI's. For a customer deployment,
confirm it against that tenant's agreement and record the outcome in the customer's `instance/provider_approvals.json`.

## Status

`pending`: no item confirmed in writing yet. The lane is off until `SSAI_COPILOT_KEY` is set on the hub.
