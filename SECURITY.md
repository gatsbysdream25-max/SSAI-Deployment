# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately to **gatsbyssai@hotmail.com** rather than opening a public issue.
Include what you found, how to reproduce it, and the version (`git rev-parse --short HEAD`). You will get an
acknowledgement within a few days. Please give us a reasonable time to fix a problem before discussing it publicly.

## What the design protects, and what it does not

- **Sign-in.** People sign in with a password (stored only as a salted scrypt hash). The dashboard is view-only until
  then, and the machine API key is never sent to a browser.
- **Machines.** Each enrolled machine has its own revocable credential that can only report its own data.
- **Privacy.** Real LAN addresses are kept in an admin-only field and never published; the exported ledger is scrubbed of
  hostnames, usernames and email addresses.
- **Not yet covered:** traffic is plain HTTP (put the hub behind a TLS reverse proxy off a trusted LAN); the web app
  runs `sudo ufw` for the Block button, which limits how far it can be sandboxed; there is no role-based access control
  or multi-tenant isolation; content of AI-model output is untrusted and only ever advisory.

## Hardening you can turn on

- `sudo deploy/harden.sh apply` sandboxes the services with systemd (reverts itself if anything breaks).
- Set `SSAI_COOKIE_SECURE=1` when serving over HTTPS, and `SSAI_TRUSTED_PROXIES` to your proxy's address.
- `SSAI_STORE_REAL_ADDRESSES=0` stops real LAN addresses from being stored at all.
- `deploy/set-password.sh` changes the admin password; `backend/retention.py` reports and (on request) removes old data.
