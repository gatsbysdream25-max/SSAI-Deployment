# Changelog

## Unreleased (2026-10-18)

### Pre-pilot hardening
- Threat data and the deployment's posture (ten `GET` endpoints) now need a signed-in admin, the admin key, or the
  display's read-only viewer key (`SSAI_VIEWER_KEY`, sent by the kiosk's proxy as `X-SSAI-Viewer`). Health checks use
  `/health`. Existing displays must be given the key; see `deploy/tls/README.md`.
- Single sign-on for the dashboard admin (OIDC, Entra ID by default): `SSAI_SSO_*` settings in `backend/sso.py`.
  `SSAI_SSO_ONLY=1` turns the local password off.
- Content-Security-Policy on every response; HSTS when `SSAI_HSTS=1` over real HTTPS.
- TLS reverse-proxy support: `deploy/tls/`, `deploy/check-tls.sh`, `install.sh --bind`.
- An AI provider that stops answering is logged as `DEGRADED` (rate-limited) instead of being silent.
- `docs/plans/threat-model.md`.

## Unreleased (2026-10-11)

### Packaging and deployment
- `deploy/make-release.sh` builds a downloadable `swarmsentinel-<version>.tar.gz` from any commit: no git history, no
  secrets, no lab data (`export-ignore` paths are excluded and the build refuses if an `.env`, database or key slips in).
  Install on a fresh machine: `tar xzf swarmsentinel-<version>.tar.gz && cd SwarmSentinel && sudo deploy/install.sh`.
- `deploy/install.sh` now restarts the services after installing them, so a re-run applies new code.
- `deploy/sandbox/`: a VirtualBox test VM (Ubuntu autoinstall) and setup scripts for installing a release on a clean
  machine and running live red-team drills against it.

### Governance and AI safety
- Provider approvals: a cloud AI provider only receives data after it has been explicitly approved; per-provider
  shared-responsibility notes live in `docs/third-party-ai/`.
- Agent state store (local shared state, see `docs/plans/2026-10-08-local-shared-state.md`) and decision lineage
  (each verdict records which code version and inputs produced it); the governance page can read agent state.
- `RedTeamAgent` runs adversarial self-tests every 6 hours (sanitizer, cloud gate, remediation) and reports pass/fail.
  Gaps it found in the cloud gate and remediation actions are closed.

### Detection
- Distributed SSH brute-force detection (many hosts, one target), reported as one finding per host.
- `ProcessMonitorAgent` no longer flags any `python -c` one-liner. It now matches the executable name for miners,
  `nc` only with an exec flag, `/dev/tcp` shells, and interpreter `-c`/`-e` only when the code contains reverse-shell
  primitives. This removes a class of false positives that the AI panel escalated to fabricated CRITICAL verdicts.
- Agent interval floor applies only when scaling shortens an interval.
- Tools locate their install without `DATA_DIR`.

### Fixes
- Findings from the 2026-09-30 code review fixed (see `backend/tools/test_review_fixes.py`).
- Sandbox drills: new sightings of an existing finding count as caught; drills wait for the agent runner to take its
  baselines.

### Tests
- New suites for lineage, provider approvals, red team, state store, sanitizer, sandbox, process monitor and the review
  fixes (44 test files passing at this commit).
