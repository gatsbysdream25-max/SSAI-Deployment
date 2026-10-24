#!/usr/bin/env bash
# GITHUB_AUTOPUSH_ENABLED is off by default -- most installs have no git
# remote/credentials configured, and unlike the other two agents this one
# can't gracefully no-op internally without a real git repo to push to.
if [ "${GITHUB_AUTOPUSH_ENABLED:-false}" = "true" ]; then
  exec python3 /app/backend/github_reporter.py
fi

echo "[ssai-github] GITHUB_AUTOPUSH_ENABLED is not 'true' -- staying idle."
exec sleep infinity
