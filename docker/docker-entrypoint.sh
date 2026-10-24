#!/usr/bin/env bash
set -euo pipefail

DATA_DIR="${DATA_DIR:-/data}"
ENV_FILE="$DATA_DIR/.env"

mkdir -p "$DATA_DIR/backend/instance" "$DATA_DIR/logs"

# First-boot bootstrap: generate real secrets once and persist them in the
# /data volume, instead of shipping a known default in source (see
# ssai_config.py / app.py -- SECRET_KEY's fallback there is a last-resort
# for a manual install that skipped .env entirely, not what Docker uses).
if [ ! -f "$ENV_FILE" ]; then
  echo "[entrypoint] No $ENV_FILE found -- first run, generating fresh secrets."
  SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
  SSAI_API_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
  SSAI_VIEWER_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
  ( umask 077; cat > "$ENV_FILE.tmp" ) <<EOF
SECRET_KEY=$SECRET_KEY
SSAI_API_KEY=$SSAI_API_KEY
SSAI_VIEWER_KEY=$SSAI_VIEWER_KEY
GITHUB_AUTOPUSH_ENABLED=false
EOF
  chmod 600 "$ENV_FILE.tmp"
  mv "$ENV_FILE.tmp" "$ENV_FILE"          # a crash mid-write must not leave a half-written .env that the next start trusts
fi

# app.py loads .env itself via python-dotenv, but agent_runner.py and
# github_reporter.py read straight from the process environment (under
# systemd, EnvironmentFile= does this injection for them) -- export it here
# so supervisord and everything it spawns inherits the same values.
set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

# db.create_all() runs unconditionally in app.py's own app-context block at
# import time and is idempotent -- importing once here, before gunicorn
# spins up multiple workers, avoids every worker racing to create tables
# on first boot.
cd /app/backend
python3 -c "import app" >/tmp/db-init.log 2>&1 || {
  echo "[entrypoint] DB init failed:"; cat /tmp/db-init.log; exit 1;
}

exec supervisord -c /etc/supervisor/conf.d/swarmsentinel.conf
