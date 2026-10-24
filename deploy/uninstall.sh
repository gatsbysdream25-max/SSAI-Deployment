#!/usr/bin/env bash
# Remove the SwarmSentinel services from this machine. Your data (database, .env, logs) is kept unless --purge.
#   sudo deploy/uninstall.sh [--purge]
set -euo pipefail
PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1
[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 1; }
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

for u in ssai-retention.timer ssai-retention.service ssai-update.timer ssai-update.service ssai-agents.service swarmsentinel.service; do
  if systemctl list-unit-files "$u" 2>/dev/null | grep -q "^$u"; then
    systemctl disable --now "$u" 2>/dev/null || true
    rm -f "/etc/systemd/system/$u"
    echo "removed $u"
  fi
done
systemctl daemon-reload
rm -f /etc/sudoers.d/ssai-* && echo "removed sudo rules"

if [ "$PURGE" = 1 ]; then
  read -r -p "Delete the database, settings and logs in $REPO (backend/instance, .env, logs, swarmsentinel-env)? [y/N] " a
  if [ "$a" = y ] || [ "$a" = Y ]; then rm -rf "$REPO/backend/instance" "$REPO/.env" "$REPO/logs" "$REPO/swarmsentinel-env" "$REPO/deploy/rendered"; echo "data removed"; fi
else
  echo "your data is untouched (add --purge to delete it)"
fi
