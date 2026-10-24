#!/usr/bin/env bash
# Set or reset the dashboard admin password. Run on the hub machine.
#   deploy/set-password.sh                       prompt for a password
#   deploy/set-password.sh --generate            generate a strong one and print it once
#   deploy/set-password.sh --generate --out F    write the generated one to file F (mode 600) instead of printing it
#   deploy/set-password.sh status                say whether one is set
# Works as root or as the account that owns the install. Signed-in sessions end when the password changes.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$REPO/swarmsentinel-env/bin/python3"
[ -x "$PY" ] || { echo "error: no virtualenv at $REPO/swarmsentinel-env (run deploy/install.sh first)" >&2; exit 1; }

cmd=set-password
if [ "${1:-}" = status ]; then cmd=status; shift; elif [ "${1:-}" = set-password ]; then shift; fi
run_cmd=(env DATA_DIR="$REPO" "$PY" "$REPO/backend/adminctl.py" "$cmd" "$@")

# The web app reads the file as the install's owner, so write it as that account.
owner="$(stat -c %U "$REPO/backend/instance" 2>/dev/null || id -un)"
if [ "$(id -u)" = 0 ] && [ "$owner" != root ]; then
  exec runuser -u "$owner" -- "${run_cmd[@]}"
fi
exec "${run_cmd[@]}"
