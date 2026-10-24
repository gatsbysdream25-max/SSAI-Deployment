#!/usr/bin/env bash
# Turn an existing install into a clean, self-contained DEMO machine, and put it back afterwards. Nothing is deleted:
# your real database and settings are set aside in a private folder and restored by "off".
#
#   sudo deploy/demo-mode.sh on         # fresh empty database + example findings, AI models on this machine only, no cloud, no GitHub push
#   sudo deploy/demo-mode.sh off        # your real data and settings come back exactly as they were
#   sudo deploy/demo-mode.sh status
#   add --dry-run to any of them to see what would happen
#
# Both directions STOP the dashboard and agents for about a minute while the data is swapped.
# While it is on: the dashboard login is unchanged; nothing is sent to GitHub or any cloud AI; the nightly backup backs up the DEMO
# database (your real one is safe in _archive/demo-mode/). Do not leave a box in demo mode for weeks: the retention job keeps only
# 7 nightly backups, so after a week none of them is from your real data (the saved copy in _archive/ is unaffected).
set -euo pipefail
say() { printf '\n== %s\n' "$*"; }
die() { echo "ERROR: $*" >&2; exit 1; }

ACTION="${1:-}"; shift || true
DRY=0; [ "${1:-}" = "--dry-run" ] && DRY=1
run() { if [ "$DRY" = 1 ]; then echo "   [dry-run] $*"; else "$@"; fi; }

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INST="$REPO/backend/instance"
HOME_DIR="$REPO/_archive/demo-mode"
MARK="$HOME_DIR/ACTIVE"                       # holds the name of the folder with the saved real data; present only while demo mode is on
OWNER="$(stat -c %U "$REPO")"
VENV_PY="$REPO/swarmsentinel-env/bin/python3"
SVCS="swarmsentinel ssai-agents ssai-github"
FILES="swarmsentinel.db swarmsentinel.db-wal swarmsentinel.db-shm ai_models.json ai_providers.json github_reporter_state.json"

[ "$(id -u)" = 0 ] || [ "$DRY" = 1 ] || [ "$ACTION" = status ] || die "run with sudo"
as_owner() { sudo -u "$OWNER" env DATA_DIR="$REPO" "$@"; }

stop_all()  { for s in $SVCS; do run systemctl stop "$s" 2>/dev/null || true; done; }
start_all() { for s in swarmsentinel ssai-agents; do run systemctl start "$s"; done; }

set_env() {            # set KEY=value in .env, replacing an existing line
  local k="$1" v="$2" tmp; tmp="$(mktemp)"
  { grep -v "^${k}=" "$REPO/.env" || true; printf '%s=%s\n' "$k" "$v"; } > "$tmp"
  run install -m 600 -o "$OWNER" "$tmp" "$REPO/.env"; rm -f "$tmp"
}

# The port the dashboard listens on: read from its service file ("-b HOST:PORT"), 5000 if that cannot be found.
PORT="$(systemctl cat swarmsentinel 2>/dev/null | grep -oE -- '-b [0-9.]+:[0-9]+' | head -1 | sed 's/.*://')"
PORT="${PORT:-5000}"

wait_healthy() {
  [ "$DRY" = 0 ] || return 0
  for _ in $(seq 1 40); do curl -fsS -m 3 "http://127.0.0.1:$PORT/health" >/dev/null 2>&1 && return 0; sleep 1; done
  die "the dashboard did not come back in 40 s: journalctl -u swarmsentinel -n 50"
}

case "$ACTION" in
  status)
    if [ -f "$MARK" ]; then echo "demo mode is ON (your real data is in $HOME_DIR/$(cat "$MARK"))"; else echo "demo mode is off"; fi ;;

  on)
    [ ! -f "$MARK" ] || die "demo mode is already on (use 'off' first)"
    [ -f "$INST/swarmsentinel.db" ] || die "no database found at $INST/swarmsentinel.db"
    STAMP="$(date +%Y%m%d-%H%M%S)"; SAVE="$HOME_DIR/$STAMP"
    say "setting your real data aside in $SAVE"
    run mkdir -p "$SAVE"; run chmod 700 "$REPO/_archive" "$HOME_DIR" "$SAVE"
    stop_all
    for f in $FILES; do [ -e "$INST/$f" ] && run mv "$INST/$f" "$SAVE/$f"; done
    run cp -p "$REPO/.env" "$SAVE/dot-env"
    say "settings for a machine on its own"
    set_env OLLAMA_URL "http://127.0.0.1:11434"
    set_env SSAI_MIN_VOTERS 2
    if [ "$DRY" = 0 ]; then
      as_owner "$VENV_PY" "$REPO/backend/tools/enable_local_models.py" --local-only || echo "   (could not set the panel; do it under Settings -> AI panel)"
    else echo "   [dry-run] switch on the models installed here, switch every cloud voice off"; fi
    run systemctl disable ssai-github 2>/dev/null || true         # a demo must never push anything to GitHub
    say "starting with an empty database"
    start_all; wait_healthy
    if [ "$DRY" = 0 ]; then
      sleep 2; as_owner python3 "$REPO/deploy/demo_seed.py" --url "http://127.0.0.1:$PORT" || echo "   (examples not added; run deploy/demo_seed.py)"
      echo "$STAMP" > "$MARK"
    fi
    echo; echo "Demo mode is ON. The AI panel judges the examples within a few minutes (it checks every 5). Undo with: sudo deploy/demo-mode.sh off" ;;

  off)
    [ -f "$MARK" ] || die "demo mode is not on"
    SAVE="$HOME_DIR/$(cat "$MARK")"; [ -d "$SAVE" ] || die "the saved data folder $SAVE is missing; nothing was changed"
    say "putting your real data back from $SAVE"
    stop_all
    DEMO="$HOME_DIR/demo-db-$(date +%Y%m%d-%H%M%S)"; run mkdir -p "$DEMO"; run chmod 700 "$DEMO"
    for f in $FILES; do [ -e "$INST/$f" ] && run mv "$INST/$f" "$DEMO/$f"; done        # keep the demo data, in case it is wanted
    for f in $FILES; do [ -e "$SAVE/$f" ] && run mv "$SAVE/$f" "$INST/$f"; done
    [ -f "$SAVE/dot-env" ] && run install -m 600 -o "$OWNER" "$SAVE/dot-env" "$REPO/.env"
    run chown -R "$OWNER" "$INST"
    run systemctl enable ssai-github 2>/dev/null || true
    for s in swarmsentinel ssai-agents ssai-github; do run systemctl start "$s"; done
    wait_healthy
    [ "$DRY" = 1 ] || rm -f "$MARK"
    echo; echo "Demo mode is OFF; your data and settings are back. (The demo database is kept in $DEMO.)" ;;

  *) die "usage: sudo deploy/demo-mode.sh on|off|status [--dry-run]" ;;
esac
