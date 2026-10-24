#!/usr/bin/env bash
# Optional systemd sandboxing for the SwarmSentinel services.
#
#   sudo deploy/harden.sh apply      install the hardening, restart, verify; undo automatically if anything looks wrong
#   sudo deploy/harden.sh revert     remove it
#   deploy/harden.sh status          show each service's systemd exposure score and whether hardening is on
#
# The agent runner (root) and the web app are restricted to what they need: no new privileges, a short capability list,
# a read-only filesystem except the data directory, no kernel/cgroup/clock access, only the socket families they use.
# Drop-ins live in /etc/systemd/system/<unit>.d/10-hardening.conf and change nothing else.
set -euo pipefail

SYSTEMD_DIR="${SSAI_SYSTEMD_DIR:-/etc/systemd/system}"
WAIT_HUB="${SSAI_HARDEN_WAIT_HUB:-40}"
WAIT_RUNNER="${SSAI_HARDEN_WAIT_RUNNER:-100}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TPL="$REPO/deploy/systemd/hardening"
DROPIN=10-hardening.conf
log() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

# The unit's own WorkingDirectory tells us where the install lives (it may differ from this checkout).
install_dir() {
  local dir; dir="$(sed -n 's/^Environment=DATA_DIR=//p' "$SYSTEMD_DIR/$1.service" 2>/dev/null | head -1)"
  [ -n "$dir" ] || dir="$REPO"
  printf '%s' "$dir"
}
present() { [ -f "$SYSTEMD_DIR/$1.service" ]; }
units() { local u; for u in swarmsentinel ssai-agents; do present "$u" && printf '%s ' "$u"; done; }

need_root() {
  if [ "$(id -u)" != 0 ] && [ -z "${SSAI_SYSTEMD_DIR:-}" ]; then die "run with sudo"; fi
}

install_dropins() {
  local u
  for u in "$@"; do
    [ -f "$TPL/$u.conf.in" ] || die "missing template deploy/systemd/hardening/$u.conf.in"
    mkdir -p "$SYSTEMD_DIR/$u.service.d"
    sed "s#@DIR@#$(install_dir "$u")#g" "$TPL/$u.conf.in" > "$SYSTEMD_DIR/$u.service.d/$DROPIN"
    chmod 644 "$SYSTEMD_DIR/$u.service.d/$DROPIN"
  done
}

remove_dropins() {
  local u
  for u in swarmsentinel ssai-agents; do
    rm -f "$SYSTEMD_DIR/$u.service.d/$DROPIN"
    rmdir "$SYSTEMD_DIR/$u.service.d" 2>/dev/null || true
  done
}

restart_units() {
  systemctl daemon-reload
  local u
  for u in "$@"; do systemctl restart "$u"; done          # the web app first: the runner depends on it
}

hub_port() {
  systemctl cat swarmsentinel 2>/dev/null | grep -oE -- '-b [0-9.]+:[0-9]+' | head -1 | sed 's/.*://'
}
hub_host() {          # where the hub listens: a specific --bind address, or loopback when it listens on every address
  local h; h="$(systemctl cat swarmsentinel 2>/dev/null | grep -oE -- '-b [0-9.]+:[0-9]+' | head -1 | sed -e 's/^-b //' -e 's/:.*//')"
  { [ -z "$h" ] || [ "$h" = 0.0.0.0 ]; } && h=127.0.0.1
  printf '%s' "$h"
}

healthy() {           # healthy <since-timestamp> <units...>
  local since="$1"; shift
  local u
  for u in "$@"; do
    if [ "$u" = swarmsentinel ]; then
      local ok=0 i
      for i in $(seq 1 "$WAIT_HUB"); do
        if curl -fsS -m 3 "http://$(hub_host):$(hub_port || true)/health" >/dev/null 2>&1 || curl -fsS -m 3 "http://$(hub_host):5000/health" >/dev/null 2>&1; then ok=1; break; fi
        sleep 1
      done
      [ "$ok" = 1 ] || { log "  the dashboard did not answer within ${WAIT_HUB}s"; return 1; }
    else
      local i alive=0
      for i in $(seq 1 "$WAIT_RUNNER"); do
        local out; out="$(journalctl -u ssai-agents --since "$since" --no-pager -o cat 2>/dev/null || true)"
        if printf '%s\n' "$out" | grep -qE 'Traceback|Read-only file system|Operation not permitted|PermissionError'; then
          log "  the agent runner logged a sandbox-type error:"; printf '%s\n' "$out" | grep -E 'Traceback|Read-only file system|Operation not permitted|PermissionError' | head -3 | sed 's/^/    /'
          return 1
        fi
        if printf '%s\n' "$out" | grep -qE 'Heartbeat: ([0-9]+)/\1 agents alive'; then alive=1; break; fi
        sleep 1
      done
      [ "$alive" = 1 ] || { log "  the agent runner did not report all agents alive within ${WAIT_RUNNER}s"; return 1; }
    fi
  done
}

cmd="${1:-status}"
case "$cmd" in
  apply)
    need_root
    set -- $(units)
    [ $# -gt 0 ] || die "no SwarmSentinel service is installed in $SYSTEMD_DIR (run deploy/install.sh first)"
    log "Hardening: $*"
    since="$(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    install_dropins "$@"
    if restart_units "$@" && healthy "$since" "$@"; then
      log "Done. Services are running with the hardening on (undo: sudo deploy/harden.sh revert)."
    else
      log "Something did not come up healthy: undoing the hardening."
      remove_dropins
      restart_units "$@" || true
      die "hardening was rolled back; the services are running as before. Send the lines above to whoever maintains this."
    fi
    ;;
  revert)
    need_root
    set -- $(units)
    remove_dropins
    [ $# -eq 0 ] || restart_units "$@"
    log "Hardening removed."
    ;;
  status)
    [ -n "$(units)" ] || die "no SwarmSentinel service installed"
    for u in $(units); do
      on="no"; [ -f "$SYSTEMD_DIR/$u.service.d/$DROPIN" ] && on="yes"
      score="$(systemd-analyze security "$u" --no-pager 2>/dev/null | tail -1 | grep -oE '[0-9]+\.[0-9]+ [A-Z]+' || echo unknown)"
      printf '%-15s hardening: %-3s  exposure: %s\n' "$u" "$on" "$score"
    done
    ;;
  *) die "usage: deploy/harden.sh apply|revert|status" ;;
esac
