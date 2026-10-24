#!/usr/bin/env bash
# Pieces shared by the two updaters: update.sh (an install that is a git checkout) and update-package.sh (an install
# unpacked from a release package). Sourced, never run on its own.
#
# The caller sets REPO (the install folder) and PY (its virtualenv's python) before using run_tests.

log()  { printf '%s %s\n' "$(date '+%F %T')" "$*"; }
die()  { log "ERROR: $*" >&2; exit 1; }

# is_unit NAME: is NAME installed as a systemd service?
is_unit() { command -v systemctl >/dev/null && systemctl list-unit-files "$1.service" 2>/dev/null | grep -q "^$1.service"; }

# sc ARGS: run systemctl (directly as root, otherwise through the scoped sudo rule install.sh set up).
sc()      { if [ "$(id -u)" = 0 ]; then systemctl "$@"; else sudo -n systemctl "$@"; fi; }

healthy() {           # hub: the API answers; node (no local API): the runner is up
  if is_unit swarmsentinel; then
    # Find the address and port the web app listens on from its service file ("-b HOST:PORT"); 0.0.0.0 means "any", so ask 127.0.0.1.
    local b h p; b="$(systemctl cat swarmsentinel 2>/dev/null | grep -oE -- "-b [0-9.]+:[0-9]+" | head -1 | sed "s/^-b //")"
    h="${b%%:*}"; p="${b##*:}"; { [ -z "$h" ] || [ "$h" = 0.0.0.0 ]; } && h=127.0.0.1       # the address it listens on, not always loopback
    local up=1
    for _ in $(seq 1 30); do curl -fsS -m 3 "http://$h:${p:-5000}/health" >/dev/null 2>&1 && { up=0; break; }; sleep 1; done
    [ "$up" = 0 ] || return 1
    # The runner is half the product: a hub that answers while the runner crash-loops must not count as a good update.
    if is_unit ssai-agents; then sleep 5; systemctl is-active --quiet ssai-agents || return 1; fi
    return 0
  fi
  sleep 5; systemctl is-active --quiet ssai-agents
}

restart_all() {
  if is_unit swarmsentinel; then sc restart swarmsentinel || return 1; fi
  if is_unit ssai-agents; then sc restart ssai-agents || return 1; fi
  return 0
}

# run_tests: run every backend/tools/test_*.py with the install's python. Prints the names of the ones that failed
# (empty when all pass). Tests that simulate "out of credits" write to a temporary folder, never the live instance folder.
run_tests() {
  local failed="" rest_tmp out t
  rest_tmp="$(mktemp -d)"
  for t in "$REPO"/backend/tools/test_*.py; do
    out="$(cd "$REPO" && SSAI_PROVIDER_REST_FILE="$rest_tmp/rest.json" "$PY" "$t" 2>&1)" \
      || { failed="$failed $(basename "$t")"; printf '%s\n' "$out" | tail -15 >&2; }
  done
  rm -rf "$rest_tmp"
  printf '%s' "$failed"
}
