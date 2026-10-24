#!/usr/bin/env bash
# Exercises deploy/harden.sh with stub systemctl/journalctl/curl and a scratch systemd directory (touches nothing real).
set -u
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
W="$(mktemp -d /tmp/harden-test.XXXXXX)"
trap 'rm -rf "$W"' EXIT
mkdir -p "$W/shims" "$W/sd"
pass=0; fail=0
ok()   { pass=$((pass+1)); printf '  PASS  %s\n' "$*"; }
bad()  { fail=$((fail+1)); printf '  FAIL  %s\n' "$*"; }
check(){ if eval "$2"; then ok "$1"; else bad "$1  [$2]"; printf '%s\n' "${out:-}" | tail -5 | sed 's/^/        | /'; fi; }

cat > "$W/shims/systemctl" <<'EOS'
#!/usr/bin/env bash
echo "systemctl $*" >> "$STUB_DIR/calls"
[ "$1" = cat ] && echo "ExecStart=/x/gunicorn -w 2 -b 0.0.0.0:5000 app:app"
exit 0
EOS
cat > "$W/shims/journalctl" <<'EOS'
#!/usr/bin/env bash
cat "$STUB_DIR/journal" 2>/dev/null
EOS
cat > "$W/shims/curl" <<'EOS'
#!/usr/bin/env bash
[ -e "$STUB_DIR/hub_down" ] && exit 22
exit 0
EOS
cat > "$W/shims/id" <<'EOS'
#!/usr/bin/env bash
[ "$1" = "-u" ] && { echo 1000; exit 0; }
exec /usr/bin/id "$@"
EOS
chmod +x "$W/shims/"*
export STUB_DIR="$W/stub"; mkdir -p "$STUB_DIR"
export PATH="$W/shims:$PATH" SSAI_SYSTEMD_DIR="$W/sd" SSAI_HARDEN_WAIT_HUB=2 SSAI_HARDEN_WAIT_RUNNER=2
H() { "$REPO/deploy/harden.sh" "$@" 2>&1; }
units() { printf '[Service]\nEnvironment=DATA_DIR=/srv/ssai\nExecStart=/x\n' > "$W/sd/swarmsentinel.service"; printf '[Service]\nEnvironment=DATA_DIR=/srv/ssai\nExecStart=/y\n' > "$W/sd/ssai-agents.service"; }
healthy_journal() { printf 'Heartbeat: 9/9 agents alive\n' > "$STUB_DIR/journal"; rm -f "$STUB_DIR/hub_down"; }

echo "1) nothing installed"
out=$(H apply); rc=$?
check "refuses with a pointer to the installer" '[ $rc -eq 1 ] && echo "$out" | grep -q "install.sh"'

echo "2) apply on a hub (both units), everything healthy"
units; healthy_journal; : > "$STUB_DIR/calls"
out=$(H apply); rc=$?
check "exit 0" '[ $rc -eq 0 ]'
check "drop-ins written for both units" '[ -f "$W/sd/swarmsentinel.service.d/10-hardening.conf" ] && [ -f "$W/sd/ssai-agents.service.d/10-hardening.conf" ]'
check "the runner drop-in is confined to the install directory" 'grep -q "^ReadWritePaths=/srv/ssai$" "$W/sd/ssai-agents.service.d/10-hardening.conf" && ! grep -q "@DIR@" "$W/sd/ssai-agents.service.d/10-hardening.conf"'
check "the web app keeps sudo working (no NoNewPrivileges/ProtectSystem)" '! grep -qE "^(NoNewPrivileges|ProtectSystem|CapabilityBoundingSet)" "$W/sd/swarmsentinel.service.d/10-hardening.conf"'
check "the runner gets NoNewPrivileges and a capability list" 'grep -q "^NoNewPrivileges=yes" "$W/sd/ssai-agents.service.d/10-hardening.conf" && grep -q "^CapabilityBoundingSet=" "$W/sd/ssai-agents.service.d/10-hardening.conf"'
check "reloaded, then restarted the web app before the runner" '[ "$(grep -E "restart|daemon-reload" "$STUB_DIR/calls" | tr "\n" ";")" = "systemctl daemon-reload;systemctl restart swarmsentinel;systemctl restart ssai-agents;" ]'

echo "3) applying twice is harmless"
: > "$STUB_DIR/calls"; out=$(H apply); rc=$?
check "exit 0 and still one drop-in per unit" '[ $rc -eq 0 ] && [ "$(ls "$W/sd/ssai-agents.service.d" | wc -l)" = 1 ]'

echo "4) revert"
: > "$STUB_DIR/calls"; out=$(H revert); rc=$?
check "removes the drop-ins and the directories" '[ $rc -eq 0 ] && [ ! -e "$W/sd/ssai-agents.service.d" ] && [ ! -e "$W/sd/swarmsentinel.service.d" ]'
check "restarts the services afterwards" 'grep -q "restart ssai-agents" "$STUB_DIR/calls"'

echo "5) the runner logs a sandbox error: rolled back automatically"
units; printf 'Heartbeat: 9/9 agents alive\nOSError: [Errno 30] Read-only file system: /x\n' > "$STUB_DIR/journal"; : > "$STUB_DIR/calls"
out=$(H apply); rc=$?
check "exit 1 and says it rolled back" '[ $rc -eq 1 ] && echo "$out" | grep -q "rolled back"'
check "drop-ins are gone" '[ ! -e "$W/sd/ssai-agents.service.d" ] && [ ! -e "$W/sd/swarmsentinel.service.d" ]'
check "the services were restarted again without hardening (2 rounds)" '[ "$(grep -c "restart ssai-agents" "$STUB_DIR/calls")" = 2 ]'
check "the offending line is shown to the operator" 'echo "$out" | grep -q "Read-only file system"'

echo "6) the runner never reports all agents alive: rolled back"
units; printf 'starting up\n' > "$STUB_DIR/journal"
out=$(H apply); rc=$?
check "exit 1, drop-ins removed" '[ $rc -eq 1 ] && [ ! -e "$W/sd/ssai-agents.service.d" ] && echo "$out" | grep -q "did not report all agents alive"'

echo "7) the dashboard does not answer: rolled back"
units; healthy_journal; touch "$STUB_DIR/hub_down"
out=$(H apply); rc=$?
check "exit 1, drop-ins removed" '[ $rc -eq 1 ] && [ ! -e "$W/sd/swarmsentinel.service.d" ] && echo "$out" | grep -q "dashboard did not answer"'
rm -f "$STUB_DIR/hub_down"

echo "8) a node (runner only) is hardened without a dashboard check"
rm -f "$W/sd/swarmsentinel.service"; units_node() { printf '[Service]\nExecStart=/y\n' > "$W/sd/ssai-agents.service"; }; units_node; healthy_journal; touch "$STUB_DIR/hub_down"
out=$(H apply); rc=$?
check "exit 0; only the runner drop-in exists; DATA_DIR falls back to the checkout" '[ $rc -eq 0 ] && [ -f "$W/sd/ssai-agents.service.d/10-hardening.conf" ] && [ ! -e "$W/sd/swarmsentinel.service.d" ] && grep -q "^ReadWritePaths=$REPO$" "$W/sd/ssai-agents.service.d/10-hardening.conf"'
rm -f "$STUB_DIR/hub_down"

echo "9) bad usage"
out=$(H frobnicate); rc=$?
check "usage error" '[ $rc -eq 1 ] && echo "$out" | grep -q usage'

echo
echo "RESULT: $pass passed, $fail failed"
[ "$fail" = 0 ]
