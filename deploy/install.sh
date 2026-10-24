#!/usr/bin/env bash
# SwarmSentinel installer for Linux hosts that use systemd. Idempotent: safe to run again to repair or upgrade.
#
#   sudo deploy/install.sh                                  # a hub: dashboard + API + agents on this machine
#   sudo deploy/install.sh --role node --hub-url http://HUB:5000 --enroll-code XXXX-XXXX-XXXX-XXXX
#                                                           # an extra machine that reports to a hub
#                                                           # (get a code on the hub with deploy/new-node.sh)
# Run it from a clone of the repository (git clone <repo> && cd SwarmSentinel). Everything lives in that directory:
# the virtualenv (swarmsentinel-env/), the settings file (.env), the database and state (backend/instance/).
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: deploy/install.sh [options]

  --role hub|node        hub (default): dashboard, API and all agents. node: host sensors only, reports to a hub.
  --user NAME            account the web app runs as (default: the user who ran sudo). Agents run as root so they
                         can read system logs and inspect connections.
  --port N               dashboard port for a hub (default 5000)
  --bind ADDR            address the hub listens on (default 0.0.0.0, but 127.0.0.1 with --standalone or inside WSL, so only this
                         machine can open it; use 127.0.0.1 behind a TLS proxy)
  --hub-url URL          node only: where the hub is, e.g. http://192.168.1.10:5000
  --enroll-code CODE     node only: a single-use enrollment code from the hub (run deploy/new-node.sh on the hub, or use
                         Settings -> Machines). The machine trades it for its OWN credential; the hub's admin key never
                         leaves the hub. Also read from SSAI_ENROLL_CODE or --enroll-code-file.
  --enroll-code-file F   node only: read the code from a file
  --re-enroll            node only: replace an existing credential (needs a new code)
  --node-id NAME         node only: how this machine is named on the hub (default: its hostname)
  --auto-update          also install a daily timer that runs deploy/update.sh
  --no-retention         hub only: do not install the daily retention timer (removes low rows older than 30 days and
                         info rows older than 14; active medium+ findings are never removed; backs up first)
  --wheelhouse DIR       install Python packages from DIR only (no internet): the folder deploy/make-usb-kit.sh builds
  --standalone           a hub that works with nothing else on the network: AI models on THIS machine (deploy/local-ai.sh),
                         and a panel of 2 local models counts as a full panel (SSAI_MIN_VOTERS=2). Cloud keys stay optional.
  --no-systemd           do everything except install services (units are rendered to deploy/rendered/ for review)
  --no-sudoers           do not install the scoped sudo rules (firewall blocking and restarts from the dashboard)
  --no-start             install but do not start the services
  --no-packages          do not install missing system packages (python3-venv, curl, git, nmap, ...) with apt; just report them
  --dry-run              show what would happen and change nothing
  -h, --help             this text
EOF
}

ROLE=hub PORT=5000 BIND="" USER_NAME="" HUB_URL="" ENROLL_CODE="${SSAI_ENROLL_CODE:-}" ENROLL_CODE_FILE="" RE_ENROLL=0 NODE_ID="" WHEELHOUSE="" STANDALONE=0 AUTOUPDATE=0 RETENTION=1 SYSTEMD=1 SUDOERS=1 START=1 PACKAGES=1 DRY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --role) ROLE="${2:-}"; shift 2 ;;
    --user) USER_NAME="${2:-}"; shift 2 ;;
    --port) PORT="${2:-}"; shift 2 ;;
    --bind) BIND="${2:-}"; shift 2 ;;       # 127.0.0.1 when a TLS proxy sits in front (deploy/tls/README.md)
    --hub-url) HUB_URL="${2:-}"; shift 2 ;;
    --enroll-code) ENROLL_CODE="${2:-}"; shift 2 ;;
    --enroll-code-file) ENROLL_CODE_FILE="${2:-}"; shift 2 ;;
    --re-enroll) RE_ENROLL=1; shift ;;
    --node-id) NODE_ID="${2:-}"; shift 2 ;;
    --wheelhouse) WHEELHOUSE="${2:-}"; shift 2 ;;
    --standalone) STANDALONE=1; shift ;;
    --auto-update) AUTOUPDATE=1; shift ;;
    --no-retention) RETENTION=0; shift ;;
    --no-systemd) SYSTEMD=0; shift ;;
    --no-sudoers) SUDOERS=0; shift ;;
    --no-start) START=0; shift ;;
    --no-packages) PACKAGES=0; shift ;;
    --dry-run) DRY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

say()  { printf '\033[1m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }
# Print every state-changing command; run it unless --dry-run.
run()  { if [ "$DRY" = 1 ]; then printf '   [dry-run] %s\n' "$*"; else "$@"; fi; }

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[ -f "$REPO/requirements.txt" ] && [ -d "$REPO/backend" ] || die "run this from a SwarmSentinel checkout (no backend/ next to deploy/)"
case "$ROLE" in hub|node) ;; *) die "--role must be hub or node" ;; esac
case "$PORT" in ''|*[!0-9]*) die "--port must be a number" ;; esac
# A one-machine hub, or any install inside WSL (where "all interfaces" can mean the whole LAN under mirrored networking),
# listens on this machine only unless --bind says otherwise. A hub that serves other machines still defaults to all interfaces.
if [ -z "$BIND" ]; then
  if [ "$STANDALONE" = 1 ] || grep -qi microsoft /proc/version 2>/dev/null; then BIND=127.0.0.1; else BIND=0.0.0.0; fi
fi
case "$BIND" in *[!0-9.]*) die "--bind must be an IPv4 address (for example 127.0.0.1)" ;; esac

# ── who runs what ────────────────────────────────────────────────────────────
if [ "$SYSTEMD" = 1 ] && [ "$DRY" = 0 ] && [ "$(id -u)" != 0 ]; then
  die "installing services needs root: run 'sudo deploy/install.sh ...' (or add --no-systemd to set up without services)"
fi
[ -n "$USER_NAME" ] || USER_NAME="${SUDO_USER:-$(id -un)}"
id "$USER_NAME" >/dev/null 2>&1 || die "no such user: $USER_NAME"
[ "$USER_NAME" != root ] || warn "the web app will run as root; a dedicated unprivileged user is safer (--user NAME)"

as_user() {           # run a command as the service user (files must not end up root-owned)
  if [ "$(id -u)" = 0 ] && [ "$USER_NAME" != root ]; then run runuser -u "$USER_NAME" -- "$@"; else run "$@"; fi
}

PY=python3
VENV="$REPO/swarmsentinel-env"
ENV_FILE="$REPO/.env"
SYSTEMCTL="$(command -v systemctl || true)"
[ "$SYSTEMD" = 0 ] || [ -n "$SYSTEMCTL" ] || die "systemctl not found: this host does not use systemd; use --no-systemd or the Docker image"

say "SwarmSentinel install: role=$ROLE dir=$REPO user=$USER_NAME$([ "$DRY" = 1 ] && echo " (dry run)")"

# ── 1. prerequisites ─────────────────────────────────────────────────────────
# A fresh Debian/Ubuntu (and especially the minimal Ubuntu inside WSL) often lacks python3-venv, curl, git or nmap. On such a
# system, when run as root, install what is missing instead of making the person do it by hand. --no-packages turns this off.
install_missing_packages() {
  local wanted="python3 python3-venv python3-pip curl git nmap iproute2 procps sudo ca-certificates" missing="" pkg
  [ "$ROLE" != hub ] || wanted="$wanted ufw"          # installed, not switched on: the dashboard's "block this address" needs it
  for pkg in $wanted; do dpkg -s "$pkg" >/dev/null 2>&1 || missing="$missing $pkg"; done
  [ -n "$missing" ] || return 0
  if [ "$PACKAGES" = 0 ] || [ "$(id -u)" != 0 ] || ! command -v apt-get >/dev/null; then
    warn "missing system packages:$missing (Debian/Ubuntu: sudo apt-get install$missing)"
    return 0
  fi
  say "installing missing system packages:$missing"
  run apt-get update -qq
  run env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $missing
}
if command -v dpkg >/dev/null; then install_missing_packages; fi
command -v "$PY" >/dev/null || die "python3 is required (3.10 or newer)"
"$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' || die "python3 3.10+ required (found $("$PY" -V 2>&1))"
"$PY" -c 'import venv, ensurepip' 2>/dev/null || die "python3-venv is missing (Debian/Ubuntu: sudo apt install python3-venv)"
if [ "$DRY" = 0 ] && [ "$(id -u)" = 0 ] && [ "$USER_NAME" != root ] && ! runuser -u "$USER_NAME" -- test -w "$REPO"; then
  die "$USER_NAME cannot write to $REPO (the folder belongs to someone else). Fix: sudo chown -R $USER_NAME: $REPO   or pass --user <the folder's owner>"
fi
command -v curl >/dev/null || warn "curl not found: the health check and node verification will be skipped"
[ -d "$REPO/.git" ] || warn "not a git checkout: deploy/update.sh cannot update this install"

# ── 2. node: enroll with the hub (before anything is built, so a bad code stops here) ──
set_env() {           # set KEY=value, replacing any existing line (used for the credential, which must be replaceable)
  local k="$1" v="$2" tmp
  tmp="$(mktemp)"
  { [ -f "$ENV_FILE" ] && grep -v "^${k}=" "$ENV_FILE" || true; printf '%s=%s\n' "$k" "$v"; } > "$tmp"
  as_user tee "$ENV_FILE" < "$tmp" >/dev/null
  as_user chmod 600 "$ENV_FILE"
  rm -f "$tmp"
}
if [ "$ROLE" = node ]; then
  [ -n "$HUB_URL" ] || die "--role node needs --hub-url http://HUB:5000"
  case "$HUB_URL" in http://*|https://*) ;; *) die "--hub-url must start with http:// or https://" ;; esac
  HUB_URL="${HUB_URL%/}"
  have_token="$(grep -E '^SSAI_API_KEY=ssn_' "$ENV_FILE" 2>/dev/null | head -1 || true)"
  if [ -n "$have_token" ] && [ "$RE_ENROLL" = 0 ]; then
    say "this machine is already enrolled (credential in $ENV_FILE); pass --re-enroll with a new code to replace it"
  else
    if [ -n "$ENROLL_CODE_FILE" ]; then
      [ -r "$ENROLL_CODE_FILE" ] || die "cannot read $ENROLL_CODE_FILE"
      ENROLL_CODE="$(tr -d '[:space:]' < "$ENROLL_CODE_FILE")"
    fi
    [ -n "$ENROLL_CODE" ] || die "a node needs an enrollment code from the hub admin: on the hub run deploy/new-node.sh (or Settings -> Machines), then pass --enroll-code CODE"
    command -v curl >/dev/null || die "curl is required to enroll"
    if [ "$DRY" = 1 ]; then
      echo "   [dry-run] enroll with $HUB_URL using the given code"
    else
      say "enrolling with $HUB_URL"
      body="$("$PY" -c 'import json,sys; print(json.dumps({"enrollCode": sys.argv[1], "nodeId": sys.argv[2], "hostname": sys.argv[3], "platform": "linux"}))' \
              "$ENROLL_CODE" "${NODE_ID:-}" "$(hostname)")"
      # The body (with the one-time code) goes to curl on stdin so it never appears in the process list.
      resp="$(printf '%s' "$body" | curl -sS -m 20 -w '\n%{http_code}' -X POST -H 'Content-Type: application/json' --data-binary @- "$HUB_URL/api/node/register" 2>&1)" \
        || die "cannot reach the hub at $HUB_URL ($(printf "%s" "$resp" | head -1))"
      status="${resp##*$'\n'}"; json="${resp%$'\n'*}"
      err() { printf '%s' "$json" | "$PY" -c 'import json,sys; print(json.load(sys.stdin).get("error",""))' 2>/dev/null || true; }
      case "$status" in
        200) ;;
        401) die "the hub refused the enrollment code (invalid, expired or already used); ask the admin for a new one" ;;
        409) die "$(err)" ;;
        429) die "the hub is rate-limiting this address after failed attempts; wait a few minutes" ;;
        000|"") die "cannot reach the hub at $HUB_URL" ;;
        *) die "unexpected answer from the hub (HTTP $status): $(err)" ;;
      esac
      # Save the credential straight away: the code is spent, so a later failure must not lose it.
      creds="$(printf '%s' "$json" | "$PY" -c 'import json,sys; d=json.load(sys.stdin); print(d["nodeId"]); print(d["token"])')" \
        || die "the hub's answer could not be read"
      NODE_ID="$(printf '%s\n' "$creds" | sed -n 1p)"
      set_env SSAI_API_KEY "$(printf '%s\n' "$creds" | sed -n 2p)"
      set_env SSAI_NODE_ID "$NODE_ID"
      echo "   enrolled as '$NODE_ID'"
    fi
  fi
fi

# ── 3. directories, virtualenv, dependencies ─────────────────────────────────
say "creating directories and the Python environment"
as_user mkdir -p "$REPO/backend/instance" "$REPO/logs"
if [ ! -x "$VENV/bin/python3" ]; then as_user "$PY" -m venv "$VENV"; fi
if [ -n "$WHEELHOUSE" ]; then
  [ -d "$WHEELHOUSE" ] || die "--wheelhouse $WHEELHOUSE is not a folder"
  # Offline: take every package from the folder and never reach for the internet (and skip upgrading pip, which would).
  as_user "$VENV/bin/pip" install --disable-pip-version-check --quiet --no-index --find-links "$WHEELHOUSE" -r "$REPO/requirements.txt"
else
  as_user "$VENV/bin/pip" install --disable-pip-version-check --quiet --upgrade pip
  as_user "$VENV/bin/pip" install --disable-pip-version-check --quiet -r "$REPO/requirements.txt"
fi

# ── 4. settings (.env): create once, never overwrite ────────────────────────
rand() { "$PY" -c 'import secrets; print(secrets.token_hex(24))'; }
add_env() {           # add KEY=value only if KEY is not already set (an existing choice is never changed)
  local k="$1" v="$2"
  if [ -f "$ENV_FILE" ] && grep -qE "^${k}=" "$ENV_FILE"; then return 0; fi
  if [ "$DRY" = 1 ]; then echo "   [dry-run] .env: add $k"; return 0; fi
  printf '%s=%s\n' "$k" "$v" | as_user tee -a "$ENV_FILE" >/dev/null
}
say "writing settings to $ENV_FILE (existing values are kept)"
if [ "$DRY" = 0 ]; then as_user touch "$ENV_FILE"; as_user chmod 600 "$ENV_FILE"; fi
add_env DATA_DIR "$REPO"
if [ "$ROLE" = hub ]; then
  add_env SECRET_KEY "$(rand)"
  add_env SSAI_API_KEY "$(rand)"
  add_env SSAI_VIEWER_KEY "$(rand)"      # read-only: for a wall display's proxy (X-SSAI-Viewer header); see deploy/README.md
  if [ "$STANDALONE" = 1 ]; then
    add_env OLLAMA_URL "http://127.0.0.1:11434"     # the models run on this machine (deploy/local-ai.sh)
    add_env SSAI_MIN_VOTERS 2                       # two local models are the whole panel here; see docs/consensus-operating-guide.md
  fi
else
  add_env SSAI_ROLE node
  set_env_api() { if [ "$DRY" = 1 ]; then echo "   [dry-run] .env: set SSAI_API"; else set_env SSAI_API "$HUB_URL/api"; fi; }
  set_env_api                      # the hub address may change on a re-run; the credential is only ever set by enrolment
fi

# ── 4b. hub: make sure someone can sign in (a fresh install must never be left with no login) ──
INITIAL_PASSWORD=""
if [ "$ROLE" = hub ] && [ ! -f "$REPO/backend/instance/admin.json" ]; then
  if [ "$DRY" = 1 ]; then
    echo "   [dry-run] generate an initial admin password"
  else
    say "creating the initial admin password"
    INITIAL_PASSWORD="$(as_user env DATA_DIR="$REPO" "$VENV/bin/python3" "$REPO/backend/adminctl.py" set-password --generate)" \
      || die "could not create the admin password (run deploy/set-password.sh)"
  fi
fi

# ── 5. render the service units from the repository templates ───────────────
render() {            # render <template> -> stdout
  sed -e "s#@DIR@#$REPO#g" -e "s#@USER@#$USER_NAME#g" -e "s#@PORT@#$PORT#g" -e "s#@BIND@#$BIND#g" "$1"
}
TPL="$REPO/deploy/systemd"
if [ "$ROLE" = hub ]; then
  UNITS="swarmsentinel:swarmsentinel.service.in ssai-agents:ssai-agents.service.in"
else
  UNITS="ssai-agents:ssai-agents-node.service.in"
fi
[ "$AUTOUPDATE" = 0 ] || UNITS="$UNITS ssai-update:ssai-update.service.in ssai-update:ssai-update.timer.in"
[ "$ROLE" != hub ] || [ "$RETENTION" = 0 ] || UNITS="$UNITS ssai-retention:ssai-retention.service.in ssai-retention:ssai-retention.timer.in"

RENDERED="$REPO/deploy/rendered"
say "rendering service units"
run mkdir -p "$RENDERED"
[ "$DRY" = 1 ] || rm -f "$RENDERED"/*.service "$RENDERED"/*.timer      # never carry units over from a previous role
for pair in $UNITS; do
  name="${pair%%:*}"; tpl="${pair#*:}"; ext="${tpl%.in}"; ext="${ext##*.}"
  target="$name.$ext"
  [ -f "$TPL/$tpl" ] || die "missing template deploy/systemd/$tpl"
  if [ "$DRY" = 1 ]; then echo "   [dry-run] render $tpl -> $target"; else render "$TPL/$tpl" > "$RENDERED/$target"; fi
done

if [ "$SYSTEMD" = 1 ]; then
  say "installing services"
  changed=0
  for f in "$RENDERED"/*.service "$RENDERED"/*.timer; do
    [ -e "$f" ] || continue
    dst="/etc/systemd/system/$(basename "$f")"
    if [ "$DRY" = 0 ] && ! cmp -s "$f" "$dst" 2>/dev/null; then cp "$f" "$dst"; changed=1; echo "   installed $(basename "$f")"; fi
  done
  [ "$DRY" = 1 ] || { [ "$changed" = 0 ] || "$SYSTEMCTL" daemon-reload; }
fi

# ── 6. scoped sudo rules for the web app (firewall blocking, restart after key changes) ──
if [ "$SYSTEMD" = 1 ] && [ "$SUDOERS" = 1 ] && [ "$USER_NAME" != root ]; then
  say "installing scoped sudo rules for $USER_NAME"
  rules=""
  if [ "$ROLE" = hub ]; then
    UFW="$(command -v ufw || true)"
    # Only what backend/remediation.py runs: status, add a deny rule (at the top or appended) and delete one. Not
    # "ufw <anything>", which let the web account disable the firewall or open any port (code review 2026-09-30, #10).
    [ -z "$UFW" ] || rules="$UFW status, $UFW insert 1 deny from *, $UFW insert 1 deny out to *, $UFW deny from *, $UFW deny out to *, $UFW delete deny from *, $UFW delete deny out to *"
    [ -z "$rules" ] || rules="$rules, "
    rules="${rules}$SYSTEMCTL restart swarmsentinel, $SYSTEMCTL restart ssai-agents"
  else
    rules="$SYSTEMCTL restart ssai-agents"
  fi
  tmp="$(mktemp)"
  printf '# Installed by SwarmSentinel deploy/install.sh: the web app and updater may restart these services and manage ufw rules.\n%s ALL=(root) NOPASSWD: %s\n' "$USER_NAME" "$rules" > "$tmp"
  if [ "$DRY" = 1 ]; then echo "   [dry-run] sudoers: $(tail -n1 "$tmp")"
  elif command -v visudo >/dev/null && ! visudo -cf "$tmp" >/dev/null; then warn "generated sudo rule failed validation; not installed"
  else install -m 0440 "$tmp" "/etc/sudoers.d/ssai-$USER_NAME"; echo "   installed /etc/sudoers.d/ssai-$USER_NAME"; fi
  rm -f "$tmp"
fi

# ── 6b. firewall: keep this machine's own traffic working if ufw is switched on now or later ──
# ufw's default "allow loopback" only covers an interface called lo. Under WSL mirrored networking it is called loopback0, and
# a firewall that blocks it cuts the dashboard off from its own agents (found on the first laptop install, 2026-10-23).
if [ "$ROLE" = hub ] && [ "$DRY" = 0 ] && [ "$(id -u)" = 0 ] && command -v ufw >/dev/null; then
  for iface in lo loopback0; do
    ip link show "$iface" >/dev/null 2>&1 || continue
    ufw allow in on "$iface" >/dev/null 2>&1 && ufw allow out on "$iface" >/dev/null 2>&1 && echo "   firewall: allowed traffic on $iface"
  done
  ufw status 2>/dev/null | grep -qi "status: active"     || echo "   Firewall:    ufw is installed but switched off. Blocking a bad address from the dashboard needs it on (allow SSH first if you use it): sudo ufw enable"
fi

# ── 7. start and verify ─────────────────────────────────────────────────────
if [ "$SYSTEMD" = 1 ] && [ "$START" = 1 ] && [ "$DRY" = 0 ]; then
  say "starting services"
  # enable, then RESTART: "enable --now" leaves an already-running service alone, so re-running the installer (a repair,
  # or a newer package in another directory) kept serving the OLD code, settings and key while the agents used the new
  # key and were refused (found by the second clean install in the sandbox, 2026-10-10).
  if [ "$ROLE" = hub ]; then SVCS="swarmsentinel ssai-agents"; else SVCS="ssai-agents"; fi
  "$SYSTEMCTL" enable $SVCS
  "$SYSTEMCTL" restart $SVCS
  [ "$AUTOUPDATE" = 0 ] || "$SYSTEMCTL" enable --now ssai-update.timer
  [ "$ROLE" != hub ] || [ "$RETENTION" = 0 ] || "$SYSTEMCTL" enable --now ssai-retention.timer
  if [ "$ROLE" = hub ] && command -v curl >/dev/null; then
    ok=0
    for _ in $(seq 1 40); do
      if curl -fsS -m 3 "http://$([ "$BIND" = 0.0.0.0 ] && echo 127.0.0.1 || echo "$BIND"):$PORT/health" >/dev/null 2>&1; then ok=1; break; fi
      sleep 1
    done
    [ "$ok" = 1 ] || { warn "the dashboard did not answer in 40 s: journalctl -u swarmsentinel -n 50"; exit 1; }
    say "dashboard is up"
  fi
  sleep 3
  "$SYSTEMCTL" is-active --quiet ssai-agents || { warn "the agent runner is not running: journalctl -u ssai-agents -n 50"; exit 1; }
fi

echo
say "done"
if [ "$ROLE" = hub ]; then
  ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  [ "$BIND" != 127.0.0.1 ] || ip=127.0.0.1               # listening on this machine only, so that is the address to open
  echo "   Dashboard:   http://${ip:-this-host}:$PORT/dashboard"
  echo "   Setup/keys:  http://${ip:-this-host}:$PORT/setup   (add an AI provider key to enable AI verdicts)"
  if [ -n "$INITIAL_PASSWORD" ]; then
    echo "   Sign in:     http://${ip:-this-host}:$PORT/login"
    echo "   Admin password (shown once, not stored anywhere): $INITIAL_PASSWORD"
    echo "                change it with deploy/set-password.sh, or under Settings once signed in"
  else
    echo "   Sign in:     http://${ip:-this-host}:$PORT/login   (forgotten password: deploy/set-password.sh)"
  fi
  echo "   API key:     stored in $ENV_FILE (SSAI_API_KEY): for machines (nodes, scripts, the browser extension), never shown in the dashboard"
  echo "   Add a machine:  here, run deploy/new-node.sh (or Settings -> Machines) for a one-time code; then on the machine:"
  echo "                   sudo deploy/install.sh --role node --hub-url http://${ip:-HUB}:$PORT --enroll-code CODE"
  command -v ufw >/dev/null && echo "   Firewall:    if ufw is active, allow your LAN to reach the dashboard: sudo ufw allow from <your-lan>/24 to any port $PORT"
else
  echo "   This machine reports to $HUB_URL as '${NODE_ID:-$(hostname)}'. Look for it on the hub's dashboard."
fi
# What this machine can honestly protect, from its memory, disk, tools and AI models (backend/agents/capability.py).
if [ "$DRY" = 0 ] && [ -x "$REPO/swarmsentinel-env/bin/python3" ]; then
  echo; say "what this machine can protect"
  SSAI_ROLE="$ROLE" "$REPO/swarmsentinel-env/bin/python3" "$REPO/backend/agents/capability.py" 2>/dev/null | sed 's/^/   /' || true
fi
[ "$SYSTEMD" = 1 ] || echo "   (services not installed; unit files for review are in deploy/rendered/)"
[ "$DRY" = 0 ] || echo "   (dry run: nothing was changed)"
