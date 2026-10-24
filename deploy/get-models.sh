#!/usr/bin/env bash
# Put local AI models on THIS machine over the internet, sized to its memory, and put them on the panel.
#
#   sudo deploy/get-models.sh                      pick models by this machine's memory, install Ollama, pull them, switch them on
#   sudo deploy/get-models.sh --dry-run            say what it would do and change nothing
#   sudo deploy/get-models.sh --models "hermes3 mistral"     choose the models yourself
#   sudo deploy/get-models.sh --user NAME          the account SwarmSentinel runs as (default: the user who ran sudo)
#
# Use this on a normal connected machine. (deploy/local-ai.sh is the offline twin: it copies models from a USB kit.)
# Needs internet for the Ollama program and for each model (several GB). Safe to run again: models already there are kept.
# Models listen on 127.0.0.1 only, so they are never reachable from the network.
set -euo pipefail
say() { printf '\n== %s\n' "$*"; }
die() { echo "ERROR: $*" >&2; exit 1; }

DRY=0 MODELS="" USER_NAME="${SUDO_USER:-}"
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY=1; shift ;;
    --models) MODELS="${2:-}"; shift 2 ;;
    --user) USER_NAME="${2:-}"; shift 2 ;;
    -h|--help) sed -n '2,11p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done
[ "$(id -u)" = 0 ] || die "run with sudo"
[ -n "$USER_NAME" ] || die "cannot tell which account SwarmSentinel runs as; pass --user NAME"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ── how much memory? (the smaller of the machine's memory and any container limit, like the capability check) ──
ram_gb() {
  local kb limit
  kb=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
  limit=$(cat /sys/fs/cgroup/memory.max 2>/dev/null || echo max)
  if [ "$limit" != max ] && [ "$limit" -lt $((kb * 1024)) ] 2>/dev/null; then kb=$((limit / 1024)); fi
  echo $((kb / 1024 / 1024))
}
RAM=$(ram_gb)
FREE_GB=$(df -BG --output=avail "$REPO" | tail -1 | tr -dc '0-9')

# ── which models? Three local voices let the panel reach its normal minimum of 3 voters without any cloud help. ──
if [ -z "$MODELS" ]; then
  if   [ "$RAM" -ge 15 ]; then MODELS="hermes3 mistral gemma4:12b"     # about 17 GB of disk, one in memory at a time
  elif [ "$RAM" -ge 8 ];  then MODELS="hermes3 mistral"                # about 9 GB of disk, taking turns
  else die "only $RAM GB of memory: too little for a useful local model. Use free cloud keys instead (Settings, AI models and API keys)"
  fi
fi
NEED_GB=$(( $(echo "$MODELS" | wc -w) * 8 + 4 ))
say "this machine: ${RAM} GB memory, ${FREE_GB} GB free disk. Models: $MODELS (needs about ${NEED_GB} GB)"
[ "$FREE_GB" -ge "$NEED_GB" ] || die "not enough free disk: have ${FREE_GB} GB, need about ${NEED_GB} GB"
if [ "$DRY" = 1 ]; then echo "[dry-run] would install Ollama if missing, pull: $MODELS, then switch them on for the panel"; exit 0; fi

# ── the Ollama program: its own official installer, downloaded to a file first so it can be read ──
if ! command -v ollama >/dev/null; then
  say "installing Ollama (official installer from ollama.com)"
  TMP="$(mktemp)"; trap 'rm -f "$TMP"' EXIT
  curl -fsSL https://ollama.com/install.sh -o "$TMP" || die "could not download the Ollama installer (is the internet up?)"
  sh "$TMP"
fi
if command -v systemctl >/dev/null && [ -d /run/systemd/system ]; then
  systemctl enable --now ollama >/dev/null 2>&1 || true
else
  die "this machine has no systemd, so Ollama cannot be kept running here. On WSL2, enable systemd first (deploy/install-windows.ps1 does)"
fi
for _ in $(seq 1 30); do curl -fsS -m 2 http://127.0.0.1:11434/api/tags >/dev/null 2>&1 && break; sleep 1; done
curl -fsS -m 2 http://127.0.0.1:11434/api/tags >/dev/null 2>&1 || die "Ollama did not start: check 'journalctl -u ollama'"

# ── the models ──
for m in $MODELS; do
  say "pulling $m (this can take several minutes)"
  ollama pull "$m" || die "could not pull $m"
done

# ── put them on the panel (only installed models that config/ai_models.json describes; never touches cloud settings) ──
say "switching the installed models on for the panel"
sudo -u "$USER_NAME" "$REPO/swarmsentinel-env/bin/python3" "$REPO/backend/tools/enable_local_models.py"
if systemctl is-active --quiet ssai-agents 2>/dev/null; then systemctl restart ssai-agents; fi
say "done. Settings, then the Protection level card, shows the level this machine reached."
