#!/usr/bin/env bash
# Put the AI models on THIS machine, so SwarmSentinel works with nothing else on the network and no internet.
#
#   sudo deploy/local-ai.sh --from /path/to/kit/ai          # copy the Ollama program and models from a USB kit, start them
#   sudo deploy/local-ai.sh --from /path/to/kit/ai --user NAME
#
# The kit folder holds bin/ollama and models/ (deploy/make-usb-kit.sh builds it). Everything is copied into <install>/ai/ and
# runs as the ssai-ollama service, listening on 127.0.0.1 only. Safe to run again: it never deletes a model that is already there.
set -euo pipefail
say() { printf '\n== %s\n' "$*"; }
die() { echo "ERROR: $*" >&2; exit 1; }

FROM="" USER_NAME="${SUDO_USER:-}"
while [ $# -gt 0 ]; do
  case "$1" in
    --from) FROM="${2:-}"; shift 2 ;;
    --user) USER_NAME="${2:-}"; shift 2 ;;
    -h|--help) sed -n '2,9p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done
[ "$(id -u)" = 0 ] || die "run with sudo"
[ -n "$USER_NAME" ] || die "cannot tell which account to run the models as; pass --user NAME"
[ -x "$FROM/bin/ollama" ] || die "$FROM/bin/ollama not found: --from must be the kit's ai folder"
[ -d "$FROM/models" ] || die "$FROM/models not found"

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AI="$REPO/ai"
say "copying the AI program and models into $AI (a few GB; this takes a while)"
mkdir -p "$AI/bin" "$AI/models"
install -m 0755 "$FROM/bin/ollama" "$AI/bin/ollama"
cp -a -n "$FROM/models/." "$AI/models/"          # -n: never overwrite a model that is already here
chown -R "$USER_NAME" "$AI"

say "installing the service"
sed -e "s#@DIR@#$REPO#g" -e "s#@USER@#$USER_NAME#g" "$REPO/deploy/systemd/ssai-ollama.service.in" > /etc/systemd/system/ssai-ollama.service
systemctl daemon-reload
systemctl enable ssai-ollama
systemctl restart ssai-ollama

say "waiting for the models to answer"
for _ in $(seq 1 30); do
  if tags="$(curl -fsS -m 3 http://127.0.0.1:11434/api/tags 2>/dev/null)"; then
    echo "$tags" | grep -o '"name":"[^"]*"' | sed 's/"name":/   model: /'
    # A fresh install keeps local models off the panel until measured; on a stand-alone machine they ARE the panel, so switch on the ones just installed.
    sudo -u "$USER_NAME" env DATA_DIR="$REPO" "$REPO/swarmsentinel-env/bin/python3" "$REPO/backend/tools/enable_local_models.py" || echo "   (could not switch the models on; do it under Settings -> AI panel)"
    # the agent runner reads its list of models when it starts, so restart it to pick the new ones up
    systemctl is-enabled --quiet ssai-agents 2>/dev/null && systemctl restart ssai-agents && echo "   restarted ssai-agents"
    exit 0
  fi
  sleep 1
done
die "the models did not answer in 30 s: journalctl -u ssai-ollama -n 50"
