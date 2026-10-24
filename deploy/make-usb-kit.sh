#!/usr/bin/env bash
# Build a folder you can copy to a USB stick and install SwarmSentinel from on a Linux machine with NO internet.
#
#   deploy/make-usb-kit.sh /media/usb                                   # code + Python packages (about 100 MB)
#   deploy/make-usb-kit.sh /media/usb --models hermes3,mistral          # also two local AI models (about 9 GB more)
#   deploy/make-usb-kit.sh /media/usb --models hermes3 --ollama ~/ollama
#
# --models   comma list of models already pulled on THIS machine (name or name:tag)
# --ollama   the folder that holds bin/ollama and models/ (default ~/ollama)
#
# The kit works on machines like the one that builds it: same CPU type (x86_64) and the same Python minor version (INSTALL.sh checks
# and says so). Build it on the machine you will install on, or one of the same kind. Nothing here changes this install.
set -euo pipefail
die() { echo "ERROR: $*" >&2; exit 1; }
say() { printf '\n== %s\n' "$*"; }

OUT="${1:-}"; [ -n "$OUT" ] && [ "${OUT#-}" = "$OUT" ] || die "usage: make-usb-kit.sh OUTPUT_FOLDER [--models a,b] [--ollama DIR]"
shift
MODELS="" OLLAMA="$HOME/ollama"
while [ $# -gt 0 ]; do
  case "$1" in
    --models) MODELS="${2:-}"; shift 2 ;;
    --ollama) OLLAMA="${2:-}"; shift 2 ;;
    *) die "unknown option: $1" ;;
  esac
done

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="$(git -C "$REPO" describe --tags --always 2>/dev/null || echo unknown)"
KIT="$OUT/ssai-kit-$VERSION"
[ ! -e "$KIT" ] || die "$KIT already exists; remove it or choose another folder"
mkdir -p "$KIT/wheels" "$KIT/release"

say "1/4 the program (committed code only: no keys, no databases, no settings of yours)"
"$REPO/deploy/make-release.sh" --out "$KIT/release" | tail -2

say "2/4 Python packages, so the install needs no internet"
PIP="$REPO/swarmsentinel-env/bin/pip"; [ -x "$PIP" ] || PIP="python3 -m pip"
$PIP download --quiet --disable-pip-version-check -r "$REPO/requirements.txt" -d "$KIT/wheels"
echo "   $(ls "$KIT/wheels" | wc -l) packages"

if [ -n "$MODELS" ]; then
  say "3/4 local AI models"
  [ -x "$OLLAMA/bin/ollama" ] || die "$OLLAMA/bin/ollama not found (use --ollama DIR)"
  mkdir -p "$KIT/ai/bin" "$KIT/ai/models/blobs"
  cp "$OLLAMA/bin/ollama" "$KIT/ai/bin/ollama"
  for m in ${MODELS//,/ }; do
    name="${m%%:*}"; tag="latest"; [ "$m" = "$name" ] || tag="${m#*:}"
    manifest="manifests/registry.ollama.ai/library/$name/$tag"
    [ -f "$OLLAMA/models/$manifest" ] || die "model $m is not pulled on this machine (ollama pull $m)"
    mkdir -p "$KIT/ai/models/$(dirname "$manifest")"
    cp "$OLLAMA/models/$manifest" "$KIT/ai/models/$manifest"
    # A manifest names the pieces ("blobs") of a model by checksum; copy exactly those, nothing else.
    python3 - "$OLLAMA/models/$manifest" <<'PY' | while read -r digest; do cp "$OLLAMA/models/blobs/${digest/:/-}" "$KIT/ai/models/blobs/"; done
import json, sys
m = json.load(open(sys.argv[1]))
for d in [m["config"]["digest"]] + [l["digest"] for l in m["layers"]]:
    print(d)
PY
    echo "   $m copied"
  done
else
  say "3/4 local AI models: none asked for (the target needs its own, or a cloud key)"
fi

say "4/4 installer and checksums"
cp "$REPO/deploy/kit/INSTALL.sh" "$REPO/deploy/kit/README.txt" "$KIT/"
chmod +x "$KIT/INSTALL.sh"
python3 -c "import sys; print('%d.%d' % sys.version_info[:2])" > "$KIT/PYTHON_VERSION"
(cd "$KIT" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS)
echo
echo "Kit ready: $KIT  ($(du -sh "$KIT" | cut -f1))"
echo "Copy that whole folder to the USB stick. On the target:  cd <kit folder> && sudo ./INSTALL.sh --demo"
