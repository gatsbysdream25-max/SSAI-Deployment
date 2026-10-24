#!/usr/bin/env bash
# Install SwarmSentinel from this USB kit. No internet needed.
#
#   sudo ./INSTALL.sh                    # install into /opt/swarmsentinel, as the account that ran sudo
#   sudo ./INSTALL.sh --demo             # ...and add a few labelled example findings to watch the AI panel judge
#   sudo ./INSTALL.sh --dir /srv/ssai --port 5000
#
# It prints the dashboard address and a one-time admin password at the end. Re-running repairs the install and keeps your data.
set -euo pipefail
die() { echo "ERROR: $*" >&2; exit 1; }
say() { printf '\n== %s\n' "$*"; }

KIT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIR=/opt/swarmsentinel PORT=5000 DEMO=0
while [ $# -gt 0 ]; do
  case "$1" in
    --dir) DIR="${2:-}"; shift 2 ;;
    --port) PORT="${2:-}"; shift 2 ;;
    --demo) DEMO=1; shift ;;
    -h|--help) sed -n '2,9p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done
[ "$(id -u)" = 0 ] || die "run with sudo:  sudo ./INSTALL.sh"
USER_NAME="${SUDO_USER:-}"; [ -n "$USER_NAME" ] && [ "$USER_NAME" != root ] || die "run it with sudo from your normal account (not a root login)"

say "checking the kit is intact"
(cd "$KIT" && sha256sum --quiet -c SHA256SUMS) || die "a file on the stick is damaged or missing; copy the kit again"

HAVE="$(python3 -c "import sys; print('%d.%d' % sys.version_info[:2])" 2>/dev/null || echo none)"
WANT="$(cat "$KIT/PYTHON_VERSION")"
[ "$HAVE" = "$WANT" ] || die "this kit's packages are for Python $WANT; this machine has $HAVE. Build the kit on a machine like this one (deploy/make-usb-kit.sh)."
[ "$(uname -m)" = x86_64 ] || die "this kit is for x86_64 machines; this one is $(uname -m)"

say "unpacking into $DIR"
[ ! -e "$DIR" ] || [ -f "$DIR/deploy/install.sh" ] || die "$DIR exists and is not a SwarmSentinel install"
mkdir -p "$DIR"
tar xzf "$KIT"/release/swarmsentinel-*.tar.gz -C "$DIR" --strip-components=1     # a re-run overwrites the program files, never .env or data
chown -R "$USER_NAME" "$DIR"

say "installing (hub, standalone, offline)"
if ! "$DIR/deploy/install.sh" --user "$USER_NAME" --port "$PORT" --standalone --wheelhouse "$KIT/wheels" | tee "$KIT/.install.log"; then
  rm -f "$KIT/.install.log"; die "the install did not finish; the messages above say why"
fi
# the installer prints the one-time password; make sure it does not stay on the stick
PW_LINE="$(grep "Admin password" "$KIT/.install.log" 2>/dev/null || true)"; rm -f "$KIT/.install.log"

if [ -d "$KIT/ai" ]; then
  say "starting the local AI models"
  "$DIR/deploy/local-ai.sh" --from "$KIT/ai" --user "$USER_NAME"
else
  echo; echo "NOTE: this kit has no AI models. Findings are judged by the built-in stand-in panel until you add models or a cloud key (Settings)."
fi

if [ "$DEMO" = 1 ]; then
  say "adding example findings"
  sleep 2
  python3 "$DIR/deploy/demo_seed.py" --url "http://127.0.0.1:$PORT" || echo "   (could not add the examples; run deploy/demo_seed.py later)"
fi

echo; echo "Installed in $DIR."; [ -z "$PW_LINE" ] || echo "$PW_LINE"
