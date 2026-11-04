#!/usr/bin/env bash
# SwarmSentinel one-line installer for Linux. Downloads the newest published release, checks it, unpacks it, and runs
# deploy/install.sh on it. Nothing needs to be cloned or edited first.
#
#   curl -fsSL https://github.com/gatsbysdream25-max/SSAI-Deployment/releases/latest/download/get-ssai.sh | sudo bash
#       a hub: dashboard + API + agents on this machine (the new admin password is shown once at the end)
#   curl -fsSL .../get-ssai.sh | sudo bash -s -- --role node --hub-url http://HUB:5000 --enroll-code XXXX-XXXX-XXXX-XXXX
#       an extra machine that reports to a hub (the code comes from Settings -> Machines on the hub)
#
# Options for this script (everything else is handed to deploy/install.sh unchanged; see its --help):
#   --dir DIR        where to unpack (default: SwarmSentinel in the home folder of the user who ran sudo)
#   --version TAG    install this release instead of the newest one (for example v0.1.5)
#   -h, --help       this text
#
# What it checks: the package is downloaded over https, its SHA-256 must match the checksum published beside it, it must look
# like SwarmSentinel and carry the version it claims, and its file paths must stay inside its own folder. The checksum proves
# the download is whole and is the file that was published; it does not prove WHO published it (signed releases are a later step).
# Run again any time: if this version is already unpacked in DIR it just re-runs the installer there, which repairs or finishes it.
set -euo pipefail

SLUG="${SSAI_UPDATE_REPO:-gatsbysdream25-max/SSAI-Deployment}"
VALID_TAG='^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'

say() { printf '\033[1m==>\033[0m %s\n' "$*"; }
die() { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# Everything below is in functions and the last line calls main: when this script is piped from curl, bash must have read the
# whole of it before anything runs, so a download cut short can never run half an installer.

show_help() { sed -n '2,19p' "$0" 2>/dev/null | sed 's/^# \{0,1\}//' || true; }

parse_arguments() {
  DIR="" WANT_TAG="" PASS_ON=()
  while [ $# -gt 0 ]; do
    case "$1" in
      --dir) DIR="${2:-}"; [ -n "$DIR" ] || die "--dir needs a folder"; shift 2 ;;
      --version) WANT_TAG="${2:-}"; shift 2 ;;
      -h|--help) show_help; exit 0 ;;
      *) PASS_ON+=("$1"); shift ;;
    esac
  done
}

# Installing services needs root. A trial run (--dry-run) or an install without services (--no-systemd) does not.
check_privileges() {
  local uid="${SSAI_GET_UID:-$(id -u)}" arg
  [ "$uid" = 0 ] && return 0
  for arg in ${PASS_ON[@]+"${PASS_ON[@]}"}; do
    case "$arg" in --no-systemd|--dry-run) return 0 ;; esac
  done
  die "this installs services, so it needs root. Run it as:  curl -fsSL <this script's address> | sudo bash -s -- <options>"
}

check_tools() {
  local tool
  for tool in curl tar sha256sum awk sed grep; do
    command -v "$tool" >/dev/null || die "$tool is not installed (Debian/Ubuntu: sudo apt-get install -y curl)"
  done
}

# default_folder: SwarmSentinel in the home folder of the person who ran sudo (so they can read and update it).
default_folder() {
  local owner="${SUDO_USER:-$(id -un)}" home
  home="$(getent passwd "$owner" | cut -d: -f6)"
  [ -n "$home" ] || home="$HOME"
  printf '%s/SwarmSentinel' "$home"
}

# fetch URL FILE: download over https. Tests point the check at local files and say so with SSAI_UPDATE_API.
fetch() {
  local protocols='=https'
  [ -z "${SSAI_UPDATE_API:-}" ] || protocols='=https,file'
  curl -fsSL --proto "$protocols" -m 900 -o "$2" "$1"
}

# find_tag: which release to install. Sets TAG and BASE (the address its files are under).
find_tag() {
  local api
  if [ -n "$WANT_TAG" ]; then
    TAG="$WANT_TAG"
  else
    api="${SSAI_UPDATE_API:-https://api.github.com/repos/$SLUG/releases/latest}"
    fetch "$api" "$WORK/release.json" || die "could not read the newest release from $api (no internet, or none is published yet)"
    TAG="$(sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$WORK/release.json" | head -1)"
  fi
  printf '%s' "$TAG" | grep -Eq "$VALID_TAG" || die "the release has no usable version tag ('$TAG')"
  BASE="${SSAI_GET_BASE:-https://github.com/$SLUG/releases/download/$TAG}"
}

download_and_check() {
  local name="swarmsentinel-$TAG.tar.gz" expected actual
  say "downloading SwarmSentinel $TAG"
  fetch "$BASE/$name" "$WORK/package.tar.gz" || die "download of $name failed"
  fetch "$BASE/$name.sha256" "$WORK/package.sha256" || die "download of the checksum file failed"
  expected="$(awk '{print $1; exit}' "$WORK/package.sha256")"
  actual="$(sha256sum "$WORK/package.tar.gz" | awk '{print $1}')"
  [ -n "$expected" ] && [ "$expected" = "$actual" ] || die "the download does not match its published checksum; nothing was installed"
  say "checksum matches"
}

unpack_and_inspect() {
  if tar tzf "$WORK/package.tar.gz" | grep -qE '(^/|(^|/)\.\.(/|$))'; then
    die "the package contains paths that point outside its own folder; refusing it"
  fi
  mkdir -p "$WORK/new"
  tar xzf "$WORK/package.tar.gz" -C "$WORK/new"
  NEW="$WORK/new/SwarmSentinel"
  [ -f "$NEW/backend/app.py" ] && [ -f "$NEW/deploy/install.sh" ] && [ -f "$NEW/VERSION" ] \
    || die "the package does not look like SwarmSentinel; nothing was installed"
  [ "$(awk '{print $1; exit}' "$NEW/VERSION")" = "$TAG" ] \
    || die "the package says it is version $(awk '{print $1; exit}' "$NEW/VERSION"), not $TAG; refusing it"
}

# place_files: put the package at DIR, or reuse DIR when this exact version is already there (a repair or a second try).
place_files() {
  if [ -f "$DIR/backend/app.py" ]; then
    if [ "$(awk '{print $1; exit}' "$DIR/VERSION" 2>/dev/null)" = "$TAG" ]; then
      say "$TAG is already unpacked in $DIR; running the installer there again"
      return 0
    fi
    die "$DIR already holds SwarmSentinel ($(awk '{print $1; exit}' "$DIR/VERSION" 2>/dev/null || echo unknown)). To update it run: bash $DIR/deploy/update.sh"
  fi
  [ ! -e "$DIR" ] || [ -z "$(ls -A "$DIR" 2>/dev/null)" ] || die "$DIR exists and is not empty; choose another folder with --dir"
  mkdir -p "$(dirname "$DIR")"
  rmdir "$DIR" 2>/dev/null || true
  mv "$NEW" "$DIR"
  ( cd "$DIR" && find . -type f | sed 's,^\./,,' | sort ) > "$DIR/.release-files"      # lets the updater remove files a later release drops
  local owner="${SUDO_USER:-}"
  if [ "${SSAI_GET_UID:-$(id -u)}" = 0 ] && [ -n "$owner" ] && [ "$owner" != root ]; then chown -R "$owner:" "$DIR"; fi
  say "unpacked to $DIR"
}

main() {
  parse_arguments "$@"
  check_privileges
  check_tools
  WORK="$(mktemp -d)"
  trap 'rm -rf "$WORK"' EXIT
  [ -n "$DIR" ] || DIR="$(default_folder)"
  find_tag
  download_and_check
  unpack_and_inspect
  place_files
  say "running the installer"
  bash "$DIR/deploy/install.sh" ${PASS_ON[@]+"${PASS_ON[@]}"}
}

main "$@"
