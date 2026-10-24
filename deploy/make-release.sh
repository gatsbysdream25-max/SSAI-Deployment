#!/usr/bin/env bash
# Build the downloadable SwarmSentinel package from a commit: one .tar.gz a customer unpacks and installs, with no
# access to this repository and no git history (only the files of that commit, minus what .gitattributes marks
# export-ignore: ledger data, internal plans, the lab's network map, legacy code).
#
#   deploy/make-release.sh                 package HEAD into dist/
#   deploy/make-release.sh --ref v0.4.0    package a tag or commit
#   deploy/make-release.sh --out /tmp/x    somewhere else
#   deploy/make-release.sh --version v0.4.0   name the version (use the same text as the GitHub release tag: installs compare it)
#
# Prints the package path and its SHA-256 (also written next to it). Install on a fresh machine:
#   tar xzf swarmsentinel-<version>.tar.gz && cd SwarmSentinel && sudo deploy/install.sh
set -euo pipefail
REF=HEAD OUT="" NAME=""
while [ $# -gt 0 ]; do
  case "$1" in
    --ref) REF="${2:-}"; shift 2 ;;
    --out) OUT="${2:-}"; shift 2 ;;
    --version) NAME="${2:-}"; shift 2 ;;
    -h|--help) sed -n '2,13p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"
git rev-parse --verify --quiet "$REF^{commit}" >/dev/null || { echo "no such commit: $REF" >&2; exit 1; }
SHA="$(git rev-parse --short=12 "$REF")"
VERSION="${NAME:-$(git describe --tags --always "$REF" 2>/dev/null || echo "$SHA")}"
case "$VERSION" in *[!A-Za-z0-9._-]*) echo "the version may only use letters, digits, dot, dash and underscore" >&2; exit 2 ;; esac
OUT="${OUT:-$REPO/dist}"
mkdir -p "$OUT"
PKG="$OUT/swarmsentinel-$VERSION.tar.gz"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
printf '%s\n' "$VERSION ($SHA)" > "$tmp/VERSION"          # read by lineage.code_version() when there is no .git
git -c core.autocrlf=false -c core.eol=lf archive --format=tar --prefix=SwarmSentinel/ "$REF" > "$tmp/pkg.tar"
tar --transform 's,^,SwarmSentinel/,' -C "$tmp" -rf "$tmp/pkg.tar" VERSION
gzip -9n < "$tmp/pkg.tar" > "$PKG"

# Never ship a secret or the lab's own data by accident: refuse if the package carries any of these.
bad="$(tar tzf "$PKG" | grep -E '(^|/)\.env$|\.db$|/instance/|known_threats\.json|Topography|\.pem$|id_rsa' || true)"
if [ -n "$bad" ]; then
  rm -f "$PKG"
  echo "refusing: the package would contain:" >&2
  echo "$bad" >&2
  exit 1
fi
( cd "$OUT" && sha256sum "$(basename "$PKG")" > "$(basename "$PKG").sha256" )
echo "$PKG"
cat "$PKG.sha256"
