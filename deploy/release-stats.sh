#!/usr/bin/env bash
# How many times has each release been downloaded? Reads GitHub's public release data; sends nothing about anyone.
#
#   deploy/release-stats.sh OWNER/REPO            e.g. deploy/release-stats.sh yourname/SwarmSentinel
#
# GitHub counts every download of every file attached to a release (the package, the Windows installer, the checksums) and
# shows the count on the release page too. Nothing runs on a customer's machine, so no customer is tracked: the count is kept
# by GitHub at the place the file is downloaded from. The repository must be public for people to download from it.
set -euo pipefail
REPO="${1:-}"
[ -n "$REPO" ] || { sed -n '2,8p' "${BASH_SOURCE[0]:-$0}" | sed 's/^# \{0,1\}//'; exit 2; }
case "$REPO" in */*) ;; *) echo "give it as OWNER/REPO" >&2; exit 2 ;; esac

DATA="$(mktemp)"; trap 'rm -f "$DATA"' EXIT
curl -fsS -m 20 -H "Accept: application/vnd.github+json" -o "$DATA" \
  "https://api.github.com/repos/$REPO/releases?per_page=100" \
  || { echo "could not read the releases of $REPO (is the repository public and the name right?)" >&2; exit 1; }

python3 - "$DATA" <<'PY'
import json
import sys

releases = json.load(open(sys.argv[1]))
if not releases:
    print("no releases yet")
total = 0
for release in releases:
    files = release.get("assets", [])
    subtotal = sum(f["download_count"] for f in files)
    total += subtotal
    print(f"{release['tag_name']:<14} {release['published_at'][:10]}  {subtotal:>6} downloads")
    for f in files:
        print(f"    {f['name']:<48} {f['download_count']:>6}")
print(f"{'total':<14} {'':<10}  {total:>6} downloads")
PY
