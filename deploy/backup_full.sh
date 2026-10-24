#!/usr/bin/env bash
# Full off-box backup of this SwarmSentinel install: code, settings, keys, databases, installer, service files.
# It is NOT a replacement for GitHub (which holds only the code): this is the copy that also holds everything GitHub must never see.
#
#   deploy/backup_full.sh user@backup-host:/path/to/folder            # code + settings + databases (small)
#   deploy/backup_full.sh user@backup-host:/path/to/folder --with-models   # also the local AI model files (several GB)
#
# Safe by design: it only READS this install and only ADDS one new file at the destination. It never deletes or overwrites anything.
# The archive contains secrets (.env, admin settings, API keys). It is written readable by its owner only; keep the drive somewhere
# you trust, or encrypt it (for example: gpg --symmetric FILE) before it leaves your hands.
#
# A backup nobody has restored is a hope: prove this one with  deploy/test-restore.sh ARCHIVE.tar.gz  (rebuilds a hub from it in a
# throwaway container and checks it serves your data).
#
# Other folders in your home directory can be added by name: SSAI_BACKUP_EXTRA="promtail notes" deploy/backup_full.sh ...
set -euo pipefail

DEST="${1:?usage: backup_full.sh user@host:/folder [--with-models]}"
WITH_MODELS="${2:-}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
HOST="${DEST%%:*}"
FOLDER="${DEST#*:}"
STAMP="$(date +%Y%m%d-%H%M%S)"
NAME="ssai-full-${STAMP}"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

# 1. A database copied while the app is writing can be torn, so ask SQLite for a consistent snapshot of each one.
mkdir -p "$STAGE/$NAME/db-snapshots"
for db in "$ROOT"/backend/instance/*.db; do
  [ -f "$db" ] && sqlite3 "$db" ".backup '$STAGE/$NAME/db-snapshots/$(basename "$db")'"
done

# 2. Things that live outside the repository but are part of how this box runs (service files, schedule, a note on the network).
mkdir -p "$STAGE/$NAME/system"
cp /etc/systemd/system/ssai-*.service /etc/systemd/system/swarmsentinel.service "$STAGE/$NAME/system/" 2>/dev/null || true
crontab -l > "$STAGE/$NAME/system/crontab.txt" 2>/dev/null || true
{ echo "taken: $(date -u +%FT%TZ) on $(hostname)"; echo "commit: $(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"; \
  echo "network settings (netplan) need root and are NOT in this archive; copy /etc/netplan by hand if you want them."; } > "$STAGE/$NAME/system/README.txt"

# 3. Pack it all and stream it to the other machine; a checksum is computed on the way so we can prove the copy is intact.
# EXTRA collects the folders to add to the archive besides the install itself: any named in SSAI_BACKUP_EXTRA, and the models if asked.
EXTRA=()
for d in ${SSAI_BACKUP_EXTRA:-}; do [ -d "$HOME/$d" ] && EXTRA+=("$HOME/$d"); done
[ "$WITH_MODELS" = "--with-models" ] && [ -d "$HOME/ollama" ] && EXTRA+=("$HOME/ollama")

ssh "$HOST" "umask 077; mkdir -p '$FOLDER'"
# One stream does three jobs: tar packs (skipping unreadable root-owned files instead of failing), tee feeds a copy to sha256sum so we
# know what was sent, and ssh writes the archive on the far side. "${EXTRA[@]/#\//}" strips the leading slash tar would otherwise warn about.
tar --warning=no-file-changed --ignore-failed-read -czf - -C "$STAGE" "$NAME" -C / "${ROOT#/}" "${EXTRA[@]/#\//}" \
  | tee >(sha256sum | cut -d' ' -f1 > "$STAGE/sum") \
  | ssh "$HOST" "umask 077; cat > '$FOLDER/$NAME.tar.gz'" 2> >(tee "$STAGE/warnings" >&2)
SUM="$(cat "$STAGE/sum")"
SKIPPED="$(grep -c 'Permission denied' "$STAGE/warnings" 2>/dev/null || true)"
[ "${SKIPPED:-0}" -gt 0 ] && echo "NOTE: $SKIPPED file(s) were owned by root and could not be read; they are listed above and are not in the archive (logs and a regenerable baseline)."

# 4. Check the far side: same checksum, and the archive opens end to end.
REMOTE_SUM="$(ssh "$HOST" "sha256sum '$FOLDER/$NAME.tar.gz'" | cut -d' ' -f1)"
if [ "$SUM" != "$REMOTE_SUM" ]; then echo "FAILED: the copy at $DEST does not match what was sent" >&2; exit 1; fi
ssh "$HOST" "echo '$SUM  $NAME.tar.gz' > '$FOLDER/$NAME.sha256'; gzip -t '$FOLDER/$NAME.tar.gz'"
echo "OK: $DEST/$NAME.tar.gz  ($(ssh "$HOST" "du -h '$FOLDER/$NAME.tar.gz'" | cut -f1), sha256 ${SUM:0:12}...)"
