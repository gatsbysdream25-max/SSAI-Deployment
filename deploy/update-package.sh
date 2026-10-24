#!/usr/bin/env bash
# Update a SwarmSentinel install that was unpacked from a release package (so it has no git history).
#
#   deploy/update-package.sh            download the newest release, check it, test it, restart, verify; roll back if anything fails
#   deploy/update-package.sh --check    only report whether a newer release exists (exit 10 if one does)
#   deploy/update-package.sh --target DIR   update the install in DIR (run this from a freshly unpacked newer package)
#
# deploy/update.sh calls this by itself when the install is not a git checkout, so people only ever need to run update.sh.
#
# Safety, in order:
#   - the download must come over https and its SHA-256 must match the checksum file published with it;
#   - the package must look like SwarmSentinel and must carry the version it claims (an old package cannot be replayed);
#   - the current version is saved first (.update-backup.tar.gz) and restored if the tests or the restart fail;
#   - settings, the database, keys and logs (backend/instance, .env, logs, the virtualenv) are never touched.
# Nothing is restarted unless the new version passes its own tests first.
set -euo pipefail

# Everything below lives in functions and the last line calls main: bash reads a function whole before running it, so replacing
# this very file in the middle of the update cannot corrupt the run.

# Paths in the install folder that belong to the machine, not to the release. They are never replaced, removed or backed up.
KEEP_TOP=(swarmsentinel-env logs .env .update.lock .update-backup.tar.gz)

in_keep_list() {          # in_keep_list NAME: is this top-level name one of the machine's own?
  local name
  for name in "${KEEP_TOP[@]}"; do [ "$name" = "$1" ] && return 0; done
  return 1
}

parse_arguments() {
  CHECK=0 RESTART=1 TESTS=1 TARGET=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --check) CHECK=1; shift ;;
      --no-restart) RESTART=0; shift ;;
      --skip-tests) TESTS=0; shift ;;
      --target) TARGET="${2:-}"; shift 2 ;;            # update the install in this folder (used to bring an older install up to date)
      --branch|--remote) shift 2 ;;                  # update.sh passes these on; a package install has no branch or remote
      -h|--help) sed -n '2,7p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
      *) echo "Unknown option: $1" >&2; exit 2 ;;
    esac
  done
}

# find_release: ask the release check what is newest; sets LATEST, PACKAGE_URL, CHECKSUM_URL. Returns 10 if nothing newer exists.
find_release() {
  local info line_name line_value
  info="$("$PY" "$SCRIPT_DIR/backend/agents/release_check.py" "$REPO")" || die "$(printf '%s' "$info" | sed -n 's/^error //p')"
  INSTALLED="" LATEST="" PACKAGE_URL="" CHECKSUM_URL="" AVAILABLE=no
  while read -r line_name line_value; do
    case "$line_name" in
      installed) INSTALLED="$line_value" ;;
      latest) LATEST="$line_value" ;;
      available) AVAILABLE="$line_value" ;;
      package_url) PACKAGE_URL="$line_value" ;;
      checksum_url) CHECKSUM_URL="$line_value" ;;
    esac
  done <<< "$info"
  if [ "$AVAILABLE" != yes ]; then log "already up to date ($INSTALLED)"; return 1; fi
  log "update available: $INSTALLED -> $LATEST"
  return 0
}

# download_and_check: fetch the package and its checksum into $WORK and prove the package is the one that was published.
download_and_check() {
  local protocols='=https' expected actual
  [ -z "${SSAI_UPDATE_API:-}" ] || protocols='=https,file'      # tests serve a local file instead of GitHub
  log "downloading $LATEST"
  curl -fsSL --proto "$protocols" -m 900 -o "$WORK/package.tar.gz" "$PACKAGE_URL" || die "download of the package failed"
  curl -fsSL --proto "$protocols" -m 60 -o "$WORK/package.sha256" "$CHECKSUM_URL" || die "download of the checksum failed"
  expected="$(awk '{print $1; exit}' "$WORK/package.sha256")"
  actual="$(sha256sum "$WORK/package.tar.gz" | awk '{print $1}')"
  [ -n "$expected" ] && [ "$expected" = "$actual" ] || die "the downloaded package does not match its published checksum; nothing was changed"
  log "checksum matches"
}

# unpack_and_inspect: unpack into $WORK/new and make sure it is a SwarmSentinel package of the version it claims to be.
unpack_and_inspect() {
  if tar tzf "$WORK/package.tar.gz" | grep -qE '(^/|(^|/)\.\.(/|$))'; then
    die "the package contains paths that point outside its own folder; refusing it"
  fi
  mkdir -p "$WORK/new"
  tar xzf "$WORK/package.tar.gz" -C "$WORK/new"
  NEW="$WORK/new/SwarmSentinel"
  [ -f "$NEW/backend/app.py" ] && [ -f "$NEW/deploy/update-package.sh" ] && [ -f "$NEW/VERSION" ] \
    || die "the package does not look like SwarmSentinel; nothing was changed"
  [ "$(awk '{print $1; exit}' "$NEW/VERSION")" = "$LATEST" ] \
    || die "the package says it is version $(awk '{print $1; exit}' "$NEW/VERSION"), not $LATEST; refusing it"
}

# list_files DIR: every file under DIR as a sorted list of relative paths.
list_files() { ( cd "$1" && find . -type f | sed 's,^\./,,' | sort ); }

save_current_version() {
  local excludes=() name
  for name in "${KEEP_TOP[@]}"; do excludes+=(--exclude="./$name"); done
  # Written beside the install first and moved in after: an archive created inside the folder it is archiving trips tar.
  # deploy/rendered holds unit files install.sh generated for review (possibly owned by root); it is not part of a release.
  tar czf "$WORK/backup.tar.gz" "${excludes[@]}" --exclude='./backend/instance' --exclude='./deploy/rendered' --exclude='__pycache__' -C "$REPO" .
  mv -f "$WORK/backup.tar.gz" "$REPO/.update-backup.tar.gz"
  log "saved the current version (.update-backup.tar.gz)"
}

# put_new_version_in_place: remove files the old release had and the new one dropped, then lay the new files over the folder.
put_new_version_in_place() {
  local stale
  if [ -f "$REPO/.release-files" ]; then
    stale="$(comm -23 "$REPO/.release-files" <(list_files "$NEW"))"
    # shellcheck disable=SC2162
    [ -z "$stale" ] || while read path; do
      case "$path" in backend/instance/*|.env|logs/*|swarmsentinel-env/*) continue ;; esac
      rm -f "$REPO/$path"
    done <<< "$stale"
  fi
  cp -a "$NEW"/. "$REPO"/
  # Run as root (for instance through `wsl -u root`), the copied files would belong to root and the install's own account
  # could not update them next time. Give everything back to whoever owns the install folder.
  if [ "$(id -u)" = 0 ]; then chown -R "$(stat -c '%U:%G' "$REPO")" "$REPO"; fi
  list_files "$NEW" > "$REPO/.release-files"
}

# restore_previous_version: put the saved copy back and remove any file only the new version brought.
restore_previous_version() {
  log "rolling back to $INSTALLED"
  local brought
  brought="$(comm -13 <(tar tzf "$REPO/.update-backup.tar.gz" | grep -v '/$' | sed 's,^\./,,' | sort) <(list_files "$NEW") || true)"
  # shellcheck disable=SC2162
  [ -z "$brought" ] || while read path; do rm -f "$REPO/$path"; done <<< "$brought"
  # Keep going if a few files cannot be written (a file owned by someone else): say so, then check the result below.
  tar xzf "$REPO/.update-backup.tar.gz" -C "$REPO" --overwrite || log "WARNING: some files could not be put back; check $REPO"
  if [ "$(awk '{print $1; exit}' "$REPO/VERSION")" != "$INSTALLED" ]; then
    log "WARNING: the install still says $(awk '{print $1; exit}' "$REPO/VERSION") instead of $INSTALLED; restore it by hand from $REPO/.update-backup.tar.gz"
  fi
  if [ "$DEPS_CHANGED" = 1 ]; then
    "$REPO/swarmsentinel-env/bin/pip" install --disable-pip-version-check --quiet -r "$REPO/requirements.txt" || true
  fi
}

main() {
  parse_arguments "$@"
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  REPO="${TARGET:-$SCRIPT_DIR}"            # the install being updated; normally the folder this script lives in
  [ -f "$REPO/backend/app.py" ] || die "$REPO is not a SwarmSentinel install"
  . "$SCRIPT_DIR/deploy/update-lib.sh"
  cd "$REPO"
  PY="$REPO/swarmsentinel-env/bin/python3"
  [ -x "$PY" ] || die "no virtualenv at $REPO/swarmsentinel-env (run deploy/install.sh first)"

  exec 9>"$REPO/.update.lock"
  command -v flock >/dev/null && { flock -n 9 || die "another update is running"; }

  find_release || exit 0
  [ "$CHECK" = 0 ] || exit 10

  WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
  download_and_check
  unpack_and_inspect

  DEPS_CHANGED=0
  cmp -s "$REPO/requirements.txt" "$NEW/requirements.txt" || DEPS_CHANGED=1
  save_current_version
  put_new_version_in_place
  if [ "$DEPS_CHANGED" = 1 ]; then
    log "requirements changed: installing dependencies"
    "$REPO/swarmsentinel-env/bin/pip" install --disable-pip-version-check --quiet -r requirements.txt \
      || { restore_previous_version; die "dependency install failed; the previous version is restored"; }
  fi

  if [ "$TESTS" = 1 ] && ls backend/tools/test_*.py >/dev/null 2>&1; then
    log "running the test suite on the new code"
    local failed; failed="$(run_tests)"
    if [ -n "$failed" ]; then restore_previous_version; die "tests failed ($failed ); the previous version is restored and nothing was restarted"; fi
    log "tests passed"
  fi

  if [ "$RESTART" = 1 ]; then
    log "restarting services"
    restart_all || { restore_previous_version; restart_all || true; die "restart failed; rolled back"; }
    if ! healthy; then
      restore_previous_version; restart_all || true
      healthy && die "the new version did not come up healthy; the previous version is running again" \
              || die "the new version did not come up healthy and the rollback did not either: check 'journalctl -u swarmsentinel -u ssai-agents'"
    fi
  fi
  log "updated to $LATEST"
}

main "$@"
exit $?
