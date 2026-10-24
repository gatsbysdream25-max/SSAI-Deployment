#!/usr/bin/env bash
# Update a SwarmSentinel install (hub or node) from its git remote, safely.
#
#   deploy/update.sh            fetch, test the new code, restart, verify; roll back automatically if anything fails
#   deploy/update.sh --check    only report whether an update is available (exit 10 if one is)
#
# Nothing is restarted unless the new code passes its own test suite first, and a failed restart puts the previous
# version back. Runs as the install's owner; restarts use the scoped sudo rule that install.sh set up.
# WARNING: a rollback runs `git reset --hard` to the previous commit, which discards the failed update's commits and any
# uncommitted edits to tracked files (settings in .env and backend/instance/ are untracked and are not touched).
set -euo pipefail

BRANCH=main CHECK=0 RESTART=1 TESTS=1 REMOTE=origin
ORIGINAL_ARGS=("$@")            # handed on unchanged when this install turns out to be a package, not a git checkout
while [ $# -gt 0 ]; do
  case "$1" in
    --check) CHECK=1; shift ;;
    --branch) BRANCH="${2:-}"; shift 2 ;;
    --remote) REMOTE="${2:-}"; shift 2 ;;
    --no-restart) RESTART=0; shift ;;
    --skip-tests) TESTS=0; shift ;;
    -h|--help) sed -n '2,10p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. "$REPO/deploy/update-lib.sh"
cd "$REPO"
# An install unpacked from a release package has no git history. It updates from the newest published release instead.
if [ ! -d .git ]; then exec "$REPO/deploy/update-package.sh" ${ORIGINAL_ARGS[@]+"${ORIGINAL_ARGS[@]}"}; fi
PY="$REPO/swarmsentinel-env/bin/python3"
[ -x "$PY" ] || die "no virtualenv at $REPO/swarmsentinel-env (run deploy/install.sh first)"

# One update at a time (the daily timer and a person can overlap).
exec 9>"$REPO/.update.lock"
command -v flock >/dev/null && { flock -n 9 || die "another update is running"; }

# Never clobber local edits: an update replaces tracked files.
if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
  die "tracked files have local changes; commit or stash them first:$(printf '\n')$(git status --short --untracked-files=no)"
fi

log "fetching $REMOTE/$BRANCH"
git fetch --quiet "$REMOTE" "$BRANCH"
OLD="$(git rev-parse HEAD)"
NEW="$(git rev-parse "$REMOTE/$BRANCH")"
if [ "$OLD" = "$NEW" ]; then log "already up to date ($(git rev-parse --short HEAD))"; exit 0; fi
# The ledger pusher (ssai-github) commits the threats/ folder on this machine. If someone else pushed first, its push is refused and its
# commit waits here, so history looks diverged. A local commit that changes ONLY threats/ is safe to replay on top of the update (the
# update still runs the tests and can roll back); a local change to anything else is a real divergence and is refused.
LEDGER_ONLY=0
if ! git merge-base --is-ancestor "$OLD" "$NEW"; then
  local_changes="$(git diff --name-only "$(git merge-base "$OLD" "$NEW")" "$OLD")"
  if [ -n "$local_changes" ] && ! printf '%s
' "$local_changes" | grep -qv '^threats/'; then
    LEDGER_ONLY=1
    log "local history differs only by ledger commits (threats/); they will be kept on top of the update"
  else
    die "local history has diverged from $REMOTE/$BRANCH; refusing to update (resolve by hand)"
  fi
fi
log "update available: $(git rev-parse --short "$OLD") -> $(git rev-parse --short "$NEW")"
git --no-pager log --oneline "$OLD..$NEW" | head -20
[ "$CHECK" = 0 ] || exit 10

rollback() {
  log "rolling back to $(git rev-parse --short "$OLD")"
  git reset --hard --quiet "$OLD"
  git diff --quiet "$OLD" "$NEW" -- requirements.txt || "$REPO/swarmsentinel-env/bin/pip" install --disable-pip-version-check --quiet -r requirements.txt || true
}

if [ "$LEDGER_ONLY" = 1 ]; then
  # A rebase writes new commits, which needs an identity; the account running the updater may have none configured.
  if ! rb_err="$(git -c user.name="SwarmSentinel updater" -c user.email="swarmsentinel@local.host" rebase --quiet "$NEW" 2>&1)"; then
    git rebase --abort 2>/dev/null
    die "could not replay the local ledger commits on top of $REMOTE/$BRANCH; nothing was changed: $(printf '%s' "$rb_err" | tail -3)"
  fi
else
  git merge --ff-only --quiet "$NEW"
fi
if ! git diff --quiet "$OLD" "$NEW" -- requirements.txt; then
  log "requirements changed: installing dependencies"
  "$REPO/swarmsentinel-env/bin/pip" install --disable-pip-version-check --quiet -r requirements.txt || { rollback; die "dependency install failed"; }
fi

if [ "$TESTS" = 1 ] && ls backend/tools/test_*.py >/dev/null 2>&1; then
  log "running the test suite on the new code"
  failed="$(run_tests)"
  if [ -n "$failed" ]; then rollback; die "tests failed ($failed ); the previous version is restored and nothing was restarted"; fi
  log "tests passed"
fi

if [ "$RESTART" = 1 ]; then
  log "restarting services"
  restart_all || { rollback; restart_all || true; die "restart failed; rolled back"; }
  if ! healthy; then
    rollback; restart_all || true
    healthy && die "the new version did not come up healthy; the previous version is running again" \
            || die "the new version did not come up healthy and the rollback did not either: check 'journalctl -u swarmsentinel -u ssai-agents'"
  fi
fi
log "updated to $(git rev-parse --short HEAD)"
