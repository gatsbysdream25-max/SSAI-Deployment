#!/usr/bin/env bash
# Exercises deploy/update.sh against a throwaway origin (safe: touches only a temp dir). Needs the repo venv: run
# deploy/install.sh first. Usage: deploy/test_update.sh
set -u
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
W="$(mktemp -d /tmp/upd-test.XXXXXX)"
G="git -c user.name=t -c user.email=t@t"
mkdir -p "$W/shims"; cd "$W"
pass=0; fail=0
ok()   { pass=$((pass+1)); printf '  PASS  %s\n' "$*"; }
bad()  { fail=$((fail+1)); printf '  FAIL  %s\n' "$*"; }
check(){ if eval "$2"; then ok "$1"; else bad "$1  [$2]"; printf "%s
" "${out:-}" | tail -6 | sed "s/^/        | /"; fi; }

git clone -q --bare "$SRC" origin.git
git clone -q origin.git a && git clone -q origin.git b
ln -s "$SRC/swarmsentinel-env" a/swarmsentinel-env
head_a() { git -C a rev-parse HEAD; }
push_commit() { (cd b && git pull -q --ff-only && "$@" && $G add -A && $G commit -q -m "$MSG" && git push -q origin HEAD:main); }
U() { (cd a && deploy/update.sh "$@" 2>&1); }

echo "1) already up to date"
out=$(U --no-restart); rc=$?
check "exit 0 and says so" '[ $rc -eq 0 ] && echo "$out" | grep -q "already up to date"'

echo "2) an update exists"
MSG="benign change" push_commit sh -c 'echo hello > docs-note.txt'
out=$(U --check); rc=$?
check "--check exits 10 and names the commit" '[ $rc -eq 10 ] && echo "$out" | grep -q "benign change"'
check "--check changes nothing" '[ "$(head_a)" != "$(git -C b rev-parse HEAD)" ]'

echo "3) good update runs the test suite on the new code, then applies"
old=$(head_a)
out=$(U --no-restart); rc=$?
check "exit 0" '[ $rc -eq 0 ]'
check "tests ran and passed" 'echo "$out" | grep -q "tests passed"'
check "working tree is at the new commit" '[ "$(head_a)" = "$(git -C b rev-parse HEAD)" ] && [ "$(head_a)" != "$old" ]'

echo "4) a commit that breaks the tests is refused and rolled back; nothing is restarted"
MSG="broken change" push_commit sh -c 'printf "raise SystemExit(\"boom\")\n" > backend/tools/test_zz_broken.py'
old=$(head_a)
out=$(U); rc=$?
check "exit 1 naming the failing test" '[ $rc -eq 1 ] && echo "$out" | grep -q "test_zz_broken.py"'
check "previous version restored" '[ "$(head_a)" = "$old" ] && [ ! -e a/backend/tools/test_zz_broken.py ]'
check "no restart was attempted" '! echo "$out" | grep -q "restarting services"'
# make origin healthy again for the rest: revert the broken commit
MSG="revert broken" push_commit sh -c 'git rm -q backend/tools/test_zz_broken.py'

echo "5) local edits to tracked files are never clobbered"
echo "# local" >> a/README.md
out=$(U --no-restart); rc=$?
check "refuses with an explanation" '[ $rc -eq 1 ] && echo "$out" | grep -q "local changes"'
check "the local edit is intact" 'tail -1 a/README.md | grep -q "# local"'
git -C a checkout -q README.md

echo "6) diverged history is refused"
(cd a && echo local > local-only.txt && $G add local-only.txt && $G commit -q -m "local commit")
MSG="upstream change" push_commit sh -c 'echo up > upstream.txt'
out=$(U --no-restart); rc=$?
check "refuses" '[ $rc -eq 1 ] && echo "$out" | grep -q "diverged"'
git -C a reset -q --hard origin/main 2>/dev/null; (cd a && git fetch -q && git reset -q --hard origin/main)

echo "6b) a local commit that changes only threats/ (the ledger pusher's) is kept on top of the update"
(cd a && mkdir -p threats && echo '{}' > threats/ledger-test.json && $G add threats/ledger-test.json && $G commit -q -m "ledger commit")
MSG="upstream code change" push_commit sh -c 'echo up2 > upstream2.txt'
out=$(U --no-restart); rc=$?
check "update succeeds" '[ $rc -eq 0 ] && echo "$out" | grep -q "only by ledger commits"'
check "the new upstream file arrived" '[ -e a/upstream2.txt ]'
check "the ledger commit is still there, now on top" 'git -C a log -1 --format=%s | grep -q "ledger commit"'
check "the tree is clean" '[ -z "$(git -C a status --porcelain --untracked-files=no)" ]'
git -C a reset -q --hard origin/main 2>/dev/null; (cd a && git fetch -q && git reset -q --hard origin/main)

# ---- restart / health paths, with stub systemctl, sudo and curl ----
cat > shims/systemctl <<'EOS'
#!/usr/bin/env bash
case "$1" in
  list-unit-files) echo "$2 enabled" ;;
  cat) echo "ExecStart=/x/gunicorn -w 2 -b 0.0.0.0:5999 --timeout 60 app:app" ;;
  restart) echo "$2" >> "$STUB_DIR/restarts"; [ -e "$STUB_DIR/restart_fails" ] && [ "$2" = swarmsentinel ] && [ ! -e "$STUB_DIR/rolled" ] && exit 1; exit 0 ;;
  is-active) exit 0 ;;
esac
EOS
cat > shims/curl <<'EOS'
#!/usr/bin/env bash
# healthy unless the marker says the NEW version is running and unhealthy
[ -e "$STUB_DIR/unhealthy" ] && exit 22
exit 0
EOS
cat > shims/sudo <<'EOS'
#!/usr/bin/env bash
[ "$1" = "-n" ] && shift
exec "$@"
EOS
cat > shims/id <<'EOS'
#!/usr/bin/env bash
[ "$1" = "-u" ] && { echo 1000; exit 0; }
exec /usr/bin/id "$@"
EOS
chmod +x shims/*
export STUB_DIR="$W/stub"; mkdir -p "$STUB_DIR"
SU() { (cd a && PATH="$W/shims:$PATH" STUB_DIR="$STUB_DIR" deploy/update.sh --skip-tests "$@" 2>&1); }

echo "7) restarts app then agents, verifies health, keeps the new version"
: > "$STUB_DIR/restarts"
MSG="change 7" push_commit sh -c 'echo 7 > n7.txt'
out=$(SU); rc=$?
check "exit 0 and healthy" '[ $rc -eq 0 ] && echo "$out" | grep -q "updated to"'
check "restarted swarmsentinel then ssai-agents" '[ "$(paste -sd, "$STUB_DIR/restarts")" = "swarmsentinel,ssai-agents" ]'
check "at the new commit" '[ "$(head_a)" = "$(git -C b rev-parse HEAD)" ]'

echo "8) the new version comes up unhealthy: roll back and restart the old one"
MSG="change 8" push_commit sh -c 'echo 8 > n8.txt'
old=$(head_a); : > "$STUB_DIR/restarts"
# unhealthy until the rollback has happened: the shim goes healthy once HEAD is back at the old commit
cat > shims/curl <<EOS
#!/usr/bin/env bash
[ "\$(git -C $W/a rev-parse HEAD)" = "$old" ] && exit 0
exit 22
EOS
chmod +x shims/curl
out=$(SU); rc=$?
check "exit 1 saying the previous version is running again" '[ $rc -eq 1 ] && echo "$out" | grep -q "previous version is running again"'
check "rolled back to the old commit" '[ "$(head_a)" = "$old" ]'
check "old version restarted after the rollback (2 restart rounds)" '[ "$(grep -c swarmsentinel "$STUB_DIR/restarts")" = 2 ]'
git -C a fetch -q; (cd a && git reset -q --hard "$old")

echo "9) a restart command that fails also rolls back"
: > "$STUB_DIR/restarts"; rm -f "$STUB_DIR/rolled"; touch "$STUB_DIR/restart_fails"
cat > shims/systemctl <<'EOS'
#!/usr/bin/env bash
case "$1" in
  list-unit-files) echo "$2 enabled" ;;
  cat) echo "ExecStart=/x/gunicorn -b 0.0.0.0:5999 app:app" ;;
  restart) echo "$2" >> "$STUB_DIR/restarts"
           # fails the first time only (the new code); succeeds after the rollback
           n=$(grep -c "^$2$" "$STUB_DIR/restarts"); [ "$2" = swarmsentinel ] && [ "$n" = 1 ] && exit 1; exit 0 ;;
  is-active) exit 0 ;;
esac
EOS
chmod +x shims/systemctl
printf '#!/usr/bin/env bash\nexit 0\n' > shims/curl
old=$(head_a)
out=$(SU); rc=$?
check "exit 1 and rolled back" '[ $rc -eq 1 ] && echo "$out" | grep -q "restart failed; rolled back" && [ "$(head_a)" = "$old" ]'

echo
echo "RESULT: $pass passed, $fail failed"
rm -rf "$W"
[ "$fail" = 0 ]
