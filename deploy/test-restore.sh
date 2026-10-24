#!/usr/bin/env bash
# Prove a backup works: rebuild a hub from the archive alone, in a throwaway container, and check it serves your data.
#
#   deploy/test-restore.sh /path/to/ssai-full-YYYYMMDD-HHMMSS.tar.gz        (the file deploy/backup_full.sh made)
#
# A backup nobody has restored is a hope, not a backup. This unpacks the archive into a private temporary folder, starts a clean
# Ubuntu container, rebuilds the Python environment from the restored installer, starts the web app the way the service does, and
# prints how many findings and machines it finds, whether sign-in works, and whether the restored admin key is accepted.
#
# Safe by design: it only READS the archive. The restored copy lives in a temporary folder (owner-only) that is deleted at the end,
# the container has no access to your real install, only the web app starts (never the agents), and provider checks are switched off
# so no key in the restored settings is used to call a cloud service. Needs Docker and an internet connection (for apt and pip).
set -euo pipefail
die() { echo "ERROR: $*" >&2; exit 1; }

ARCHIVE="${1:?usage: deploy/test-restore.sh ARCHIVE.tar.gz}"
[ -f "$ARCHIVE" ] || die "no such file: $ARCHIVE"
command -v docker >/dev/null || die "Docker is needed (the restore is tried in a clean container, not on this machine)"

# Check the copy is intact first, when its checksum file is next to it.
SUMFILE="${ARCHIVE%.tar.gz}.sha256"
if [ -f "$SUMFILE" ]; then (cd "$(dirname "$ARCHIVE")" && sha256sum -c "$(basename "$SUMFILE")") || die "the archive does not match its checksum"; fi

WORK="$(mktemp -d)"; chmod 700 "$WORK"
trap 'rm -rf "$WORK"' EXIT
echo "unpacking into a private temporary folder"
tar -xzf "$ARCHIVE" -C "$WORK" 2>/dev/null || die "the archive could not be unpacked"

# The install sits inside the archive under its original path; find it by the installer it contains.
INSTALL="$(find "$WORK" -maxdepth 6 -path '*/deploy/install.sh' -not -path '*/_archive/*' | head -1)"
[ -n "$INSTALL" ] || die "no deploy/install.sh found in the archive: is this a backup_full.sh archive?"
REPO="$(dirname "$(dirname "$INSTALL")")"

cat > "$WORK/drill.sh" <<'DRILL'
#!/usr/bin/env bash
# Runs INSIDE the container. /restore is the restored install, read-only.
export DEBIAN_FRONTEND=noninteractive SSAI_PROVIDER_CHECK=0
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq python3 python3-venv python3-pip curl nmap git iproute2 procps sudo >/dev/null 2>&1 || { echo "could not install the system packages"; exit 1; }
cp -a /restore /srv/hub && cd /srv/hub
rm -rf swarmsentinel-env            # a virtualenv belongs to its folder: the point is that it is REBUILT, not restored
echo "== 1. rebuild from the restored installer"
./deploy/install.sh --user root --no-systemd --no-sudoers --no-start > /tmp/install.out 2>&1; rc=$?
echo "   installer exit code: $rc"; [ $rc = 0 ] || { tail -15 /tmp/install.out; exit 1; }
echo "== 2. start the web app as the service does (agents are NOT started)"
cd backend; set -a; . ../.env 2>/dev/null; set +a
PYTHONPATH=/srv/hub/backend ../swarmsentinel-env/bin/gunicorn -w 1 -b 127.0.0.1:5055 --timeout 60 app:app > /tmp/app.out 2>&1 &
for _ in $(seq 1 40); do curl -fsS -m 2 localhost:5055/health >/dev/null 2>&1 && break; sleep 1; done
echo "   health: $(curl -s -m 3 localhost:5055/health)"
echo "== 3. is your data there? (the restored admin key is used, never printed)"
KEY="$(grep -E '^SSAI_API_KEY=' ../.env | cut -d= -f2- | tr -d "\"'")"
curl -s -m 10 -H "X-API-Key: $KEY" localhost:5055/api/summary | python3 -c "import sys,json; d=json.load(sys.stdin); print('   findings:', d.get('total_threats'), ' by severity:', d.get('by_severity'))"
curl -s -m 10 -H "X-API-Key: $KEY" localhost:5055/api/nodes | python3 -c "import sys,json; d=json.load(sys.stdin); print('   machines:', len(d))"
echo "   sign-in page: $(curl -s -o /dev/null -w %{http_code} localhost:5055/login)   without a key the API answers: $(curl -s -o /dev/null -w %{http_code} localhost:5055/api/nodes) (401 is correct)"
echo "   admin password file restored: $([ -f instance/admin.json ] && echo yes || echo NO)"
echo "   errors in the app log: $(grep -ciE 'traceback|error' /tmp/app.out || true)"
DRILL

echo "starting a clean container (a few minutes: it installs packages)"
docker run --rm --cpus 2 --memory 2g -v "$REPO":/restore:ro -v "$WORK/drill.sh":/drill.sh:ro ubuntu:24.04 bash /drill.sh
echo "done: the temporary copy of your data has been deleted."
