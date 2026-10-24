#!/usr/bin/env bash
# Run on the HUB: create a single-use enrollment code for a new machine and print the command to run there.
#   deploy/new-node.sh [--node-id NAME] [--ttl MINUTES] [--url http://HUB:5000]
# The hub's admin key is read from .env and never printed or sent anywhere but this machine's own API.
set -euo pipefail
NODE_ID="" TTL=60 URL="" PORT="${SSAI_PORT:-5000}"
while [ $# -gt 0 ]; do
  case "$1" in
    --node-id) NODE_ID="${2:-}"; shift 2 ;;
    --ttl) TTL="${2:-}"; shift 2 ;;
    --url) URL="${2:-}"; shift 2 ;;
    --port) PORT="${2:-}"; shift 2 ;;
    -h|--help) sed -n '2,4p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$REPO/.env"
[ -r "$ENV_FILE" ] || { echo "error: cannot read $ENV_FILE (run this as the user that installed the hub, or with sudo)" >&2; exit 1; }
KEY="$(grep -E '^SSAI_API_KEY=' "$ENV_FILE" | head -1 | cut -d= -f2-)"
[ -n "$KEY" ] || { echo "error: no SSAI_API_KEY in $ENV_FILE: is this a hub?" >&2; exit 1; }
grep -qE '^SSAI_ROLE=node' "$ENV_FILE" && { echo "error: this machine is a node; run this on the hub" >&2; exit 1; }

body="$(python3 -c 'import json,sys; d={"ttl_minutes": int(sys.argv[2])}; d.update({"node_id": sys.argv[1]} if sys.argv[1] else {}); print(json.dumps(d))' "$NODE_ID" "$TTL")"
# The key goes to curl on stdin, not on the command line, so it never shows in the process list.
resp="$(printf 'X-API-Key: %s\n' "$KEY" | curl -sS -m 15 -w '\n%{http_code}' -X POST -H @- -H 'Content-Type: application/json' \
        -d "$body" "http://127.0.0.1:$PORT/api/nodes/enrollment-codes")" || { echo "error: cannot reach the hub on port $PORT (is it running? use --port)" >&2; exit 1; }
status="${resp##*$'\n'}"; json="${resp%$'\n'*}"
[ "$status" = 200 ] || { echo "error: the hub answered HTTP $status: $json" >&2; exit 1; }
read -r CODE EXPIRES NAME < <(printf '%s' "$json" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["code"], d["ttl_minutes"], d.get("node_id") or "-")')
[ -n "$URL" ] || { ip="$(hostname -I 2>/dev/null | awk '{print $1}')"; URL="http://${ip:-HUB-ADDRESS}:$PORT"; }

echo
echo "Enrollment code:  $CODE"
echo "Single use, expires in $EXPIRES minutes.$([ "$NAME" = "-" ] || echo " Bound to machine name: $NAME")"
echo
echo "On the new machine:"
echo "  git clone https://github.com/gatsbysdream25-max/SSAI-Deployment.git && cd SSAI-Deployment"
echo "  sudo deploy/install.sh --role node --hub-url $URL --enroll-code $CODE$([ -z "$NODE_ID" ] || echo " --node-id $NODE_ID")"
