#!/usr/bin/env bash
# Deployment check for HTTPS in front of the hub (deploy/tls/README.md). Prints PASS/FAIL per line; exit 1 if any FAIL.
#   deploy/check-tls.sh https://ssai.bank.example [--insecure]      (--insecure: the certificate is from a CA this machine
#                                                                    does not trust yet; the certificate is then not checked)
#   add --hub-port N if the hub is not on 5000
# Run it from a machine OTHER than the hub, so the "plain HTTP is closed" lines test what the network sees.
set -u
URL="${1:-}"; shift || true
CURL=(curl -sS -m 8 --connect-timeout 5)
HUB_PORT=5000
prev=""
for a in "$@"; do
  [ "$a" = "--insecure" ] && CURL+=(-k)
  [ "$prev" = "--hub-port" ] && HUB_PORT="$a"
  prev="$a"
done
case "$URL" in https://*) ;; *) echo "usage: $0 https://host[:port] [--insecure]" >&2; exit 2 ;; esac
HOST="${URL#https://}"; HOST="${HOST%%/*}"; NAME="${HOST%%:*}"
FAIL=0
pass() { echo "PASS  $1"; }
fail() { echo "FAIL  $1"; FAIL=1; }

code="$("${CURL[@]}" -o /dev/null -w '%{http_code}' "$URL/health" 2>/dev/null)" || code=000
[ "$code" = 200 ] && pass "HTTPS answers on $URL/health" || fail "HTTPS did not answer on $URL/health (got $code)"

hdrs="$("${CURL[@]}" -D - -o /dev/null "$URL/login" 2>/dev/null)" || hdrs=""
csp="$(echo "$hdrs" | grep -i '^content-security-policy:' || true)"
if [ -z "$csp" ]; then fail "no Content-Security-Policy header"
elif echo "$csp" | grep -oiE "script-src[^;]*" | grep -qi "unsafe-inline"; then fail "Content-Security-Policy allows inline scripts (script-src 'unsafe-inline')"
else pass "Content-Security-Policy header present, no inline scripts allowed"; fi
echo "$hdrs" | grep -qi '^strict-transport-security:' && pass "HSTS header present" || echo "NOTE  no HSTS yet: add SSAI_HSTS=1 once everything above passes"

# The session cookie is set when a sign-in starts; a bad password is enough to see the flags without signing in.
cookie="$("${CURL[@]}" -D - -o /dev/null -X POST -H 'Content-Type: application/json' -d '{"password":"x"}' "$URL/login" 2>/dev/null | grep -i '^set-cookie:.*ssai_session' || true)"
if [ -z "$cookie" ]; then echo "NOTE  no session cookie issued by a failed sign-in (normal); check SSAI_COOKIE_SECURE=1 in the hub's .env"
elif echo "$cookie" | grep -qi 'secure'; then pass "session cookie is marked Secure"; else fail "session cookie is NOT marked Secure (set SSAI_COOKIE_SECURE=1)"; fi

# Plain HTTP must not hand out data: port 80 may redirect to HTTPS or be closed, never serve the app.
# Closed means the connection was refused (curl exit 7) or never opened before the timeout (exit 28 with no connect time).
# A connection that opened and then answered slowly is an open port, not a closed one.
closed() { case "$1" in 7) return 0 ;; 28) [ "${2:-0}" = 0 ] || [ "${2:-0}" = 0.000000 ] ;; *) return 1 ;; esac; }
probe() { curl -sS -m 8 --connect-timeout 5 -o /dev/null -w '%{http_code} %{time_connect}' "$1" 2>/dev/null; }
out80="$(probe "http://$NAME/api/threats/")"; rc80=$?; code80="${out80%% *}"; tc80="${out80##* }"
if [ "$rc80" = 0 ]; then
  case "$code80" in 301|302|307|308) pass "plain HTTP on port 80 redirects ($code80)" ;; *) fail "plain HTTP on port 80 answered $code80" ;; esac
elif closed "$rc80" "$tc80"; then pass "plain HTTP on port 80 is closed"
else fail "could not test plain HTTP on port 80 (curl exit $rc80)"; fi

# The hub's own port must not be reachable from here.
outhub="$(probe "http://$NAME:$HUB_PORT/health")"; rchub=$?; codehub="${outhub%% *}"; tchub="${outhub##* }"
if [ "$rchub" = 0 ]; then fail "hub port $HUB_PORT answered $codehub from this machine: bind it to 127.0.0.1 and block it in the firewall"
elif closed "$rchub" "$tchub"; then pass "hub port $HUB_PORT is not reachable from this machine"
else fail "could not test hub port $HUB_PORT (curl exit $rchub)"; fi

exit $FAIL
