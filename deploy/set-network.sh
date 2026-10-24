#!/usr/bin/env bash
# Change this machine's network address for a new location, with an automatic way back if it goes wrong.
#
#   sudo deploy/set-network.sh dhcp                                 # take whatever address the new network hands out
#   sudo deploy/set-network.sh static 192.0.2.50/24 192.0.2.1       # a fixed address (CIDR) and gateway
#   sudo deploy/set-network.sh show                                 # what it is now
#
# It writes one netplan file and applies it with "netplan try": if you cannot reach the machine afterwards and do not press
# Enter within 2 minutes, the old settings return by themselves. The old file is kept as a .saved copy.
# Other netplan files are renamed to .off while the new one is tried (and restored if it fails), because an old static
# address in them would fight the new settings. With static, the gateway is also used as the DNS server (a safe default
# on most home and office networks; edit /etc/netplan/60-ssai-site.yaml afterwards if yours differs).
# Run it at the machine's own keyboard (or a console), not over the network you are about to leave.
set -euo pipefail
die() { echo "ERROR: $*" >&2; exit 1; }

MODE="${1:-}"
FILE=/etc/netplan/60-ssai-site.yaml
if [ "$MODE" = show ]; then ip -br a; ip route | head -3; exit 0; fi
[ "$(id -u)" = 0 ] || die "run with sudo"
command -v netplan >/dev/null || die "netplan not found (this script is for Ubuntu)"
IFACE="$(ip route show default 2>/dev/null | awk '{print $5; exit}')"
[ -n "$IFACE" ] || IFACE="$(ip -br link | awk '$1!="lo" && $2=="UP"{print $1; exit}')"
[ -n "$IFACE" ] || die "no network interface found"

case "$MODE" in
  dhcp)   BODY="      dhcp4: true" ;;
  static) ADDR="${2:-}"; GW="${3:-}"
          [[ "$ADDR" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]] || die "give the address as a.b.c.d/24"
          [[ "$GW" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "give the gateway as a.b.c.d"
          BODY="      dhcp4: false
      addresses: [$ADDR]
      routes:
        - to: default
          via: $GW
      nameservers:
        addresses: [$GW]" ;;
  *) die "usage: set-network.sh dhcp | static ADDRESS/PREFIX GATEWAY | show" ;;
esac

# An older static file would fight the new one (the address of the old network), so set old ones aside; they are restored on failure.
SAVED=()
for f in /etc/netplan/*.yaml; do
  [ "$f" = "$FILE" ] && continue
  cp -p "$f" "$f.saved"; SAVED+=("$f")
  mv "$f" "$f.off"
done
restore() { for f in "${SAVED[@]}"; do [ -e "$f.off" ] && mv "$f.off" "$f"; done; rm -f "$FILE"; }
cat > "$FILE" <<EOF
network:
  version: 2
  ethernets:
    $IFACE:
$BODY
EOF
chmod 600 "$FILE"
echo "Applying to $IFACE ($MODE). If you lose the connection, do nothing: it reverts in 2 minutes."
if netplan try --timeout 120; then
  for f in "${SAVED[@]}"; do rm -f "$f.off"; done
  echo "Done."; ip -br a show "$IFACE"
else
  restore; netplan apply; die "the new settings were not kept; the old ones are back"
fi
