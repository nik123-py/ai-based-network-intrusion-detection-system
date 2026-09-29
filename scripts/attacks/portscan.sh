#!/bin/sh
# Port scan with nmap. Sends a TCP SYN to many ports on the victim.
# Netra should raise a PortScan alert (signature rule: more than 30 distinct
# destination ports probed by one source inside a 5 s window).
#
# Usage: sh portscan.sh [victim_ip] [port_range]
set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"

TARGET="${1:-$VICTIM_DEFAULT}"
PORTS="${2:-1-1000}"
require_lab_target "$TARGET"

banner "PortScan  ->  $TARGET   (nmap -sS, ports $PORTS)"
echo "Expected Netra alert: PortScan, then the source is blocked."
echo

# -sS SYN scan, -T4 fast timing, -Pn skip host discovery (host is known up),
# -n no DNS. Each probed port is a distinct SYN the NIDS counts.
nmap -sS -T4 -Pn -n -p "$PORTS" "$TARGET"

echo
echo "Port scan finished."
