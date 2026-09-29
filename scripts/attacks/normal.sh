#!/bin/sh
# Normal web traffic baseline. Ordinary HTTP GETs to the victim's home page.
# Netra should score these flows as Benign and raise no alert. Run this before
# the attacks to show the detector does not fire on legitimate traffic.
#
# Usage: sh normal.sh [victim_ip] [request_count] [delay_seconds]
set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"

TARGET="${1:-$VICTIM_DEFAULT}"
COUNT="${2:-40}"
DELAY="${3:-0.5}"
require_lab_target "$TARGET"

banner "Normal traffic ->  http://$TARGET/   ($COUNT requests)"
echo "Expected: no alert. These flows should be scored Benign."
echo

i=0
while [ "$i" -lt "$COUNT" ]; do
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 4 "http://$TARGET/")"
    printf 'GET / -> %s\n' "$code"
    i=$((i + 1))
    sleep "$DELAY"
done

echo
echo "Normal traffic finished."
