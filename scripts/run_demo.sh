#!/usr/bin/env bash
# Netra Phase 8 demo driver.
#
# Brings up the Docker lab (attacker, victim, nids) and runs each attack from
# the attacker container against the victim, so Netra detects and responds live
# while you watch the desktop app. A benign baseline runs first to show the
# detector does not fire on normal traffic.
#
# Safety: every attack targets only the victim (10.77.0.10) on the internal lab
# network, which has no route to the host or the internet.
#
# Usage:
#   bash scripts/run_demo.sh                 interactive, pauses before each step
#   bash scripts/run_demo.sh --yes           unattended, sleeps between steps
#   bash scripts/run_demo.sh --attacks "portscan synflood"   run a subset
#   bash scripts/run_demo.sh --yes --down    unattended, then tear the lab down
set -euo pipefail

# On Windows Git Bash (MSYS), a leading-slash argument like /attacks/foo.sh is
# rewritten to a Windows path before it reaches the container. Disable that; the
# variable is ignored on Linux and macOS.
export MSYS_NO_PATHCONV=1

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
NETRA_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
cd "$NETRA_DIR"

VICTIM="10.77.0.10"
API="http://127.0.0.1:8000"
PAUSE=10
AUTO=0
DOWN=0
ATTACKS="portscan synflood slowloris bruteforce"

usage() { sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
    case "$1" in
        -y|--yes)     AUTO=1 ;;
        --pause)      shift; PAUSE="$1" ;;
        --attacks)    shift; ATTACKS="$1" ;;
        --down)       DOWN=1 ;;
        -h|--help)    usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage; exit 1 ;;
    esac
    shift
done

step()  { echo; echo ">>> $*"; }
pause() {
    if [ "$AUTO" -eq 1 ]; then
        echo "(waiting ${PAUSE}s)"; sleep "$PAUSE"
    else
        printf 'Press Enter to continue (Ctrl+C to stop)... '; read -r _ || true
    fi
}

command -v docker >/dev/null 2>&1 || { echo "docker not found on PATH." >&2; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "docker compose v2 is required." >&2; exit 1; }

victim_http() {
    docker compose exec -T attacker curl -s -o /dev/null -w '%{http_code}' \
        --max-time 3 "http://$VICTIM/" 2>/dev/null || true
}

step "Building and starting the lab (attacker, victim, nids)"
docker compose up -d --build

step "Waiting for the victim to answer from the attacker container"
tries=0
until [ "$(victim_http)" = "200" ]; do
    tries=$((tries + 1))
    if [ "$tries" -gt 40 ]; then echo "victim did not come up." >&2; exit 1; fi
    sleep 1
done
echo "victim is up (HTTP 200)."

cat <<EOF

The lab is running:
  attacker 10.77.0.66     victim 10.77.0.10 (nginx)     nids (shares victim namespace)

In a SEPARATE terminal, open the Netra desktop app to watch detection live:
  .venv/Scripts/python.exe -m src.cli app --url ws://127.0.0.1:8000/ws

Each step runs from the attacker container. Watch the app for the alert and the
automatic, timed block after each attack.
EOF
pause

step "BASELINE: normal traffic (should NOT raise an alert)"
docker compose exec -T attacker sh /attacks/normal.sh "$VICTIM" 20 0.2 || true
echo "--- baseline finished. The app should show flows scored, zero alerts. ---"
pause

run_attack() {
    name="$1"
    step "ATTACK: $name"
    docker compose exec -T attacker sh "/attacks/$name.sh" "$VICTIM" || true
    echo "--- $name finished. The app should show the alert and a block. ---"
    pause
}

for a in $ATTACKS; do run_attack "$a"; done

step "Clearing all Netra blocks (unblock-all)"
if command -v curl >/dev/null 2>&1; then
    curl -s -X POST "$API/api/unblock-all" -H 'Content-Type: application/json' -d '{}' \
        && echo || echo "(could not reach the event API; the blocks will also expire on their own)"
else
    echo "curl not found on the host; blocks expire automatically after their timers."
fi

if [ "$DOWN" -eq 1 ]; then
    step "Tearing down the lab"
    docker compose down
else
    echo
    echo "Lab left running. Stop it with:  docker compose down"
fi

echo
echo "Demo complete."
