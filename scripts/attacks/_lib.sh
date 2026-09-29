# Shared helpers for the Netra attack scripts (POSIX sh).
#
# SAFETY: these tools (nmap, hping3, slowhttptest, hydra) may only be pointed at
# the victim container on the internal lab network 10.77.0.0/24, which has no
# route to the host or the internet. Every script sources this file and calls
# require_lab_target before doing anything, so a stray address is refused.

VICTIM_DEFAULT="10.77.0.10"
LAB_PREFIX="10.77.0."

# require_lab_target <ip>: refuse anything outside the lab subnet 10.77.0.0/24.
require_lab_target() {
    case "$1" in
        "${LAB_PREFIX}"[0-9]*) : ;;
        *)
            echo "REFUSED: '$1' is outside the Netra lab subnet 10.77.0.0/24." >&2
            echo "These attack tools may only target the lab victim. See the README safety note." >&2
            exit 2
            ;;
    esac
}

banner() {
    echo "======================================================================"
    echo "  $1"
    echo "======================================================================"
}
