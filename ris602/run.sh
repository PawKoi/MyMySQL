#!/usr/bin/env bash
# AutoPwn — One-click automated penetration testing
# Usage: sudo bash run.sh
# Optionally: sudo bash run.sh --target 10.0.0.0/24 --speed balanced
set -e
cd "$(dirname "$0")"

# ── Colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'
banner(){ echo -e "\n${BLUE}${BOLD}========================================================${NC}"; echo -e "${BLUE}${BOLD}  $1${NC}"; echo -e "${BLUE}${BOLD}========================================================${NC}\n"; }
ok(){ echo -e "${GREEN}[+]${NC} $1"; }
info(){ echo -e "${CYAN}[*]${NC} $1"; }
warn(){ echo -e "${YELLOW}[!]${NC} $1"; }
err(){ echo -e "${RED}[-]${NC} $1"; }

banner "AutoPwn — Automated Penetration Testing Framework"

# ── Root check ────────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    err "This script must be run as root (needed for raw sockets, ARP scan, masscan)."
    echo "  Try: sudo bash run.sh"
    exit 1
fi

# ── Python check ─────────────────────────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
    err "python3 not found. Install it: apt install python3"
    exit 1
fi

# ── Auto-detect network interface and subnet ─────────────────────────────────
detect_network() {
    # Get the default route interface
    IFACE=$(ip route get 1.1.1.1 2>/dev/null | awk '/dev/{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1)
    if [[ -z "$IFACE" ]]; then
        IFACE=$(ip link show | awk -F': ' '/^[0-9]+: (eth|ens|eno|enp|wlan|wlp)/{print $2}' | head -1)
    fi
    if [[ -z "$IFACE" ]]; then
        err "Cannot detect network interface. Use --target and --iface flags."
        exit 1
    fi
    # Get subnet CIDR
    SUBNET=$(ip -o -f inet addr show "$IFACE" 2>/dev/null | awk '{print $4}' | head -1)
    if [[ -z "$SUBNET" ]]; then
        err "Cannot detect subnet on $IFACE. Use --target flag."
        exit 1
    fi
    ok "Interface: $IFACE"
    ok "Subnet   : $SUBNET"
}

# ── Parse arguments ───────────────────────────────────────────────────────────
TARGET=""
IFACE_ARG=""
SPEED="balanced"
EXTRA_ARGS=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --target)   TARGET="$2"; shift 2;;
        --iface)    IFACE_ARG="$2"; shift 2;;
        --speed)    SPEED="$2"; shift 2;;
        --domain)   EXTRA_ARGS="$EXTRA_ARGS --domain $2"; shift 2;;
        --no-brute) EXTRA_ARGS="$EXTRA_ARGS --no-brute"; shift;;
        --exclude)    EXCLUDE_IPS="$2"; shift 2;;
        --deep-pivot) EXTRA_ARGS="$EXTRA_ARGS --deep-pivot"; shift;;
        --mssql-only) EXTRA_ARGS="$EXTRA_ARGS --mssql-only"; shift;;
        --out)      EXTRA_ARGS="$EXTRA_ARGS --out $2"; shift 2;;
        *) shift;;
    esac
done

# Auto-detect if target not supplied
if [[ -z "$TARGET" ]]; then
    info "No --target specified. Auto-detecting local subnet..."
    detect_network
    TARGET="$SUBNET"
    [[ -z "$IFACE_ARG" ]] && IFACE_ARG="$IFACE"
fi

[[ -n "$IFACE_ARG" ]] && EXTRA_ARGS="$EXTRA_ARGS --iface $IFACE_ARG"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
info "Target  : $TARGET"
info "Speed   : $SPEED"
info "Started : $(date)"
echo ""
warn "Full scan will run. All modules: discovery, enumeration, exploitation, post-exploitation."
warn "Output saved to /tmp/autopwn_<timestamp>/"
echo ""

# ── Launch ────────────────────────────────────────────────────────────────────
OWN_IP=$(ip route get 1 2>/dev/null | awk '{print $7}' | head -1)
exec python3 autopwn/main.py --target "$TARGET" --speed "$SPEED" --exclude "$OWN_IP,$EXCLUDE_IPS" $EXTRA_ARGS
