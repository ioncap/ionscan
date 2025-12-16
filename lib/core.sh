#!/usr/bin/env bash

# --- 1. CORE CONFIGURATION & HYGIENE ---
set -u              # Error on unset variables
set -o pipefail     # Fail if pipe fails
shopt -s nocasematch

# Auto-Escalate to Root safely at start
if [[ $EUID -ne 0 ]]; then
   exec sudo "$0" "$@"
fi

# Constants & Paths
INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../" && pwd)"
LOG_DIR="$INSTALL_DIR/ionscan_logs"
mkdir -p "$LOG_DIR"

CONFIG_FILE="$LOG_DIR/ionscan.conf"
OUI_DB="$LOG_DIR/oui.txt"
REPORT_FILE="$LOG_DIR/dashboard.html"
MAIN_LOG="$LOG_DIR/ionscan.log"
NMAP_SCRIPT_DIR="/usr/share/nmap/scripts"
LOCK_FILE="/tmp/ionscan.lock"

# Secure Temp Files (Auto-cleaned on exit)
TMP_TARGETS=$(mktemp)
TMP_WIFI=$(mktemp)

# --- 2. LOGGING ENGINE ---
# Colors are in ui.sh

get_config() {
    local key=$1
    if [[ -f "$CONFIG_FILE" ]]; then
        grep "^$key=" "$CONFIG_FILE" | head -n1 | cut -d'=' -f2- | tr -d '"' | tr -d "'"
    fi
}

log_raw() {
    local level="$1"; local msg="$2"; local color="$3"
    local ts; ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    if [[ -t 1 ]]; then printf "${color}[%s] %s${NC}\n" "$level" "$msg"; fi
    printf "%s [%s] %s\n" "$ts" "$level" "$msg" >> "$MAIN_LOG"
}

log_info()    { log_raw "INFO" "$1" "$BLUE"; }
log_success() { log_raw "OK"   "$1" "$GREEN"; }
log_warning() { log_raw "WARN" "$1" "$YELLOW"; }
log_error()   { log_raw "ERR"  "$1" "$RED" >&2; }

# --- 3. SAFETY & CLEANUP ---
cleanup() {
    rm -f "$LOCK_FILE" "$TMP_TARGETS" "$TMP_WIFI"

    if [[ -n "${BG_PID:-}" ]] && kill -0 "$BG_PID" 2>/dev/null;
        then kill "$BG_PID" 2>/dev/null;
    fi

    # Kill Spoofing PIDs
    if [[ -n "${SPOOF_PID1:-}" ]] && kill -0 "$SPOOF_PID1" 2>/dev/null;
        then kill "$SPOOF_PID1" 2>/dev/null;
    fi
    if [[ -n "${SPOOF_PID2:-}" ]] && kill -0 "$SPOOF_PID2" 2>/dev/null;
        then kill "$SPOOF_PID2" 2>/dev/null;
    fi

    # Reset IP Forwarding
    if [[ -f /proc/sys/net/ipv4/ip_forward ]]; then echo 0 > /proc/sys/net/ipv4/ip_forward; fi

    # Restore Wifi
    if [[ -n "${MON_IFACE:-}" ]]; then
        airmon-ng stop "$MON_IFACE" >/dev/null 2>&1
        service NetworkManager start 2>/dev/null
    fi
    tput cnorm 2>/dev/null || true
}

trap cleanup EXIT
trap 'log_warning "Interrupted"; exit 1' INT TERM

# --- 4. UTILITIES ---
safe_download() {
    curl -fL --retry 3 --connect-timeout 10 -o "${2}.tmp" "$1" && mv "${2}.tmp" "$2"
}

setup_config() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        cp "$INSTALL_DIR/config/ionscan.conf" "$CONFIG_FILE"
    fi
}

open_browser() {
    local url="$1"
    if [[ -n "${SUDO_USER:-}" ]]; then
        sudo -u "$SUDO_USER" xdg-open "$url" >/dev/null 2>&1
    else
        xdg-open "$url" >/dev/null 2>&1
    fi
}

send_webhook() {
    local msg="$1"
    local url; url=$(get_config WEBHOOK_URL)
    if [[ -n "$url" ]]; then
        log_info "Sending Webhook..."
        curl -H "Content-Type: application/json" -d "{\"content\": \"$msg\"}" "$url" >/dev/null 2>&1 || log_warning "Webhook failed."
    fi
}

show_help() {
    echo -e "${BOLD}IonScan v22.0 (Git Edition) - Usage:${NC}"
    echo "  sudo ionscan [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --auto       Run in headless mode (Passive Scan + Report)"
    echo "  --setup      Install dependencies via apt"
    echo "  --help       Show this message"
    echo "  --agree      Skip disclaimer"
    echo ""
    exit 0
}

# --- 6. DEPENDENCIES ---
check_deps() {
    local silent="${1:-}"
    declare -A tools=(
        ["sqlite3"]="sqlite3"
        ["nmap"]="nmap"
        ["macchanger"]="macchanger"
        ["tcpdump"]="tcpdump"
        ["curl"]="curl"
        ["awk"]="gawk"
        ["aircrack-ng"]="aircrack-ng"
        ["gobuster"]="gobuster"
        ["hydra"]="hydra"
        ["tshark"]="tshark"
        ["flock"]="util-linux"
        ["hcitool"]="bluez"
        ["msfconsole"]="metasploit-framework"
        ["nc"]="netcat-openbsd"
        ["arpspoof"]="dsniff"
        ["dig"]="dnsutils"
        ["avahi-browse"]="avahi-utils"
        ["snmpwalk"]="snmp"
        ["nbtscan"]="nbtscan"
    )
    local missing=()

    for cmd in "${!tools[@]}"; do
        if ! command -v "$cmd" &>/dev/null;
            then
            if [[ "$cmd" == "msfconsole" && -x "/opt/metasploit-framework/bin/msfconsole" ]]; then continue; fi
            missing+=("${tools[$cmd]}")
        fi
    done

    # Data Downloads
    if [[ -d "$NMAP_SCRIPT_DIR" && ! -f "$NMAP_SCRIPT_DIR/vulners.nse" ]]; then
        safe_download "https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse" "$NMAP_SCRIPT_DIR/vulners.nse" || true
        command -v nmap &>/dev/null && sudo nmap --script-updatedb >/dev/null 2>&1
    fi
    if [[ ! -f "$OUI_DB" ]]; then safe_download "https://standards-oui.ieee.org/oui/oui.txt" "$OUI_DB"; fi

    if [[ ${#missing[@]} -gt 0 ]]; then
        if [[ "$silent" == "silent" ]]; then exit 1; fi
        echo -e "${RED}MISSING:${NC} ${missing[*]}"
        read -rp "Install? [y/N] " c
        if [[ "$c" =~ ^[Yy]$ ]]; then
            # This part is not portable, user needs to adapt it to their distro
            log_warning "Please install the missing packages using your system's package manager."
        fi
    fi
}

run_setup_wizard() {
    log_warning "The automatic setup wizard is not supported on this system."
    log_warning "Please install the required tools manually."
}