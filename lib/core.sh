#!/usr/bin/env bash

# --- 1. CORE CONFIGURATION & HYGIENE ---
set -u              # Error on unset variables
set -o pipefail     # Fail if pipe fails
shopt -s nocasematch

# Constants & Paths
INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../" && pwd)"
LOG_DIR="$INSTALL_DIR/ionscan_logs"
TMP_DIR="$LOG_DIR/tmp"
mkdir -p "$LOG_DIR" "$TMP_DIR"

CONFIG_FILE="$LOG_DIR/ionscan.conf"
OUI_DB="$LOG_DIR/oui.txt"
REPORT_FILE="$LOG_DIR/dashboard.html"
MAIN_LOG="$LOG_DIR/ionscan.log"
NMAP_SCRIPT_DIR="/usr/share/nmap/scripts"
LOCK_FILE="/tmp/ionscan.lock"

# Secure Temp Files under $TMP_DIR (Auto-cleaned on exit)
TMP_TARGETS=$(mktemp "$TMP_DIR/targets.XXXXXX")
TMP_WIFI=$(mktemp "$TMP_DIR/wifi.XXXXXX")

# Cleanup tracking array for ad-hoc temp files
declare -a CLEANUP_FILES=("$TMP_TARGETS" "$TMP_WIFI")

# OUI in-session cache (populated lazily)
declare -A _OUI_CACHE=()

# --- 2. LOGGING ENGINE ---
# Colors are in ui.sh

get_config() {
    local key=$1
    if [[ -f "$CONFIG_FILE" ]]; then
        grep "^$key=" "$CONFIG_FILE" | head -n1 | cut -d'=' -f2- | tr -d '"' | tr -d "'"
    fi
}

# Effective log level (0=DEBUG, 1=INFO, 2=WARN, 3=ERROR)
_log_level_num() {
    local lvl; lvl=$(get_config LOG_LEVEL 2>/dev/null || echo "INFO")
    case "${lvl^^}" in
        DEBUG) echo 0 ;;
        INFO)  echo 1 ;;
        WARN|WARNING) echo 2 ;;
        ERROR) echo 3 ;;
        *)     echo 1 ;;
    esac
}

log_raw() {
    local level="$1"; local msg="$2"; local color="$3"; local num_level="$4"
    local effective_level; effective_level=$(_log_level_num)
    if (( num_level < effective_level )); then return; fi
    local ts; ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    if [[ -t 1 ]]; then printf "${color}[%s] %s${NC}\n" "$level" "$msg"; fi
    printf "%s [%s] %s\n" "$ts" "$level" "$msg" >> "$MAIN_LOG"
}

log_info()    { log_raw "INFO" "$1" "$BLUE"   1; }
log_success() { log_raw "OK"   "$1" "$GREEN"  1; }
log_warning() { log_raw "WARN" "$1" "$YELLOW" 2; }
log_error()   { log_raw "ERR"  "$1" "$RED"    3 >&2; }

# --- 3. SAFETY & CLEANUP ---
cleanup() {
    # Remove all registered temp files
    for f in "${CLEANUP_FILES[@]:-}"; do
        rm -f "$f" 2>/dev/null || true
    done
    rm -f "$LOCK_FILE"

    if [[ -n "${BG_PID:-}" ]] && kill -0 "$BG_PID" 2>/dev/null;
        then kill "$BG_PID" 2>/dev/null;
    fi

    # Kill Spoofing PIDs
    if [[ -n "${SPOOF_PID1:-}" ]] && kill -0 "$SPOOF_PID1" 2>/dev/null;
        then sudo kill "$SPOOF_PID1" 2>/dev/null;
    fi
    if [[ -n "${SPOOF_PID2:-}" ]] && kill -0 "$SPOOF_PID2" 2>/dev/null;
        then sudo kill "$SPOOF_PID2" 2>/dev/null;
    fi

    # Reset IP Forwarding
    if [[ -f /proc/sys/net/ipv4/ip_forward ]]; then echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward > /dev/null; fi

    # Restore Wifi
    if [[ -n "${MON_IFACE:-}" ]]; then
        sudo airmon-ng stop "$MON_IFACE" >/dev/null 2>&1
        sudo service NetworkManager start 2>/dev/null
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

# Improved structured webhook with summary counts
send_webhook() {
    local msg="$1"
    local module="${2:-}"
    local hosts_found="${3:-0}"
    local ports_found="${4:-0}"
    local vulns_found="${5:-0}"
    local report_link="${6:-}"

    local ts; ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    # Support separate Discord vs Slack webhook URLs
    local discord_url; discord_url=$(get_config DISCORD_WEBHOOK_URL 2>/dev/null || true)
    local slack_url;   slack_url=$(get_config SLACK_WEBHOOK_URL 2>/dev/null || true)
    local generic_url; generic_url=$(get_config WEBHOOK_URL 2>/dev/null || true)

    # Build JSON payload (works for both Discord and Slack)
    local json
    json=$(printf '{"content":"%s","embeds":[{"title":"IonScan Module Run","description":"%s","fields":[{"name":"Module","value":"%s","inline":true},{"name":"Hosts","value":"%s","inline":true},{"name":"Ports","value":"%s","inline":true},{"name":"Vulns","value":"%s","inline":true}],"timestamp":"%s"}]}' \
        "$msg" "$msg" "$module" "$hosts_found" "$ports_found" "$vulns_found" "$ts")
    local slack_json
    slack_json=$(printf '{"text":"%s | module=%s hosts=%s ports=%s vulns=%s ts=%s"}' \
        "$msg" "$module" "$hosts_found" "$ports_found" "$vulns_found" "$ts")

    for url in "$discord_url" "$slack_url" "$generic_url"; do
        if [[ -n "$url" ]]; then
            log_info "Sending webhook to $url..."
            if [[ "$url" == *"slack"* ]]; then
                curl -sf -H "Content-Type: application/json" -d "$slack_json" "$url" >/dev/null 2>&1 || log_warning "Webhook failed."
            else
                curl -sf -H "Content-Type: application/json" -d "$json" "$url" >/dev/null 2>&1 || log_warning "Webhook failed."
            fi
        fi
    done
}

show_help() {
    echo -e "${BOLD}IonScan v24.0 (Git Edition) - Usage:${NC}"
    echo "  ionscan [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --auto       Run in headless mode (Fast Scan + Vuln + Report)"
    echo "  --setup      Install dependencies via apt"
    echo "  --help       Show this message"
    echo "  --agree      Skip disclaimer"
    echo "  --dry-run    Print commands without executing them"
    echo ""
    exit 0
}

# --- 5. NMAP HELPER ---
# Centralised nmap runner to avoid duplication across modules.
# Usage: run_nmap <output_xml_file> <parser_script> <nmap_args...>
run_nmap() {
    local output_xml="$1"; shift
    local parser_script="$1"; shift
    local nmap_args=("$@")

    export DB_FILE

    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        log_info "[DRY-RUN] nmap ${nmap_args[*]} -oX $output_xml"
        return 0
    fi

    local spinner_pid=""
    # Background spinner
    (while true; do printf '.'; sleep 2; done) &
    spinner_pid=$!

    sudo nmap "${nmap_args[@]}" -oX "$output_xml" 2>/dev/null | \
        python3 "$INSTALL_DIR/$parser_script"
    local exit_code=$?

    kill "$spinner_pid" 2>/dev/null; echo ""
    return $exit_code
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
            log_warning "Please install the missing packages using your system's package manager."
        fi
    fi
}

run_setup_wizard() {
    log_warning "The automatic setup wizard is not supported on this system."
    log_warning "Please install the required tools manually."
}
