#!/usr/bin/env bash

# ==============================================================================
#  UTILITY MODULES
# ==============================================================================

# Required tools declarations for pre-flight checks
declare -gA REQUIRED_TOOLS_UTILS_MAC=([0]="macchanger")
declare -gA REQUIRED_TOOLS_UTILS_DECOY=([0]="nmap")

# Utility Modules Options

# Options for mod_mac (mac address spoof)
declare -gA MOD_OPTIONS_UTILS_MAC
MOD_OPTIONS_UTILS_MAC[INTERFACE]="description='Interface to change MAC address on' required=true default='$DEFAULT_IFACE' type='string'"

# Options for mod_ssl
declare -gA MOD_OPTIONS_UTILS_SSL
MOD_OPTIONS_UTILS_SSL[TARGET]="description='Target IP or \"all\"' required=true type='ip_or_cidr'"
MOD_OPTIONS_UTILS_SSL[PORT]="description='Port to check SSL on' required=false default='443' type='port'"

# Options for mod_serve
declare -gA MOD_OPTIONS_UTILS_SERVE
MOD_OPTIONS_UTILS_SERVE[PORT]="description='Port to serve files on' required=false default='8080' type='port'"

# Options for mod_decoy
declare -gA MOD_OPTIONS_UTILS_DECOY
MOD_OPTIONS_UTILS_DECOY[TARGET]="description='Target IP or \"all\"' required=true type='ip_or_cidr'"
MOD_OPTIONS_UTILS_DECOY[DECOYS]="description='Number of decoys to use' required=false default='10' type='string'"

# Options for mod_cron
declare -gA MOD_OPTIONS_UTILS_CRON
MOD_OPTIONS_UTILS_CRON[SCHEDULE]="description='Scan schedule: daily or weekly' required=false default='daily' type='string'"
MOD_OPTIONS_UTILS_CRON[TARGET_SUBNET]="description='Subnet to scan automatically' required=false default='auto' type='string'"


# [4] MAC SPOOF
mod_mac() {
    local interface="${MODULE_OPTIONS[INTERFACE]:-}"

    if [[ -z "$interface" ]]; then
        log_error "Required option 'INTERFACE' not set."
        return 1
    fi

    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        log_info "[DRY-RUN] macchanger -r $interface"
        return 0
    fi

    log_info "Shifting MAC on $interface..."
    sudo macchanger -r "$interface"
    log_info "MAC address changed."
    return 0
}

# [5] ARP WATCH
mod_arp() {
    get_interface
    local G; G=$(ip route | grep default | awk '{print $3}' | head -n1)
    if [[ -z "$G" ]]; then log_error "No gateway found."; return 1; fi

    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        log_info "[DRY-RUN] ARP watch on gateway $G"
        return 0
    fi

    log_info "Monitoring Gateway: $G (CTRL+C to stop)"
    local M1; M1=$(arp -n | grep "$G" | awk '{print $3}')
    while true; do
        if ! ping -c1 -W1 "$G" >/dev/null 2>&1; then sleep 1; continue; fi
        local M2; M2=$(arp -n | grep "$G" | awk '{print $3}')
        if [[ "$M1" != "$M2" && -n "$M2" ]]; then
            echo -e "\n${RED}[!] ARP SPOOF DETECTED!${NC}"
            echo -e "\a"
            break
        fi
        read -t 2 -N 1 input || true
    done
    log_info "ARP monitoring stopped."
    return 0
}

# [17] SSL
mod_ssl() {
    local target="${MODULE_OPTIONS[TARGET]:-}"
    local port="${MODULE_OPTIONS[PORT]:-443}"

    if [[ -z "$target" ]]; then
        log_error "Required option 'TARGET' not set."
        return 1
    fi

    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        log_info "[DRY-RUN] nmap -sV -p $port --script ssl-enum-ciphers,ssl-cert $target"
        return 0
    fi

    local targets_to_scan=()
    if [[ "$target" == "all" ]]; then
        if [[ ${#TARGETS[@]} -eq 0 ]]; then
            log_error "TARGET is 'all' but target list is empty."
            return 1
        fi
        for t in "${TARGETS[@]}"; do targets_to_scan+=("$t"); done
    else
        validate_ip "$target" || { log_error "Invalid IP."; return 1; }
        targets_to_scan+=("$target")
    fi

    for t in "${targets_to_scan[@]}"; do
        log_info "Checking SSL on $t:$port..."
        nmap -sV -p "$port" --script ssl-enum-ciphers,ssl-cert "$t"
    done
    log_info "SSL inspection complete."
    return 0
}

# [15] PAYLOAD SERVER
mod_serve() {
    local port="${MODULE_OPTIONS[PORT]:-8080}"

    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        log_info "[DRY-RUN] python3 -m http.server $port"
        return 0
    fi

    log_info "Serving HTTP on http://$MY_IP:$port..."
    python3 -m http.server "$port"
    log_info "HTTP server stopped."
    return 0
}

# [3] DECOY SWARM
mod_decoy() {
    local target="${MODULE_OPTIONS[TARGET]:-}"
    local decoys="${MODULE_OPTIONS[DECOYS]:-10}"

    if [[ -z "$target" ]]; then
        log_error "Required option 'TARGET' not set."
        return 1
    fi

    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        log_info "[DRY-RUN] nmap -D RND:$decoys -sS --top-ports 50 <targets>"
        return 0
    fi

    local targets_to_scan=()
    if [[ "$target" == "all" ]]; then
        if [[ ${#TARGETS[@]} -eq 0 ]]; then
            log_error "TARGET is 'all' but target list is empty."
            return 1
        fi
        for t in "${TARGETS[@]}"; do targets_to_scan+=("$t"); done
    else
        validate_ip "$target" || { log_error "Invalid IP."; return 1; }
        targets_to_scan+=("$target")
    fi

    for t in "${targets_to_scan[@]}"; do
        log_info "Swarming $t with $decoys decoys..."
        sudo nmap -D RND:"$decoys" -sS --top-ports 50 "$t"
    done
    log_info "Decoy scan complete."
    return 0
}

# [20] AUTO-SCHEDULER
mod_cron() {
    local schedule="${MODULE_OPTIONS[SCHEDULE]:-daily}"
    local subnet="${MODULE_OPTIONS[TARGET_SUBNET]:-auto}"

    if [[ "$subnet" == "auto" ]]; then
        get_interface
        subnet=$(echo "$MY_IP" | cut -d'.' -f1-3).0/24
    fi

    local ionscan_bin="$INSTALL_DIR/bin/ionscan"
    local cron_cmd="$ionscan_bin --auto --agree"
    local cron_entry=""

    case "${schedule,,}" in
        daily)
            cron_entry="0 2 * * * $cron_cmd >> $LOG_DIR/cron.log 2>&1"
            ;;
        weekly)
            cron_entry="0 2 * * 0 $cron_cmd >> $LOG_DIR/cron.log 2>&1"
            ;;
        *)
            log_error "Invalid SCHEDULE '$schedule'. Valid: daily, weekly"
            return 1
            ;;
    esac

    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        log_info "[DRY-RUN] Would add crontab entry: $cron_entry"
        return 0
    fi

    log_info "Current crontab:"
    crontab -l 2>/dev/null || true
    echo ""
    log_info "New entry to add: $cron_entry"
    read -rp "Add this cron entry? [y/N] " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        log_warning "Cron entry NOT added."
        return 0
    fi

    # Add entry (remove any existing ionscan cron lines first)
    local tmp_cron
    tmp_cron=$(mktemp "$TMP_DIR/cron.XXXXXX")
    CLEANUP_FILES+=("$tmp_cron")
    crontab -l 2>/dev/null | grep -v "ionscan" > "$tmp_cron" || true
    echo "$cron_entry" >> "$tmp_cron"
    crontab "$tmp_cron"

    log_success "Cron entry added ($schedule): $cron_entry"
    log_info "Use 'crontab -l' to verify. Use 'show schedule' via 'use utils/show_schedule'."
    log_info "Logs will be written to $LOG_DIR/cron.log"
    return 0
}

# SHOW SCHEDULE
mod_show_schedule() {
    log_info "Current IonScan cron entries:"
    crontab -l 2>/dev/null | grep "ionscan" || log_info "No IonScan cron entries found."
    return 0
}

# RM SCHEDULE
mod_rm_schedule() {
    local tmp_cron
    tmp_cron=$(mktemp "$TMP_DIR/cron.XXXXXX")
    CLEANUP_FILES+=("$tmp_cron")

    crontab -l 2>/dev/null | grep -v "ionscan" > "$tmp_cron" || true
    crontab "$tmp_cron"
    log_success "All IonScan cron entries removed."
    return 0
}
