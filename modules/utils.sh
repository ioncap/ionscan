#!/usr/bin/env bash

# ==============================================================================
#  UTILITY MODULES
# ==============================================================================

# Utility Modules Options

# Options for mod_mac
declare -gA MOD_OPTIONS_UTILS_MAC
MOD_OPTIONS_UTILS_MAC[INTERFACE]="description='Interface to change MAC address on' required=true default='$DEFAULT_IFACE'"

# Options for mod_ssl
declare -gA MOD_OPTIONS_UTILS_SSL
MOD_OPTIONS_UTILS_SSL[TARGET]="description='Target IP or "all"' required=true"
MOD_OPTIONS_UTILS_SSL[PORT]="description='Port to check SSL on' required=false default='443'"

# Options for mod_serve
declare -gA MOD_OPTIONS_UTILS_SERVE
MOD_OPTIONS_UTILS_SERVE[PORT]="description='Port to serve files on' required=false default='8080'"

# Options for mod_decoy
declare -gA MOD_OPTIONS_UTILS_DECOY
MOD_OPTIONS_UTILS_DECOY[TARGET]="description='Target IP or "all"' required=true"
MOD_OPTIONS_UTILS_DECOY[DECOYS]="description='Number of decoys to use' required=false default='10'"

# Options for mod_cron
declare -gA MOD_OPTIONS_UTILS_CRON
MOD_OPTIONS_UTILS_CRON[ACTION]="description='Action to perform: list, add, or remove' required=false default='list' type='string'"
MOD_OPTIONS_UTILS_CRON[SCHEDULE]="description='Cron schedule expression (used with ACTION=add)' required=false default='0 2 * * *' type='string'"


# [4] MAC
mod_mac() {
    if ! command -v macchanger &> /dev/null; then
        log_error "macchanger is not installed. Please install it first."
        return
    fi
    local interface="${MODULE_OPTIONS[INTERFACE]}"

    if [[ -z "$interface" ]]; then
        log_error "Required option 'INTERFACE' not set. Use 'set INTERFACE <interface>'."
        return
    fi
    
    log_info "Shifting MAC on $interface..."
    sudo macchanger -r "$interface"
    log_info "MAC address changed."
}

# [5] ARP WATCH
mod_arp() {
    # This module doesn't currently take options from MODULE_OPTIONS.
    # It watches the default gateway.
    get_interface; local G; G=$(ip route | grep default | awk '{print $3}' | head -n1)
    if [[ -z "$G" ]]; then log_error "No gateway found."; return; fi
    log_info "Monitoring Gateway: $G (CTRL+C to stop)"
    M1=$(arp -n | grep "$G" | awk '{print $3}')
    while true; do
        if ! ping -c1 -W1 "$G" >/dev/null 2>&1; then sleep 1; continue; fi
        M2=$(arp -n | grep "$G" | awk '{print $3}')
        if [[ "$M1" != "$M2" && -n "$M2" ]]; then echo -e "\n${RED}[!] ARP SPOOF DETECTED!${NC}"; echo -e "\a"; break; fi
        read -t 2 -N 1 input || true
    done
    log_info "ARP monitoring stopped."
}

# [17] SSL
mod_ssl() {
    local target="${MODULE_OPTIONS[TARGET]}"
    local port="${MODULE_OPTIONS[PORT]}"

    if [[ -z "$target" ]]; then
        log_error "Required option 'TARGET' not set. Use 'set TARGET <ip/all>'."
        return
    fi
    
    local targets_to_scan=()
    if [[ "$target" == "all" ]]; then
        if [[ ${#TARGETS[@]} -eq 0 ]]; then
            log_error "TARGET is set to 'all' but the target list is empty. Use 'add target <ip>'."
            return
        fi
        log_info "Scanning all targets in the target list..."
        for t in "${TARGETS[@]}"; do
            targets_to_scan+=("$t")
        done
    else
        validate_ip "$target" || { log_error "Invalid IP for TARGET option."; return; }
        targets_to_scan+=("$target")
    fi

    for t in "${targets_to_scan[@]}"; do
        log_info "Checking SSL on $t:$port..."
        nmap -sV -p "$port" --script ssl-enum-ciphers,ssl-cert "$t"
    done
    log_info "SSL inspection complete."
}

# [15] PAYLOAD
mod_serve() {
    local port="${MODULE_OPTIONS[PORT]}"
    
    if [[ -z "$port" ]]; then
        log_error "Required option 'PORT' not set. Use 'set PORT <port>'."
        return
    fi

    log_info "Serving HTTP on http://$MY_IP:$port..."
    python3 -m http.server "$port"
    log_info "HTTP server stopped."
}

# [3] DECOY SWARM
mod_decoy() {
    local target="${MODULE_OPTIONS[TARGET]}"
    local decoys="${MODULE_OPTIONS[DECOYS]}"

    if [[ -z "$target" ]]; then
        log_error "Required option 'TARGET' not set. Use 'set TARGET <ip/all>'."
        return
    fi
    
    local targets_to_scan=()
    if [[ "$target" == "all" ]]; then
        if [[ ${#TARGETS[@]} -eq 0 ]]; then
            log_error "TARGET is set to 'all' but the target list is empty. Use 'add target <ip>'."
            return
        fi
        log_info "Scanning all targets in the target list..."
        for t in "${TARGETS[@]}"; do
            targets_to_scan+=("$t")
        done
    else
        validate_ip "$target" || { log_error "Invalid IP for TARGET option."; return; }
        targets_to_scan+=("$target")
    fi

    for t in "${targets_to_scan[@]}"; do
        log_info "Swarming $t with $decoys decoys..."
        sudo nmap -D RND:"$decoys" -sS --top-ports 50 "$t"
    done
    log_info "Decoy scan complete."
}

# [20] AUTO-SCHEDULER
mod_cron() {
    local action="${MODULE_OPTIONS[ACTION]:-list}"
    local schedule="${MODULE_OPTIONS[SCHEDULE]:-0 2 * * *}"
    local ionscan_bin="$INSTALL_DIR/bin/ionscan"
    local cron_entry="$schedule $ionscan_bin --auto --agree >> $LOG_DIR/auto.log 2>&1 # ionscan-auto"

    case "$action" in
        list)
            log_info "Current IonScan cron jobs:"
            local current_cron; current_cron=$(crontab -l 2>/dev/null | grep "ionscan" || true)
            if [[ -z "$current_cron" ]]; then
                log_info "No IonScan cron jobs found."
            else
                echo "$current_cron"
            fi
            ;;
        add)
            if crontab -l 2>/dev/null | grep -q "ionscan-auto"; then
                log_warning "An IonScan cron job already exists. Remove it first with ACTION=remove."
                return 1
            fi
            (crontab -l 2>/dev/null; echo "$cron_entry") | crontab -
            log_success "Cron job added. IonScan will auto-run at: $schedule"
            ;;
        remove)
            log_info "Removing IonScan cron jobs..."
            crontab -l 2>/dev/null | grep -v "ionscan-auto" | crontab -
            log_success "IonScan cron jobs removed."
            ;;
        *)
            log_error "Unknown ACTION: '$action'. Valid values: list, add, remove"
            ;;
    esac
}
