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
MOD_OPTIONS_UTILS_SSL[TARGET]="description='Target IP' required=true"
MOD_OPTIONS_UTILS_SSL[PORT]="description='Port to check SSL on' required=false default='443'"

# Options for mod_serve
declare -gA MOD_OPTIONS_UTILS_SERVE
MOD_OPTIONS_UTILS_SERVE[PORT]="description='Port to serve files on' required=false default='8080'"

# Options for mod_decoy
declare -gA MOD_OPTIONS_UTILS_DECOY
MOD_OPTIONS_UTILS_DECOY[TARGET]="description='Target IP for decoy scan' required=true"
MOD_OPTIONS_UTILS_DECOY[DECOYS]="description='Number of decoys to use' required=false default='10'"

# Options for mod_cron
# This module will be refactored later to be configurable via options.
# For now, it will simply log a warning message.


# [4] MAC
mod_mac() {
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
    if [[ -z "$G" ]]; then log_error "No gateway found."; return; }
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
        log_error "Required option 'TARGET' not set. Use 'set TARGET <ip>'."
        return
    fi
    
    log_info "Checking SSL on $target:$port..."
    nmap -sV -p "$port" --script ssl-enum-ciphers,ssl-cert "$target"
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
        log_error "Required option 'TARGET' not set. Use 'set TARGET <ip>'."
        return
    fi
    
    log_info "Swarming $target with $decoys decoys..."
    sudo nmap -D RND:"$decoys" -sS --top-ports 50 "$target"
    log_info "Decoy scan complete."
}

# [20] AUTO-SCHEDULER (Fixed)
mod_cron() {
    log_warning "mod_cron is not yet fully supported in the interactive shell due to its interactive nature."
    log_warning "Please run the main script with '--setup' to manage cron jobs."
}