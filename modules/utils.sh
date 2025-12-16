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

# [4] MAC
mod_mac() { header; get_interface; log_info "Shifting MAC..."; sudo macchanger -r "$DEFAULT_IFACE"; pause; }

# [5] ARP WATCH
mod_arp() {
    header; get_interface; local G; G=$(ip route | grep default | awk '{print $3}' | head -n1)
    if [[ -z "$G" ]]; then log_error "No gateway found."; pause; return; fi
    log_info "Monitoring Gateway: $G (CTRL+C to stop)"
    M1=$(arp -n | grep "$G" | awk '{print $3}')
    while true; do
        if ! ping -c1 -W1 "$G" >/dev/null 2>&1; then sleep 1; continue; fi
        M2=$(arp -n | grep "$G" | awk '{print $3}')
        if [[ "$M1" != "$M2" && -n "$M2" ]]; then echo -e "\n${RED}[!] ARP SPOOF DETECTED!${NC}"; echo -e "\a"; break; fi
        read -t 2 -N 1 input || true
    done; pause
}

# [17] SSL
mod_ssl() {
    read -rp "Target IP: " t; read -rp "Port (443): " p
    nmap -sV -p "${p:-443}" --script ssl-enum-ciphers,ssl-cert "$t"; pause
}

# [15] PAYLOAD
mod_serve() {
    read -rp "Port (8080): " p; p=${p:-8080}
    log_info "http://$MY_IP:$p"
    python3 -m http.server "$p"; pause
}

# [3] DECOY SWARM
mod_decoy() {
    header
    read -rp "Target IP (b=back): " T
    [[ "$T" =~ ^[bB]$ ]] && return
    log_info "Swarming..."; sudo nmap -D RND:10 -sS --top-ports 50 "$T"; pause
}

# [20] AUTO-SCHEDULER (Fixed)
mod_cron() {
    header; echo -e "${CYAN}[ AUTO-SCHEDULER ]${NC}"
    SCRIPT_PATH=$(readlink -f "$0")
    echo "Current path: $SCRIPT_PATH"
    echo "This will add a cron job to run IonScan every hour."
    read -rp "Add to crontab? (y/n): " C
    if [[ "$C" =~ ^[Yy]$ ]]; then
        (crontab -l 2>/dev/null; echo "0 * * * * /usr/bin/flock -n /tmp/ionscan.lock $SCRIPT_PATH --auto") | crontab -
        log_success "Cron job added."
    fi
    pause
}