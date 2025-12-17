#!/usr/bin/env bash

# ==============================================================================
#  RECONNAISSANCE MODULES
# ==============================================================================

# Reconnaissance Modules Options
# Each sub-module (mod_*) can have its own options.
# Options are defined as associative arrays.
# Key format: MOD_OPTIONS_<MODULE_CATEGORY>_<MODULE_NAME>
# Value format: "description='...' required=<true/false> default='...'"

# Options for mod_passive
declare -gA MOD_OPTIONS_RECON_PASSIVE
MOD_OPTIONS_RECON_PASSIVE[INTERFACE]="description='Network interface to listen on' required=true default='$DEFAULT_IFACE'"
MOD_OPTIONS_RECON_PASSIVE[DURATION]="description='Duration to listen in seconds' required=false default='30'"

# Options for mod_fast_scan
declare -gA MOD_OPTIONS_RECON_FAST_SCAN
MOD_OPTIONS_RECON_FAST_SCAN[TARGET]="description='Target IP, CIDR, or "all"' required=true"

# Options for mod_dns
declare -gA MOD_OPTIONS_RECON_DNS
MOD_OPTIONS_RECON_DNS[DOMAIN]="description='Domain to query' required=true"

# Options for mod_snmp
declare -gA MOD_OPTIONS_RECON_SNMP
MOD_OPTIONS_RECON_SNMP[TARGET]="description='Target IP or "all"' required=true"
MOD_OPTIONS_RECON_SNMP[COMMUNITY]="description='SNMP Community string' required=false default='public'"

# Options for mod_web
declare -gA MOD_OPTIONS_RECON_WEB
MOD_OPTIONS_RECON_WEB[TARGET]="description='Target IP, Hostname, or "all"' required=true"
MOD_OPTIONS_RECON_WEB[WORDLIST]="description='Path to wordlist for gobuster' required=false default='$LOG_DIR/common.txt'"


# Options for mod_netbios
declare -gA MOD_OPTIONS_RECON_NETBIOS
MOD_OPTIONS_RECON_NETBIOS[SUBNET]="description='Subnet to scan (e.g., 192.168.1.0/24)' required=false default='auto'"


# [1] GHOST WITNESS
mod_passive() {
    if ! command -v tcpdump &> /dev/null; then
        log_error "tcpdump is not installed. Please install it first."
        return
    fi
    local interface="${MODULE_OPTIONS[INTERFACE]}"
    local duration="${MODULE_OPTIONS[DURATION]}"

    if [[ -z "$interface" ]]; then
        log_error "Required option 'INTERFACE' not set. Use 'set INTERFACE <interface>'."
        return
    fi

    log_success "Listening on $interface for $duration seconds..."
    local cap="$LOG_DIR/live_traffic.pcap"
    rm -f "$cap" # Remove old capture
    sudo tcpdump -i "$interface" -n -e "arp or udp port 5353" -w "$cap" 2>/dev/null & BG_PID=$!
    for i in $(seq 1 "$duration"); do printf "\rScanning... %d%%" $((i*100/duration)); sleep 1; done; sudo kill "$BG_PID" 2>/dev/null; echo ""
    
    log_info "Parsing captured traffic..."
    # Extract arp requests to get IP-MAC mappings
    sudo tcpdump -ennr "$cap" arp 2>/dev/null | while read -r line; do
        if [[ "$line" =~ "who-has" ]]; then
            local ip; ip=$(echo "$line" | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -n1)
            local mac; mac=$(echo "$line" | awk '{print $2}')
            mac=${mac%,} # remove trailing comma
            
            if [[ -n "$ip" && -n "$mac" ]]; then
                local vendor; vendor=$(get_vendor "$mac")
                db_add_or_get_host "$ip" "$mac" "$vendor"
            fi
        fi
    done
    
    log_info "Passive scan complete. Data stored in database."
}

# [18] FAST SCAN
mod_fast_scan() {
    local target="${MODULE_OPTIONS[TARGET]:-}"
    
    if [[ -z "$target" ]]; then
        log_error "Required option 'TARGET' not set. Use 'set TARGET <ip/cidr/all>'."
        return
    fi
    
    log_success "Starting fast scan on targets..."
    
    # Export DB_FILE for the parser to use
    export DB_FILE

    if [[ "$target" == "all" ]]; then
        if [[ ${#TARGETS[@]} -eq 0 ]]; then
            log_error "TARGET is set to 'all' but the target list is empty. Use 'add target <ip>'."
            return
        fi
        log_info "Scanning all targets in the target list..."
        > "$TMP_TARGETS"
        printf '%s\n' "${TARGETS[@]}" > "$TMP_TARGETS"
        sudo nmap -F -T4 -n --stats-every 10s -oX - -iL "$TMP_TARGETS" | python3 "$INSTALL_DIR/parsers/nmap_fast_scan_parser.py"
    else
        validate_ip "$target" || { log_error "Invalid IP for TARGET option."; return; }
        sudo nmap -F -T4 -n --stats-every 10s -oX - "$target" | python3 "$INSTALL_DIR/parsers/nmap_fast_scan_parser.py"
    fi

    log_info "Fast scan complete. Data stored in database."
}

# [19] DNS
mod_dns() {
    if ! command -v dig &> /dev/null; then
        log_error "dig is not installed. Please install it first (usually in 'dnsutils' or 'bind-utils' package)."
        return
    fi
    local domain="${MODULE_OPTIONS[DOMAIN]}"

    if [[ -z "$domain" ]]; then
        log_error "Required option 'DOMAIN' not set. Use 'set DOMAIN <domain>'."
        return
    fi

    log_info "Querying DNS for $domain..."
    dig "$domain" ANY +noall +answer
    local ns; ns=$(dig "$domain" NS +short | head -n1)
    if [[ -n "$ns" ]]; then dig "@$ns" "$domain" axfr; else log_warning "No NS for AXFR"; fi
    log_info "DNS query complete."
}

# [21] mDNS DISCOVERY
mod_mdns() {
    if ! command -v avahi-browse &> /dev/null; then
        log_error "avahi-browse is not installed. Please install it first (usually in 'avahi-utils' package)."
        return
    fi
    log_info "Scanning for local services (Bonjour/ZeroConf)..."
    avahi-browse -atr | head -n 20
    log_info "mDNS discovery complete. Note: Use 'avahi-browse -atr' manually for full live stream."
}

# [22] SNMP WALKER
mod_snmp() {
    if ! command -v snmpwalk &> /dev/null; then
        log_error "snmpwalk is not installed. Please install it first (usually in 'snmp' package)."
        return
    fi
    local target="${MODULE_OPTIONS[TARGET]}"
    local community="${MODULE_OPTIONS[COMMUNITY]}"

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
        log_info "Walking SNMP on $t (Community: $community)..."
        snmpwalk -v2c -c "$community" "$t" | head -n 20
    done
    log_info "SNMP walk complete."
}

# [23] NETBIOS SCAN
mod_netbios() {
    if ! command -v nbtscan &> /dev/null; then
        log_error "nbtscan is not installed. Please install it manually. On Debian/Ubuntu: 'sudo apt-get install nbtscan', on Fedora: 'sudo dnf install nbtscan' or compile from source."
        return
    fi
    
    local subnet_to_scan="${MODULE_OPTIONS[SUBNET]:-auto}"
    if [[ "$subnet_to_scan" == "auto" ]]; then
        get_interface
        subnet_to_scan=$(echo "$MY_IP" | cut -d'.' -f1-3).0/24
    fi

    log_info "Scanning $subnet_to_scan for NetBIOS names..."
    nbtscan -r "$subnet_to_scan"
    log_info "NetBIOS scan complete."
}

# [10] WEB SPIDER
mod_web() {
    if ! command -v gobuster &> /dev/null; then
        log_error "gobuster is not installed. Please install it first."
        return
    fi
    local target="${MODULE_OPTIONS[TARGET]}"
    local wordlist="${MODULE_OPTIONS[WORDLIST]}"

    if [[ -z "$target" ]]; then
        log_error "Required option 'TARGET' not set. Use 'set TARGET <ip/hostname/all>'."
        return
    fi
    if [[ -z "$wordlist" ]]; then
        log_error "Required option 'WORDLIST' not set. Use 'set WORDLIST <path>'."
        return
    fi

    if [[ ! -f "$wordlist" ]]; then
        log_info "Wordlist '$wordlist' not found. Attempting to download default..."
        safe_download "https://raw.githubusercontent.com/v0re/dirb/master/wordlists/common.txt" "$wordlist" || { log_error "Failed to download wordlist."; return; }
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
        targets_to_scan+=("$target")
    fi

    for t in "${targets_to_scan[@]}"; do
        log_success "Web spidering http://$t with wordlist $wordlist..."
        gobuster dir -u "http://$t" -w "$wordlist" -t 20 --no-error -o "$LOG_DIR/web_scan_${t}.txt"
    done
    log_info "Web spider complete."
}
