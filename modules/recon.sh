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


# [1] GHOST WITNESS
mod_passive() {
    local interface="${MODULE_OPTIONS[INTERFACE]}"
    local duration="${MODULE_OPTIONS[DURATION]}"

    if [[ -z "$interface" ]]; then
        log_error "Required option 'INTERFACE' not set. Use 'set INTERFACE <interface>'."
        return
    fi

    log_success "Listening on $interface for $duration seconds..."
    local cap="$LOG_DIR/live_traffic.pcap"
    rm -f "$cap" # Remove old capture
    tcpdump -i "$interface" -n -e "arp or udp port 5353" -w "$cap" 2>/dev/null & BG_PID=$!
    for i in $(seq 1 "$duration"); do printf "\rScanning... %d%%" $((i*100/duration)); sleep 1; done; kill "$BG_PID" 2>/dev/null; echo ""
    
    log_info "Parsing captured traffic..."
    # Extract arp requests to get IP-MAC mappings
    tcpdump -ennr "$cap" arp 2>/dev/null | while read -r line; do
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
    local target="${MODULE_OPTIONS[TARGET]}"
    
    if [[ -z "$target" ]]; then
        log_error "Required option 'TARGET' not set. Use 'set TARGET <ip/cidr/all>'."
        return
    fi
    
    local targets_param=""
    if [[ "$target" == "all" ]]; then
        if [[ ${#TARGETS[@]} -eq 0 ]]; then
            log_error "TARGET is set to 'all' but the target list is empty. Use 'add target <ip>'."
            return
        fi
        log_info "Scanning all targets in the target list..."
        # Create a temporary file with all targets
        for t in "${TARGETS[@]}"; do
            echo "$t" >> "$TMP_TARGETS"
        done
        targets_param="-iL $TMP_TARGETS"
    else
        validate_ip "$target" || { log_error "Invalid IP for TARGET option."; return; }
        targets_param="$target"
    fi
    
    log_success "Starting fast scan on targets..."
    
    # Export DB_FILE for the parser to use
    export DB_FILE

    # Run nmap and pipe to the parser
    nmap -F -T4 -n -oX - "$targets_param" | python3 "$INSTALL_DIR/parsers/nmap_fast_scan_parser.py"

    log_info "Fast scan complete. Data stored in database."
}

# [19] DNS
mod_dns() {
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
    log_info "Scanning for local services (Bonjour/ZeroConf)..."
    avahi-browse -atr | head -n 20
    log_info "mDNS discovery complete. Note: Use 'avahi-browse -atr' manually for full live stream."
}

# [22] SNMP WALKER
mod_snmp() {
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
    get_interface
    local subnet; subnet=$(echo "$MY_IP" | cut -d'.' -f1-3)
    log_info "Scanning $subnet.0/24 for NetBIOS names..."
    nbtscan -r "$subnet.0/24"
    log_info "NetBIOS scan complete."
}

# [10] WEB SPIDER
mod_web() {
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
