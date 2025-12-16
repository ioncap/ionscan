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
MOD_OPTIONS_RECON_FAST_SCAN[TARGET]="description='Target IP or CIDR' required=true"

# Options for mod_dns
declare -gA MOD_OPTIONS_RECON_DNS
MOD_OPTIONS_RECON_DNS[DOMAIN]="description='Domain to query' required=true"

# Options for mod_snmp
declare -gA MOD_OPTIONS_RECON_SNMP
MOD_OPTIONS_RECON_SNMP[TARGET]="description='Target IP' required=true"
MOD_OPTIONS_RECON_SNMP[COMMUNITY]="description='SNMP Community string' required=false default='public'"

# Options for mod_web
declare -gA MOD_OPTIONS_RECON_WEB
MOD_OPTIONS_RECON_WEB[TARGET]="description='Target IP or Hostname' required=true"
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
    tcpdump -i "$interface" -n -e "arp or udp port 5353" -w "$cap" 2>/dev/null & BG_PID=$!
    for i in $(seq 1 "$duration"); do printf "\rScanning... %d%%" $((i*100/duration)); sleep 1; done; kill "$BG_PID" 2>/dev/null; echo ""
    tcpdump -nn -e -r "$cap" 2>/dev/null | grep -oE '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' | sort | uniq | while read -r mac; do
        mac=$(echo "$mac" | tr '[:lower:]' '[:upper:]')
        if [[ "$mac" =~ ^(FF:FF|01:00|33:33) ]]; then continue; fi
        ip=$(arp -n | grep -i "$mac" | awk '{print $1}')
        printf " %-16s %-18s %s\n" "${ip:--}" "$mac" "$(get_vendor "$mac" | cut -c1-25)"
    done
    log_info "Passive scan complete."
}

# [18] FAST SCAN
mod_fast_scan() {
    local target="${MODULE_OPTIONS[TARGET]}"
    
    if [[ -z "$target" ]]; then
        log_error "Required option 'TARGET' not set. Use 'set TARGET <ip>'."
        return
    fi
    
    validate_ip "$target" || { log_error "Invalid IP in TARGET option."; return; }
    
    log_success "Fast Scan on $target..."
    nmap -F -T4 -n "$target"
    log_info "Scan complete."
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
        log_error "Required option 'TARGET' not set. Use 'set TARGET <ip>'."
        return
    fi

    log_info "Walking SNMP on $target (Community: $community)..."
    snmpwalk -v2c -c "$community" "$target" | head -n 20
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
        log_error "Required option 'TARGET' not set. Use 'set TARGET <ip/hostname>'."
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

    log_success "Web spidering http://$target with wordlist $wordlist..."
    gobuster dir -u "http://$target" -w "$wordlist" -t 20 --no-error -o "$LOG_DIR/web_scan_${target}.txt"
    log_info "Web spider complete. Report saved to $LOG_DIR/web_scan_${target}.txt"
}