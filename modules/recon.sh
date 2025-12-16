#!/usr/bin/env bash

# ==============================================================================
#  RECONNAISSANCE MODULES
# ==============================================================================

# [1] GHOST WITNESS
mod_passive() {
    get_interface
    log_success "Listening on $DEFAULT_IFACE (30s)..."
    local cap="$LOG_DIR/live_traffic.pcap"
    tcpdump -i "$DEFAULT_IFACE" -n -e "arp or udp port 5353" -w "$cap" 2>/dev/null & BG_PID=$!
    for i in {1..30}; do printf "\rScanning... %d%%" $((i*100/30)); sleep 1; done; kill "$BG_PID" 2>/dev/null; echo ""
    tcpdump -nn -e -r "$cap" 2>/dev/null | grep -oE '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' | sort | uniq | while read -r mac; do
        mac=$(echo "$mac" | tr '[:lower:]' '[:upper:]')
        if [[ "$mac" =~ ^(FF:FF|01:00|33:33) ]]; then continue; fi
        ip=$(arp -n | grep -i "$mac" | awk '{print $1}')
        printf " %-16s %-18s %s\n" "${ip:--}" "$mac" "$(get_vendor "$mac" | cut -c1-25)"
    done
    read -rp "Press Enter..."
}

# [18] FAST SCAN
mod_fast_scan() {
    read -rp "Target IP/CIDR (b=back): " t
    if [[ "$t" == "b" ]]; then return; fi
    validate_ip "$t" || { log_error "Invalid IP"; return; }
    log_success "Fast Scan on $t..."
    nmap -F -T4 -n "$t"
    read -rp "Press Enter..."
}

# [19] DNS
mod_dns() {
    read -rp "Domain: " d
    dig "$d" ANY +noall +answer
    local ns; ns=$(dig "$d" NS +short | head -n1)
    if [[ -n "$ns" ]]; then dig "@$ns" "$d" axfr; else log_warning "No NS for AXFR"; fi
    read -rp "Press Enter..."
}

# [21] mDNS DISCOVERY
mod_mdns() {
    header; echo -e "${CYAN}[ mDNS DISCOVERY ]${NC}"
    log_info "Scanning for local services (Bonjour/ZeroConf)..."
    avahi-browse -atr | head -n 20
    echo -e "${YELLOW}Note: Use 'avahi-browse -atr' manually for full live stream.${NC}"
    read -rp "Press Enter..."
}

# [22] SNMP WALKER
mod_snmp() {
    header; echo -e "${CYAN}[ SNMP WALKER ]${NC}"
    read -rp "Target IP (b=back): " t
    if [[ "$t" == "b" ]]; then return; fi
    log_info "Walking SNMP on $t (Community: public)..."
    snmpwalk -v2c -c public "$t" | head -n 20
    echo -e "..."
    read -rp "Press Enter..."
}

# [23] NETBIOS SCAN
mod_netbios() {
    header; echo -e "${CYAN}[ NETBIOS SCAN ]${NC}"
    get_interface
    local subnet; subnet=$(echo "$MY_IP" | cut -d'.' -f1-3)
    log_info "Scanning $subnet.0/24 for NetBIOS names..."
    nbtscan -r "$subnet.0/24"
    read -rp "Press Enter..."
}

# [10] WEB SPIDER
mod_web() {
    read -rp "Target IP: " t
    local wl="$LOG_DIR/common.txt"
    if [[ ! -f "$wl" ]]; then safe_download "https://raw.githubusercontent.com/v0re/dirb/master/wordlists/common.txt" "$wl"; fi
    gobuster dir -u "http://$t" -w "$wl" -t 20 --no-error -o "$LOG_DIR/web_scan_${t}.txt"
    read -rp "Press Enter..."
}
