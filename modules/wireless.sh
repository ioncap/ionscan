#!/usr/bin/env bash

# ==============================================================================
#  WIRELESS MODULES
# ==============================================================================

# [7] WIFI
mod_wifi() {
    wlan=$(iw dev | awk '$1=="Interface"{print $2}'); local wlan
    [[ -z "$wlan" ]] && { log_error "No WiFi card."; return; }
    echo "Interface: $wlan"; read -rp "Confirm? [y/N] " c
    if [[ ! "$c" =~ ^[Yy]$ ]]; then return; fi
    airmon-ng check kill >/dev/null 2>&1
    airmon-ng start "$wlan" >/dev/null
    MON_IFACE=$(iw dev | awk '$1=="Interface" && $2~"mon"{print $2}' | head -n1)
    if [[ -z "$MON_IFACE" ]]; then MON_IFACE=$wlan; fi
    log_success "Monitoring on $MON_IFACE (CTRL+C stop)"
    airodump-ng "$MON_IFACE"
    cleanup
    read -rp "Press Enter..."
}

# [8] BLUETOOTH
mod_bt() {
    header; echo -e "${CYAN}[ BLUE HUNTER ]${NC}"
    if ! command -v hciconfig &>/dev/null; then log_error "Bluez tools missing."; return; fi
    sudo hciconfig hci0 down && sudo hciconfig hci0 up
    log_info "Scanning..."
    hcitool scan > bt.txt; sudo timeout 10s hcitool lescan 2>/dev/null | sudo tee -a bt.txt || true
    cat bt.txt; rm bt.txt; pause
}
