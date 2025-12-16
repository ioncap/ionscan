#!/usr/bin/env bash

# ==============================================================================
#  WIRELESS MODULES
# ==============================================================================

# Wireless Modules Options
# Each sub-module (mod_*) can have its own options.
# Options are defined as associative arrays.
# Key format: MOD_OPTIONS_<MODULE_CATEGORY>_<MODULE_NAME>
# Value format: "description='...' required=<true/false> default='...'"

# Options for mod_wifi
declare -gA MOD_OPTIONS_WIRELESS_WIFI
MOD_OPTIONS_WIRELESS_WIFI[INTERFACE]="description='Wireless interface for monitoring' required=true default='$DEFAULT_IFACE'"

# Options for mod_bt
# No specific options needed for mod_bt beyond the default behavior.

# [7] WIFI
mod_wifi() {
    local interface="${MODULE_OPTIONS[INTERFACE]}"

    if [[ -z "$interface" ]]; then
        log_error "Required option 'INTERFACE' not set. Use 'set INTERFACE <interface>'."
        return
    fi

    # The original script had an interactive confirmation.
    # In an interactive shell, we assume the user has configured options.
    # The original code's `[[ -z "$wlan" ]]` check should be replaced by option validation earlier.
    # For now, I'll keep it simple and assume the interface is valid from the option.

    airmon-ng check kill >/dev/null 2>&1
    airmon-ng start "$interface" >/dev/null
    MON_IFACE=$(iw dev | awk '$1=="Interface" && $2~"mon"{print $2}' | head -n1)
    if [[ -z "$MON_IFACE" ]]; then MON_IFACE=$interface; fi
    
    log_success "Monitoring on $MON_IFACE (CTRL+C stop)"
    airodump-ng "$MON_IFACE"
    cleanup # Cleanup is handled by trap EXIT in core.sh, but calling explicitly here for immediate effect
    log_info "WiFi monitoring complete."
}

# [8] BLUETOOTH
mod_bt() {
    # No specific options needed for mod_bt.
    # It just runs a scan.

    if ! command -v hciconfig &>/dev/null; then
        log_error "Bluez tools missing. Please install 'bluez'."
        return
    fi
    
    log_info "Scanning for Bluetooth devices..."
    sudo hciconfig hci0 down && sudo hciconfig hci0 up
    hcitool scan > bt.txt; sudo timeout 10s hcitool lescan 2>/dev/null | sudo tee -a bt.txt || true
    cat bt.txt
    rm bt.txt
    log_info "Bluetooth scan complete."
}