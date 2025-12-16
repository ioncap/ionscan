#!/usr/bin/env bash

# --- NETWORK CORE ---
get_interface() {
    cfg_iface=$(get_config DEFAULT_IFACE); local cfg_iface
    if [[ -n "$cfg_iface" ]] && ip link show "$cfg_iface" &>/dev/null; then
        DEFAULT_IFACE="$cfg_iface"
    else
        DEFAULT_IFACE=$(ip route | grep '^default' | awk '{print $5}' | head -n1)
        [[ -z "$DEFAULT_IFACE" ]] && DEFAULT_IFACE=$(ip -o link show up | awk -F': ' '$2 != "lo" {print $2}' | head -n1)
    fi

    [[ -z "$DEFAULT_IFACE" ]] && { log_error "No interface found."; exit 1; }

    MY_IP=$(ip -4 -o addr show dev "$DEFAULT_IFACE" | awk '{print $4}' | cut -d'/' -f1 | head -n1)
    [[ -z "$MY_IP" ]] && MY_IP="Unknown"
}

get_vendor() {
    mac=$(echo "$1" | tr -d ':' | tr '[:lower:]' '[:upper:]' | head -c 6); local mac
    [[ ! -f "$OUI_DB" ]] && echo "Unknown" && return
    grep -i "^${mac}" "$OUI_DB" | cut -f 3- | head -n 1 | xargs || echo "Unknown"
}

validate_ip() {
    local ip=$1
    if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(/[0-9]{1,2})?$ ]]; then return 0; else return 1; fi
}
