#!/usr/bin/env bash

# --- NETWORK CORE ---
get_interface() {
    local cfg_iface; cfg_iface=$(get_config DEFAULT_IFACE)
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

# OUI lookup with in-session Bash associative array cache.
# Builds the cache from the OUI file once per session using awk.
get_vendor() {
    local mac="$1"
    local prefix; prefix=$(echo "$mac" | tr -d ':' | tr '[:lower:]' '[:upper:]' | head -c 6)

    # Return from cache if available
    if [[ -v "_OUI_CACHE[$prefix]" ]]; then
        echo "${_OUI_CACHE[$prefix]}"
        return
    fi

    [[ ! -f "$OUI_DB" ]] && echo "Unknown" && return

    local vendor
    vendor=$(awk -v p="$prefix" 'toupper($1) == p {$1=""; sub(/^[[:space:]]+/,""); print; exit}' "$OUI_DB")
    if [[ -z "$vendor" ]]; then vendor="Unknown"; fi

    _OUI_CACHE["$prefix"]="$vendor"
    echo "$vendor"
}

# validate_ip: strict octet-range check (0-255), optional /prefix
validate_ip() {
    local ip="$1"

    # Strip optional CIDR prefix for the octet check
    local addr="${ip%%/*}"
    local prefix="${ip##*/}"

    # Basic format check
    if ! [[ "$addr" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then
        return 1
    fi

    # Octet range check
    local octet
    for octet in "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}" "${BASH_REMATCH[4]}"; do
        if (( octet < 0 || octet > 255 )); then
            return 1
        fi
    done

    # If CIDR was present, validate prefix length
    if [[ "$ip" == */* ]]; then
        if ! [[ "$prefix" =~ ^[0-9]{1,2}$ ]] || (( prefix < 0 || prefix > 32 )); then
            return 1
        fi
    fi

    return 0
}
