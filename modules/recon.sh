#!/usr/bin/env bash

# ==============================================================================
#  RECONNAISSANCE MODULES
# ==============================================================================

# Required tools declarations for pre-flight checks
declare -gA REQUIRED_TOOLS_RECON_PASSIVE=([0]="tcpdump")
declare -gA REQUIRED_TOOLS_RECON_FAST_SCAN=([0]="nmap")
declare -gA REQUIRED_TOOLS_RECON_PORTSCAN=([0]="nmap")
declare -gA REQUIRED_TOOLS_RECON_DNS=([0]="dig")
declare -gA REQUIRED_TOOLS_RECON_SNMP=([0]="snmpwalk")
declare -gA REQUIRED_TOOLS_RECON_WEB=([0]="gobuster")
declare -gA REQUIRED_TOOLS_RECON_NETBIOS=([0]="nbtscan")
declare -gA REQUIRED_TOOLS_RECON_OS_DETECT=([0]="nmap")
declare -gA REQUIRED_TOOLS_RECON_HTTP_PROBE=([0]="curl")

# Options for mod_passive
declare -gA MOD_OPTIONS_RECON_PASSIVE
MOD_OPTIONS_RECON_PASSIVE[INTERFACE]="description='Network interface to listen on' required=true default='$DEFAULT_IFACE' type='string'"
MOD_OPTIONS_RECON_PASSIVE[DURATION]="description='Duration to listen in seconds' required=false default='30' type='port'"

# Options for mod_fast_scan
declare -gA MOD_OPTIONS_RECON_FAST_SCAN
MOD_OPTIONS_RECON_FAST_SCAN[TARGET]="description='Target IP, CIDR, or \"all\"' required=true type='ip_or_cidr'"

# Options for mod_portscan
declare -gA MOD_OPTIONS_RECON_PORTSCAN
MOD_OPTIONS_RECON_PORTSCAN[TARGET]="description='Target IP or CIDR' required=true type='ip_or_cidr'"
MOD_OPTIONS_RECON_PORTSCAN[PORTS]="description='Port range or comma-list (e.g. 22,80,443 or 1-1024)' required=false default='1-1024' type='string'"
MOD_OPTIONS_RECON_PORTSCAN[TIMING]="description='Nmap timing template 0-5' required=false default='4' type='string'"
MOD_OPTIONS_RECON_PORTSCAN[OUTPUT_FORMAT]="description='Output format: xml|greppable|normal' required=false default='xml' type='string'"

# Options for mod_dns
declare -gA MOD_OPTIONS_RECON_DNS
MOD_OPTIONS_RECON_DNS[DOMAIN]="description='Domain to query' required=true type='string'"

# Options for mod_snmp
declare -gA MOD_OPTIONS_RECON_SNMP
MOD_OPTIONS_RECON_SNMP[TARGET]="description='Target IP or \"all\"' required=true type='ip_or_cidr'"
MOD_OPTIONS_RECON_SNMP[COMMUNITY]="description='SNMP Community string' required=false default='public' type='string'"

# Options for mod_web
declare -gA MOD_OPTIONS_RECON_WEB
MOD_OPTIONS_RECON_WEB[TARGET]="description='Target IP, Hostname, or \"all\"' required=true type='string'"
MOD_OPTIONS_RECON_WEB[WORDLIST]="description='Path to wordlist for gobuster' required=false default='$LOG_DIR/common.txt' type='string'"

# Options for mod_netbios
declare -gA MOD_OPTIONS_RECON_NETBIOS
MOD_OPTIONS_RECON_NETBIOS[SUBNET]="description='Subnet to scan (e.g., 192.168.1.0/24)' required=false default='auto' type='string'"

# Options for mod_os_detect
declare -gA MOD_OPTIONS_RECON_OS_DETECT
MOD_OPTIONS_RECON_OS_DETECT[TARGET]="description='Target IP or CIDR' required=true type='ip_or_cidr'"

# Options for mod_http_probe
declare -gA MOD_OPTIONS_RECON_HTTP_PROBE
MOD_OPTIONS_RECON_HTTP_PROBE[TARGET]="description='Target IP/host or \"all\"' required=true type='string'"
MOD_OPTIONS_RECON_HTTP_PROBE[PORTS]="description='Comma-separated ports to probe' required=false default='80,443,8080,8443' type='string'"

# Options for mod_screenshot
declare -gA MOD_OPTIONS_RECON_SCREENSHOT
MOD_OPTIONS_RECON_SCREENSHOT[TARGET]="description='Target IP/host or \"all\"' required=true type='string'"
MOD_OPTIONS_RECON_SCREENSHOT[PORTS]="description='Comma-separated web ports' required=false default='80,443,8080,8443' type='string'"


# [1] GHOST WITNESS
mod_passive() {
    local interface="${MODULE_OPTIONS[INTERFACE]:-}"
    local duration="${MODULE_OPTIONS[DURATION]:-30}"

    if [[ -z "$interface" ]]; then
        log_error "Required option 'INTERFACE' not set."
        return 1
    fi

    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        log_info "[DRY-RUN] tcpdump -i $interface -n -e 'arp or udp port 5353' for ${duration}s"
        return 0
    fi

    log_success "Listening on $interface for $duration seconds..."
    local cap
    cap=$(mktemp "$TMP_DIR/passive.XXXXXX.pcap")
    CLEANUP_FILES+=("$cap")

    sudo tcpdump -i "$interface" -n -e "arp or udp port 5353" -w "$cap" 2>/dev/null & BG_PID=$!
    for i in $(seq 1 "$duration"); do printf "\rScanning... %d%%" $((i*100/duration)); sleep 1; done
    sudo kill "$BG_PID" 2>/dev/null; echo ""

    log_info "Parsing captured traffic..."
    sudo tcpdump -ennr "$cap" arp 2>/dev/null | while read -r line; do
        if [[ "$line" =~ "who-has" ]]; then
            local ip; ip=$(echo "$line" | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -n1)
            local mac; mac=$(echo "$line" | awk '{print $2}')
            mac=${mac%,}

            if [[ -n "$ip" && -n "$mac" ]]; then
                local vendor; vendor=$(get_vendor "$mac")
                db_add_or_get_host "$ip" "$mac" "$vendor"
            fi
        fi
    done

    log_info "Passive scan complete. Data stored in database."
    return 0
}

# [18] FAST SCAN
mod_fast_scan() {
    local target="${MODULE_OPTIONS[TARGET]:-}"

    if [[ -z "$target" ]]; then
        log_error "Required option 'TARGET' not set."
        return 1
    fi

    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        log_info "[DRY-RUN] nmap -F -T4 -n --stats-every 10s -oX <xml> $target | parser"
        return 0
    fi

    log_success "Starting fast scan on targets..."
    export DB_FILE

    local nmap_xml
    nmap_xml=$(mktemp "$TMP_DIR/fast_scan.XXXXXX.xml")
    CLEANUP_FILES+=("$nmap_xml")

    if [[ "$target" == "all" ]]; then
        if [[ ${#TARGETS[@]} -eq 0 ]]; then
            log_error "TARGET is 'all' but target list is empty."
            return 1
        fi
        > "$TMP_TARGETS"
        printf '%s\n' "${TARGETS[@]}" > "$TMP_TARGETS"
        sudo nmap -F -T4 -n --stats-every 10s -oX "$nmap_xml" -iL "$TMP_TARGETS" 2>/dev/null | \
            python3 "$INSTALL_DIR/parsers/nmap_fast_scan_parser.py"
    else
        validate_ip "$target" || { log_error "Invalid IP/CIDR for TARGET."; return 1; }
        sudo nmap -F -T4 -n --stats-every 10s -oX "$nmap_xml" "$target" 2>/dev/null | \
            python3 "$INSTALL_DIR/parsers/nmap_fast_scan_parser.py"
    fi

    log_info "Fast scan complete. Data stored in database."
    return 0
}

# [NEW] CUSTOM PORT RANGE SCAN
mod_portscan() {
    local target="${MODULE_OPTIONS[TARGET]:-}"
    local ports="${MODULE_OPTIONS[PORTS]:-1-1024}"
    local timing="${MODULE_OPTIONS[TIMING]:-4}"
    local output_fmt="${MODULE_OPTIONS[OUTPUT_FORMAT]:-xml}"

    if [[ -z "$target" ]]; then
        log_error "Required option 'TARGET' not set."
        return 1
    fi

    validate_ip "$target" || { log_error "Invalid IP/CIDR for TARGET."; return 1; }

    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        log_info "[DRY-RUN] nmap -sV -p $ports -T$timing $target"
        return 0
    fi

    log_info "Starting custom port scan on $target (ports: $ports, timing: T$timing)..."
    export DB_FILE

    local nmap_xml
    nmap_xml=$(mktemp "$TMP_DIR/portscan.XXXXXX.xml")
    CLEANUP_FILES+=("$nmap_xml")

    local extra_flags=()
    case "$output_fmt" in
        greppable) extra_flags+=("-oG" "$LOG_DIR/portscan_${target//[^a-zA-Z0-9]/_}.gnmap") ;;
        normal)    extra_flags+=("-oN" "$LOG_DIR/portscan_${target//[^a-zA-Z0-9]/_}.txt") ;;
        *)         ;; # xml is the default and fed to parser
    esac

    sudo nmap -sV -p "$ports" -T"$timing" -n --stats-every 10s \
        -oX "$nmap_xml" "${extra_flags[@]}" "$target" 2>/dev/null | \
        python3 "$INSTALL_DIR/parsers/nmap_fast_scan_parser.py"

    log_info "Port scan complete. Results in database."
    return 0
}

# [19] DNS
mod_dns() {
    local domain="${MODULE_OPTIONS[DOMAIN]:-}"

    if [[ -z "$domain" ]]; then
        log_error "Required option 'DOMAIN' not set."
        return 1
    fi

    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        log_info "[DRY-RUN] dig $domain ANY; zone transfer attempt"
        return 0
    fi

    log_info "Querying DNS for $domain..."
    dig "$domain" ANY +noall +answer
    local ns; ns=$(dig "$domain" NS +short | head -n1)
    if [[ -n "$ns" ]]; then dig "@$ns" "$domain" axfr; else log_warning "No NS for AXFR"; fi
    log_info "DNS query complete."
    return 0
}

# [21] mDNS DISCOVERY
mod_mdns() {
    if ! command -v avahi-browse &> /dev/null; then
        log_error "avahi-browse is not installed."
        return 1
    fi
    log_info "Scanning for local services (Bonjour/ZeroConf)..."
    avahi-browse -atr | head -n 20
    log_info "mDNS discovery complete."
    return 0
}

# [22] SNMP WALKER
mod_snmp() {
    local target="${MODULE_OPTIONS[TARGET]:-}"
    local community="${MODULE_OPTIONS[COMMUNITY]:-public}"

    if [[ -z "$target" ]]; then
        log_error "Required option 'TARGET' not set."
        return 1
    fi

    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        log_info "[DRY-RUN] snmpwalk -v2c -c $community $target"
        return 0
    fi

    local targets_to_scan=()
    if [[ "$target" == "all" ]]; then
        if [[ ${#TARGETS[@]} -eq 0 ]]; then
            log_error "TARGET is 'all' but target list is empty."
            return 1
        fi
        for t in "${TARGETS[@]}"; do targets_to_scan+=("$t"); done
    else
        validate_ip "$target" || { log_error "Invalid IP."; return 1; }
        targets_to_scan+=("$target")
    fi

    for t in "${targets_to_scan[@]}"; do
        log_info "Walking SNMP on $t (Community: $community)..."
        snmpwalk -v2c -c "$community" "$t" | head -n 20
    done
    log_info "SNMP walk complete."
    return 0
}

# [23] NETBIOS SCAN
mod_netbios() {
    local subnet_to_scan="${MODULE_OPTIONS[SUBNET]:-auto}"
    if [[ "$subnet_to_scan" == "auto" ]]; then
        get_interface
        subnet_to_scan=$(echo "$MY_IP" | cut -d'.' -f1-3).0/24
    fi

    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        log_info "[DRY-RUN] nbtscan -r $subnet_to_scan"
        return 0
    fi

    log_info "Scanning $subnet_to_scan for NetBIOS names..."
    nbtscan -r "$subnet_to_scan"
    log_info "NetBIOS scan complete."
    return 0
}

# [10] WEB SPIDER
mod_web() {
    local target="${MODULE_OPTIONS[TARGET]:-}"
    local wordlist="${MODULE_OPTIONS[WORDLIST]:-}"

    if [[ -z "$target" ]]; then
        log_error "Required option 'TARGET' not set."
        return 1
    fi
    if [[ -z "$wordlist" ]]; then
        log_error "Required option 'WORDLIST' not set."
        return 1
    fi

    if [[ ! -f "$wordlist" ]]; then
        log_info "Wordlist '$wordlist' not found. Attempting to download default..."
        safe_download "https://raw.githubusercontent.com/v0re/dirb/master/wordlists/common.txt" "$wordlist" || {
            log_error "Failed to download wordlist."
            return 1
        }
    fi

    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        log_info "[DRY-RUN] gobuster dir -u http://<target> -w $wordlist -t 20"
        return 0
    fi

    local targets_to_scan=()
    if [[ "$target" == "all" ]]; then
        if [[ ${#TARGETS[@]} -eq 0 ]]; then
            log_error "TARGET is 'all' but target list is empty."
            return 1
        fi
        for t in "${TARGETS[@]}"; do targets_to_scan+=("$t"); done
    else
        targets_to_scan+=("$target")
    fi

    for t in "${targets_to_scan[@]}"; do
        log_success "Web spidering http://$t with wordlist $wordlist..."
        gobuster dir -u "http://$t" -w "$wordlist" -t 20 --no-error \
            -o "$LOG_DIR/web_scan_${t//[^a-zA-Z0-9]/_}.txt"
    done
    log_info "Web spider complete."
    return 0
}

# [NEW] OS FINGERPRINTING
mod_os_detect() {
    local target="${MODULE_OPTIONS[TARGET]:-}"

    if [[ -z "$target" ]]; then
        log_error "Required option 'TARGET' not set."
        return 1
    fi

    validate_ip "$target" || { log_error "Invalid IP/CIDR for TARGET."; return 1; }

    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        log_info "[DRY-RUN] nmap -O -sV $target"
        return 0
    fi

    log_info "Running OS detection on $target..."
    export DB_FILE

    local nmap_xml
    nmap_xml=$(mktemp "$TMP_DIR/os_detect.XXXXXX.xml")
    CLEANUP_FILES+=("$nmap_xml")

    sudo nmap -O -sV -T4 -n --stats-every 10s "$target" -oX "$nmap_xml" 2>/dev/null

    # Parse OS guess from XML and store in DB
    local os_guess
    os_guess=$(python3 - "$nmap_xml" <<'PYEOF'
import sys, xml.etree.ElementTree as ET
try:
    tree = ET.parse(sys.argv[1])
    for host in tree.findall('host'):
        for osmatch in host.findall('.//osmatch'):
            name = osmatch.get('name','')
            acc = osmatch.get('accuracy','0')
            if name:
                print(f"{name} ({acc}%)")
                break
except Exception as e:
    pass
PYEOF
    )

    if [[ -n "$os_guess" ]]; then
        log_success "OS guess for $target: $os_guess"
        export DB_FILE
        flock -x "$DB_LOCK_FILE" python3 "$INSTALL_DIR/lib/db_write.py" \
            update_os_guess "$target" "$os_guess" 2>/dev/null || true
    else
        log_warning "Could not determine OS for $target (may need root/sudo privileges)."
    fi

    # Also parse ports via fast scan parser
    python3 "$INSTALL_DIR/parsers/nmap_fast_scan_parser.py" < "$nmap_xml" 2>/dev/null || true

    log_info "OS detection complete."
    return 0
}

# [NEW] HTTP SERVICE PROFILER
mod_http_probe() {
    local target="${MODULE_OPTIONS[TARGET]:-}"
    local ports="${MODULE_OPTIONS[PORTS]:-80,443,8080,8443}"

    if [[ -z "$target" ]]; then
        log_error "Required option 'TARGET' not set."
        return 1
    fi

    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        log_info "[DRY-RUN] curl HEAD/GET against $target on ports $ports"
        return 0
    fi

    local targets_to_scan=()
    if [[ "$target" == "all" ]]; then
        if [[ ${#TARGETS[@]} -eq 0 ]]; then
            log_error "TARGET is 'all' but target list is empty."
            return 1
        fi
        for t in "${TARGETS[@]}"; do targets_to_scan+=("$t"); done
    else
        targets_to_scan+=("$target")
    fi

    export DB_FILE

    for t in "${targets_to_scan[@]}"; do
        # Get or create host record
        local host_id
        host_id=$(db_add_or_get_host "$t" "" "")

        IFS=',' read -ra port_list <<< "$ports"
        for p in "${port_list[@]}"; do
            local scheme="http"
            [[ "$p" == "443" || "$p" == "8443" ]] && scheme="https"
            local url="${scheme}://${t}:${p}/"

            log_info "Probing $url ..."
            local resp_headers
            resp_headers=$(curl -sk --max-time 5 --connect-timeout 3 -I "$url" 2>/dev/null || true)

            if [[ -z "$resp_headers" ]]; then
                log_warning "No response from $url"
                continue
            fi

            local server_hdr
            server_hdr=$(echo "$resp_headers" | grep -i '^server:' | head -1 | cut -d: -f2- | xargs)
            local status_code
            status_code=$(echo "$resp_headers" | head -1 | awk '{print $2}')

            # Follow redirects to get redirect chain
            local redirect_chain
            redirect_chain=$(curl -sk --max-time 10 --connect-timeout 3 -w "%{url_effective}" -o /dev/null -L "$url" 2>/dev/null || true)

            # Get cert info for HTTPS
            local cert_info=""
            if [[ "$scheme" == "https" ]]; then
                cert_info=$(echo | openssl s_client -connect "${t}:${p}" 2>/dev/null | \
                    openssl x509 -noout -subject -issuer -dates 2>/dev/null | tr '\n' '|' || true)
            fi

            log_success "  [$status_code] $url | Server: ${server_hdr:-unknown}"
            if [[ -n "$redirect_chain" && "$redirect_chain" != "$url" ]]; then
                log_info "  Redirect chain ends at: $redirect_chain"
            fi
            if [[ -n "$cert_info" ]]; then
                log_info "  Cert: $cert_info"
            fi

            # Store in DB
            export DB_FILE
            flock -x "$DB_LOCK_FILE" python3 "$INSTALL_DIR/lib/db_write.py" \
                add_http_info "$host_id" "$p" \
                "${server_hdr:-}" "${status_code:-0}" "${redirect_chain:-}" "${cert_info:-}" 2>/dev/null || true
        done
    done

    log_info "HTTP probe complete."
    return 0
}

# [NEW] WEB SCREENSHOT CAPTURE
mod_screenshot() {
    local target="${MODULE_OPTIONS[TARGET]:-}"
    local ports="${MODULE_OPTIONS[PORTS]:-80,443,8080,8443}"

    if [[ -z "$target" ]]; then
        log_error "Required option 'TARGET' not set."
        return 1
    fi

    # Check for a screenshot tool
    local screenshot_tool=""
    if command -v chromium-browser &>/dev/null; then
        screenshot_tool="chromium-browser"
    elif command -v chromium &>/dev/null; then
        screenshot_tool="chromium"
    elif command -v google-chrome &>/dev/null; then
        screenshot_tool="google-chrome"
    elif command -v cutycapt &>/dev/null; then
        screenshot_tool="cutycapt"
    else
        log_warning "No screenshot tool found (chromium, google-chrome, or cutycapt required)."
        log_info "Screenshots will be skipped."
        return 0
    fi

    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        log_info "[DRY-RUN] Screenshots via $screenshot_tool for $target:$ports"
        return 0
    fi

    local targets_to_scan=()
    if [[ "$target" == "all" ]]; then
        for t in "${TARGETS[@]}"; do targets_to_scan+=("$t"); done
    else
        targets_to_scan+=("$target")
    fi

    local screenshots_dir="$LOG_DIR/screenshots"
    mkdir -p "$screenshots_dir"

    for t in "${targets_to_scan[@]}"; do
        IFS=',' read -ra port_list <<< "$ports"
        for p in "${port_list[@]}"; do
            local scheme="http"
            [[ "$p" == "443" || "$p" == "8443" ]] && scheme="https"
            local url="${scheme}://${t}:${p}/"
            local out_file="$screenshots_dir/${t//[^a-zA-Z0-9]/_}_${p}.png"

            log_info "Capturing screenshot of $url..."

            if [[ "$screenshot_tool" == "cutycapt" ]]; then
                cutycapt --url="$url" --out="$out_file" 2>/dev/null || \
                    log_warning "Screenshot failed for $url"
            else
                "$screenshot_tool" --headless --disable-gpu \
                    --screenshot="$out_file" \
                    --window-size=1280,800 \
                    --no-sandbox \
                    "$url" 2>/dev/null || log_warning "Screenshot failed for $url"
            fi

            if [[ -f "$out_file" ]]; then
                log_success "Screenshot saved: $out_file"
            fi
        done
    done

    log_info "Screenshot capture complete. Images in $screenshots_dir/"
    return 0
}
