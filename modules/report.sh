#!/usr/bin/env bash

# ==============================================================================
#  REPORTING MODULE
# ==============================================================================

mod_report() {
    header
    log_info "Generating Enterprise Dashboard..."
    export LOG_DIR OUI_DB
    export PUB_IP=$(curl -s --connect-timeout 3 ifconfig.me || echo "Offline")
    export GATEWAY=$(ip route | grep default | awk '{print $3}' | head -n1)
    export DNS_SRV=$(grep "nameserver" /etc/resolv.conf | awk '{print $2}' | head -n1)
    export MY_IP DEFAULT_IFACE

    local template_file="$INSTALL_DIR/templates/dashboard.html"
    local report_content_file=$(mktemp)

    # Generate content from python script
    python3 "$INSTALL_DIR/modules/report.py" > "$report_content_file"

    # Assemble the final report
    sed "s|__DATE__|$(date)|" "$template_file" | sed "/<!-- REPORT_CONTENT -->/r $report_content_file" > "$REPORT_FILE"

    rm "$report_content_file"

    log_success "Generated: $REPORT_FILE"

    # Send Webhook
    local HOSTS=0
    if [[ -f "$LOG_DIR/live_traffic.pcap" ]]; then
        HOSTS=$(tcpdump -nn -e -r "$LOG_DIR/live_traffic.pcap" 2>/dev/null | grep -oE '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' | sort -u | wc -l)
    fi
    send_webhook "Report generated. $HOSTS active hosts found."

    if command -v xdg-open &> /dev/null && [[ "${1:-}" != "--auto" ]]; then
        read -p "    Open in browser? (y/n): " OPEN
        if [[ "$OPEN" =~ ^[Yy]$ ]]; then open_browser "$REPORT_FILE"; fi
    fi
    if [[ "${1:-}" != "--auto" ]]; then pause; fi
}
