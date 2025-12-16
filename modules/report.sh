#!/usr/bin/env bash

# ==============================================================================
#  REPORTING MODULE
# ==============================================================================

# Reporting Module Options

# Options for mod_report
declare -gA MOD_OPTIONS_REPORT_REPORT
MOD_OPTIONS_REPORT_REPORT[FORMAT]="description='Output format (html or json)' required=false default='html'"
MOD_OPTIONS_REPORT_REPORT[AUTO_OPEN]="description='Automatically open HTML report in browser' required=false default='false'"

mod_report() {
    local _output_format="${MODULE_OPTIONS[FORMAT]}"
    local _auto_open="${MODULE_OPTIONS[AUTO_OPEN]}"

    # Prepare environment variables for the Python script
    export LOG_DIR OUI_DB
    PUB_IP=$(curl -s --connect-timeout 3 ifconfig.me || echo "Offline"); export PUB_IP
    GATEWAY=$(ip route | grep default | awk '{print $3}' | head -n1); export GATEWAY
    DNS_SRV=$(grep "nameserver" /etc/resolv.conf | awk '{print $2}' | head -n1); export DNS_SRV
    export MY_IP DEFAULT_IFACE # These are already set in lib/core.sh or network.sh

    log_info "Generating report (format: $_output_format)..."

    local python_args=""
    if [[ "$_output_format" == "json" ]]; then
        python_args="--json"
    fi

    local report_output=$(python3 "$INSTALL_DIR/modules/report.py" $python_args)

    if [[ "$_output_format" == "json" ]]; then
        echo "$report_output"
        log_success "JSON report generated to stdout."
        # No webhook or browser open for JSON to stdout
    else # HTML output
        local report_file="$LOG_DIR/dashboard.html"
        local template_file="$INSTALL_DIR/templates/dashboard.html"

        # Assemble the final report
        sed "s|__DATE__|$(date)|" "$template_file" | sed "/<!-- REPORT_CONTENT -->/r /dev/stdin" <<< "$report_output" > "$report_file"

        log_success "Generated: $report_file"

        # Send Webhook
        local HOSTS=0
        if [[ -f "$LOG_DIR/live_traffic.pcap" ]]; then
            HOSTS=$(tcpdump -nn -e -r "$LOG_DIR/live_traffic.pcap" 2>/dev/null | grep -oE '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' | sort -u | wc -l)
        fi
        send_webhook "Report generated. $HOSTS active hosts found."

        if [[ "$_auto_open" == "true" ]]; then
            open_browser "$report_file"
        fi
        log_info "Report generation complete."
    fi
}
