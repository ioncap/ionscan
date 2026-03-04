#!/usr/bin/env bash

# ==============================================================================
#  REPORTING MODULE
# ==============================================================================

# Reporting Module Options
declare -gA MOD_OPTIONS_REPORT_REPORT
MOD_OPTIONS_REPORT_REPORT[FORMAT]="description='Output format: html, json, csv, pdf' required=false default='html' type='string'"
MOD_OPTIONS_REPORT_REPORT[AUTO_OPEN]="description='Automatically open HTML report in browser' required=false default='false' type='boolean'"
MOD_OPTIONS_REPORT_REPORT[OUTPUT_PATH]="description='Custom output path for csv/pdf (default: auto)' required=false default='' type='string'"

mod_report() {
    local _output_format="${MODULE_OPTIONS[FORMAT]:-html}"
    local _auto_open="${MODULE_OPTIONS[AUTO_OPEN]:-false}"
    local _output_path="${MODULE_OPTIONS[OUTPUT_PATH]:-}"

    # Prepare environment variables for the Python script
    export LOG_DIR OUI_DB DB_FILE
    PUB_IP=$(curl -s --connect-timeout 3 ifconfig.me 2>/dev/null || echo "Offline")
    export PUB_IP
    GATEWAY=$(ip route | grep default | awk '{print $3}' | head -n1 2>/dev/null || echo "")
    export GATEWAY
    DNS_SRV=$(grep "nameserver" /etc/resolv.conf 2>/dev/null | awk '{print $2}' | head -n1 || echo "")
    export DNS_SRV
    export MY_IP DEFAULT_IFACE

    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        log_info "[DRY-RUN] report.py --${_output_format} ..."
        return 0
    fi

    log_info "Generating report (format: $_output_format)..."

    case "${_output_format,,}" in
        json)
            python3 "$INSTALL_DIR/modules/report.py" --json
            log_success "JSON report generated to stdout."
            ;;
        csv)
            local csv_out="${_output_path:-$LOG_DIR/report_$(date +%Y%m%d_%H%M%S).csv}"
            python3 "$INSTALL_DIR/modules/report.py" --csv "$csv_out"
            log_success "CSV report generated: $csv_out"
            ;;
        pdf)
            local template_file="$INSTALL_DIR/templates/dashboard.html"
            local pdf_out="${_output_path:-$LOG_DIR/report_$(date +%Y%m%d_%H%M%S).pdf}"
            python3 "$INSTALL_DIR/modules/report.py" --pdf "$template_file" "$pdf_out"
            log_success "PDF report generated: $pdf_out"
            if [[ "$_auto_open" == "true" ]]; then
                open_browser "$pdf_out"
            fi
            ;;
        html|*)
            local report_file="$LOG_DIR/dashboard.html"
            local template_file="$INSTALL_DIR/templates/dashboard.html"
            python3 "$INSTALL_DIR/modules/report.py" "$template_file" "$report_file"
            log_success "Generated: $report_file"

            # Collect summary counts for webhook
            local host_count port_count vuln_count
            host_count=$(db_exec "SELECT COUNT(*) FROM hosts;" 2>/dev/null || echo 0)
            port_count=$(db_exec "SELECT COUNT(*) FROM ports;" 2>/dev/null || echo 0)
            vuln_count=$(db_exec "SELECT COUNT(*) FROM vulnerabilities;" 2>/dev/null || echo 0)

            send_webhook "Report generated." "report/generate" \
                "$host_count" "$port_count" "$vuln_count" "$report_file"

            if [[ "$_auto_open" == "true" ]]; then
                open_browser "$report_file"
            fi
            log_info "Report generation complete."
            ;;
    esac
    return 0
}
