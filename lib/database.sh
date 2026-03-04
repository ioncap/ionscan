#!/usr/bin/env bash

# ==============================================================================
#  DATABASE LIBRARY — parameterized writes via lib/db_write.py
# ==============================================================================

DB_FILE="$LOG_DIR/ionscan.db"
DB_LOCK_FILE="$LOG_DIR/ionscan.db.lock"

# Internal helper: run a raw SQLite read query with flock to avoid write contention.
_db_read() {
    flock -x "$DB_LOCK_FILE" sqlite3 "$DB_FILE" "$1"
}

# --- DATABASE INITIALIZATION ---
db_init() {
    if [[ ! -f "$DB_FILE" ]]; then
        log_info "Initializing database at $DB_FILE..."
        touch "$DB_LOCK_FILE"
        export DB_FILE
        if python3 "$INSTALL_DIR/lib/db_write.py" init_db; then
            log_success "Database initialized successfully."
        else
            log_error "Failed to initialize database."
            exit 1
        fi
    else
        # Ensure the lock file exists even if db already existed
        touch "$DB_LOCK_FILE"
        # Migrate: add new columns/tables silently
        export DB_FILE
        python3 "$INSTALL_DIR/lib/db_write.py" init_db 2>/dev/null || true
    fi
}

# --- DATABASE HELPER FUNCTIONS ---

# Generic read-only SQL (SELECT queries)
db_exec() {
    flock -x "$DB_LOCK_FILE" sqlite3 "$DB_FILE" "$1"
}

# Add or update a host; returns the host ID
db_add_or_get_host() {
    local ip_address="$1"
    local mac_address="${2:-}"
    local vendor="${3:-}"
    export DB_FILE
    flock -x "$DB_LOCK_FILE" python3 "$INSTALL_DIR/lib/db_write.py" \
        add_host "$ip_address" "$mac_address" "$vendor"
}

# Add a port for a host; returns the port ID
db_add_or_get_port() {
    local host_id="$1"
    local port_number="$2"
    local protocol="$3"
    local service_name="${4:-}"
    local state="${5:-open}"
    export DB_FILE
    flock -x "$DB_LOCK_FILE" python3 "$INSTALL_DIR/lib/db_write.py" \
        add_port "$host_id" "$port_number" "$protocol" "$service_name" "$state"
}

# Add a vulnerability for a port
db_add_vulnerability() {
    local port_id="$1"
    local cve_id="$2"
    local cvss_score="${3:-0.0}"
    local description="${4:-}"
    export DB_FILE
    flock -x "$DB_LOCK_FILE" python3 "$INSTALL_DIR/lib/db_write.py" \
        add_vuln "$port_id" "$cve_id" "$cvss_score" "$description"
}

# Record a module run; returns the run ID
db_insert_run() {
    local module="$1"
    local duration="$2"
    local status="$3"
    local options_json="${4:-{}}"
    export DB_FILE
    flock -x "$DB_LOCK_FILE" python3 "$INSTALL_DIR/lib/db_write.py" \
        insert_run "$module" "$duration" "$status" "$options_json"
}
