#!/usr/bin/env bash

# ==============================================================================
#  DATABASE LIBRARY
# ==============================================================================

DB_FILE="$LOG_DIR/ionscan.db"

# --- DATABASE INITIALIZATION ---
db_init() {
    if [[ ! -f "$DB_FILE" ]]; then
        log_info "Initializing database at $DB_FILE..."
        sqlite3 "$DB_FILE" <<'EOF'
            CREATE TABLE IF NOT EXISTS hosts (
                id INTEGER PRIMARY KEY,
                ip_address TEXT UNIQUE NOT NULL,
                mac_address TEXT,
                vendor TEXT,
                os_guess TEXT,
                first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS ports (
                id INTEGER PRIMARY KEY,
                host_id INTEGER NOT NULL,
                port_number INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                service_name TEXT,
                state TEXT,
                FOREIGN KEY (host_id) REFERENCES hosts(id)
            );
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY,
                port_id INTEGER NOT NULL,
                cve_id TEXT NOT NULL,
                cvss_score REAL,
                description TEXT,
                FOREIGN KEY (port_id) REFERENCES ports(id)
            );
            CREATE TABLE IF NOT EXISTS http_info (
                id INTEGER PRIMARY KEY,
                host_id INTEGER NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT,
                server_header TEXT,
                status_code INTEGER,
                redirect_url TEXT,
                title TEXT,
                FOREIGN KEY (host_id) REFERENCES hosts(id)
            );
            CREATE TABLE IF NOT EXISTS runs (
                id INTEGER PRIMARY KEY,
                module TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                duration_seconds INTEGER,
                status TEXT,
                options_json TEXT
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_host_port_proto ON ports (host_id, port_number, protocol);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_vuln_port_cve ON vulnerabilities (port_id, cve_id);
EOF
        if [[ $? -eq 0 ]]; then
            log_success "Database initialized successfully."
        else
            log_error "Failed to initialize database."
            exit 1
        fi
    else
        # Schema migrations for existing databases — safe to run repeatedly
        sqlite3 "$DB_FILE" "ALTER TABLE hosts ADD COLUMN os_guess TEXT;" 2>/dev/null || true
        sqlite3 "$DB_FILE" "CREATE TABLE IF NOT EXISTS http_info (
            id INTEGER PRIMARY KEY, host_id INTEGER NOT NULL, port INTEGER NOT NULL,
            protocol TEXT, server_header TEXT, status_code INTEGER,
            redirect_url TEXT, title TEXT, FOREIGN KEY (host_id) REFERENCES hosts(id));" 2>/dev/null || true
        sqlite3 "$DB_FILE" "CREATE TABLE IF NOT EXISTS runs (
            id INTEGER PRIMARY KEY, module TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            duration_seconds INTEGER, status TEXT, options_json TEXT);" 2>/dev/null || true
    fi
}

# --- DATABASE HELPER FUNCTIONS ---

# Generic SQL execution
db_exec() {
    sqlite3 "$DB_FILE" "$1"
}

# Add or update a host; returns the host ID
db_add_or_get_host() {
    local ip_address="$1"
    local mac_address="${2:-NULL}"
    local vendor="${3:-NULL}"

    # Escape single quotes to prevent SQL injection
    local safe_ip="${ip_address//\'/\'\'}"
    local safe_mac="${mac_address//\'/\'\'}"
    local safe_vendor="${vendor//\'/\'\'}"

    db_exec "INSERT OR IGNORE INTO hosts (ip_address, mac_address, vendor) VALUES ('$safe_ip', '$safe_mac', '$safe_vendor');"
    db_exec "UPDATE hosts SET last_seen = CURRENT_TIMESTAMP WHERE ip_address = '$safe_ip';"
    db_exec "SELECT id FROM hosts WHERE ip_address = '$safe_ip';"
}

# Add a port for a host; returns the port ID
db_add_or_get_port() {
    local host_id="$1"
    local port_number="$2"
    local protocol="$3"
    local service_name="${4:-NULL}"
    local state="${5:-open}"

    local safe_proto="${protocol//\'/\'\'}"
    local safe_svc="${service_name//\'/\'\'}"
    local safe_state="${state//\'/\'\'}"

    db_exec "INSERT OR IGNORE INTO ports (host_id, port_number, protocol, service_name, state) VALUES ($host_id, $port_number, '$safe_proto', '$safe_svc', '$safe_state');"
    db_exec "SELECT id FROM ports WHERE host_id = $host_id AND port_number = $port_number AND protocol = '$safe_proto';"
}

# Add a vulnerability for a port
db_add_vulnerability() {
    local port_id="$1"
    local cve_id="$2"
    local cvss_score="${3:-0.0}"
    local description="${4:-NULL}"

    local safe_cve="${cve_id//\'/\'\'}"
    local safe_desc="${description//\'/\'\'}"

    db_exec "INSERT OR IGNORE INTO vulnerabilities (port_id, cve_id, cvss_score, description) VALUES ($port_id, '$safe_cve', $cvss_score, '$safe_desc');"
}

# Record a module execution run in the runs table
db_add_run() {
    local module="${1//\'/\'\'}"
    local duration="${2:-0}"
    local status="${3//\'/\'\'}"
    local options_json="${4//\'/\'\'}"

    db_exec "INSERT INTO runs (module, duration_seconds, status, options_json) VALUES ('$module', $duration, '$status', '$options_json');"
}

# Return recent runs as pipe-delimited rows: id|module|timestamp|duration|status
db_get_runs() {
    local limit="${1:-20}"
    db_exec "SELECT id, module, timestamp, duration_seconds, status FROM runs ORDER BY timestamp DESC LIMIT $limit;"
}
