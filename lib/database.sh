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
            CREATE TABLE hosts (
                id INTEGER PRIMARY KEY,
                ip_address TEXT UNIQUE NOT NULL,
                mac_address TEXT,
                vendor TEXT,
                first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE ports (
                id INTEGER PRIMARY KEY,
                host_id INTEGER NOT NULL,
                port_number INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                service_name TEXT,
                state TEXT,
                FOREIGN KEY (host_id) REFERENCES hosts(id)
            );
            CREATE TABLE vulnerabilities (
                id INTEGER PRIMARY KEY,
                port_id INTEGER NOT NULL,
                cve_id TEXT NOT NULL,
                cvss_score REAL,
                description TEXT,
                FOREIGN KEY (port_id) REFERENCES ports(id)
            );
            CREATE UNIQUE INDEX idx_host_port_proto ON ports (host_id, port_number, protocol);
            CREATE UNIQUE INDEX idx_vuln_port_cve ON vulnerabilities (port_id, cve_id);
EOF
        if [[ $? -eq 0 ]]; then
            log_success "Database initialized successfully."
        else
            log_error "Failed to initialize database."
            exit 1
        fi
    fi
}

# --- DATABASE HELPER FUNCTIONS ---

# Generic function to execute SQL
db_exec() {
    sqlite3 "$DB_FILE" "$1"
}

# Function to add or update a host
# Returns the host ID
db_add_or_get_host() {
    local ip_address="$1"
    local mac_address="${2:-NULL}"
    local vendor="${3:-NULL}"

    # Try to insert, ignore if it already exists
    db_exec "INSERT OR IGNORE INTO hosts (ip_address, mac_address, vendor) VALUES ('$ip_address', '$mac_address', '$vendor');"
    
    # Update last_seen timestamp
    db_exec "UPDATE hosts SET last_seen = CURRENT_TIMESTAMP WHERE ip_address = '$ip_address';"

    # Get the ID of the host
    db_exec "SELECT id FROM hosts WHERE ip_address = '$ip_address';"
}

# Function to add a port for a host
# Returns the port ID
db_add_or_get_port() {
    local host_id="$1"
    local port_number="$2"
    local protocol="$3"
    local service_name="${4:-NULL}"
    local state="${5:-open}"
    
    db_exec "INSERT OR IGNORE INTO ports (host_id, port_number, protocol, service_name, state) VALUES ($host_id, $port_number, '$protocol', '$service_name', '$state');"
    
    db_exec "SELECT id FROM ports WHERE host_id = $host_id AND port_number = $port_number AND protocol = '$protocol';"
}

# Function to add a vulnerability for a port
db_add_vulnerability() {
    local port_id="$1"
    local cve_id="$2"
    local cvss_score="${3:-0.0}"
    local description="${4:-NULL}"

    db_exec "INSERT OR IGNORE INTO vulnerabilities (port_id, cve_id, cvss_score, description) VALUES ($port_id, '$cve_id', $cvss_score, '$description');"
}
