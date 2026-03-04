#!/usr/bin/env python3
"""
db_write.py — Parameterized database write helper for IonScan.

Called from Bash via: python3 lib/db_write.py <operation> [args...]

Operations:
  add_host <ip> [mac] [vendor]         -> prints host_id
  add_port <host_id> <port> <proto> [svc] [state]  -> prints port_id
  add_vuln <port_id> <cve> [cvss] [desc]            -> no output
  update_seen <ip>                     -> no output
  init_db                              -> creates schema if needed
  add_runs_table                       -> creates runs table if needed
  insert_run <module> <duration> <status> <options_json>  -> prints run_id
"""

from __future__ import annotations

import os
import sys
import sqlite3
from typing import Optional


def get_db_path() -> str:
    """Return the database path from environment."""
    db_path = os.environ.get("DB_FILE", "")
    if not db_path:
        print("Error: DB_FILE environment variable is not set.", file=sys.stderr)
        sys.exit(1)
    return db_path


def get_connection(db_path: str) -> sqlite3.Connection:
    """Open and return a sqlite3 connection with WAL mode for concurrency."""
    conn = sqlite3.connect(db_path, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(db_path: str) -> None:
    """Create the schema tables if they do not yet exist."""
    conn = get_connection(db_path)
    with conn:
        conn.executescript("""
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
                FOREIGN KEY (host_id) REFERENCES hosts(id),
                UNIQUE (host_id, port_number, protocol)
            );
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY,
                port_id INTEGER NOT NULL,
                cve_id TEXT NOT NULL,
                cvss_score REAL,
                description TEXT,
                FOREIGN KEY (port_id) REFERENCES ports(id),
                UNIQUE (port_id, cve_id)
            );
            CREATE TABLE IF NOT EXISTS http_info (
                id INTEGER PRIMARY KEY,
                host_id INTEGER NOT NULL,
                port_number INTEGER NOT NULL,
                server_header TEXT,
                status_code INTEGER,
                redirect_chain TEXT,
                cert_info TEXT,
                scanned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (host_id) REFERENCES hosts(id)
            );
            CREATE TABLE IF NOT EXISTS runs (
                id INTEGER PRIMARY KEY,
                module TEXT NOT NULL,
                started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                duration_s INTEGER,
                status TEXT,
                options_json TEXT
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_host_port_proto
                ON ports (host_id, port_number, protocol);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_vuln_port_cve
                ON vulnerabilities (port_id, cve_id);
        """)
    conn.close()


def add_host(db_path: str, ip: str, mac: Optional[str], vendor: Optional[str]) -> int:
    """Insert or update a host; return its id."""
    conn = get_connection(db_path)
    with conn:
        conn.execute(
            "INSERT OR IGNORE INTO hosts (ip_address, mac_address, vendor) VALUES (?, ?, ?)",
            (ip, mac, vendor),
        )
        conn.execute(
            "UPDATE hosts SET last_seen = CURRENT_TIMESTAMP WHERE ip_address = ?",
            (ip,),
        )
        row = conn.execute(
            "SELECT id FROM hosts WHERE ip_address = ?", (ip,)
        ).fetchone()
    conn.close()
    return row[0]


def add_port(
    db_path: str,
    host_id: int,
    port_number: int,
    protocol: str,
    service_name: Optional[str],
    state: str,
) -> int:
    """Insert or ignore a port; return its id."""
    conn = get_connection(db_path)
    with conn:
        conn.execute(
            "INSERT OR IGNORE INTO ports "
            "(host_id, port_number, protocol, service_name, state) "
            "VALUES (?, ?, ?, ?, ?)",
            (host_id, port_number, protocol, service_name, state),
        )
        row = conn.execute(
            "SELECT id FROM ports WHERE host_id = ? AND port_number = ? AND protocol = ?",
            (host_id, port_number, protocol),
        ).fetchone()
    conn.close()
    return row[0]


def add_vulnerability(
    db_path: str,
    port_id: int,
    cve_id: str,
    cvss_score: float,
    description: Optional[str],
) -> None:
    """Insert a vulnerability (ignore duplicates)."""
    conn = get_connection(db_path)
    with conn:
        conn.execute(
            "INSERT OR IGNORE INTO vulnerabilities "
            "(port_id, cve_id, cvss_score, description) VALUES (?, ?, ?, ?)",
            (port_id, cve_id, cvss_score, description),
        )
    conn.close()


def update_last_seen(db_path: str, ip: str) -> None:
    """Update last_seen timestamp for a host."""
    conn = get_connection(db_path)
    with conn:
        conn.execute(
            "UPDATE hosts SET last_seen = CURRENT_TIMESTAMP WHERE ip_address = ?",
            (ip,),
        )
    conn.close()


def insert_run(
    db_path: str,
    module: str,
    duration: int,
    status: str,
    options_json: str,
) -> int:
    """Record a module run; return its id."""
    conn = get_connection(db_path)
    with conn:
        cursor = conn.execute(
            "INSERT INTO runs (module, duration_s, status, options_json) "
            "VALUES (?, ?, ?, ?)",
            (module, duration, status, options_json),
        )
        run_id = cursor.lastrowid
    conn.close()
    return run_id


def update_os_guess(db_path: str, ip: str, os_guess: str) -> None:
    """Update the os_guess field for a host."""
    conn = get_connection(db_path)
    with conn:
        conn.execute(
            "UPDATE hosts SET os_guess = ? WHERE ip_address = ?",
            (os_guess, ip),
        )
    conn.close()


def add_http_info(
    db_path: str,
    host_id: int,
    port_number: int,
    server_header: Optional[str],
    status_code: Optional[int],
    redirect_chain: Optional[str],
    cert_info: Optional[str],
) -> None:
    """Insert HTTP probe result for a host/port."""
    conn = get_connection(db_path)
    with conn:
        conn.execute(
            "INSERT INTO http_info "
            "(host_id, port_number, server_header, status_code, redirect_chain, cert_info) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (host_id, port_number, server_header, status_code, redirect_chain, cert_info),
        )
    conn.close()


def main() -> None:
    """Dispatch CLI operations."""
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        sys.exit(1)

    db_path = get_db_path()
    op = sys.argv[1]

    if op == "init_db":
        init_db(db_path)

    elif op == "add_host":
        if len(sys.argv) < 3:
            print("Usage: db_write.py add_host <ip> [mac] [vendor]", file=sys.stderr)
            sys.exit(1)
        ip = sys.argv[2]
        mac = sys.argv[3] if len(sys.argv) > 3 else None
        vendor = sys.argv[4] if len(sys.argv) > 4 else None
        print(add_host(db_path, ip, mac, vendor))

    elif op == "add_port":
        if len(sys.argv) < 6:
            print("Usage: db_write.py add_port <host_id> <port> <proto> [svc] [state]",
                  file=sys.stderr)
            sys.exit(1)
        host_id = int(sys.argv[2])
        port_number = int(sys.argv[3])
        protocol = sys.argv[4]
        svc = sys.argv[5] if len(sys.argv) > 5 else None
        state = sys.argv[6] if len(sys.argv) > 6 else "open"
        print(add_port(db_path, host_id, port_number, protocol, svc, state))

    elif op == "add_vuln":
        if len(sys.argv) < 4:
            print("Usage: db_write.py add_vuln <port_id> <cve> [cvss] [desc]",
                  file=sys.stderr)
            sys.exit(1)
        port_id = int(sys.argv[2])
        cve_id = sys.argv[3]
        cvss = float(sys.argv[4]) if len(sys.argv) > 4 else 0.0
        desc = sys.argv[5] if len(sys.argv) > 5 else None
        add_vulnerability(db_path, port_id, cve_id, cvss, desc)

    elif op == "update_seen":
        if len(sys.argv) < 3:
            print("Usage: db_write.py update_seen <ip>", file=sys.stderr)
            sys.exit(1)
        update_last_seen(db_path, sys.argv[2])

    elif op == "insert_run":
        if len(sys.argv) < 6:
            print("Usage: db_write.py insert_run <module> <duration> <status> <options_json>",
                  file=sys.stderr)
            sys.exit(1)
        module = sys.argv[2]
        duration = int(sys.argv[3])
        status = sys.argv[4]
        options_json = sys.argv[5]
        print(insert_run(db_path, module, duration, status, options_json))

    elif op == "update_os_guess":
        if len(sys.argv) < 4:
            print("Usage: db_write.py update_os_guess <ip> <os_guess>", file=sys.stderr)
            sys.exit(1)
        update_os_guess(db_path, sys.argv[2], sys.argv[3])

    elif op == "add_http_info":
        if len(sys.argv) < 4:
            print("Usage: db_write.py add_http_info <host_id> <port> [server] [code] "
                  "[redirect_chain] [cert_info]", file=sys.stderr)
            sys.exit(1)
        host_id = int(sys.argv[2])
        port_number = int(sys.argv[3])
        server = sys.argv[4] if len(sys.argv) > 4 else None
        code = int(sys.argv[5]) if len(sys.argv) > 5 and sys.argv[5].isdigit() else None
        redirect_chain = sys.argv[6] if len(sys.argv) > 6 else None
        cert_info = sys.argv[7] if len(sys.argv) > 7 else None
        add_http_info(db_path, host_id, port_number, server, code, redirect_chain, cert_info)

    else:
        print(f"Unknown operation: {op}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
