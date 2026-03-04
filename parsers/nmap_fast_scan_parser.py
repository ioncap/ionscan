#!/usr/bin/env python3
"""nmap_fast_scan_parser.py — Parse Nmap XML output (fast/port scans) into SQLite."""

from __future__ import annotations

import os
import sys
import sqlite3
import xml.etree.ElementTree as ET
from typing import Optional


def parse_nmap_xml(xml_input: str, db_path: str) -> None:
    """Parse Nmap XML output for open ports and update the database atomically."""
    try:
        tree = ET.fromstring(xml_input)
    except ET.ParseError as exc:
        print(f"Error: Nmap XML is malformed or incomplete: {exc}", file=sys.stderr)
        sys.exit(1)

    conn = sqlite3.connect(db_path, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")

    try:
        with conn:  # single atomic transaction for the entire import
            for host in tree.findall('host'):
                ip_elem = host.find('address')
                if ip_elem is None:
                    continue
                ip_address: str = ip_elem.get('addr', '')
                if not ip_address:
                    continue

                mac_elem: Optional[ET.Element] = host.find("address[@addrtype='mac']")
                mac_address: Optional[str] = mac_elem.get('addr') if mac_elem is not None else None
                vendor: Optional[str] = mac_elem.get('vendor') if mac_elem is not None else None

                conn.execute(
                    "INSERT OR IGNORE INTO hosts (ip_address, mac_address, vendor) "
                    "VALUES (?, ?, ?)",
                    (ip_address, mac_address, vendor),
                )
                conn.execute(
                    "UPDATE hosts SET last_seen = CURRENT_TIMESTAMP "
                    "WHERE ip_address = ?",
                    (ip_address,),
                )
                row = conn.execute(
                    "SELECT id FROM hosts WHERE ip_address = ?", (ip_address,)
                ).fetchone()
                if row is None:
                    continue
                host_id: int = row[0]

                for port_elem in host.findall('.//port'):
                    port_number = int(port_elem.get('portid', 0))
                    protocol: str = port_elem.get('protocol', 'tcp')
                    state_elem = port_elem.find('state')
                    state: str = state_elem.get('state', '') if state_elem is not None else ''
                    svc_elem = port_elem.find('service')
                    service_name: Optional[str] = (
                        svc_elem.get('name') if svc_elem is not None else None
                    )

                    if state == 'open':
                        conn.execute(
                            "INSERT OR IGNORE INTO ports "
                            "(host_id, port_number, protocol, service_name, state) "
                            "VALUES (?, ?, ?, ?, ?)",
                            (host_id, port_number, protocol, service_name, state),
                        )

    except sqlite3.Error as exc:
        print(f"Database error during import: {exc}", file=sys.stderr)
        conn.close()
        sys.exit(1)
    finally:
        conn.close()

    print("Successfully parsed and updated database with open ports.")


if __name__ == "__main__":
    db_path = os.environ.get("DB_FILE", "")
    if not db_path:
        print("Error: DB_FILE environment variable is not set.", file=sys.stderr)
        sys.exit(1)

    xml_input_data = sys.stdin.read()
    if not xml_input_data.strip():
        print("No XML data received from stdin.", file=sys.stderr)
        sys.exit(1)

    parse_nmap_xml(xml_input_data, db_path)
