#!/usr/bin/env python3
import sys
import xml.etree.ElementTree as ET
import sqlite3
import os
import re


def parse_nmap_xml(xml_input, db_path):
    """Parses Nmap XML output and inserts vulnerability findings into the database."""

    try:
        tree = ET.fromstring(xml_input)
    except ET.ParseError as e:
        print(f"Error: Failed to parse Nmap XML output: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cve_pat = re.compile(r"(CVE-\d{4}-\d+)")

        with conn:  # single transaction — auto-commit on success, rollback on error
            for host in tree.findall('host'):
                ip_address = host.find('address').get('addr')
                mac_address_elem = host.find("address[@addrtype='mac']")
                mac_address = mac_address_elem.get('addr') if mac_address_elem is not None else None
                vendor_elem = host.find("address[@addrtype='mac']")
                vendor = vendor_elem.get('vendor') if vendor_elem is not None else None

                cursor.execute(
                    "INSERT OR IGNORE INTO hosts (ip_address, mac_address, vendor) VALUES (?, ?, ?)",
                    (ip_address, mac_address, vendor)
                )
                cursor.execute(
                    "UPDATE hosts SET last_seen = CURRENT_TIMESTAMP WHERE ip_address = ?",
                    (ip_address,)
                )
                host_row = cursor.execute(
                    "SELECT id FROM hosts WHERE ip_address = ?", (ip_address,)
                ).fetchone()
                if host_row is None:
                    continue
                host_id = host_row[0]

                for port_elem in host.findall('.//port'):
                    port_number = int(port_elem.get('portid'))
                    protocol = port_elem.get('protocol')
                    state_elem = port_elem.find('state')
                    state = state_elem.get('state') if state_elem is not None else 'unknown'
                    service_name_elem = port_elem.find('service')
                    service_name = service_name_elem.get('name') if service_name_elem is not None else None

                    cursor.execute(
                        "INSERT OR IGNORE INTO ports "
                        "(host_id, port_number, protocol, service_name, state) "
                        "VALUES (?, ?, ?, ?, ?)",
                        (host_id, port_number, protocol, service_name, state)
                    )
                    port_row = cursor.execute(
                        "SELECT id FROM ports WHERE host_id = ? AND port_number = ? AND protocol = ?",
                        (host_id, port_number, protocol)
                    ).fetchone()
                    if port_row is None:
                        continue
                    port_id = port_row[0]

                    # Extract CVEs from vulners NSE script output
                    for script_elem in port_elem.findall("script[@id='vulners']"):
                        for table_elem in script_elem.findall("table"):
                            for row in table_elem.findall("table"):
                                id_nd = row.find("elem[@key='id']")
                                cvss_nd = row.find("elem[@key='cvss']")

                                if id_nd is not None:
                                    cve_id_full = id_nd.text or ''
                                    cvss_score = 0.0
                                    if cvss_nd is not None and cvss_nd.text:
                                        try:
                                            cvss_score = float(cvss_nd.text)
                                        except ValueError:
                                            cvss_score = 0.0

                                    match = cve_pat.search(cve_id_full)
                                    cve_id = match.group(1) if match else cve_id_full

                                    cursor.execute(
                                        "INSERT OR IGNORE INTO vulnerabilities "
                                        "(port_id, cve_id, cvss_score) VALUES (?, ?, ?)",
                                        (port_id, cve_id, cvss_score)
                                    )

        conn.close()
        print("Successfully parsed and updated database.")

    except Exception as e:
        print(f"Error updating database: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    db_path = os.environ.get("DB_FILE")
    if not db_path:
        print("Error: DB_FILE environment variable is not set.", file=sys.stderr)
        sys.exit(1)

    xml_input_data = sys.stdin.read()
    if not xml_input_data:
        print("No XML data received from stdin.", file=sys.stderr)
        sys.exit(1)

    parse_nmap_xml(xml_input_data, db_path)
