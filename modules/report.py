#!/usr/bin/env python3
"""
report.py — IonScan report generator.

Supports HTML, JSON, and CSV output formats.
Optionally generates PDF via weasyprint if available.

Usage:
    report.py <template_path> <output_path>       # HTML
    report.py --json                               # JSON to stdout
    report.py --csv <output_path>                  # CSV flat export
    report.py --pdf <template_path> <output_path>  # PDF (requires weasyprint)
"""

from __future__ import annotations

import csv
import json
import os
import sys
import sqlite3
from datetime import datetime
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Type aliases
# ---------------------------------------------------------------------------
InventoryItem = Dict[str, Any]
Inventory = Dict[str, InventoryItem]


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

def get_data_from_db(db_path: str) -> Inventory:
    """Fetch and structure all data from the SQLite database."""
    inventory: Inventory = {}
    if not os.path.exists(db_path):
        return inventory

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT * FROM hosts ORDER BY last_seen DESC")
    except sqlite3.OperationalError:
        conn.close()
        return inventory

    hosts = cursor.fetchall()

    for host in hosts:
        host_id: int = host['id']
        ip_address: str = host['ip_address']

        try:
            os_guess: Optional[str] = host['os_guess']
        except IndexError:
            os_guess = None

        inventory[ip_address] = {
            "mac": host['mac_address'],
            "vendor": host['vendor'],
            "os_guess": os_guess,
            "first_seen": host['first_seen'],
            "last_seen": host['last_seen'],
            "ports": [],
            "vulns": [],
            "max_score": 0.0,
            "http_info": [],
        }

        cursor.execute("SELECT * FROM ports WHERE host_id = ?", (host_id,))
        ports = cursor.fetchall()

        for port in ports:
            port_id: int = port['id']
            inventory[ip_address]['ports'].append({
                "port": port['port_number'],
                "proto": port['protocol'],
                "service": port['service_name'],
                "state": port['state'],
            })

            cursor.execute(
                "SELECT * FROM vulnerabilities WHERE port_id = ?", (port_id,)
            )
            vulns = cursor.fetchall()

            for vuln in vulns:
                vuln_data: Dict[str, Any] = {
                    'id': vuln['cve_id'],
                    'score': vuln['cvss_score'],
                    'port': port['port_number'],
                    'svc': port['service_name'],
                }
                inventory[ip_address]['vulns'].append(vuln_data)
                if vuln['cvss_score'] > inventory[ip_address]['max_score']:
                    inventory[ip_address]['max_score'] = vuln['cvss_score']

        try:
            cursor.execute(
                "SELECT * FROM http_info WHERE host_id = ? ORDER BY port_number", (host_id,)
            )
            for row in cursor.fetchall():
                inventory[ip_address]['http_info'].append({
                    "port": row['port_number'],
                    "server": row['server_header'],
                    "status": row['status_code'],
                    "redirect_chain": row['redirect_chain'],
                    "cert_info": row['cert_info'],
                })
        except sqlite3.OperationalError:
            pass

    conn.close()
    return inventory


# ---------------------------------------------------------------------------
# Risk classification
# ---------------------------------------------------------------------------

def classify_risk(score: float) -> tuple:
    """Return (risk_label, css_class) for a CVSS score."""
    if score >= 9.0:
        return "CRITICAL", "risk-critical"
    if score >= 7.0:
        return "HIGH", "risk-high"
    if score >= 4.0:
        return "MEDIUM", "risk-medium"
    if score > 0:
        return "LOW", "risk-low"
    return "NONE", "risk-none"


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

def generate_html_report(
    inventory_data: Inventory,
    template_path: str,
    output_path: str,
) -> None:
    """Generate an HTML dashboard report."""
    risk_data: Dict[str, Dict[str, Any]] = {
        "Critical": {"count": 0, "color": "#ef4444"},
        "High":     {"count": 0, "color": "#f97316"},
        "Medium":   {"count": 0, "color": "#eab308"},
        "Low":      {"count": 0, "color": "#22c55e"},
        "None":     {"count": 0, "color": "#38bdf8"},
    }
    vuln_counts: Dict[str, int] = {}

    for _ip, data in inventory_data.items():
        score: float = data['max_score']
        if score >= 9.0:
            risk_data["Critical"]["count"] += 1
        elif score >= 7.0:
            risk_data["High"]["count"] += 1
        elif score >= 4.0:
            risk_data["Medium"]["count"] += 1
        elif score > 0:
            risk_data["Low"]["count"] += 1
        else:
            risk_data["None"]["count"] += 1

        for vuln in data['vulns']:
            vuln_id: str = vuln['id']
            vuln_counts[vuln_id] = vuln_counts.get(vuln_id, 0) + 1

    top_vulnerabilities = dict(
        sorted(vuln_counts.items(), key=lambda item: item[1], reverse=True)[:5]
    )

    chart_data: Dict[str, Any] = {
        "risk_distribution": [{"label": k, **v} for k, v in risk_data.items()],
        "top_vulnerabilities": top_vulnerabilities,
    }
    chart_data_json: str = json.dumps(chart_data)

    pub_ip: str = os.environ.get("PUB_IP", "?")
    my_ip: str = os.environ.get("MY_IP", "?")
    gateway: str = os.environ.get("GATEWAY", "?")

    html_output = (
        f'<div class="card" style="border-top:4px solid var(--purple);">'
        f'<details open><summary style="cursor:pointer">'
        f'<h2 style="display:inline;font-size:1.2rem">Network Scope</h2>'
        f'<span style="float:right;color:#94a3b8">&#9660;</span></summary>'
        f'<div style="margin-top:15px;display:grid;gap:10px;'
        f'grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));">'
        f'<div><div class="stat-lbl">Public IP</div>'
        f'<div style="font-family:monospace">{pub_ip}</div></div>'
        f'<div><div class="stat-lbl">Sensor IP</div>'
        f'<div style="font-family:monospace">{my_ip}</div></div>'
        f'<div><div class="stat-lbl">Gateway</div>'
        f'<div style="font-family:monospace">{gateway}</div></div>'
        f'</div></details></div>'
    )

    html_output += '<div class="card" id="asset-table">'
    html_output += (
        '<div class="filter-toolbar">'
        '<input type="text" id="search-input" placeholder="Search IP or Vendor...">'
        '<div class="risk-filters">'
    )
    html_output += '<span class="badge risk-filter" data-risk="All" style="opacity:1">All</span>'
    for r in risk_data:
        html_output += (
            f'<span class="badge risk-{r.lower()} risk-filter" data-risk="{r}">{r}</span>'
        )
    html_output += '</div></div>'

    html_output += (
        '<table><thead><tr>'
        '<th style="width:30px"></th>'
        '<th>Asset</th><th>Risk</th><th>Findings</th>'
        '<th>OS</th><th>First Seen</th><th>Last Seen</th>'
        '</tr></thead><tbody>'
    )

    rid = 0
    sorted_inventory = sorted(
        inventory_data.items(),
        key=lambda item: item[1]['max_score'],
        reverse=True,
    )

    for ip, data in sorted_inventory:
        rid += 1
        cnt = len(data['vulns'])
        score = data['max_score']
        risk, cls = classify_risk(score)
        os_guess_str: str = data.get('os_guess') or '&#8212;'

        html_output += (
            f'<tr class="asset-row" data-risk="{risk}" '
            f'onclick="toggle({rid}, this)" style="cursor:pointer">'
            f'<td>&#9654;</td>'
            f'<td><strong>{ip}</strong>'
            f'<div style="font-size:0.8rem;opacity:0.7">{data["vendor"]}</div></td>'
            f'<td><span class="badge {cls}">{risk}</span></td>'
            f'<td>{cnt}</td>'
            f'<td style="font-size:0.8rem">{os_guess_str}</td>'
            f'<td>{data["first_seen"]}</td>'
            f'<td>{data["last_seen"]}</td>'
            f'</tr>'
        )
        html_output += (
            f'<tr id="row-{rid}" class="details-row">'
            f'<td colspan="7" style="padding:0 20px 20px 50px">'
            f'<table style="background:#0f172a;border-radius:8px">'
        )

        if cnt > 0:
            for v in sorted(data['vulns'], key=lambda x: x['score'], reverse=True):
                score_v: float = v['score']
                if score_v >= 9.0:
                    score_color = "#ef4444"
                elif score_v >= 7.0:
                    score_color = "#f97316"
                elif score_v >= 4.0:
                    score_color = "#eab308"
                else:
                    score_color = "#22c55e"
                html_output += (
                    f'<tr>'
                    f'<td><a href="https://nvd.nist.gov/vuln/detail/{v["id"]}" '
                    f'target="_blank">{v["id"]}</a></td>'
                    f'<td>{v["svc"]}/{v["port"]}</td>'
                    f'<td style="color:{score_color}">{v["score"]}</td>'
                    f'</tr>'
                )
        else:
            html_output += "<tr><td style='color:#22c55e'>No vulnerabilities found.</td></tr>"

        if data.get('http_info'):
            html_output += (
                '<tr><td colspan="3" style="padding-top:8px;font-weight:bold">'
                'HTTP Services:</td></tr>'
            )
            for h in data['http_info']:
                html_output += (
                    f'<tr><td colspan="3" style="font-size:0.8rem;color:#94a3b8">'
                    f':{h["port"]} [{h["status"]}] {h["server"] or ""}</td></tr>'
                )

        html_output += '</table></td></tr>'

    html_output += '</tbody></table></div>'

    with open(template_path, 'r') as f:
        template = f.read()

    final_html = template.replace('__DATE__', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    final_html = final_html.replace('__CHART_DATA__', chart_data_json)
    final_html = final_html.replace('<!-- REPORT_CONTENT -->', html_output)

    with open(output_path, 'w') as f:
        f.write(final_html)


# ---------------------------------------------------------------------------
# JSON report
# ---------------------------------------------------------------------------

def export_json_report(inventory_data: Inventory) -> None:
    """Print a structured JSON report to stdout."""
    report_data: Dict[str, Any] = {
        "generated_at": datetime.now().isoformat(),
        "network_scope": {
            "public_ip": os.environ.get("PUB_IP", "?"),
            "sensor_ip": os.environ.get("MY_IP", "?"),
            "gateway": os.environ.get("GATEWAY", "?"),
        },
        "asset_inventory": [],
    }

    sorted_inventory = sorted(
        inventory_data.items(),
        key=lambda item: sum(v['score'] for v in item[1]['vulns']),
        reverse=True,
    )

    for ip, data in sorted_inventory:
        risk_label, _ = classify_risk(data.get('max_score', 0.0))
        asset: Dict[str, Any] = {
            "ip": ip,
            "mac": data.get("mac", "-"),
            "vendor": data.get("vendor", "Unknown"),
            "os_guess": data.get("os_guess"),
            "risk": risk_label,
            "max_risk_score": data.get("max_score", 0.0),
            "ports": data.get("ports", []),
            "vulnerabilities": [],
            "http_info": data.get("http_info", []),
        }
        for v in sorted(data['vulns'], key=lambda x: x['score'], reverse=True):
            asset["vulnerabilities"].append({
                "id": v["id"],
                "score": v["score"],
                "port": v["port"],
                "service": v["svc"],
            })
        report_data["asset_inventory"].append(asset)

    print(json.dumps(report_data, indent=4))


# ---------------------------------------------------------------------------
# CSV export
# ---------------------------------------------------------------------------

def export_csv_report(inventory_data: Inventory, output_path: str) -> None:
    """Write a flat CSV of all host/port/vulnerability rows."""
    fieldnames = [
        "ip", "mac", "vendor", "os_guess", "risk",
        "port", "protocol", "service", "state",
        "cve_id", "cvss_score",
        "first_seen", "last_seen",
    ]

    rows: List[Dict[str, Any]] = []

    for ip, data in inventory_data.items():
        risk_label, _ = classify_risk(data.get('max_score', 0.0))
        base = {
            "ip": ip,
            "mac": data.get("mac") or "",
            "vendor": data.get("vendor") or "",
            "os_guess": data.get("os_guess") or "",
            "risk": risk_label,
            "first_seen": data.get("first_seen") or "",
            "last_seen": data.get("last_seen") or "",
        }

        if not data.get("ports") and not data.get("vulns"):
            row = dict(base)
            for f in ("port", "protocol", "service", "state", "cve_id", "cvss_score"):
                row[f] = ""
            rows.append(row)
            continue

        port_vuln_map: Dict[int, List[Dict[str, Any]]] = {}
        for v in data.get("vulns", []):
            port_vuln_map.setdefault(v["port"], []).append(v)

        for p in data.get("ports", []):
            port_num = p["port"]
            port_vulns = port_vuln_map.get(port_num, [])
            if port_vulns:
                for v in port_vulns:
                    row = dict(base)
                    row.update({
                        "port": port_num,
                        "protocol": p.get("proto", ""),
                        "service": p.get("service") or "",
                        "state": p.get("state") or "",
                        "cve_id": v["id"],
                        "cvss_score": v["score"],
                    })
                    rows.append(row)
            else:
                row = dict(base)
                row.update({
                    "port": port_num,
                    "protocol": p.get("proto", ""),
                    "service": p.get("service") or "",
                    "state": p.get("state") or "",
                    "cve_id": "",
                    "cvss_score": "",
                })
                rows.append(row)

    with open(output_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"CSV report written to {output_path}")


# ---------------------------------------------------------------------------
# PDF export
# ---------------------------------------------------------------------------

def export_pdf_report(
    inventory_data: Inventory,
    template_path: str,
    output_path: str,
) -> None:
    """Generate a PDF report via weasyprint (must be installed)."""
    try:
        from weasyprint import HTML as WeasyHTML  # type: ignore
    except ImportError:
        print(
            "Error: weasyprint is not installed. "
            "Install with: pip install weasyprint",
            file=sys.stderr,
        )
        sys.exit(1)

    import tempfile
    with tempfile.NamedTemporaryFile(suffix='.html', delete=False) as tmp:
        tmp_path = tmp.name

    try:
        generate_html_report(inventory_data, template_path, tmp_path)
        WeasyHTML(filename=tmp_path).write_pdf(output_path)
        print(f"PDF report written to {output_path}")
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    db_path = os.environ.get("DB_FILE", "")
    if not db_path:
        print("Error: DB_FILE environment variable is not set.", file=sys.stderr)
        sys.exit(1)

    inventory_data = get_data_from_db(db_path)

    if "--json" in sys.argv:
        export_json_report(inventory_data)

    elif "--csv" in sys.argv:
        idx = sys.argv.index("--csv")
        if idx + 1 >= len(sys.argv):
            print("Usage: report.py --csv <output_path>", file=sys.stderr)
            sys.exit(1)
        export_csv_report(inventory_data, sys.argv[idx + 1])

    elif "--pdf" in sys.argv:
        idx = sys.argv.index("--pdf")
        if idx + 2 >= len(sys.argv):
            print("Usage: report.py --pdf <template_path> <output_path>", file=sys.stderr)
            sys.exit(1)
        export_pdf_report(inventory_data, sys.argv[idx + 1], sys.argv[idx + 2])

    elif len(sys.argv) == 3:
        generate_html_report(inventory_data, sys.argv[1], sys.argv[2])

    else:
        print(
            "Usage:\n"
            "  report.py <template_path> <output_path>\n"
            "  report.py --json\n"
            "  report.py --csv <output_path>\n"
            "  report.py --pdf <template_path> <output_path>",
            file=sys.stderr,
        )
        sys.exit(1)
