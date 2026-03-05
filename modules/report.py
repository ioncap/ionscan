#!/usr/bin/env python3
import sys
import os
import sqlite3
import json
import csv
import io
import html as html_lib
from datetime import datetime


def get_data_from_db(db_path):
    """Fetches and structures data from the SQLite database."""
    inventory = {}
    if not os.path.exists(db_path):
        return inventory

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM hosts ORDER BY last_seen DESC")
    hosts = cursor.fetchall()

    for host in hosts:
        host_id = host['id']
        ip_address = host['ip_address']
        host_dict = dict(host)
        os_guess = host_dict.get('os_guess') or ''

        inventory[ip_address] = {
            "mac": host['mac_address'] or '',
            "vendor": host['vendor'] or '',
            "os_guess": os_guess,
            "first_seen": host['first_seen'],
            "last_seen": host['last_seen'],
            "ports": [],
            "vulns": [],
            "max_score": 0.0
        }

        cursor.execute("SELECT * FROM ports WHERE host_id = ?", (host_id,))
        ports = cursor.fetchall()

        for port in ports:
            port_id = port['id']
            port_info = {
                'port': port['port_number'],
                'proto': port['protocol'],
                'service': port['service_name'] or '',
                'state': port['state'] or 'open'
            }
            inventory[ip_address]['ports'].append(port_info)

            cursor.execute("SELECT * FROM vulnerabilities WHERE port_id = ?", (port_id,))
            vulns = cursor.fetchall()

            for vuln in vulns:
                vuln_data = {
                    'id': vuln['cve_id'],
                    'score': vuln['cvss_score'],
                    'port': port['port_number'],
                    'proto': port['protocol'],
                    'svc': port['service_name'] or ''
                }
                inventory[ip_address]['vulns'].append(vuln_data)
                if vuln['cvss_score'] > inventory[ip_address]['max_score']:
                    inventory[ip_address]['max_score'] = vuln['cvss_score']

    conn.close()
    return inventory


def _risk_label(score):
    """Return a risk label string for a given CVSS score."""
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    elif score > 0:
        return "LOW"
    return "NONE"


def generate_html_report(inventory_data, template_path, output_path):
    """Generates an interactive HTML dashboard report."""
    risk_data = {
        "Critical": {"count": 0, "color": "#ef4444"},
        "High": {"count": 0, "color": "#f97316"},
        "Medium": {"count": 0, "color": "#eab308"},
        "Low": {"count": 0, "color": "#22c55e"},
        "None": {"count": 0, "color": "#38bdf8"}
    }
    vuln_counts = {}

    for ip, data in inventory_data.items():
        score = data['max_score']
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
            vuln_id = vuln['id']
            vuln_counts[vuln_id] = vuln_counts.get(vuln_id, 0) + 1

    top_vulnerabilities = dict(
        sorted(vuln_counts.items(), key=lambda item: item[1], reverse=True)[:5]
    )

    chart_data = {
        "risk_distribution": [{"label": k, **v} for k, v in risk_data.items()],
        "top_vulnerabilities": top_vulnerabilities,
    }
    chart_data_json = json.dumps(chart_data)

    # Network Scope Card
    PUB_IP = html_lib.escape(os.environ.get("PUB_IP", "?"))
    MY_IP = html_lib.escape(os.environ.get("MY_IP", "?"))
    GATEWAY = html_lib.escape(os.environ.get("GATEWAY", "?"))

    html_output = (
        f'<div class="card" style="border-top:4px solid var(--purple);">'
        f'<details open><summary style="cursor:pointer">'
        f'<h2 style="display:inline;font-size:1.2rem">Network Scope</h2>'
        f'<span style="float:right;color:#94a3b8">&#9660;</span></summary>'
        f'<div style="margin-top:15px;display:grid;gap:10px;'
        f'grid-template-columns:repeat(auto-fit,minmax(200px,1fr));">'
        f'<div><div class="stat-lbl">Public IP</div>'
        f'<div style="font-family:monospace">{PUB_IP}</div></div>'
        f'<div><div class="stat-lbl">Sensor IP</div>'
        f'<div style="font-family:monospace">{MY_IP}</div></div>'
        f'<div><div class="stat-lbl">Gateway</div>'
        f'<div style="font-family:monospace">{GATEWAY}</div></div>'
        f'</div></details></div>'
    )

    # Asset Inventory Table
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
        '<th style="width:30px"></th><th>Asset</th><th>Risk</th>'
        '<th>Findings</th><th>Open Ports</th><th>First Seen</th><th>Last Seen</th>'
        '</tr></thead><tbody>'
    )

    rid = 0
    sorted_inventory = sorted(
        inventory_data.items(), key=lambda item: item[1]['max_score'], reverse=True
    )

    for ip, data in sorted_inventory:
        rid += 1
        cnt = len(data['vulns'])
        score = data['max_score']
        risk = _risk_label(score)
        cls = f"risk-{risk.lower()}"

        safe_ip = html_lib.escape(ip)
        safe_vendor = html_lib.escape(data["vendor"] or "Unknown")
        port_count = len(data['ports'])

        html_output += (
            f'<tr class="asset-row" data-risk="{risk}" data-rid="{rid}" style="cursor:pointer">'
            f'<td>&#9658;</td>'
            f'<td><strong>{safe_ip}</strong>'
            f'<div style="font-size:0.8rem;opacity:0.7">{safe_vendor}</div></td>'
            f'<td><span class="badge {cls}">{risk}</span></td>'
            f'<td>{cnt}</td><td>{port_count}</td>'
            f'<td>{data["first_seen"]}</td><td>{data["last_seen"]}</td></tr>'
        )

        html_output += (
            f'<tr id="row-{rid}" class="details-row">'
            f'<td colspan="7" style="padding:0 20px 20px 50px">'
        )

        # Vulnerabilities sub-table
        if cnt > 0:
            html_output += (
                '<table style="background:#0f172a;border-radius:8px;margin-bottom:8px">'
                '<thead><tr><th>CVE</th><th>Service</th><th>CVSS</th></tr></thead><tbody>'
            )
            for v in sorted(data['vulns'], key=lambda x: x['score'], reverse=True):
                s_color = (
                    "#ef4444" if v['score'] >= 9.0 else
                    "#f97316" if v['score'] >= 7.0 else
                    "#eab308" if v['score'] >= 4.0 else "#22c55e"
                )
                safe_cve = html_lib.escape(v['id'])
                safe_svc = html_lib.escape(v['svc'])
                html_output += (
                    f'<tr><td><a href="https://nvd.nist.gov/vuln/detail/{safe_cve}" '
                    f'target="_blank">{safe_cve}</a></td>'
                    f'<td>{safe_svc}/{v["port"]}</td>'
                    f'<td style="color:{s_color}">{v["score"]}</td></tr>'
                )
            html_output += '</tbody></table>'
        else:
            html_output += "<p style='color:#22c55e;margin:8px 0'>No vulnerabilities found.</p>"

        # Open ports sub-table
        if data['ports']:
            html_output += (
                '<table style="background:#0f172a;border-radius:8px">'
                '<thead><tr><th>Port</th><th>Protocol</th><th>Service</th><th>State</th></tr></thead><tbody>'
            )
            for pinfo in sorted(data['ports'], key=lambda x: x['port']):
                safe_svc = html_lib.escape(pinfo['service'] or '')
                html_output += (
                    f'<tr><td>{pinfo["port"]}</td>'
                    f'<td>{html_lib.escape(pinfo["proto"])}</td>'
                    f'<td>{safe_svc}</td>'
                    f'<td>{html_lib.escape(pinfo["state"])}</td></tr>'
                )
            html_output += '</tbody></table>'

        html_output += '</td></tr>'

    html_output += '</tbody></table></div>'

    with open(template_path, 'r') as f:
        template = f.read()

    final_html = template.replace('__DATE__', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    final_html = final_html.replace('__CHART_DATA__', chart_data_json)
    final_html = final_html.replace('<!-- REPORT_CONTENT -->', html_output)

    with open(output_path, 'w') as f:
        f.write(final_html)


def export_json_report(inventory_data):
    """Exports a structured JSON report to stdout."""
    report_data = {
        "network_scope": {
            "public_ip": os.environ.get("PUB_IP", "?"),
            "sensor_ip": os.environ.get("MY_IP", "?"),
            "gateway": os.environ.get("GATEWAY", "?")
        },
        "asset_inventory": []
    }

    sorted_inventory = sorted(
        inventory_data.items(),
        key=lambda item: sum(v['score'] for v in item[1]['vulns']),
        reverse=True
    )
    for ip, data in sorted_inventory:
        asset = {
            "ip": ip,
            "mac": data.get("mac", ""),
            "vendor": data.get("vendor", "Unknown"),
            "os_guess": data.get("os_guess", ""),
            "max_risk_score": data.get("max_score", 0.0),
            "open_ports": data.get("ports", []),
            "vulnerabilities": []
        }
        for v in sorted(data['vulns'], key=lambda x: x['score'], reverse=True):
            asset["vulnerabilities"].append({
                "id": v["id"],
                "score": v["score"],
                "port": v["port"],
                "service": v["svc"]
            })
        report_data["asset_inventory"].append(asset)

    print(json.dumps(report_data, indent=4))


def export_csv_report(inventory_data):
    """Exports a flat CSV report of all assets, ports, and vulnerabilities to stdout."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        'ip', 'mac', 'vendor', 'os_guess', 'risk_level',
        'port', 'protocol', 'service', 'state',
        'cve_id', 'cvss_score'
    ])

    sorted_inventory = sorted(
        inventory_data.items(), key=lambda x: x[1]['max_score'], reverse=True
    )

    for ip, data in sorted_inventory:
        risk = _risk_label(data['max_score'])

        if data['vulns']:
            for v in sorted(data['vulns'], key=lambda x: x['score'], reverse=True):
                writer.writerow([
                    ip, data.get('mac', ''), data.get('vendor', ''),
                    data.get('os_guess', ''), risk,
                    v['port'], v.get('proto', ''), v['svc'], 'open',
                    v['id'], v['score']
                ])
        elif data['ports']:
            for pinfo in sorted(data['ports'], key=lambda x: x['port']):
                writer.writerow([
                    ip, data.get('mac', ''), data.get('vendor', ''),
                    data.get('os_guess', ''), risk,
                    pinfo['port'], pinfo.get('proto', ''),
                    pinfo.get('service', ''), pinfo.get('state', 'open'),
                    '', ''
                ])
        else:
            writer.writerow([
                ip, data.get('mac', ''), data.get('vendor', ''),
                data.get('os_guess', ''), risk,
                '', '', '', '', '', ''
            ])

    print(output.getvalue(), end='')


# --- Main execution ---
if __name__ == "__main__":
    db_path = os.environ.get("DB_FILE")
    if not db_path:
        print("Error: DB_FILE environment variable is not set.", file=sys.stderr)
        sys.exit(1)

    inventory_data = get_data_from_db(db_path)

    if "--json" in sys.argv:
        export_json_report(inventory_data)
    elif "--csv" in sys.argv:
        export_csv_report(inventory_data)
    elif len(sys.argv) == 3:
        template_path = sys.argv[1]
        output_path = sys.argv[2]
        generate_html_report(inventory_data, template_path, output_path)
    else:
        print(
            "Usage: report.py <template_path> <output_path> | --json | --csv",
            file=sys.stderr
        )
        sys.exit(1)
