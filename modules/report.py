#!/usr/bin/env python3
import sys
import os
import sqlite3
import json
from datetime import datetime

def get_data_from_db(db_path):
    """Fetches and structures data from the SQLite database."""
    inventory = {}
    if not os.path.exists(db_path):
        return inventory

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Fetch hosts
    cursor.execute("SELECT * FROM hosts ORDER BY last_seen DESC")
    hosts = cursor.fetchall()

    for host in hosts:
        host_id = host['id']
        ip_address = host['ip_address']
        inventory[ip_address] = {
            "mac": host['mac_address'],
            "vendor": host['vendor'],
            "vulns": [],
            "max_score": 0.0
        }

        # Fetch ports for this host
        cursor.execute("SELECT * FROM ports WHERE host_id = ?", (host_id,))
        ports = cursor.fetchall()
        
        for port in ports:
            port_id = port['id']
            # We can add port info to the inventory if needed, but for now, we just need vulnerabilities
            
            # Fetch vulnerabilities for this port
            cursor.execute("SELECT * FROM vulnerabilities WHERE port_id = ?", (port_id,))
            vulns = cursor.fetchall()
            
            for vuln in vulns:
                vuln_data = {
                    'id': vuln['cve_id'],
                    'score': vuln['cvss_score'],
                    'port': port['port_number'],
                    'svc': port['service_name']
                }
                inventory[ip_address]['vulns'].append(vuln_data)
                if vuln['cvss_score'] > inventory[ip_address]['max_score']:
                    inventory[ip_address]['max_score'] = vuln['cvss_score']

    conn.close()
    return inventory

def generate_html_report(inventory_data, template_path, output_path):
    # --- Chart Data Generation ---
    risk_distribution = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "None": 0}
    vuln_counts = {}
    for ip, data in inventory_data.items():
        score = data['max_score']
        if score >= 9.0:
            risk_distribution["Critical"] += 1
        elif score >= 7.0:
            risk_distribution["High"] += 1
        elif score >= 4.0:
            risk_distribution["Medium"] += 1
        elif score > 0:
            risk_distribution["Low"] += 1
        else:
            risk_distribution["None"] += 1

        for vuln in data['vulns']:
            vuln_id = vuln['id']
            vuln_counts[vuln_id] = vuln_counts.get(vuln_id, 0) + 1

    top_vulnerabilities = dict(sorted(vuln_counts.items(), key=lambda item: item[1], reverse=True)[:5])

    chart_data = {
        "risk_distribution": risk_distribution,
        "top_vulnerabilities": top_vulnerabilities,
    }
    chart_data_json = json.dumps(chart_data)

    # --- HTML Content Generation ---
    html_output = ""
    # Network Scope Card
    PUB_IP = os.environ.get("PUB_IP","?")
    MY_IP = os.environ.get("MY_IP","?")
    GATEWAY = os.environ.get("GATEWAY","?")
    
    html_output += f"""<div class="card" style="border-top:4px solid var(--purple);"><details open><summary style="cursor:pointer"><h2 style="display:inline;font-size:1.2rem">Network Scope</h2><span style="float:right;color:#94a3b8">▼</span></summary><div style="margin-top:15px;display:grid;gap:10px; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));">
    <div><div class="stat-lbl">Public IP</div><div style="font-family:monospace">{PUB_IP}</div></div>
    <div><div class="stat-lbl">Sensor IP</div><div style="font-family:monospace">{MY_IP}</div></div>
    <div><div class="stat-lbl">Gateway</div><div style="font-family:monospace">{GATEWAY}</div></div>
    </div></details></div>"""

    # Asset Inventory Table
    html_output += '<div class="card"><table><thead><tr><th style="width:30px"></th><th>Asset</th><th>Risk</th><th>Findings</th></tr></thead><tbody>'
    rid = 0
    sorted_inventory = sorted(inventory_data.items(), key=lambda item: item[1]['max_score'], reverse=True)

    for ip, data in sorted_inventory:
        rid += 1; cnt = len(data['vulns']); score = data['max_score']
        risk = "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW" if score > 0 else "NONE"
        cls = "risk-high" if score >= 7 else "risk-medium" if score >=4 else "risk-low"
        html_output += f'<tr onclick="toggle({rid}, this)" style="cursor:pointer"><td>▶</td><td><strong>{ip}</strong><div style="font-size:0.8rem;opacity:0.7">{data["vendor"]}</div></td><td><span class="badge {cls}">{risk}</span></td><td>{cnt}</td></tr>'
        html_output += f'<tr id="row-{rid}" class="details-row"><td colspan="4" style="padding:0 20px 20px 50px"><table style="background:#0f172a;border-radius:8px">'
        if cnt > 0:
            for v in sorted(data['vulns'], key=lambda x: x['score'], reverse=True):
                score_color = "#ef4444" if v['score'] >= 7 else "#eab308" if v['score'] >= 4 else "#22c55e"
                html_output += f'<tr><td><a href="https://nvd.nist.gov/vuln/detail/{v["id"]}" target="_blank">{v["id"]}</a></td><td>{v["svc"]}/{v["port"]}</td><td style="color:{score_color}">{v["score"]}</td></tr>'
        else:
            html_output += "<tr><td style='color:#22c55e'>No vulnerabilities found.</td></tr>"
        html_output += '</table></td></tr>'
    html_output += '</tbody></table></div>'

    # --- Final Assembly ---
    with open(template_path, 'r') as f:
        template = f.read()

    final_html = template.replace('__DATE__', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    final_html = final_html.replace('__CHART_DATA__', chart_data_json)
    final_html = final_html.replace('<!-- REPORT_CONTENT -->', html_output)

    with open(output_path, 'w') as f:
        f.write(final_html)

def export_json_report(inventory_data):
    report_data = {
        "network_scope": {
            "public_ip": os.environ.get("PUB_IP","?"),
            "sensor_ip": os.environ.get("MY_IP","?"),
            "gateway": os.environ.get("GATEWAY","?")
        },
        "asset_inventory": []
    }

    sorted_inventory = sorted(inventory_data.items(), key=lambda item: sum(v['score'] for v in item[1]['vulns']), reverse=True)
    for ip, data in sorted_inventory:
        asset = {
            "ip": ip,
            "mac": data.get("mac", "-"),
            "vendor": data.get("vendor", "Unknown"),
            "max_risk_score": data.get("max_score", 0.0),
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

# --- Main execution logic ---
if __name__ == "__main__":
    db_path = os.environ.get("DB_FILE")
    if not db_path:
        print("Error: DB_FILE environment variable is not set.", file=sys.stderr)
        sys.exit(1)
        
    inventory_data = get_data_from_db(db_path)

    if "--json" in sys.argv:
        export_json_report(inventory_data)
    elif len(sys.argv) == 3:
        template_path = sys.argv[1]
        output_path = sys.argv[2]
        generate_html_report(inventory_data, template_path, output_path)
    else:
        print("Usage: report.py <template_path> <output_path> or report.py --json", file=sys.stderr)
        sys.exit(1)

