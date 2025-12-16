#!/usr/bin/env python3

import sys, glob, re, os, subprocess
import xml.etree.ElementTree as ET
import json # Added json import

LOG_DIR = os.environ.get("LOG_DIR", ".")
OUI_DB = os.environ.get("OUI_DB", "oui.txt")
PCAP_FILE = os.path.join(LOG_DIR, "live_traffic.pcap")
PUB_IP, GATEWAY, DNS_SRV, MY_IP, IFACE = os.environ.get("PUB_IP","?"), os.environ.get("GATEWAY","?"), os.environ.get("DNS_SRV","?"), os.environ.get("MY_IP","?"), os.environ.get("DEFAULT_IFACE","?")
inventory = {}

def get_vendor(mac_addr):
    if not os.path.exists(OUI_DB): return "Unknown"
    clean = mac_addr.replace(":", "").upper()[:6]
    try:
        with open(OUI_DB, "r", encoding='utf-8', errors='ignore') as f:
            for line in f:
                if line.startswith(clean):
                    parts = line.split("\t")
                    if len(parts) >= 2:
                        return parts[1].strip()
    except Exception:
        pass
    return "Unknown"

# --- Data Collection Logic (same as before) ---
if os.path.exists(PCAP_FILE):
    cmd = f"tcpdump -nn -e -r {PCAP_FILE} 2>/dev/null | grep -oE '([0-9a-fA-F]{{2}}:){{5}}[0-9a-fA-F]{{2}}' | sort | uniq"
    try:
        macs = subprocess.check_output(cmd, shell=True).decode().splitlines()
        for mac in macs:
            m = mac.upper()
            if m.startswith("FF:FF") or m.startswith("01:00") or m.startswith("33:33"): continue
            ip = subprocess.check_output(f"arp -n | grep -i {m} | awk '{{print $1}}'", shell=True).decode().strip() or "Unknown IP"
            inventory[ip] = { "mac": m, "vendor": get_vendor(m), "vulns": [], "max_score": 0.0 }
    except Exception:
        pass

cve_pat = re.compile(r"(CVE-\d{4}-\d+)") # Corrected from re.re.compile
for xml_file in glob.glob(os.path.join(LOG_DIR, "vuln_report_*.xml")):
    try:
        root = ET.parse(xml_file).getroot()
        for host in root.findall("host"):
            addr = host.find("address[@addrtype='ipv4']")
            if addr is None: continue
            ip = addr.get("addr")
            if ip not in inventory: inventory[ip] = { "mac": "-", "vendor": "Scanned", "vulns": [], "max_score": 0.0 }
            for port in host.findall(".//port"):
                pid = port.get("portid")
                svc_elem = port.find("service")
                svc = svc_elem.get("name") if svc_elem is not None else "tcp"
                for script in port.findall("script"):
                    if script.get("id") == "vulners":
                        for table in script.findall("table"):
                            for row in table.findall("table"):
                                id_nd = row.find("elem[@key='id']")
                                cv_nd = row.find("elem[@key='cvss']")
                                if id_nd is not None:
                                    rid = id_nd.text
                                    score = float(cv_nd.text) if cv_nd is not None and cv_nd.text is not None else 0.0
                                    match = cve_pat.search(rid)
                                    did = match.group(1) if match else rid
                                    if not any(v['id'] == did for v in inventory[ip]['vulns']):
                                        inventory[ip]['vulns'].append({'id':did, 'score':score, 'port':pid, 'svc':svc})
                                        if score > inventory[ip]['max_score']: inventory[ip]['max_score'] = score
    except Exception:
        continue

web_data = {}
for wlog in glob.glob(os.path.join(LOG_DIR, "web_scan_*.txt")):
    try:
        target = os.path.basename(wlog).replace("web_scan_", "").replace(".txt", "")
        with open(wlog, "r") as f: lines = [l.strip() for l in f if l.strip()]
        if lines: web_data[target] = lines
    except Exception:
        pass
# --- End Data Collection Logic ---

def generate_html_report(inventory_data, web_surface_data):
    # This function now encapsulates the HTML generation logic
    # It receives inventory and web_data as arguments
    html_output = ""

    # Network Scope Card
    html_output += f"<div class=\"card\" style=\"border-top:4px solid var(--purple);"><details open><summary style=\"cursor:pointer\"><h2 style=\"display:inline;font-size:1.2rem\">Network Scope</h2><span style=\"float:right;color:#94a3b8\">▼</span></summary><div style=\"margin-top:15px;display:grid;gap:10px; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));\">
    <div><div class=\"stat-lbl\">Public IP</div><div style=\"font-family:monospace\">{PUB_IP}</div></div>
    <div><div class=\"stat-lbl\">Sensor IP</div><div style=\"font-family:monospace\">{MY_IP}</div></div>
    <div><div class=\"stat-lbl\">Gateway</div><div style=\"font-family:monospace\">{GATEWAY}</div></div>
    </div></details></div>"

    # Asset Inventory Table
    html_output += '<div class="card"><table><thead><tr><th style="width:30px"></th><th>Asset</th><th>Risk</th><th>Findings</th></tr></thead><tbody>'
    rid = 0
    sorted_inventory = sorted(inventory_data.items(), key=lambda item: sum(v['score'] for v in item[1]['vulns']), reverse=True)

    for ip, data in sorted_inventory:
        rid += 1; cnt = len(data['vulns']); score = data['max_score']
        risk = "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW"
        cls = "risk-high" if score >= 7 else "risk-low"
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

    # Web Surface Analysis Card
    if web_surface_data:
        html_output += '<div class="card" style="border-top:4px solid #f59e0b"><h2>🌐 Web Surface Analysis</h2><table><thead><tr><th>Target Host</th><th>Discovered Paths</th></tr></thead><tbody>'
        for target, paths in web_surface_data.items():
            path_html = "<br>".join([p.replace("Status:","<span style='color:#38bdf8'>Status:</span>") for p in paths])
            html_output += f'<tr><td style="vertical-align:top"><strong>http://{target}</strong></td><td style="font-family:monospace;font-size:0.85rem">{path_html}</td></tr>'
        html_output += '</tbody></table></div>'
    
    return html_output

def export_json_report(inventory_data, web_surface_data):
    report_data = {
        "network_scope": {
            "public_ip": PUB_IP,
            "sensor_ip": MY_IP,
            "gateway": GATEWAY
        },
        "asset_inventory": [],
        "web_surface_analysis": []
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

    if web_surface_data:
        for target, paths in web_surface_data.items():
            report_data["web_surface_analysis"].append({
                "target_host": f"http://{target}",
                "discovered_paths": paths
            })
            
    print(json.dumps(report_data, indent=4))

# --- Main execution logic ---
if __name__ == "__main__":
    if "--json" in sys.argv:
        export_json_report(inventory, web_data)
    else:
        print(generate_html_report(inventory, web_data))