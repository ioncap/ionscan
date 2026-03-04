# CLAUDE.md — IonScan Codebase Guide

This document provides AI assistants with the context needed to understand, navigate, and contribute to the IonScan codebase effectively.

---

## Project Overview

**IonScan** (v24.0) is a Bash/Python network security assessment framework — an interactive shell tool for authorized network reconnaissance, vulnerability scanning, and penetration testing assistance. It provides a modular, Metasploit-like CLI interface.

**License:** MIT
**Ethical Use:** This tool is strictly for authorized network testing. Never use against networks without explicit permission.

---

## Repository Structure

```
ionscan/
├── bin/
│   └── ionscan              # Main entry point — interactive shell framework
├── lib/
│   ├── core.sh              # Config, logging, cleanup traps, utility functions
│   ├── database.sh          # SQLite database abstraction layer
│   ├── network.sh           # Network interface detection helpers
│   └── ui.sh                # ANSI color constants and terminal formatting
├── modules/
│   ├── recon.sh             # Reconnaissance modules (passive, fast scan, DNS, SNMP, web, NetBIOS)
│   ├── exploit.sh           # Vulnerability/exploitation modules (vuln scan, brute force, MITM, listener)
│   ├── wireless.sh          # WiFi monitoring and Bluetooth scanning
│   ├── utils.sh             # Utilities (MAC spoofing, ARP watch, SSL checks, decoy scans)
│   ├── report.sh            # Report orchestration (calls report.py)
│   └── report.py            # HTML dashboard and JSON report generation (Python 3)
├── parsers/
│   ├── nmap_fast_scan_parser.py   # Parses Nmap XML output into SQLite (hosts/ports)
│   └── nmap_vuln_parser.py        # Parses Nmap vulnerability script output into SQLite
├── templates/
│   └── dashboard.html       # HTML report template (Chart.js visualizations)
├── config/
│   └── ionscan.conf         # Default configuration file (copied to ionscan_logs/ on first run)
└── .github/
    └── workflows/
        └── python-package.yml  # CI: flake8 lint + pytest across Python 3.9/3.10/3.11
```

**Runtime-generated directories** (not in source control):

```
ionscan_logs/
├── ionscan.db          # SQLite database (auto-initialized)
├── ionscan.conf        # Active config (copied from config/ionscan.conf)
├── ionscan.log         # Main log file (ISO 8601 timestamps)
├── dashboard.html      # Generated HTML report
├── oui.txt             # IEEE OUI database (auto-downloaded)
└── *.pcap / *.xml      # Module capture/output files
```

---

## Architecture

### Interactive Shell Framework (`bin/ionscan`)

The main entry point implements a REPL loop that mimics Metasploit's interface:

1. Libraries are sourced in order: `ui.sh` → `core.sh` → `network.sh` → `database.sh`
2. Modules are sourced: `recon.sh`, `exploit.sh`, `wireless.sh`, `utils.sh`, `report.sh`
3. The interactive loop reads commands and dispatches to module functions

**State variables:**
```bash
CURRENT_MODULE=""           # Currently loaded module path (e.g., "recon/fast_scan")
declare -A MODULE_OPTIONS   # Key-value options for the current module
declare -A TARGETS          # Discovered/added targets (numeric ID → IP)
```

### Module System

Modules follow a strict naming convention:

- **Function name:** `mod_<name>` (e.g., `mod_fast_scan`, `mod_passive`)
- **Options array:** `MOD_OPTIONS_<CATEGORY>_<NAME>` as a global associative array
- **Option value format:** `"description='...' required=true|false default='...' type='ip|cidr|port|boolean|string'"`

Example module declaration:
```bash
declare -gA MOD_OPTIONS_RECON_FAST_SCAN
MOD_OPTIONS_RECON_FAST_SCAN[TARGET]="description='Target IP, CIDR, or all' required=true type='cidr'"

mod_fast_scan() {
    local target="${MODULE_OPTIONS[TARGET]}"
    if [[ -z "$target" ]]; then
        log_error "Required option 'TARGET' not set."
        return
    fi
    # ... implementation
}
```

**Valid module categories** (defined in `bin/ionscan`):
```bash
VALID_MODULE_CATEGORIES=("recon" "exploit" "report" "post" "auxiliary")
```

### Module Reference

| Module Path | Function | Description |
|-------------|----------|-------------|
| `recon/passive` | `mod_passive` | Capture ARP/mDNS traffic via tcpdump |
| `recon/fast_scan` | `mod_fast_scan` | Nmap service discovery (-sV) |
| `recon/dns` | `mod_dns` | Domain enumeration with dig |
| `recon/snmp` | `mod_snmp` | SNMP community string queries |
| `recon/web` | `mod_web` | Web directory discovery with gobuster |
| `recon/netbios` | `mod_netbios` | NetBIOS name scanning |
| `exploit/vuln` | `mod_vuln` | NSE-based vulnerability scanning |
| `exploit/advanced_vuln` | `mod_advanced_vuln` | Full port scan + vuln scripts |
| `exploit/brute` | `mod_brute` | Hydra-based brute force |
| `exploit/intercept` | `mod_intercept` | ARP spoofing MITM |
| `exploit/listener` | `mod_listener` | Metasploit listener setup |
| `exploit/zombie` | `mod_zombie` | Idle host scanning |
| `wireless/wifi` | `mod_wifi` | WiFi monitoring (aircrack-ng) |
| `wireless/bluetooth` | `mod_bluetooth` | Bluetooth device scanning |
| `utils/mac_spoof` | `mod_mac_spoof` | MAC address randomization |
| `utils/arp_watch` | `mod_arp_watch` | ARP change detection |
| `utils/ssl` | `mod_ssl` | SSL/TLS certificate checks |
| `utils/decoy` | `mod_decoy` | Decoy scan to obscure origin |
| `report/generate` | `mod_report` | Generate HTML dashboard |

---

## Running the Tool

### Interactive Mode (default)
```bash
sudo ./bin/ionscan
```

### Skip Disclaimer
```bash
sudo ./bin/ionscan --agree
```

### Headless Auto Mode
Runs: fast_scan → advanced_vuln → report generation on local subnet.
```bash
sudo ./bin/ionscan --auto --agree
```

### Install Dependencies
```bash
sudo ./bin/ionscan --setup
```

### Interactive Shell Commands

```
help / ?                  # Show available commands
show modules              # List all available modules (numbered)
show options              # Show options for the current module
show targets              # Show the current target list
add target <ip>           # Add a target (IP, CIDR, or domain)
rm target <id>            # Remove a target by ID
use <module>              # Load by full path: use recon/fast_scan
use <number>              # Load by number from last 'show modules' list
use <partial>             # Fuzzy match: 'use fast_scan' or 'use vuln'
set <KEY> <value>         # Set a module option
run                       # Execute the current module
search <term>             # Filter modules by keyword
back                      # Unload the current module
exit / quit               # Exit the shell
```

**Short aliases** (for common operations):
```
ls / modules              # Same as 'show modules'
opts / options / info     # Same as 'show options'
targets                   # Same as 'show targets'
```

**Tab completion** is active in the interactive shell:
- TAB on empty line or partial command → complete command name
- `use <TAB>` → complete module path
- `set <TAB>` → complete option key for the current module
- `show <TAB>` → complete subcommand (`modules`, `options`, `targets`, `history`)

---

## Key Conventions

### Bash Style

- **Strict mode:** All scripts use `set -u` (catch unset variables) and `set -o pipefail`
- **No `eval`:** Explicitly prohibited to prevent code injection
- **Local variables:** Always declare with `local` inside functions
- **Logging:** Use the four log functions — never `echo` for status output:
  ```bash
  log_info "Starting scan..."
  log_success "Scan complete."
  log_warning "Dependency missing."
  log_error "Fatal: could not connect." >&2
  ```
- **Input validation:** Always call `validate_input "$value" "type"` before using user-supplied values
- **Input sanitization:** Call `sanitize_input "$value"` to strip shell metacharacters (`;`, `&`, `|`, `` ` ``, `$`, `()`) from untrusted input

### Validation Types

The `validate_input` function (in `bin/ionscan`) supports these types:
- `ip` — IPv4 address
- `cidr` — CIDR notation (e.g., `192.168.1.0/24`)
- `port` — Integer 1–65535
- `boolean` — `true`/`false`/`yes`/`no`/`1`/`0`
- `string` — Any non-empty string (default)

### Python Style

- Python 3 only (no Python 2 compatibility required)
- Standard library only — no external package dependencies
- Max line length: **127 characters** (enforced by flake8 in CI)
- Max complexity: **10** (enforced by flake8 in CI)
- Use docstrings on functions
- Use `try/except` for error handling on file/network operations
- Configuration passed via environment variables or command-line arguments

---

## Library Reference

### `lib/core.sh`

| Function | Signature | Purpose |
|----------|-----------|---------|
| `log_info` | `log_info "msg"` | Blue info log to stdout + file |
| `log_success` | `log_success "msg"` | Green success log |
| `log_warning` | `log_warning "msg"` | Yellow warning log |
| `log_error` | `log_error "msg"` | Red error log to stderr |
| `get_config` | `get_config KEY` | Read a value from `ionscan.conf` |
| `safe_download` | `safe_download URL dest` | curl with retry (3 attempts) |
| `send_webhook` | `send_webhook "msg"` | POST to Discord/Slack webhook if configured |
| `check_deps` | `check_deps [silent]` | Verify all required tools are installed |
| `setup_config` | `setup_config` | Copy default config if not present |
| `open_browser` | `open_browser URL` | Open URL with xdg-open (respects SUDO_USER) |

### `lib/database.sh`

| Function | Signature | Purpose |
|----------|-----------|---------|
| `db_init` | `db_init` | Create SQLite DB and schema if not exists |
| `db_exec` | `db_exec "SQL"` | Execute arbitrary SQL |
| `db_add_or_get_host` | `db_add_or_get_host ip [mac] [vendor]` | Upsert host, return ID |
| `db_add_or_get_port` | `db_add_or_get_port host_id port proto [svc] [state]` | Upsert port, return ID |
| `db_add_vulnerability` | `db_add_vulnerability port_id cve [cvss] [desc]` | Insert vuln (ignore if exists) |

---

## Database Schema

SQLite database at `ionscan_logs/ionscan.db`:

```sql
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
    FOREIGN KEY (host_id) REFERENCES hosts(id),
    UNIQUE (host_id, port_number, protocol)
);

CREATE TABLE vulnerabilities (
    id INTEGER PRIMARY KEY,
    port_id INTEGER NOT NULL,
    cve_id TEXT NOT NULL,
    cvss_score REAL,
    description TEXT,
    FOREIGN KEY (port_id) REFERENCES ports(id),
    UNIQUE (port_id, cve_id)
);
```

---

## Configuration (`config/ionscan.conf`)

The file at `config/ionscan.conf` is the template; the active config is copied to `ionscan_logs/ionscan.conf` on first run.

| Key | Default | Description |
|-----|---------|-------------|
| `DEFAULT_IFACE` | `""` | Network interface used by passive/wireless modules |
| `WEBHOOK_URL` | `""` | Discord or Slack webhook for notifications |
| `LOG_LEVEL` | `"INFO"` | Logging verbosity |
| `MODULE_RECON_ENABLED` | `true` | Enable/disable recon module category |
| `MODULE_WIRELESS_ENABLED` | `true` | Enable/disable wireless module category |
| `MODULE_EXPLOIT_ENABLED` | `true` | Enable/disable exploit module category |
| `MODULE_UTILS_ENABLED` | `true` | Enable/disable utils module category |
| `MODULE_REPORT_ENABLED` | `true` | Enable/disable report module category |

---

## System Dependencies

All dependencies are checked by `check_deps` in `lib/core.sh`. The tool requires these system packages:

| Command | Package |
|---------|---------|
| `sqlite3` | sqlite3 |
| `nmap` | nmap |
| `tcpdump` | tcpdump |
| `curl` | curl |
| `awk` | gawk |
| `macchanger` | macchanger |
| `aircrack-ng` | aircrack-ng |
| `gobuster` | gobuster |
| `hydra` | hydra |
| `tshark` | tshark |
| `flock` | util-linux |
| `hcitool` | bluez |
| `msfconsole` | metasploit-framework |
| `nc` | netcat-openbsd |
| `arpspoof` | dsniff |
| `dig` | dnsutils |
| `avahi-browse` | avahi-utils |
| `snmpwalk` | snmp |
| `nbtscan` | nbtscan |

Two files are auto-downloaded at runtime if missing:
- `ionscan_logs/oui.txt` — IEEE OUI database (vendor lookups)
- `/usr/share/nmap/scripts/vulners.nse` — Nmap vulnerability script

---

## CI/CD (GitHub Actions)

Workflow: `.github/workflows/python-package.yml`

- Triggered on: push/PR to `main`
- Python versions: 3.9, 3.10, 3.11
- Steps:
  1. Install `flake8` and `pytest` (plus `requirements.txt` if present)
  2. **Lint:** `flake8` — fatal on syntax errors/undefined names; warnings on style (max-line-length=127, max-complexity=10)
  3. **Test:** `pytest` — no tests currently exist (pytest will pass with "no tests found")

When adding Python files, ensure they pass:
```bash
flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics
flake8 . --count --exit-zero --max-complexity=10 --max-line-length=127 --statistics
```

---

## Security Principles

Follow these non-negotiable rules when modifying the codebase:

1. **No `eval`** — Never use `eval` anywhere. This was explicitly removed as a security fix.
2. **Sanitize all user input** — Call `sanitize_input` before using values in shell commands.
3. **Validate typed inputs** — Call `validate_input "$val" "type"` for IP, CIDR, port, boolean values.
4. **No command injection** — Never interpolate unsanitized user input into command substitutions.
5. **Strict mode** — All bash files must use `set -u` and `set -o pipefail`.
6. **Cleanup traps** — Background processes and temp files must be tracked and cleaned up on `EXIT`/`INT`/`TERM`.
7. **Sudo scope** — Use `sudo` only for specific privileged commands (tcpdump, airmon-ng, arpspoof, ip_forward); never run the entire script as root without necessity.
8. **Database parameterization** — Use the `db_*` helper functions rather than raw `sqlite3` calls to avoid SQL issues.

---

## Adding a New Module

1. Choose a category: `recon`, `exploit`, `wireless`, `utils`, or `report`
2. Add the options array and function to the appropriate `modules/<category>.sh` file:

```bash
# Options declaration (global scope, top of file)
declare -gA MOD_OPTIONS_RECON_MY_MODULE
MOD_OPTIONS_RECON_MY_MODULE[TARGET]="description='Target IP' required=true type='ip'"
MOD_OPTIONS_RECON_MY_MODULE[TIMEOUT]="description='Timeout in seconds' required=false default='10' type='port'"

# Module function
mod_my_module() {
    local target="${MODULE_OPTIONS[TARGET]}"
    local timeout="${MODULE_OPTIONS[TIMEOUT]:-10}"

    if [[ -z "$target" ]]; then
        log_error "Required option 'TARGET' not set."
        return
    fi

    validate_input "$target" "ip" || { log_error "Invalid IP address."; return; }

    log_info "Running my_module against $target..."
    # ... implementation
    log_success "Done."
}
```

3. The module is automatically available as `use recon/my_module` in the interactive shell — the shell maps `recon/my_module` → `mod_my_module`.

---

## Git Workflow

- **Default branch:** `master`
- **Feature branches:** Use descriptive names; prefix with category (e.g., `feat/`, `fix/`, `docs/`)
- **Commit messages:** Follow conventional commits format:
  - `feat:` — new feature
  - `fix:` — bug fix
  - `refactor:` — code change without behavior change
  - `docs:` — documentation only
  - `chore:` — tooling/config changes
- **CI target branch:** `main` (note: repo default is `master`; CI workflow targets `main`)
