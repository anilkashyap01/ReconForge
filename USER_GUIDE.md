# ReconForge — Platform Operator & User Guide

**ReconForge** is a local-first reconnaissance and vulnerability assessment platform designed for cybersecurity analysts, penetration testers, and bug bounty hunters on Kali Linux. It orchestrates external security CLI scanners (Subfinder, dnsx, httpx, Naabu, Katana, Nuclei, and optional tools like Nmap, OWASP ZAP, FFUF, gau, testssl.sh), parses and normalizes output into SQLite, and provides a modern, responsive single-page web dashboard on `http://127.0.0.1:8000`.

---

## 1. Target Setup & Scope Management

Scope enforcement is strictly validated in backend code (`app/scope.py`). Scanners will never be passed arbitrary or unverified targets.

### Adding a New Target Project

1. Click **+ Add Target** in the top navigation bar or Section A controls.
2. In the modal, configure:
   - **Target Project Name**: A unique descriptive name (e.g., `Acme Corp Bug Bounty`).
   - **Description**: Optional context (e.g., `HackerOne authorized program`).
   - **In-Scope Targets**: Enter authorized domains, IPs, or CIDR blocks (one per line).
   - **Out-of-Scope Exclusions**: Enter forbidden hostnames or IP ranges that must never be scanned.
   - **Authorization Confirmation**: You must check the legal confirmation stating you possess authorization to test these targets.

### Scope Rule Syntax & Semantics

| Rule Syntax | Example | Matches | Does NOT Match |
| :--- | :--- | :--- | :--- |
| **Exact Domain** | `example.com` | `example.com` only | `sub.example.com`, `admin.example.com` |
| **Wildcard Domain** | `*.example.com` | `api.example.com`, `deep.sub.example.com` | `example.com` (apex), `lookalike.com` |
| **Single IP** | `192.168.1.50` | `192.168.1.50` only | Other IPs on subnet |
| **CIDR Network** | `192.168.1.0/24` | `192.168.1.1` – `192.168.1.254` | IPs outside `/24` prefix |
| **Exclusion** | `admin.example.com` | Prevents tests against `admin.example.com` | Any in-scope target |

> **Important Notes:**
> - **Exclusions Always Win**: If `*.example.com` is in-scope and `admin.example.com` is set as an exclusion, `admin.example.com` is immediately pruned and will never be contacted by any tool.
> - **Apex vs. Wildcards**: If you wish to test both the apex domain and all subdomains, add both entries: `example.com` AND `*.example.com`.

### Interactive Scope Boundary Verifier

Before running any scans, use the **Scope Boundary Verifier** in the **Targets** section:
1. Enter a test domain, IP, or full URL (e.g., `api.example.com` or `https://test.example.com/login`).
2. Click **Test Boundary**.
3. The dashboard executes backend validation via `POST /api/projects/{pid}/scope/test` and displays:
   - **`✔ IN SCOPE`** (Green): Target matches an authorized rule.
   - **`✖ EXCLUDED`** (Red): Target matches an out-of-scope exclusion.
   - **`⚠ NOT IN SCOPE`** (Muted): Target is unlisted or outside authorization.

---

## 2. Launching Scans & Live Monitoring

ReconForge supports 4 standard scan profiles, ranging from non-intrusive OSINT to deep web application assessment.

### Scan Profiles

| Profile | Tools Executed | Traffic Sent to Target? | Requirements |
| :--- | :--- | :---: | :--- |
| **Passive Recon** | Subfinder, gau, Shodan, urlscan | **No** (Third-party OSINT only) | In-scope domains |
| **Standard Discovery** | Subfinder, dnsx, httpx, Naabu | **Yes** (DNS, HTTP/S, TCP connects) | Scope authorization check |
| **Vulnerability Assessment** | Standard + Nuclei | **Yes** (Automated template checks) | Scope check + Active confirmation |
| **Web Assessment** | Standard + Katana + Nuclei | **Yes** (Web crawler + templates) | Scope check + Active confirmation |

### Starting a Scan

1. Select your target in the **TARGET** dropdown.
2. Click **Start Recon** for instant passive reconnaissance, or **Start Scan...** to open the Scan Wizard.
3. In the Scan Wizard:
   - Choose the desired **Profile**.
   - Select **Port Specification**: `top100`, `top1000`, or custom ports (e.g., `80,443,8080,8443`).
   - Specify **Nuclei Template Tags**: Safe tags (e.g. `exposure,misconfig,takeover`). Dangerous/DoS tags are rejected.
   - Check **Authorization Confirmation**. For Vulnerability/Web scans, check **Active Probing Confirmation**.
   - Click **Launch Scan**.

### Live Dashboard Monitoring

During an active scan:
- **Active Scan Strip**: Renders at the top of the dashboard showing live stage progress (e.g., `Stage: httpx — probing live endpoints (40%)`), scan profile, and progress bar.
- **Controls**:
  - **Pause**: Halts execution cleanly between stages.
  - **Cancel**: Terminates the active process group immediately via `SIGTERM` / `SIGKILL`.
- **Activity & Scan Queue**:
  - **Recent Scans**: Lists scan status, asset discovery counter, start and completion times.
  - **Tool Execution Matrix**: Shows exact CLI arguments, exit codes, bytes captured, and stderr output.
  - **Scan Logs**: Live timestamped console log viewer with scan selection and direct log file download.

---

## 3. Reviewing Findings & Exporting Data

### Reconnaissance & Asset Inventory

The **Reconnaissance** section categorizes discovered assets into small, filterable tabs:
- **Subdomains**: Discovered domain names with first-seen and last-seen timestamps.
- **Live Hosts**: Responding HTTP/HTTPS services, response status codes (200, 301, 404, 500), page titles, and web server banners.
- **DNS Records**: A, CNAME, and TXT records resolved by `dnsx`.
- **Open Ports**: TCP ports and service identities detected by `naabu` / `nmap`.
- **Exporting**: Click **Export CSV** in the section header to download `recon-assets.csv`.

### Vulnerabilities & Finding Details

The **Vulnerabilities & Security Findings** table displays potential security issues:
- **Severity Filters**: Quick tabs for `ALL`, `Critical`, `High`, `Medium`, `Low`, and `Info`.
- **Status Filter**: Filter by `Potential (Unvalidated)`, `Confirmed by Analyst`, `False Positive`, or `Fixed`.
- **Finding Inspection**: Click any row to reveal the detail panel:
  - **Reproduction**: Copy the affected URL or ready-to-run `curl` command.
  - **Evidence**: Raw scanner output payload matching the vulnerability condition.
  - **Remediation**: Recommended fix and linked advisory references.
  - **Analyst Actions**: Click **Confirm Finding**, **Mark False Positive**, or **Mark Fixed** to update SQLite records.

### Exporting Reports

From the **Reports & Security Exports** section (Section G):
- **Technical HTML Report**: Full report with Jinja autoescaping, CSP protection, and collapsible sections (`/scans/{sid}/report.html`).
- **Machine-Readable JSON**: Complete structured data model (`/api/scans/{sid}/report.json`).
- **Spreadsheet CSVs**: Structured CSV files for findings and assets (`/api/scans/{sid}/report.csv`).
- **Download All Logs**: Raw timestamped CLI execution logs (`/api/scans/{sid}/logs.txt`).
- **Executive Posture Summary**: Opens a summary modal with risk score badges, metrics breakdown, and a clean **Print / PDF** export preview.

---

## 4. Settings, Rate Limiting & Tool Diagnostics

Open the **Settings & Tools** menu from the top header:

### Rate Limits & Safety Controls

Configure conservative defaults backed by token-bucket rate limiters:
- **Max Requests / Second**: Global throughput cap (default: `2.0 req/s`).
- **Per-Host Requests / Second**: Dedicated per-domain budget (default: `2.0 req/s`).
- **Max Concurrent Jobs**: Maximum target-touching processes running concurrently (default: `1`).
- **Scan Timeout**: Hard limit per scan in seconds (default: `900s`).

### Threat Intelligence API Keys

Configure optional OSINT providers:
- **Shodan.io**: Passive IP port lookups and host history.
- **urlscan.io**: Passive URL submission and webpage archives.
- *Security Note*: Keys are stored strictly in `data/secrets.json` with `0600` permissions. They are never sent to external scanners, logs, or reports.

### Tool Health Matrix

Inspect the status of all CLI tools on your Kali Linux system:
- **Core Tools**: `subfinder`, `dnsx`, `httpx-toolkit`, `naabu`, `katana`, `nuclei`.
- **Optional Tools**: `nmap`, `zaproxy`, `ffuf`, `gau`, `testssl.sh`.
- The matrix displays installation status (`Installed` vs `Missing`), detected system path, version numbers, template versions, and Kali package installation hints.

```bash
# Kali Linux Tool Installation Commands
sudo apt update
sudo apt install -y subfinder dnsx httpx-toolkit naabu katana nuclei nmap zaproxy ffuf
# For gau:
go install github.com/lc/gau/v2/cmd/gau@latest
# For testssl:
sudo snap install testssl
```
