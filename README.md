# ReconForge

A local-first reconnaissance and vulnerability-assessment platform. It orchestrates open-source tools you install
yourself (Subfinder, dnsx, httpx, Naabu, Katana, Nuclei, and optionally Nmap, OWASP ZAP, FFUF, gau, testssl.sh),
parses their output into SQLite, and shows real assets, findings, scan state and errors in a web dashboard on
`127.0.0.1`.

ReconForge does not install tools, download binaries, or scan anything you have not explicitly authorised.
**Only test systems you own or have written permission to test, and follow the program's own rules and rate limits.**
Being publicly reachable is not permission.

## Install

Requirements: Python 3.10+, Kali (or any Linux), and the scanner binaries you want to use.

```bash
cd reconforge
python3 -m venv .venv            # never install into Kali's system Python
source .venv/bin/activate
pip install -r requirements.txt
python -m app                    # http://127.0.0.1:8000
```

Optional configuration: copy `.env.example` to `.env` and `chmod 600 .env`; it is read at startup (real environment variables win).
Useful variables: `RECONFORGE_PORT`, `RECONFORGE_DATA_DIR`, `RECONFORGE_WORDLIST_DIRS`. Data (database, reports, secrets) lives in `./data`.

`python -m app` refuses to bind to anything but loopback. There is no login, so do not expose it; setting
`RECONFORGE_ALLOW_REMOTE=1` is only for setups where you add your own authentication in front.

### Install the scanner tools

ReconForge only *detects* tools (open **Tool health**). It looks them up on `PATH` outside the virtualenv, checks that the
program really is the expected one, and shows its version. Install what you need from official sources:

| Tool | Role | Official source |
|---|---|---|
| Subfinder | passive subdomains (core) | https://github.com/projectdiscovery/subfinder |
| dnsx | DNS resolution (core) | https://github.com/projectdiscovery/dnsx |
| httpx (ProjectDiscovery) | HTTP probing (core) | https://github.com/projectdiscovery/httpx |
| Naabu | port discovery (core) | https://github.com/projectdiscovery/naabu |
| Katana | crawling (core) | https://github.com/projectdiscovery/katana |
| Nuclei | template checks (core) | https://github.com/projectdiscovery/nuclei |
| Nmap | service detection (optional) | https://nmap.org/download |
| OWASP ZAP | web assessment (optional) | https://www.zaproxy.org/download/ |
| FFUF | content discovery (optional) | https://github.com/ffuf/ffuf |
| gau | historical URLs (optional) | https://github.com/lc/gau |
| testssl.sh | TLS assessment (optional) | https://testssl.sh |

Kali often packages these (for example `sudo apt install katana`, which I confirmed on kali.org/tools/katana). The other package
names ReconForge shows on the Tool health page (`subfinder`, `dnsx`, `httpx-toolkit`, `naabu`, `nuclei`, `nmap`, `zaproxy`, `ffuf`,
`testssl.sh`) follow Kali's usual naming but were **not** verified against the archive: check with `apt-cache policy <name>`.
If a package is missing or old, use the upstream instructions (for the Go tools: `go install github.com/projectdiscovery/<tool>/cmd/<tool>@latest`,
see each repository). Prefer verified releases from the official repositories; do not run install scripts from unknown sources.

Notes:
* **httpx name clash.** The Python `httpx` library (a dependency of the dev/test requirements) installs an `httpx` command in the
  virtualenv. ReconForge removes the virtualenv from the PATH it uses for tools, looks for `httpx-toolkit` first, and checks the
  program identifies as ProjectDiscovery's. To pin a specific binary: `RECONFORGE_TOOL_HTTPX=/path/to/httpx` (same pattern for other tools).
* **Nuclei templates** are managed by Nuclei itself. ReconForge never updates them; run `nuclei -update-templates` when you choose to.
  ReconForge passes `-duc` (no update check) and `-ni` (no interactsh/OAST traffic to third parties).
* `naabu` may need `libpcap` installed. ReconForge runs it as a TCP connect scan, which does not need root.

## Using it

1. **Projects**: create a project and list the scope you are authorised to test, then tick the permission confirmation.
   `example.com` covers only that exact host. `*.example.com` covers its subdomains but not `example.com` itself (add both if you want both).
   IPs and CIDR ranges must be listed explicitly. Exclusions always win. Nothing outside the scope is ever tested.
2. **New scan**: choose entries, profile, limits and modules. The stage list shows exactly what will run.
3. **Scan page**: live stage-by-stage progress. Each stage says whether it contacts the target. Cancel, pause (between stages), and
   *Retry unfinished stages* (finished stages are not re-run).
4. **Assets / Findings / Scan history / Reports**: real database values, or an empty state when nothing exists.

### Profiles

| Profile | Stages | Sends traffic to the target? |
|---|---|---|
| Passive Recon | Subfinder (+ optional gau, provider enrichment) | No. Public sources only |
| Standard Recon | + dnsx, httpx, Naabu (+ optional Nmap, testssl.sh) | DNS, HTTP and TCP to authorised targets |
| Vulnerability Assessment | Standard + Nuclei | Yes. Needs a separate confirmation |
| Web Assessment | Standard + Katana + Nuclei (+ optional FFUF, ZAP) | Yes. Needs a separate confirmation |

The wizard starts on Passive. The server refuses vulnerability/web profiles without the second confirmation, no matter what the browser sends.
Nuclei runs with intrusive, DoS, fuzzing and brute-force tags excluded. FFUF and ZAP are opt-in, Web-profile only, and ZAP is described in the UI as intrusive.

### Scope enforcement (backend)

* Scope is parsed and validated server-side; malformed or option-like entries (`-x`, shell metacharacters, whitespace, `0.0.0.0/0`, huge ranges) are rejected.
* Every discovered host, URL and finding is filtered through the scope before it is stored. Out-of-scope results are dropped and counted
  ("Out-of-scope results rejected" on the scan page and in the log).
* External CNAME targets are recorded as DNS data but never probed or scanned.
* IP addresses that in-scope hostnames resolve to are **not** port-scanned unless they are listed in scope, or you tick
  "allow resolved IPs". CDN and shared-hosting addresses usually are not yours. Private, loopback and link-local addresses are never scanned via resolution.
* Immediately before every launch, the exact target list is validated again, and the tool's stdin must equal that validated list.
* Tools run through `asyncio.create_subprocess_exec` with argument arrays: no shell, never `shell=True`. Wordlists must be inside configured
  directories (symlinks that escape are rejected). Scanners receive a minimal environment, never your API keys.

### Rate limits: what is and is not enforced

Scanner binaries are separate programs; ReconForge cannot meter their packets. What it actually does:

* Passes your budget to each tool's own rate flag (`httpx -rl`, `katana -rl`, `nuclei -rl`, `ffuf -rate`, `naabu -rate`, `dnsx -rl`),
  after dividing by the number of target-touching tools allowed to run at once and capping at the per-host budget.
* By default only **one** target-touching tool process runs at a time across all scans (a shared semaphore), so tools do not add up.
* Defaults: 2 requests/second, 1 target-touching tool at a time, 2 concurrent scans, 500 assets, 1 hour per scan, 15 minute tool timeout.
* Tools only accept whole rates of at least 1/s. If you configure less, scans with httpx/Katana/Nuclei/FFUF **refuse to start** rather than exceed your budget.
* On rate-limit output (`429`, "too many requests") in a tool's stderr, the stage backs off, halves the rate and retries (bounded).
  A tool that hits its timeout is **not** retried (it would only time out again): the stage is *Partial*, and the message says that no results is not the same as clean.
* ZAP's request rate is not controlled by ReconForge. Use it only where that is acceptable.
* Pause takes effect between stages; a running tool is not suspended. Cancel kills the tool's whole process group.
* Provider API calls made by ReconForge itself go through a token bucket, honour `429`/`Retry-After`, and back off. Keys are never rotated.
* Per-host budgets are enforced through the tool's global rate (so per-host rate is at most the global rate), not by inspecting traffic.

### Results, status words and confidence

* Stage status is one of: *Completed*, *Completed, nothing found* (empty), *Partial results* (timeout, output cap or some commands failed;
  results kept), *Failed* (with the tool's error), *Tool missing*, *Skipped* (with the reason), *Cached*, *Cancelled*.
* Scanner matches are **potential findings**, stored as `unvalidated` with low scanner confidence. Only an analyst can mark one *confirmed*.
  Reports state this explicitly.
* Assets and findings are deduplicated per project with first-seen / last-seen and per-scan membership, so scans can be compared
  (new, not seen again). "Not seen again" means a scan did not observe it, not that it was fixed.
* Newly discovered assets and hosts with open high/critical findings are processed first.
* **Cache:** passive discovery (Subfinder, gau, dnsx) can be reused for the configured number of hours. A cached stage is labelled with its
  source scan and age, never refreshes `last_seen`, and is never treated as evidence. Port, HTTP, crawl and Nuclei results are never cached.

### Optional intelligence providers

Shodan and urlscan.io, off by default. The pipeline works without them. Keys are saved in `data/secrets.json` (mode 0600), shown only as
"configured", and removed from logs and reports. When a scan opts in, only in-scope IPs (Shodan host lookup) or hostnames (urlscan search of
existing public results) are sent; nothing is submitted for scanning and no evidence is uploaded. Usage numbers shown are whatever the provider
returns (Shodan `/api-info`, urlscan rate-limit headers). Censys is not implemented.

### Reports

Each finished scan writes `data/reports/scan-<id>.html` and `.json` (mode 0600); the buttons on the scan page regenerate them from the
database. Contents: scope and exclusions, times, profile and limits, tools and versions, assets and services, findings with evidence and
confidence, failed or incomplete stages, and the statement separating scanner detections from validated vulnerabilities. HTML is rendered
with autoescaping and served with a restrictive Content-Security-Policy.

## Continuing with an AI coding agent

`AGENTS.md` (read by Antigravity, Claude Code, Cursor and Codex) holds the project rules, map and next-work list; `.agent/rules` and `.agent/workflows` add a short safety rule and a verify workflow.

## Tests

```bash
pip install -r requirements-dev.txt
python -m pytest
```

111 tests cover scope validation, command construction, rate limiting, deduplication, parsers, reports (including HTML escaping), providers
(mocked network), the subprocess runner, and the full pipeline end to end using stub executables that print fixture output. No test performs a real scan.

## Debugging a scan

The scan page has a **Tool runs** section: for each tool run it shows the exact command, exit code, last error output and the first part of the tool's output (secrets redacted). Use it first when a stage fails or looks wrong. The same data is at `/api/scans/<id>/runs`. Databases from earlier versions are upgraded automatically on start.

## Honest limitations

* **Nuclei and the request budget.** Nuclei sends roughly one request per template per URL. At 2 requests/second an unfiltered run is far larger than the 15 minute tool timeout allows (a real first run timed out with no output). The wizard now starts with a narrower tag set (`exposure,misconfig,takeover`); widen it only together with a higher per-tool timeout and scan duration in Settings, and only if the program allows the request volume.
* **Hosted sites.** Owning a site does not give you the right to port-scan the platform's servers it runs on. Leave "allow resolved IPs" off for Vercel, Netlify, Cloudflare, GitHub Pages and similar.

* The adapters were written against the tools' documented JSON/JSONL output and flags, and exercised in tests with fixtures and stubs.
  The build environment did not have the real binaries, so **real-tool runs are the first thing to check on your Kali machine.** Tool flags change
  between versions; if one is rejected, the stage shows *Failed* with the tool's last error line, and the exact argv is stored in `tool_runs`.
  Start with Passive, then Standard, against a target you are authorised to test.
* Interrupted scans (server restart) are marked failed; *Retry* resumes unfinished stages. Stages that finished as *Partial* are kept, not re-run.
* ZAP integration is the least tested (quick scan, JSON report parsing).
* Concurrency limits apply after a restart; rate and timeout limits apply to new scans.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Tool shows *Missing* | Install it (table above) and press *Re-check*. Check `which <tool>` outside the venv. |
| httpx *does not look like httpx* | You have the Python CLI. Install `httpx-toolkit` or pin `RECONFORGE_TOOL_HTTPX`. |
| Stage *Failed* with a flag error | Version mismatch. Read the message, check `<tool> -h`, open an issue with the version from Tool health. |
| Naabu stage *Skipped*, "not explicitly authorised" | Resolved IPs are not in scope. Add the IPs you own, or tick "allow resolved IPs" if all of them are yours. |
| Scan *Failed*: budget below 1 rps | Raise the budget to at least 1, or use Passive. |
| "Host header not allowed" | Browse via `http://127.0.0.1:8000` or `http://localhost:8000`; add other names with `RECONFORGE_ALLOWED_HOSTS`. |
| "Cross-site or malformed request rejected" | Requests must come from the dashboard (custom header). Use the UI, or send `X-ReconForge: 1` from your own client. |
| Port already in use | `RECONFORGE_PORT=8001 python -m app` |
| FFUF wordlist rejected | It must be inside `RECONFORGE_WORDLIST_DIRS` (default `/usr/share/wordlists`, `/usr/share/seclists`). |
