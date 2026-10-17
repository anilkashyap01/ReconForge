# AGENTS.md: ReconForge

Instructions for AI coding agents (Antigravity, Claude Code, Cursor, Codex) continuing this project.
Read this fully before changing code. The safety rules are not optional.

## What this is
ReconForge is a local-first recon and vulnerability-assessment platform: FastAPI + Jinja2 + vanilla JS + SQLite. It orchestrates
external tools the user installs (Subfinder, dnsx, httpx, Naabu, Katana, Nuclei; optional Nmap, ZAP, FFUF, gau, testssl.sh), parses their
output into SQLite, and shows it in a dashboard on 127.0.0.1. Owner: Dora, cybersecurity fresher, Kali Linux. Full user docs: README.md.

## Non-negotiable rules
1. **Scope is enforced in backend code, never only in the UI.** Every host, URL and finding is filtered through `Scope` before storage, and the
   exact target list is re-validated right before each launch (`ScanRun.revalidate`). Do not add a code path that skips either.
2. **No shell.** Tools run via `asyncio.create_subprocess_exec` with argv lists (`app/services/runner.py`). Never `shell=True`, `os.system`, or string-built commands.
   User-supplied values that reach argv must pass a validator in `app/scope.py` (`validate_port_spec`, `validate_ident_list`, `safe_path_under`, scope parsing).
3. **Never launch destructive, DoS, brute-force or intrusive checks automatically.** Nuclei excludes those tags; FFUF/ZAP are opt-in, Web profile only, and need the active-testing confirmation.
4. **Conservative defaults** (2 req/s, 1 target-touching tool at a time). Do not raise defaults. Never claim a rate limit is enforced where only a tool flag is passed.
   Never rotate API keys or identities to evade provider limits; honour 429 and Retry-After.
5. **Never fabricate data.** No fake metrics, hardcoded findings or invented provider responses. Show real DB values or an empty state.
6. **Scanner matches are potential findings** (`validation_status='unvalidated'`) until an analyst confirms them. Never describe a detection as confirmed.
7. **Secrets** live only in `data/secrets.json` (0600) via `SecretStore`. Keep them out of logs, reports, templates, JS, error text, and the scanner environment (`redact()`, `safe_env()`).
8. **No third-party uploads** of scan data without explicit opt-in. Provider calls send only in-scope hostnames/IPs.
9. **Never write code that attacks, exploits, or targets anything.** This tool only wraps scanners for authorised testing.
10. Bind to loopback only. Keep the Host-header allow-list and the `X-ReconForge` CSRF check in `app/main.py`.

## Commands
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest -q            # must pass before you finish; currently 111 tests
python -m app                  # http://127.0.0.1:8000
```
Tests use stub executables (`tests/conftest.py`, fixture `fake_tools`) and temp data dirs. **Tests must never run a real scan or touch the network.**

## Map
- `app/main.py` routes, security middleware, JSON API. `app/static/app.js` + `style.css`, `app/templates/` (shell.html, report.html).
- `app/scope.py` scope parsing/validation (exact `example.com` vs wildcard `*.example.com`, IPs/CIDRs, exclusions, revalidation).
- `app/rate_limiter.py` token buckets, host budgets, retry policy, `plan_tool_rate`. `app/config.py` settings, `Limits`, hard maxima, `SecretStore`.
- `app/database.py` schema (CREATE IF NOT EXISTS; there is no migration system) and helpers. `app/models.py` request models, record dataclasses, status enums.
- `app/adapters/` one class per tool: `build()` returns `Command`s (argv, targets, target_kind, stdin), `parse()` returns `ParseResult`. Live code is `discovery.py`, `assessment.py`.
  `superseded/` holds old unused adapters; ignore it.
- `app/services/pipeline.py` stage plan, `ScanRun` (inputs, scope filter, cache, retries, persistence, finalize). `store.py` dedup upserts and compare. `runner.py` subprocess runner.
  `tools.py` detection. `providers.py` Shodan/urlscan. `reports.py` HTML/JSON reports. `app/scheduler.py` queue and the shared target semaphore.

## Conventions
- Typed Python, small functions, clear errors. Parsers must tolerate bad lines and never raise on tool output.
- Stage status vocabulary (keep distinct): completed, empty, partial, failed, missing_tool, skipped, cached, cancelled. A timeout is `partial`, never `failed`, and is never retried.
- Cached stages never refresh `last_seen` and are never evidence. Only subfinder, gau, dnsx are cacheable.
- Resolved IPs are scanned only if explicitly in scope or the user opts in (`allow_resolved_ips`). Hosted platforms (Vercel, Netlify, Cloudflare...) are not the site owner's to authorise.
- Frontend: build DOM with `h()` and text nodes only. **Never use innerHTML with data.** Report HTML relies on Jinja autoescape.
- The app sends `Content-Security-Policy: default-src 'self'`, which **blocks inline `style="..."` attributes and inline scripts/styles in markup**. Style with CSS classes, or set `el.style.*` / `el.style.cssText` from JS (`h()` does this for the `style` prop).
  Use CSS custom properties set via `el.style.setProperty` for dynamic widths. The report page is the only place with inline `<style>` (its own CSP allows it, no scripts).
- Database changes: add columns/tables with `IF NOT EXISTS` style code; changing a UNIQUE constraint needs a real table-rebuild migration that preserves existing user data.

## Adding or changing a tool adapter
1. Add the class and register it in `app/adapters/__init__.py`; give it a `ToolSpec` (identity regex so a same-named wrong program is rejected).
2. `build()`: argv list only, feed targets via stdin or validated args, set `target_kind`, honour `ctx.rate`.
3. `parse()`: fixture-tested, scope-agnostic (the pipeline filters scope).
4. Add the stage to `STAGES` / `plan_stages` / `inputs_for` in `pipeline.py` with an honest `traffic_note`.
5. Tests: command construction (`tests/test_commands.py`), parser fixture (`tests/test_parsers.py`), and a stub binary if it joins the e2e flow.

## Known issues and next work (highest value first)
1. **Verify adapters against real tool versions.** Only httpx, dnsx, naabu, nuclei were exercised for real (Naabu 2.6.1, httpx 1.9.0, dnsx 1.3.1, Nuclei 3.11.1); Subfinder, Katana, Nmap, FFUF, gau, testssl, ZAP never ran for real.
   Riskiest flags: nuclei `-irr`, `-etags`, `-bs`; katana `-fs fqdn`, `-ef`; naabu `-ec`; ZAP `-quickurl/-quickout`; testssl `--jsonfile`.
2. **Nuclei coverage.** A real unfiltered run timed out at 900 s with no output at 2 req/s. Ideas: estimate request count before launch, show progress (nuclei stats), split work into chunks so
   partial coverage is recorded, resume after timeout. Wizard now defaults tags to `exposure,misconfig,takeover` (tag names unverified; check with `nuclei -tgl`).
3. (Done) Ports are now stored per host+IP+port with a migration, and each tool run keeps its exact command, exit code, stderr tail and a redacted head of its output (scan page, "Tool runs").
   Still open: a real scan once showed Naabu "8 results" but 2 stored rows. Re-run it and compare with the saved raw output.
4. Keep more raw output than the 6000-character head if debugging needs it (cap and redact).
5. Verify Kali package names (only `katana` was confirmed); update `kali_package` in the adapters and the README table.
6. Pause is between stages only. Per-host budgets are via tool flags only. Censys is not implemented (verify its documented API before adding).
7. Stages with partial results and items>0 are not re-run by Retry.

## Working style for agents
- Inspect before editing; keep changes small; run `python -m pytest -q` and fix failures before declaring done.
- Do not run the server in the background with `pkill -f` patterns that match your own shell command.
- Python `httpx` (a dev dependency) installs an `httpx` command in the venv; ReconForge strips the venv from the tool PATH. Do not "fix" that.
- If you cannot verify something (tool flags, package names, API behaviour), say so in code comments and the README instead of guessing.
