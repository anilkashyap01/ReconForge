"""Scan orchestration: stage planning, scope enforcement, caching, retries, persistence."""
from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import os
import time
import traceback
from contextlib import nullcontext
from dataclasses import asdict, replace
from typing import Any
from urllib.parse import urlsplit

from ..adapters import REGISTRY, BuildContext, Command
from ..config import Limits, effective_limits, get_settings, redact
from ..database import db, now, parse_ts, q, q1
from ..models import ParseResult, ScanOptions, ScanStatus, StageStatus
from ..rate_limiter import RetryPolicy, plan_tool_rate
from ..scope import Scope, ScopeError, ScopeViolation, filter_hosts, revalidate_ips, revalidate_targets
from . import providers, store
from .runner import RunResult, run_command
from .tools import detect_all

STAGES: dict[str, tuple[str, bool, str]] = {
    "subfinder": ("Subdomain enumeration", False, "Queries public passive sources. Sends nothing to the target."),
    "gau": ("Historical URLs", False, "Queries public web archives. Sends nothing to the target."),
    "dnsx": ("DNS resolution", True, "Sends DNS queries through your resolvers; the target's nameservers may see them."),
    "httpx": ("HTTP probing", True, "Sends HTTP(S) requests to in-scope hosts."),
    "naabu": ("Port discovery", True, "Sends TCP connection attempts to authorised IP addresses."),
    "nmap": ("Service detection", True, "Sends probes to the open ports found by port discovery."),
    "katana": ("Crawling", True, "Crawls in-scope sites with HTTP requests."),
    "ffuf": ("Content discovery", True, "Sends wordlist-driven HTTP requests to in-scope sites."),
    "testssl": ("TLS assessment", True, "Opens many TLS connections to in-scope HTTPS services."),
    "zap": ("Web application assessment", True, "Spiders and actively tests in-scope sites. This is intrusive."),
    "nuclei": ("Vulnerability checks", True, "Sends template-based HTTP requests to in-scope URLs."),
    "enrichment": ("Provider enrichment", False, "Sends in-scope hostnames/IPs to the providers you enabled. Sends nothing to the target."),
}
CACHEABLE = {"subfinder", "gau", "dnsx"}      # passive discovery only; scan evidence is never cached
ACTIVE_PROFILES = ("vulnerability", "web")


def plan_stages(profile: str, o: ScanOptions) -> list[str]:
    s = ["subfinder"] + (["gau"] if o.enable_gau else [])
    if profile != "passive":
        s += ["dnsx", "httpx", "naabu"]
        s += ["nmap"] if o.enable_nmap else []
        s += ["katana"] if profile == "web" else []
        s += ["ffuf"] if o.enable_ffuf else []
        s += ["testssl"] if o.enable_testssl else []
        s += ["zap"] if o.enable_zap else []
        s += ["nuclei"] if profile in ACTIVE_PROFILES else []
    return s + (["enrichment"] if o.enable_enrichment else [])


def validate_request(profile: str, authorization_confirmed: bool, active_confirmed: bool, o: ScanOptions) -> None:
    """Server-side gate. The UI repeats these checks but is not trusted."""
    if not authorization_confirmed:
        raise ScopeError("You must confirm you have permission to test the selected scope.")
    if profile in ACTIVE_PROFILES and not active_confirmed:
        raise ScopeError("Active vulnerability testing needs a separate, explicit confirmation.")
    if profile == "passive" and (o.enable_nmap or o.enable_testssl or o.enable_ffuf or o.enable_zap):
        raise ScopeError("Passive Recon cannot include modules that send traffic to the target.")
    if (o.enable_ffuf or o.enable_zap) and profile != "web":
        raise ScopeError("FFUF and ZAP are only available in the Web Assessment profile.")
    if o.enable_ffuf and not o.ffuf_wordlist:
        raise ScopeError("FFUF needs a wordlist path.")


def create_scan(conn, project: dict, profile: str, include: list[str], exclude: list[str], body_options: ScanOptions,
                global_limits: dict[str, Any], authorization_confirmed: bool, active_confirmed: bool) -> int:
    overrides = {**global_limits, **{k: v for k, v in body_options.model_dump().items() if v is not None and k in asdict(Limits())}}
    limits = effective_limits(overrides)
    cfg = {"options": body_options.model_dump(), "limits": asdict(limits)}
    sid = conn.execute(
        "INSERT INTO scans(project_id,profile,status,config_json,scope_json,exclusions_json,authorization_confirmed,active_testing_confirmed,created_at)"
        " VALUES(?,?,?,?,?,?,?,?,?)", (project["id"], profile, ScanStatus.QUEUED, json.dumps(cfg), json.dumps(include), json.dumps(exclude),
                                        int(authorization_confirmed), int(active_confirmed), now())).lastrowid
    for i, name in enumerate(plan_stages(profile, body_options)):
        label, touches, note = STAGES[name]
        conn.execute("INSERT INTO scan_stages(scan_id,position,name,tool,label,touches_target,traffic_note) VALUES(?,?,?,?,?,?,?)",
                     (sid, i, name, name, label, int(touches), note))
    store.log(conn, sid, "info", f"Scan created: profile={profile}, scope={include}, exclusions={exclude}")
    return sid


def _is_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


class ScanRun:
    def __init__(self, scan_id: int, sched: "Any") -> None:
        self.sid, self.sched = scan_id, sched
        self.cancel = asyncio.Event()
        self.issues: list[str] = []
        self.rejected = 0
        self.agg = ParseResult()

    # ------------------------------------------------------------------ small helpers
    def log(self, level: str, msg: str) -> None:
        with db() as c:
            store.log(c, self.sid, level, msg)

    def set_stage(self, name: str, **f: Any) -> None:
        with db() as c:
            c.execute(f"UPDATE scan_stages SET {', '.join(k + '=?' for k in f)} WHERE scan_id=? AND name=?", (*f.values(), self.sid, name))

    def set_scan(self, **f: Any) -> None:
        with db() as c:
            c.execute(f"UPDATE scans SET {', '.join(k + '=?' for k in f)} WHERE id=?", (*f.values(), self.sid))

    def remaining(self) -> float:
        return self.deadline - time.monotonic()

    def flags(self) -> tuple[bool, bool]:
        with db() as c:
            r = q1(c, "SELECT cancel_requested,pause_requested FROM scans WHERE id=?", (self.sid,))
        return bool(r and r["cancel_requested"]), bool(r and r["pause_requested"])

    async def sleep(self, seconds: float) -> None:
        try:
            await asyncio.wait_for(self.cancel.wait(), seconds)
        except asyncio.TimeoutError:
            pass

    async def wait_if_paused(self) -> None:
        paused = False
        while True:
            cancelled, pause = self.flags()
            if cancelled or self.cancel.is_set():
                self.cancel.set()
                return
            if not pause:
                if paused:
                    self.set_scan(status=ScanStatus.RUNNING)
                    self.log("info", "Scan resumed")
                return
            if not paused:
                paused = True
                self.set_scan(status=ScanStatus.PAUSED)
                self.log("info", "Scan paused before the next stage")
            await self.sleep(1.0)

    # ------------------------------------------------------------------ state derived from stage outputs
    def hostnames(self) -> list[str]:
        seen, out = set(), []
        for h in self.scope.seed_domains() + [h for h, _ in self.agg.hosts]:
            if h not in seen and not _is_ip(h):
                seen.add(h)
                out.append(h)
        if len(out) > self.limits.max_assets:
            out = out[: self.limits.max_assets]
        return out

    def prioritised(self, hosts: list[str]) -> list[str]:
        """Newly discovered assets first, then hosts with open high/critical findings."""
        with db() as c:
            new = {r["value"] for r in q(c, "SELECT value FROM assets WHERE project_id=? AND first_scan_id=?", (self.pid, self.sid))}
            hot = {r["asset"] for r in q(c, "SELECT DISTINCT asset FROM findings WHERE project_id=? AND severity IN ('high','critical')"
                                         " AND validation_status IN ('unvalidated','confirmed')", (self.pid,))}
        return sorted(hosts, key=lambda h: (h not in new, h not in hot, h))

    def ip_hosts(self) -> dict[str, list[str]]:
        m: dict[str, list[str]] = {}
        for h, ips in (self.agg.output.get("host_ips") or {}).items():
            for ip in ips:
                m.setdefault(ip, []).append(h)
        return m

    def scannable_ips(self) -> tuple[list[str], int]:
        ips, skipped = list(self.seed_ips), 0
        for h in self.prioritised(self.hostnames()):
            for ip in (self.agg.output.get("host_ips") or {}).get(h, []):
                if ip in ips:
                    continue
                ok, _ = self.scope.ip_scannable(ip, self.opts.allow_resolved_ips)
                if ok:
                    ips.append(ip)
                else:
                    skipped += 1
        return ips[: self.limits.max_assets], skipped

    def live_urls(self) -> list[str]:
        urls = list(dict.fromkeys(self.agg.output.get("live_urls") or []))
        order = {h: i for i, h in enumerate(self.prioritised(sorted({urlsplit(u).hostname or "" for u in urls})))}
        return sorted(urls, key=lambda u: order.get(urlsplit(u).hostname or "", 0))

    def inputs_for(self, name: str) -> tuple[list[str], dict, str]:
        sc, o = self.scope, self.opts
        if name == "subfinder":
            return sc.wildcard_roots(), {}, "No wildcard domain (*.example.com) is in scope, so there is nothing to enumerate."
        if name == "gau":
            wild = sc.wildcard_roots()
            return wild + [d for d in sc.seed_domains() if d not in wild], {"wildcard_roots": wild}, "No domains are in scope."
        if name == "dnsx":
            return self.prioritised(self.hostnames()), {}, "No hostnames to resolve."
        if name == "httpx":
            hosts = self.hostnames()
            resolved = self.agg.output.get("resolved")
            if resolved is not None:
                hosts = [h for h in hosts if h in set(resolved)]
            return self.prioritised(hosts) + self.seed_ips, {}, "No resolving hostnames or in-scope IPs to probe."
        if name == "naabu":
            ips, skipped = self.scannable_ips()
            why = "No IP addresses are authorised for port discovery."
            if skipped:
                why = (f"{skipped} resolved IP address(es) were not scanned because they are not explicitly authorised. "
                       "Add them to the scope, or enable 'allow resolved IPs' if every one belongs to your target.")
            return ips, {"skipped": skipped}, why
        if name == "nmap":
            by_ip: dict[str, list[int]] = {}
            for p in self.agg.ports:
                if p.ip and p.source == "naabu":
                    by_ip.setdefault(p.ip, [])
                    if p.port not in by_ip[p.ip]:
                        by_ip[p.ip].append(p.port)
            return list(by_ip), {"ports_by_ip": by_ip}, "Port discovery found no open ports."
        if name == "katana":
            return self.live_urls()[:25], {}, "No live web endpoints to crawl."
        if name == "nuclei":
            crawled = [e.url for e in self.agg.endpoints if e.kind == "crawl"][:100]
            return list(dict.fromkeys(self.live_urls() + crawled))[: self.limits.max_assets], {}, "No live web endpoints to check."
        if name in ("ffuf", "zap"):
            return self.live_urls()[:3], {}, "No live web endpoints."
        if name == "testssl":
            hp = []
            for u in self.live_urls():
                p = urlsplit(u)
                if p.scheme == "https" and p.hostname:
                    hp.append(f"{p.hostname}:{p.port or 443}")
            return list(dict.fromkeys(hp))[:10], {}, "No HTTPS services found."
        return [], {}, "Unknown stage."

    # ------------------------------------------------------------------ scope enforcement
    def revalidate(self, kind: str, cmd: Command) -> None:
        if cmd.stdin is not None and [x for x in cmd.stdin.split("\n") if x] != cmd.targets:
            raise ScopeViolation("command input does not match the validated target list")
        if kind == "ip":
            revalidate_ips(self.scope, cmd.targets, self.opts.allow_resolved_ips)
        else:
            revalidate_targets(self.scope, cmd.target_kind, cmd.targets)

    def scope_filter(self, pr: ParseResult) -> ParseResult:
        sc, rej = self.scope, []
        hosts, r = filter_hosts(sc, [h for h, _ in pr.hosts]); rej += r
        keep, srcs = set(hosts), dict(pr.hosts)
        out = ParseResult(hosts=[(h, srcs[h]) for h in hosts], warnings=list(pr.warnings), ports=list(pr.ports))
        out.dns = [d for d in pr.dns if sc.host_allowed(d.host)[0]]
        for e in pr.endpoints:
            ok, why = sc.url_allowed(e.url)
            (out.endpoints.append(e) if ok else rej.append((e.url, why)))
        for f in pr.findings:
            ok = sc.host_allowed(f.asset)[0] and (not f.url or sc.url_allowed(f.url)[0])
            (out.findings.append(f) if ok else rej.append((f.asset, "finding outside scope")))
        for k, v in pr.output.items():
            if k == "live_urls":
                out.output[k] = [u for u in v if sc.url_allowed(u)[0]]
            elif k in ("host_ips", "cnames") and isinstance(v, dict):
                out.output[k] = {h: x for h, x in v.items() if sc.host_allowed(h)[0]}
            elif k == "resolved":
                out.output[k] = [h for h in v if sc.host_allowed(h)[0]]
            else:
                out.output[k] = v
        if rej:
            self.rejected += len(rej)
            self.log("warning", f"Rejected {len(rej)} result(s) outside the authorised scope, e.g. " + "; ".join(f"{a} ({b})" for a, b in rej[:5]))
        return out

    def map_ports(self, pr: ParseResult) -> ParseResult:
        """Port tools see IPs; store results against the in-scope hostnames (and explicit IPs) they belong to."""
        ip_hosts, mapped = self.ip_hosts(), []
        for p in pr.ports:
            if not p.ip or not self.scope.ip_scannable(p.ip, self.opts.allow_resolved_ips)[0]:
                self.rejected += 1
                continue
            if self.scope.ip_allowed(p.ip)[0]:
                mapped.append(replace(p, host=p.ip))
            mapped += [replace(p, host=h) for h in ip_hosts.get(p.ip, []) if self.scope.host_allowed(h)[0]]
        pr.ports = mapped
        return pr

    # ------------------------------------------------------------------ persistence
    def persist(self, pr: ParseResult, tool_version: str | None, cached: bool = False) -> int:
        new_findings = 0
        with db() as c:
            for host, src in pr.hosts:
                upsert = store.upsert_asset(c, self.pid, "ip" if _is_ip(host) else "domain", host, src, self.sid, cached)
            if not cached:
                for d in pr.dns:
                    store.upsert_dns(c, self.pid, d, self.sid)
                for p in pr.ports:
                    store.upsert_port(c, self.pid, p, self.sid)
                for e in pr.endpoints:
                    store.upsert_endpoint(c, self.pid, e, self.sid)
                for f in pr.findings:
                    new_findings += int(store.upsert_finding(c, self.pid, f, self.sid, tool_version)[1])
        return new_findings

    def read_file(self, path) -> str | None:
        try:
            with open(path, "rb") as fh:
                return fh.read(self.limits.max_output_bytes).decode("utf-8", "replace")
        except OSError:
            return None

    # ------------------------------------------------------------------ command execution
    def build_ctx(self, tool, rate=None) -> BuildContext:
        return BuildContext(binary=tool.path, rate=rate or self.rate, opts=self.opts, workdir=self.workdir, tool_version=tool.version,
                            template_version=tool.template_version, allowed_wordlist_dirs=get_settings().wordlist_dirs)

    async def run_cmd(self, name: str, adapter, tool, cmd: Command, extra: dict) -> tuple[RunResult, Command, int]:
        policy, attempt, rate = RetryPolicy.from_limits(self.limits), 0, self.rate
        while True:
            timeout = min(self.limits.tool_timeout_seconds, self.remaining())
            if timeout <= 1:
                return RunResult(argv=cmd.argv, error="scan time limit reached"), cmd, attempt
            gate = self.sched.target_sem if adapter.spec.touches_target else nullcontext()
            async with gate:
                self.revalidate(cmd.target_kind, cmd)          # validated again at the moment of launch
                res = await run_command(cmd.argv, stdin_text=cmd.stdin, timeout=timeout, max_output=self.limits.max_output_bytes,
                                        cancel=self.cancel, cwd=self.workdir)
            low = res.stderr_tail.lower()
            limited = "429" in low or "too many requests" in low or "rate limit" in low
            failed = (res.exit_code not in (0, None)) and not res.timed_out and not res.stdout.strip()   # timeouts are never retried
            if res.cancelled or res.error or not (failed or limited) or attempt >= policy.max_retries:
                return res, cmd, attempt + 1
            delay = max(policy.delay(attempt), 30.0 if limited else 0.0)
            if limited and adapter.spec.touches_target:
                rate = self.rate = self.rate.halved()
                self.log("warning", f"{name}: rate limiting detected; halving request rate to {rate.rps}/s")
                cmd = adapter.build(self.build_ctx(tool, rate), cmd.targets, extra)[0]
            self.log("warning", f"{name}: transient failure (attempt {attempt + 1}); retrying in {delay:.0f}s")
            self.set_stage(name, attempts=attempt + 1, message=f"Retrying after transient failure (attempt {attempt + 1})")
            await self.sleep(delay)
            attempt += 1

    def cache_lookup(self, name: str, ihash: str) -> dict | None:
        ttl = self.limits.cache_ttl_hours
        with db() as c:
            row = q1(c, "SELECT st.* FROM scan_stages st JOIN scans s ON s.id=st.scan_id WHERE s.project_id=? AND st.tool=? AND st.input_hash=?"
                        " AND st.status IN ('completed','empty') AND st.cached_from_scan IS NULL AND st.scan_id!=? ORDER BY st.finished_at DESC LIMIT 1",
                     (self.pid, name, ihash, self.sid))
        when = parse_ts(row["finished_at"]) if row else None
        if row and when and (time.time() - when.timestamp()) < ttl * 3600:
            return row
        return None

    # ------------------------------------------------------------------ stage execution
    async def run_stage(self, name: str) -> tuple[str, str, ParseResult | None, int | None]:
        if name == "enrichment":
            ips = [ip for ip in self.scannable_ips()[0]]
            ok, msgs, errs = await providers.enrich(self.pid, self.sid, self.hostnames()[:25], ips[:25], self.cancel)
            msg = "; ".join(msgs + errs) or f"{ok} lookup(s) stored"
            if errs and not ok:
                return StageStatus.FAILED, msg, None, 0
            return (StageStatus.PARTIAL if errs else StageStatus.COMPLETED if ok else StageStatus.EMPTY), msg, ParseResult(), ok
        adapter, tool = REGISTRY[name], self.tools[name]
        if not tool.installed:
            return StageStatus.MISSING_TOOL, f"{tool.label} is not usable: {tool.problem}. Install it (see Tool health) and use Retry.", None, None
        inputs, extra, why = self.inputs_for(name)
        if not inputs:
            return StageStatus.SKIPPED, why, None, None
        if name == "naabu":
            implicit = [ip for ip in inputs if ip not in self.seed_ips]
            if implicit:
                self.log("warning", f"Port scanning {len(implicit)} resolved IP(s) that are not listed in scope ({', '.join(implicit[:5])}). "
                                    "If the site is hosted on a shared platform (CDN, Vercel, Netlify, GitHub Pages...) those addresses belong to the platform, not to you.")
        ihash = hashlib.sha256(json.dumps([name, sorted(inputs), self.scope.to_json()["exclude"]]).encode()).hexdigest()
        self.set_stage(name, input_count=len(inputs), input_hash=ihash)
        if name in CACHEABLE and self.opts.use_cache:
            hit = self.cache_lookup(name, ihash)
            if hit:
                pr = self.scope_filter(store.result_from_json(hit["output_json"]))
                self.persist(pr, tool.version, cached=True)
                self.set_stage(name, cached_from_scan=hit["scan_id"], cached_at=hit["finished_at"], output_json=store.result_to_json(pr))
                self.agg.merge(pr)
                return StageStatus.CACHED, f"Reused results from scan #{hit['scan_id']} ({hit['finished_at']}). Run again with caching off to refresh.", pr, pr.item_count
        merged, fails, partials, attempts, ran = ParseResult(), [], [], 0, 0
        ctx = self.build_ctx(tool)
        for cmd in adapter.build(ctx, inputs, extra):
            if self.cancel.is_set():
                return StageStatus.CANCELLED, "Cancelled by user.", merged, merged.item_count
            started = now()
            res, cmd, n = await self.run_cmd(name, adapter, tool, cmd, extra)
            attempts += n
            ran += 1
            status = ("cancelled" if res.cancelled else "failed" if res.error or res.exit_code not in (0, None) else "completed")
            with db() as c:
                c.execute("INSERT INTO tool_runs(scan_id,stage_name,tool,version,argv_json,started_at,finished_at,exit_code,status,timed_out,truncated,stdout_bytes,stderr_tail,error,stdout_head)"
                          " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (self.sid, name, name, tool.version, json.dumps(cmd.argv), started, now(), res.exit_code,
                                                                       "timeout" if res.timed_out else status, int(res.timed_out), int(res.truncated), res.stdout_bytes,
                                                                       redact(res.stderr_tail)[-2000:], res.error, redact(res.stdout[:6000])))
            if res.cancelled:
                return StageStatus.CANCELLED, "Cancelled by user.", merged, merged.item_count
            file_text = self.read_file(cmd.out_file) if cmd.out_file else None
            try:
                pr = adapter.parse(cmd, res.stdout, file_text, ctx) if (res.stdout or file_text) else ParseResult()
            except Exception as exc:                     # a parser bug must not lose the other commands' results
                pr = ParseResult(warnings=[f"parse error: {exc}"])
                fails.append(f"{cmd.label}: could not parse output")
            if name in ("naabu", "nmap"):
                pr = self.map_ports(pr)
            pr = self.scope_filter(pr)
            err_line = redact(res.stderr_tail.strip().splitlines()[-1]) if res.stderr_tail.strip() else ""
            if res.error:
                fails.append(f"{cmd.label}: {res.error}")
            elif res.timed_out:
                partials.append(f"{cmd.label}: stopped at the {self.limits.tool_timeout_seconds}s tool timeout. Coverage is incomplete, so "
                                "having no results here does NOT mean the target is clean")
            elif res.truncated:
                partials.append(f"{cmd.label}: output exceeded {self.limits.max_output_bytes} bytes and was cut off")
            elif res.exit_code not in (0, None):
                (partials if pr.item_count else fails).append(f"{cmd.label}: exit code {res.exit_code}" + (f" ({err_line})" if err_line else ""))
            for w in pr.warnings:
                self.log("warning", f"{name}: {w}")
            merged.merge(pr)
        new_f = self.persist(merged, tool.version)
        self.agg.merge(merged)
        self.set_stage(name, attempts=attempts, output_json=store.result_to_json(merged))
        n = merged.item_count
        note = f" ({new_f} new finding(s))" if new_f else ""
        if fails and not n:
            return StageStatus.FAILED, "; ".join(fails)[:600], merged, 0
        if fails or partials:
            return StageStatus.PARTIAL, ("; ".join(fails + partials))[:600] + (f". {n} result(s) kept." if n else "."), merged, n
        if not n:
            return StageStatus.EMPTY, f"{tool.label} finished successfully and found nothing.", merged, 0
        return StageStatus.COMPLETED, f"{n} result(s){note}.", merged, n

    async def execute(self, st: dict) -> None:
        name = st["name"]
        self.set_stage(name, status=StageStatus.RUNNING, started_at=now(), finished_at=None, message=None, error=None)
        self.log("info", f"Stage {name} started")
        try:
            status, msg, _, items = await self.run_stage(name)
        except ScopeViolation as exc:
            status, msg, items = StageStatus.FAILED, f"Blocked by scope validation before launch: {exc}", 0
            self.log("error", msg)
        except ScopeError as exc:
            status, msg, items = StageStatus.FAILED, f"Invalid scan option: {exc}", 0
        except Exception as exc:                          # unexpected: record, keep the scan alive
            status, msg, items = StageStatus.FAILED, f"Internal error: {type(exc).__name__}: {redact(str(exc))[:300]}", 0
            self.log("error", redact(traceback.format_exc())[-1500:])
        fields: dict[str, Any] = dict(status=status, message=msg, finished_at=now())
        if items is not None:
            fields["items"] = items
        if status == StageStatus.FAILED:
            fields["error"] = msg
        self.set_stage(name, **fields)
        if status in (StageStatus.FAILED, StageStatus.PARTIAL, StageStatus.MISSING_TOOL, StageStatus.CANCELLED):
            self.issues.append(f"{name}: {status}")
        self.log("info" if status not in (StageStatus.FAILED,) else "error", f"Stage {name} {status}: {msg}")

    def _stage_rows(self) -> list[dict]:
        with db() as c:
            return q(c, "SELECT name FROM scan_stages WHERE scan_id=?", (self.sid,))

    # ------------------------------------------------------------------ main loop
    async def run(self) -> None:
        with db() as c:
            scan = q1(c, "SELECT * FROM scans WHERE id=?", (self.sid,))
        cfg = json.loads(scan["config_json"])
        self.pid, self.profile = scan["project_id"], scan["profile"]
        self.opts, self.limits = ScanOptions(**cfg["options"]), Limits(**cfg["limits"])
        self.scope = Scope.from_strings(json.loads(scan["scope_json"]), json.loads(scan["exclusions_json"]))
        self.rate = plan_tool_rate(self.limits)
        if self.rate.clamped:
            self.log("warning", self.rate.note)
        self.workdir = get_settings().work_dir / f"scan-{self.sid}"
        self.workdir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.workdir, 0o700)
        self.deadline = time.monotonic() + self.limits.max_scan_seconds
        self.tools = await detect_all(force=True)
        self.set_scan(status=ScanStatus.RUNNING, started_at=scan["started_at"] or now(), completed_at=None, error=None)
        try:
            planned = {r["name"] for r in self._stage_rows()}
            if self.rate.clamped and planned & {"httpx", "katana", "nuclei", "ffuf"}:
                raise ScopeError(self.rate.note + ". The scanners cannot go below 1 request per second, and ReconForge will not exceed your configured budget. "
                                 "Raise the budget to at least 1, or use the Passive profile.")
            self.seed_ips = self.scope.seed_ips(self.limits.max_assets)
            with db() as c:
                for d in self.scope.seed_domains():
                    store.upsert_asset(c, self.pid, "domain", d, "scope", self.sid)
                for ip in self.seed_ips:
                    store.upsert_asset(c, self.pid, "ip", ip, "scope", self.sid)
                stages = q(c, "SELECT * FROM scan_stages WHERE scan_id=? ORDER BY position", (self.sid,))
            for st in stages:                              # rebuild state from stages that already finished (retry/resume)
                if st["status"] in StageStatus.DONE and st["output_json"]:
                    self.agg.merge(store.result_from_json(st["output_json"]))
            for st in stages:
                await self.wait_if_paused()
                if self.cancel.is_set():
                    self.set_stage(st["name"], status=StageStatus.CANCELLED, message="Scan cancelled before this stage started.") if st["status"] not in StageStatus.DONE else None
                    continue
                if st["status"] in StageStatus.DONE:
                    continue
                if self.remaining() <= 1:
                    self.set_stage(st["name"], status=StageStatus.SKIPPED, message="Skipped: the maximum scan duration was reached.")
                    self.issues.append(f"{st['name']}: time limit")
                    continue
                await self.execute(st)
            await self.finalize()
        except ScopeError as exc:
            self.log("error", f"Scan failed: {exc}")
            self.set_scan(status=ScanStatus.FAILED, error=str(exc), completed_at=now())

    async def finalize(self) -> None:
        with db() as c:
            stages = q(c, "SELECT name,status FROM scan_stages WHERE scan_id=?", (self.sid,))
            sev = {r["severity"]: r["n"] for r in q(c, "SELECT f.severity, COUNT(*) n FROM finding_scans s JOIN findings f ON f.id=s.finding_id WHERE s.scan_id=? GROUP BY f.severity", (self.sid,))}
            assets = q1(c, "SELECT COUNT(DISTINCT asset_id) n FROM asset_scans WHERE scan_id=?", (self.sid,))["n"]
            new_assets = q1(c, "SELECT COUNT(*) n FROM assets WHERE first_scan_id=?", (self.sid,))["n"]
            new_findings = q1(c, "SELECT COUNT(*) n FROM findings WHERE first_scan_id=?", (self.sid,))["n"]
        done = sum(1 for s in stages if s["status"] in StageStatus.DONE)
        cancelled = self.cancel.is_set() or self.flags()[0]
        status = (ScanStatus.CANCELLED if cancelled else ScanStatus.FAILED if self.issues and not done
                  else ScanStatus.COMPLETED_WITH_ISSUES if self.issues else ScanStatus.COMPLETED)
        summary = {"assets": assets, "new_assets": new_assets, "findings_by_severity": sev, "new_findings": new_findings,
                   "rejected_out_of_scope": self.rejected, "stage_status": {s["name"]: s["status"] for s in stages}, "issues": self.issues}
        self.set_scan(status=status, completed_at=now(), summary_json=json.dumps(summary))
        self.log("info", f"Scan finished: {status}")
        try:
            from . import reports
            reports.write_reports(self.sid)
        except Exception as exc:
            self.log("error", f"Report generation failed: {redact(str(exc))[:200]}")
