"""Assessment adapters: Nuclei, Nmap, FFUF, testssl.sh, OWASP ZAP."""
from __future__ import annotations

import json
import xml.etree.ElementTree as ET

from ..models import SEVERITIES, EndpointRecord, FindingRecord, ParseResult, PortRecord
from ..scope import safe_path_under, validate_ident_list
from .base import TAG_RE, Adapter, Command, ToolSpec, as_list, clip, host_of, jsonl, lines

PD = "https://github.com/projectdiscovery"
# Templates carrying these tags are excluded: ReconForge never launches DoS/fuzzing/intrusive/brute-force checks.
NUCLEI_EXCLUDED_TAGS = "dos,fuzz,intrusive,bruteforce,brute-force,bf"


class Nuclei(Adapter):
    spec = ToolSpec("nuclei", "Nuclei", ("nuclei",), ("-version",), r"nuclei|projectdiscovery", r"v?(\d+\.\d+\.\d+)",
                    True, "nuclei", f"{PD}/nuclei", True, "Template-based vulnerability and exposure detection.")

    def build(self, ctx, targets, extra=None):
        r, o = ctx.rate, ctx.opts
        sev = ",".join(s for s in SEVERITIES if s in o.nuclei_severity) or "low,medium,high,critical"
        argv = [ctx.binary, "-jsonl", "-silent", "-nc", "-duc", "-ni", "-irr", "-severity", sev,
                "-rl", str(r.rps), "-c", str(r.threads), "-bs", str(r.threads), "-timeout", "10", "-retries", "1",
                "-etags", NUCLEI_EXCLUDED_TAGS]
        tags = validate_ident_list(o.nuclei_tags, "nuclei tags")
        if tags:
            argv += ["-tags", tags]
        return [Command(argv, targets, "url", stdin=lines(targets), label=f"{len(targets)} URLs")]

    def parse(self, cmd, stdout, file_text, ctx):
        pr = ParseResult()
        for o in jsonl(stdout, pr.warnings):
            info = o.get("info") if isinstance(o.get("info"), dict) else {}
            tid = str(o.get("template-id") or o.get("templateID") or "unknown")
            matched = str(o.get("matched-at") or o.get("host") or "")
            asset = host_of(matched) or host_of("http://" + matched) or matched
            sev = str(info.get("severity", "info")).lower()
            sev = sev if sev in SEVERITIES else "info"
            extracted = ", ".join(str(x) for x in as_list(o.get("extracted-results")))
            ev = f"Matched at {matched}" + (f"; matcher: {o['matcher-name']}" if o.get("matcher-name") else "")
            ev += f"; extracted: {extracted}" if extracted else ""
            details = ""
            if o.get("request") or o.get("response"):
                details = f"--- request ---\n{clip(o.get('request'), 2000)}\n--- response ---\n{clip(o.get('response'), 3000)}"
            pr.findings.append(FindingRecord(
                title=str(info.get("name") or tid), asset=asset, source="nuclei", template_id=tid, severity=sev,
                confidence="low", description=clip(info.get("description"), 2000),
                url=matched if matched.startswith("http") else "", evidence=clip(ev, 2000), details=details,
                dedupe_extra=str(o.get("matcher-name") or ""), references=[str(x) for x in as_list(info.get("reference"))][:10],
                template_version=ctx.template_version))
        return pr


class Nmap(Adapter):
    spec = ToolSpec("nmap", "Nmap", ("nmap",), ("--version",), r"Nmap version", r"Nmap version (\d+\.\d+\w*)", False,
                    "nmap", "https://nmap.org/download", True, "Service and version detection on already-discovered open ports.")

    def build(self, ctx, targets, extra=None):
        by_ip = (extra or {}).get("ports_by_ip", {})
        out = []
        for ip in targets:
            ports = sorted({int(p) for p in by_ip.get(ip, []) if 0 < int(p) < 65536})
            if not ports:
                continue
            argv = [ctx.binary, "-sV", "--version-light", "-Pn", "-n", "--open", "-T2", "--max-retries", "1",
                    "--max-rate", str(ctx.rate.pps), "-p", ",".join(map(str, ports)), "-oX", "-", ip]
            out.append(Command(argv, [ip], "ip", label=ip))
        return out

    def parse(self, cmd, stdout, file_text, ctx):
        pr = ParseResult()
        try:
            root = ET.fromstring(stdout)
        except ET.ParseError:
            pr.warnings.append("nmap XML could not be parsed")
            return pr
        for h in root.iter("host"):
            addr = h.find("address")
            ip = addr.get("addr") if addr is not None else None
            for p in h.iter("port"):
                st = p.find("state")
                if not ip or st is None or st.get("state") != "open":
                    continue
                sv = p.find("service")
                pr.ports.append(PortRecord(ip, int(p.get("portid", 0)), ip, p.get("protocol", "tcp"),
                                           sv.get("name") if sv is not None else None,
                                           sv.get("product") if sv is not None else None,
                                           sv.get("version") if sv is not None else None, "nmap"))
        return pr


class Ffuf(Adapter):
    spec = ToolSpec("ffuf", "FFUF", ("ffuf",), ("-V",), r"ffuf", r"(\d+\.\d+\.\d+)", False, "ffuf",
                    "https://github.com/ffuf/ffuf", True, "Wordlist-based web content discovery (explicit opt-in).")

    def build(self, ctx, targets, extra=None):
        wl = safe_path_under(ctx.opts.ffuf_wordlist, ctx.allowed_wordlist_dirs)
        out = []
        for i, base in enumerate(targets):
            f = ctx.workdir / f"ffuf-{i}.json"
            argv = [ctx.binary, "-u", base.rstrip("/") + "/FUZZ", "-w", str(wl), "-rate", str(ctx.rate.rps),
                    "-t", str(ctx.rate.threads), "-timeout", "10", "-mc", "200,204,301,302,307,401,403", "-ac", "-ic",
                    "-maxtime", "300", "-s", "-of", "json", "-o", str(f)]
            out.append(Command(argv, [base], "url", out_file=f, label=base))
        return out

    def parse(self, cmd, stdout, file_text, ctx):
        pr = ParseResult()
        try:
            data = json.loads(file_text or "{}")
        except json.JSONDecodeError:
            pr.warnings.append("ffuf output file could not be parsed")
            return pr
        for r in data.get("results", []) if isinstance(data, dict) else []:
            url = str(r.get("url") or "")
            if url:
                pr.endpoints.append(EndpointRecord(url, host_of(url), r.get("status"), content_length=r.get("length"),
                                                   kind="content", source="ffuf"))
        return pr


class Testssl(Adapter):
    spec = ToolSpec("testssl", "testssl.sh", ("testssl", "testssl.sh"), ("--version",), r"testssl",
                    r"(\d+\.\d+(?:\.\d+)?)", False, "testssl.sh", "https://testssl.sh", True,
                    "TLS configuration assessment.")
    SEV = {"LOW": "low", "MEDIUM": "medium", "HIGH": "high", "CRITICAL": "critical", "WARN": "low"}

    def build(self, ctx, targets, extra=None):
        out = []
        for i, hp in enumerate(targets):
            f = ctx.workdir / f"testssl-{i}.json"
            f.unlink(missing_ok=True)
            argv = [ctx.binary, "--jsonfile", str(f), "--warnings", "off", "--color", "0", "--quiet",
                    "--connect-timeout", "10", "--openssl-timeout", "10", hp]
            out.append(Command(argv, [hp], "hostport", out_file=f, label=hp))
        return out

    def parse(self, cmd, stdout, file_text, ctx):
        pr = ParseResult()
        try:
            rows = json.loads(file_text or "[]")
        except json.JSONDecodeError:
            pr.warnings.append("testssl JSON could not be parsed")
            return pr
        host = cmd.targets[0].rpartition(":")[0]
        for r in rows if isinstance(rows, list) else []:
            sev = self.SEV.get(str(r.get("severity", "")).upper())
            if not sev:
                continue
            fid = str(r.get("id", "unknown"))
            pr.findings.append(FindingRecord(
                title=f"TLS: {fid}", asset=host, source="testssl", template_id=fid, severity=sev, confidence="medium",
                description="Reported by testssl.sh from direct protocol probing.", url=f"https://{cmd.targets[0]}",
                evidence=clip(r.get("finding"), 1000), dedupe_extra=str(r.get("port", ""))))
        return pr


class Zap(Adapter):
    spec = ToolSpec("zap", "OWASP ZAP", ("zaproxy", "zap.sh"), ("-version",), r"\d+\.\d+\.\d+", r"(\d+\.\d+\.\d+)",
                    False, "zaproxy", "https://www.zaproxy.org/download/", True,
                    "Deeper web application assessment (spider + active scan; intrusive, explicit opt-in).",
                    version_timeout=60)
    RISK = {"0": "info", "1": "low", "2": "medium", "3": "high"}

    def build(self, ctx, targets, extra=None):
        out = []
        for i, base in enumerate(targets):
            f = ctx.workdir / f"zap-{i}.json"
            f.unlink(missing_ok=True)
            out.append(Command([ctx.binary, "-cmd", "-quickurl", base, "-quickout", str(f), "-quickprogress"],
                               [base], "url", out_file=f, label=base))
        return out

    def parse(self, cmd, stdout, file_text, ctx):
        pr = ParseResult()
        try:
            data = json.loads(file_text or "{}")
        except json.JSONDecodeError:
            pr.warnings.append("ZAP report could not be parsed")
            return pr
        for site in data.get("site", []) if isinstance(data, dict) else []:
            for a in site.get("alerts", []):
                inst = a.get("instances", [])[:5]
                pr.findings.append(FindingRecord(
                    title=str(a.get("alert") or a.get("name") or "ZAP alert"), asset=host_of(cmd.targets[0]), source="zap",
                    template_id=str(a.get("pluginid", "")), severity=self.RISK.get(str(a.get("riskcode")), "info"),
                    confidence="low", description=clip(TAG_RE.sub("", str(a.get("desc", ""))), 2000), url=cmd.targets[0],
                    evidence=clip("; ".join(f"{i.get('method', '')} {i.get('uri', '')}" for i in inst), 1500)))
        return pr
