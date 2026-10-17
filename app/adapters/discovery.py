"""Discovery adapters: Subfinder, gau, dnsx, httpx (ProjectDiscovery), Naabu, Katana."""
from __future__ import annotations

import re

from ..models import DnsRecord, EndpointRecord, ParseResult, PortRecord
from ..scope import HOST_RE, validate_port_spec
from .base import Adapter, BuildContext, Command, ToolSpec, as_list, host_of, jsonl, lines

PD = "https://github.com/projectdiscovery"


class Subfinder(Adapter):
    spec = ToolSpec("subfinder", "Subfinder", ("subfinder",), ("-version",), r"subfinder|projectdiscovery",
                    r"v?(\d+\.\d+\.\d+)", True, "subfinder", f"{PD}/subfinder", False,
                    "Passive subdomain enumeration from public sources.")

    def build(self, ctx, targets, extra=None):
        return [Command([ctx.binary, "-d", d, "-silent", "-json", "-timeout", "30", "-max-time", "5"],
                        [d], "domain_root", label=d) for d in targets]

    def parse(self, cmd, stdout, file_text, ctx):
        pr = ParseResult()
        for obj in jsonl(stdout, pr.warnings):
            if obj.get("host"):
                pr.hosts.append((str(obj["host"]).lower().strip(), "subfinder"))
        for line in stdout.splitlines():           # tolerate plain-text output
            line = line.strip().lower()
            if line and not line.startswith("{") and HOST_RE.match(line):
                pr.hosts.append((line, "subfinder"))
        return pr


class Gau(Adapter):
    spec = ToolSpec("gau", "gau", ("gau",), ("--version",), r"gau|\d+\.\d+", r"v?(\d+\.\d+\.\d+)", False,
                    "see README (Go install)", "https://github.com/lc/gau", False,
                    "Historical URLs from public web archives (does not contact the target).")
    MAX_URLS = 2000

    def build(self, ctx, targets, extra=None):
        wild = set((extra or {}).get("wildcard_roots", []))
        out = []
        for d in targets:
            argv = [ctx.binary, "--threads", "2", "--timeout", "30", "--retries", "1",
                    "--providers", "wayback,commoncrawl,otx"]
            if d in wild:
                argv.append("--subs")
            out.append(Command(argv + [d], [d], "domain_root" if d in wild else "host", label=d))
        return out

    def parse(self, cmd, stdout, file_text, ctx):
        pr = ParseResult()
        for line in stdout.splitlines():
            u = line.strip()
            if re.match(r"^https?://", u) and len(pr.endpoints) < self.MAX_URLS:
                pr.endpoints.append(EndpointRecord(u, host_of(u), kind="historical", source="gau"))
        if len(pr.endpoints) >= self.MAX_URLS:
            pr.warnings.append(f"gau output capped at {self.MAX_URLS} URLs")
        return pr


class Dnsx(Adapter):
    spec = ToolSpec("dnsx", "dnsx", ("dnsx",), ("-version",), r"dnsx|projectdiscovery", r"v?(\d+\.\d+\.\d+)", True,
                    "dnsx", f"{PD}/dnsx", False, "DNS resolution and verification of discovered hostnames.")

    def build(self, ctx, targets, extra=None):
        r = ctx.rate
        argv = [ctx.binary, "-silent", "-json", "-a", "-aaaa", "-cname", "-resp", "-retry", "2",
                "-t", str(min(20, r.dns_qps)), "-rl", str(r.dns_qps)]
        return [Command(argv, targets, "host", stdin=lines(targets), label=f"{len(targets)} hostnames")]

    def parse(self, cmd, stdout, file_text, ctx):
        pr = ParseResult()
        host_ips: dict[str, list[str]] = {}
        cnames: dict[str, list[str]] = {}
        resolved: list[str] = []
        for o in jsonl(stdout, pr.warnings):
            host = str(o.get("host", "")).lower().rstrip(".")
            if not host:
                continue
            ips = [str(i) for i in as_list(o.get("a")) + as_list(o.get("aaaa"))]
            for ip in as_list(o.get("a")):
                pr.dns.append(DnsRecord(host, "A", str(ip)))
            for ip in as_list(o.get("aaaa")):
                pr.dns.append(DnsRecord(host, "AAAA", str(ip)))
            cn = [str(c).rstrip(".").lower() for c in as_list(o.get("cname"))]
            for c in cn:
                pr.dns.append(DnsRecord(host, "CNAME", c))
            if cn:
                cnames[host] = cn
            if ips:
                host_ips[host] = ips
                resolved.append(host)
                pr.hosts.append((host, "dnsx"))
        pr.output = {"host_ips": host_ips, "cnames": cnames, "resolved": resolved}
        return pr


class Httpx(Adapter):
    spec = ToolSpec("httpx", "httpx (ProjectDiscovery)", ("httpx-toolkit", "httpx"), ("-version",),
                    r"projectdiscovery|Current Version", r"v?(\d+\.\d+\.\d+)", True, "httpx-toolkit", f"{PD}/httpx",
                    True, "HTTP probing and technology fingerprinting.")

    def build(self, ctx, targets, extra=None):
        r = ctx.rate
        argv = [ctx.binary, "-silent", "-json", "-nc", "-sc", "-title", "-td", "-server", "-cl",
                "-rl", str(r.rps), "-t", str(r.threads), "-timeout", "10", "-retries", "1"]
        return [Command(argv, targets, "host", stdin=lines(targets), label=f"{len(targets)} hosts")]

    def parse(self, cmd, stdout, file_text, ctx):
        pr = ParseResult()
        urls: list[str] = []
        for o in jsonl(stdout, pr.warnings):
            url = str(o.get("url") or "")
            if not url:
                continue
            tech = [str(t) for t in as_list(o.get("tech") or o.get("technologies"))]
            cl = o.get("content_length")
            pr.endpoints.append(EndpointRecord(
                url, host_of(url), o.get("status_code"), o.get("title"), o.get("webserver"), tech,
                cl if isinstance(cl, int) else None, "http", "httpx"))
            urls.append(url)
        pr.output = {"live_urls": urls}
        return pr


class Naabu(Adapter):
    spec = ToolSpec("naabu", "Naabu", ("naabu",), ("-version",), r"naabu|projectdiscovery", r"v?(\d+\.\d+\.\d+)", True,
                    "naabu", f"{PD}/naabu", True, "TCP port discovery (connect scan) on authorised IP addresses.")

    def build(self, ctx, targets, extra=None):
        spec = validate_port_spec(ctx.opts.ports)
        ports = ["-tp", spec[3:]] if spec.startswith("top") else ["-p", spec]
        argv = [ctx.binary, "-silent", "-json", "-s", "c", "-ec", "-rate", str(ctx.rate.pps), "-c", "10",
                "-timeout", "1500", "-retries", "1", *ports]
        return [Command(argv, targets, "ip", stdin=lines(targets), label=f"{len(targets)} IPs")]

    def parse(self, cmd, stdout, file_text, ctx):
        pr = ParseResult()
        for o in jsonl(stdout, pr.warnings):
            ip, port = o.get("ip") or o.get("host"), o.get("port")
            if ip and isinstance(port, int):
                pr.ports.append(PortRecord(str(ip), port, str(ip), str(o.get("protocol") or "tcp"), source="naabu"))
        return pr


class Katana(Adapter):
    spec = ToolSpec("katana", "Katana", ("katana",), ("-version",), r"katana|projectdiscovery", r"v?(\d+\.\d+\.\d+)",
                    True, "katana", f"{PD}/katana", True, "Web crawling and endpoint discovery.")

    def build(self, ctx, targets, extra=None):
        r = ctx.rate
        argv = [ctx.binary, "-silent", "-jsonl", "-nc", "-d", str(ctx.opts.crawl_depth), "-rl", str(r.rps),
                "-c", str(r.threads), "-timeout", "10", "-fs", "fqdn", "-ef", "png,jpg,jpeg,gif,svg,woff,woff2,ttf,css,ico"]
        return [Command(argv, targets, "url", stdin=lines(targets), label=f"{len(targets)} seed URLs")]

    def parse(self, cmd, stdout, file_text, ctx):
        pr = ParseResult()
        for o in jsonl(stdout, pr.warnings):
            req = o.get("request") if isinstance(o.get("request"), dict) else {}
            url = str(req.get("endpoint") or o.get("endpoint") or o.get("url") or "")
            if url.startswith(("http://", "https://")):
                resp = o.get("response") if isinstance(o.get("response"), dict) else {}
                pr.endpoints.append(EndpointRecord(url, host_of(url), resp.get("status_code"), kind="crawl", source="katana"))
        return pr
