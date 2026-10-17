from __future__ import annotations

from ..models import DnsRecord, ParseResult
from .base import Adapter, StageContext, iter_jsonl


class DnsxAdapter(Adapter):
    tool, stage = "dnsx", "dnsx"
    label = "DNS resolution and verification"
    target_kind = "host"
    traffic_note = "DNS queries go to public resolvers; authoritative servers for the target may see them."

    def build_commands(self, ctx: StageContext) -> list[list[str]]:
        lst = ctx.write_list("dnsx-input.txt", ctx.targets)
        return [[ctx.binary, "-l", str(lst), "-silent", "-json", "-a", "-aaaa", "-cname", "-resp",
                 "-rl", str(ctx.rate.dns_qps), "-t", str(min(ctx.rate.dns_qps, 50)), "-retry", "2", "-duc"]]

    def parse(self, ctx: StageContext, argv: list[str], stdout: str) -> ParseResult:
        res = ParseResult()
        resolved: dict[str, list[str]] = {}
        for obj in iter_jsonl(stdout):
            host = str(obj.get("host", "")).lower().rstrip(".")
            if not host:
                continue
            ips = [*obj.get("a", []), *obj.get("aaaa", [])]
            for rtype, key in (("A", "a"), ("AAAA", "aaaa"), ("CNAME", "cname")):
                for v in obj.get(key, []) or []:
                    res.dns.append(DnsRecord(host, rtype, str(v).rstrip(".")))
            if ips:   # CNAME targets are stored as DNS data only and are never added as scan targets
                resolved[host] = sorted({str(i) for i in ips})
                res.hosts.append((host, "dnsx"))
        res.output = {"resolved": resolved}
        return res
