from __future__ import annotations

from ..models import ParseResult
from .base import Adapter, StageContext, iter_jsonl


class SubfinderAdapter(Adapter):
    tool, stage = "subfinder", "subfinder"
    label = "Passive subdomain enumeration"
    target_kind = "domain_root"
    touches_target = False
    traffic_note = "Queries public data sources, not the target (passive)."
    cacheable = True

    def build_commands(self, ctx: StageContext) -> list[list[str]]:
        # one process per authorised wildcard root; passive mode only (no -active, no brute force)
        return [[ctx.binary, "-d", root, "-silent", "-json", "-timeout", "30", "-max-time", "10",
                 "-rl", str(max(1, min(ctx.rate.rps * 5, 20))), "-duc"] for root in ctx.targets]

    def parse(self, ctx: StageContext, argv: list[str], stdout: str) -> ParseResult:
        res = ParseResult()
        for obj in iter_jsonl(stdout):
            host = str(obj.get("host", "")).strip().lower().rstrip(".")
            if host and not host.startswith("*"):
                res.hosts.append((host, "subfinder"))
        res.output = {"hosts": sorted({h for h, _ in res.hosts})}
        return res
