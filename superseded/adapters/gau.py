from __future__ import annotations

import json

from ..models import EndpointRecord, ParseResult
from .base import Adapter, StageContext, host_of

SKIP_EXT = "png,jpg,jpeg,gif,svg,css,woff,woff2,ttf,ico,webp,mp4,mp3"


class GauAdapter(Adapter):
    tool, stage = "gau", "gau"
    label = "Historical URL discovery"
    target_kind = "domain_root"
    touches_target = False
    traffic_note = "Queries web archives (Wayback, Common Crawl, OTX), not the target."
    cacheable = True
    MAX_URLS = 2000

    def build_commands(self, ctx: StageContext) -> list[list[str]]:
        return [[ctx.binary, "--subs", "--providers", "wayback,commoncrawl,otx", "--json", "--threads", "2",
                 "--timeout", "30", "--retries", "2", "--blacklist", SKIP_EXT, root] for root in ctx.targets]

    def parse(self, ctx: StageContext, argv: list[str], stdout: str) -> ParseResult:
        res = ParseResult()
        urls: set[str] = set()
        for line in stdout.splitlines():
            line = line.strip()
            if line.startswith("{"):
                try:
                    line = str(json.loads(line).get("url", ""))
                except json.JSONDecodeError:
                    continue
            if not line.startswith(("http://", "https://")) or len(urls) >= self.MAX_URLS:
                continue
            if ctx.scope.url_allowed(line)[0]:
                urls.add(line.split("#")[0])
        for u in sorted(urls):
            res.endpoints.append(EndpointRecord(url=u, host=host_of(u), kind="historical", source="gau"))
            res.hosts.append((host_of(u), "gau"))
        res.output = {"hosts": sorted({host_of(u) for u in urls}), "urls": sorted(urls)}
        return res
