from __future__ import annotations

from ..models import EndpointRecord, ParseResult
from .base import Adapter, StageContext, host_of, iter_jsonl


class KatanaAdapter(Adapter):
    tool, stage = "katana", "katana"
    label = "Web crawling"
    target_kind = "url"
    traffic_note = "Crawls pages on the target within the same hostname (field scope fqdn)."

    def build_commands(self, ctx: StageContext) -> list[list[str]]:
        lst = ctx.write_list("katana-input.txt", ctx.targets)
        return [[ctx.binary, "-list", str(lst), "-d", str(ctx.options.get("crawl_depth", 2)), "-fs", "fqdn",
                 "-rl", str(ctx.rate.rps), "-c", str(ctx.rate.threads), "-p", "1", "-timeout", "10",
                 "-ct", "600", "-silent", "-jsonl", "-nc", "-duc"]]

    def parse(self, ctx: StageContext, argv: list[str], stdout: str) -> ParseResult:
        res = ParseResult()
        seen: set[str] = set()
        for obj in iter_jsonl(stdout):
            url = str((obj.get("request") or {}).get("endpoint") or obj.get("endpoint") or "").split("#")[0]
            if not url or url in seen:
                continue
            ok, _ = ctx.scope.url_allowed(url)
            if not ok:
                res.warnings.append(f"dropped out-of-scope crawl result {url}")
                continue
            seen.add(url)
            res.endpoints.append(EndpointRecord(url=url, host=host_of(url), kind="crawl", source="katana"))
        res.output = {"urls": sorted(seen)}
        return res
