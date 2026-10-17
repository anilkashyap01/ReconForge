from __future__ import annotations

from ..models import EndpointRecord, ParseResult
from .base import Adapter, StageContext, as_int, host_of, iter_jsonl


class HttpxAdapter(Adapter):
    tool, stage = "httpx", "httpx"
    label = "HTTP probing and fingerprinting"
    target_kind = "hostport"
    traffic_note = "Sends ordinary HTTP(S) GET requests to each authorised host."

    def build_commands(self, ctx: StageContext) -> list[list[str]]:
        lst = ctx.write_list("httpx-input.txt", ctx.targets)
        # redirects are NOT followed, so a redirect can never carry the probe outside the scope
        return [[ctx.binary, "-l", str(lst), "-silent", "-json", "-title", "-sc", "-server", "-cl", "-td",
                 "-rl", str(ctx.rate.rps), "-t", str(ctx.rate.threads), "-timeout", "10", "-retries", "1", "-nc", "-duc"]]

    def parse(self, ctx: StageContext, argv: list[str], stdout: str) -> ParseResult:
        res = ParseResult()
        urls = []
        for obj in iter_jsonl(stdout):
            if obj.get("failed"):
                continue
            url = str(obj.get("url", "")).strip()
            host = host_of(url)
            if not url or not host:
                continue
            ok, _ = ctx.scope.url_allowed(url)
            if not ok:
                res.warnings.append(f"dropped out-of-scope result {url}")
                continue
            tech = obj.get("tech") or obj.get("technologies") or []
            res.endpoints.append(EndpointRecord(url=url, host=host, status_code=as_int(obj.get("status_code")),
                                                title=(obj.get("title") or None), webserver=obj.get("webserver"),
                                                technologies=[str(t) for t in tech], content_length=as_int(obj.get("content_length")),
                                                kind="http", source="httpx"))
            res.hosts.append((host, "httpx"))
            urls.append(url)
        res.output = {"urls": sorted(set(urls))}
        return res
