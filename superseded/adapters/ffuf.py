from __future__ import annotations

import json
from pathlib import Path

from ..models import EndpointRecord, ParseResult
from .base import Adapter, StageContext, as_int, host_of


class FfufAdapter(Adapter):
    tool, stage = "ffuf", "ffuf"
    label = "Web content discovery (wordlist)"
    target_kind = "url"
    traffic_note = "Sends one request per wordlist entry. Opt-in only; rate-limited."

    def build_commands(self, ctx: StageContext) -> list[list[str]]:
        wordlist = ctx.extras["wordlist"]
        cmds = []
        for i, url in enumerate(ctx.targets):
            out = ctx.out_path(f"ffuf-{i}.json")
            cmds.append([ctx.binary, "-u", url.rstrip("/") + "/FUZZ", "-w", str(wordlist), "-rate", str(ctx.rate.rps),
                         "-t", str(ctx.rate.threads), "-mc", "200,204,301,302,307,401,403", "-ac", "-timeout", "10",
                         "-maxtime", "600", "-of", "json", "-o", str(out), "-s", "-noninteractive"])
        return cmds

    def parse(self, ctx: StageContext, argv: list[str], stdout: str) -> ParseResult:
        res = ParseResult()
        out = Path(argv[argv.index("-o") + 1])
        if not out.is_file():
            return res
        try:
            data = json.loads(out.read_text())
        except (OSError, json.JSONDecodeError):
            res.warnings.append("ffuf output file was not valid JSON")
            return res
        for r in (data.get("results") or [])[:2000]:
            url = str(r.get("url", ""))
            if url and ctx.scope.url_allowed(url)[0]:
                res.endpoints.append(EndpointRecord(url=url, host=host_of(url), status_code=as_int(r.get("status")),
                                                    content_length=as_int(r.get("length")), kind="bruteforce", source="ffuf"))
        res.output = {"urls": [e.url for e in res.endpoints]}
        return res
