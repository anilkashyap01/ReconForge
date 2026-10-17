from __future__ import annotations

import json
from pathlib import Path

from ..models import FindingRecord, ParseResult
from .base import Adapter, StageContext, host_of

RISK = {"0": "info", "1": "low", "2": "medium", "3": "high"}
CONF = {"0": "low", "1": "low", "2": "medium", "3": "high", "4": "high"}


class ZapAdapter(Adapter):
    tool, stage = "zap", "zap"
    label = "OWASP ZAP quick scan (spider + active scan)"
    target_kind = "url"
    traffic_note = "ACTIVE scan: ZAP spiders and attacks the URL. Requires explicit active-testing consent."

    def build_commands(self, ctx: StageContext) -> list[list[str]]:
        cmds = []
        for i, url in enumerate(ctx.targets):
            out = ctx.out_path(f"zap-{i}.json")
            cmds.append([ctx.binary, "-cmd", "-quickurl", url, "-quickout", str(out), "-quickprogress",
                         "-config", "scanner.threadPerHost=1", "-config", "scanner.delayInMs=500"])
        return cmds

    def parse(self, ctx: StageContext, argv: list[str], stdout: str) -> ParseResult:
        res = ParseResult()
        out = Path(argv[argv.index("-quickout") + 1])
        if not out.is_file():
            return res
        try:
            data = json.loads(out.read_text())
        except (OSError, json.JSONDecodeError):
            res.warnings.append("ZAP report was not valid JSON")
            return res
        for site in data.get("site", []) if isinstance(data, dict) else []:
            for alert in site.get("alerts", []):
                for inst in (alert.get("instances") or [{}])[:5]:
                    uri = str(inst.get("uri") or site.get("@name", ""))
                    asset = host_of(uri)
                    if not asset or not ctx.scope.host_allowed(asset)[0]:
                        continue
                    res.findings.append(FindingRecord(
                        title=str(alert.get("name") or alert.get("alert") or "ZAP alert"), asset=asset, source="zap",
                        template_id=str(alert.get("pluginid", "zap")), severity=RISK.get(str(alert.get("riskcode")), "info"),
                        confidence=CONF.get(str(alert.get("confidence")), "low"), description=str(alert.get("desc", ""))[:2000],
                        url=uri, evidence=f"{inst.get('method', '')} {uri} param={inst.get('param', '')} evidence={str(inst.get('evidence', ''))[:300]}",
                        dedupe_extra=str(inst.get("param", ""))))
        return res
