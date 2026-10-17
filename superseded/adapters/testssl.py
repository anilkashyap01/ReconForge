from __future__ import annotations

import json
from pathlib import Path

from ..models import FindingRecord, ParseResult
from .base import Adapter, StageContext

SEV = {"LOW": "low", "MEDIUM": "medium", "HIGH": "high", "CRITICAL": "critical", "WARN": "low"}


class TestsslAdapter(Adapter):
    __test__ = False   # not a pytest class
    tool, stage = "testssl", "testssl"
    label = "TLS configuration assessment"
    target_kind = "hostport"
    traffic_note = "Opens many TLS connections to each host:port. Opt-in; run serially."

    def ok_exit(self, code: int | None) -> bool:
        return code is not None and code < 240    # testssl uses high exit codes for fatal errors

    def build_commands(self, ctx: StageContext) -> list[list[str]]:
        cmds = []
        for i, target in enumerate(ctx.targets):
            out = ctx.out_path(f"testssl-{i}.json")
            cmds.append([ctx.binary, "--jsonfile", str(out), "--warnings", "off", "--color", "0", "--quiet",
                         "--connect-timeout", "10", "--openssl-timeout", "10", target])
        return cmds

    def parse(self, ctx: StageContext, argv: list[str], stdout: str) -> ParseResult:
        res = ParseResult()
        out = Path(argv[argv.index("--jsonfile") + 1])
        target = argv[-1]
        host, _, port = target.rpartition(":")
        if not out.is_file():
            return res
        try:
            rows = json.loads(out.read_text())
        except (OSError, json.JSONDecodeError):
            res.warnings.append("testssl output was not valid JSON")
            return res
        for row in rows if isinstance(rows, list) else []:
            sev = SEV.get(str(row.get("severity", "")).upper())
            if not sev:
                continue
            fid = str(row.get("id", "unknown"))
            res.findings.append(FindingRecord(
                title=f"TLS: {fid}", asset=host, source="testssl", template_id=fid, severity=sev, confidence="medium",
                description=str(row.get("finding", ""))[:1000], url=f"https://{host}:{port}",
                evidence=f"testssl.sh reported severity {row.get('severity')}: {str(row.get('finding', ''))[:500]}",
                dedupe_extra=f"{port}", references=[str(row["cve"])] if row.get("cve") else []))
        return res
