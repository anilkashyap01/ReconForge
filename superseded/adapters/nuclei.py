from __future__ import annotations

import re

from ..models import FindingRecord, ParseResult
from ..scope import validate_ident_list
from ..services.runner import run_process
from .base import Adapter, StageContext, host_of, iter_jsonl

EXCLUDED_TAGS = "dos,fuzz,intrusive,bruteforce,brute-force"   # never run intrusive/DoS/brute-force templates
SEV_OK = {"info", "low", "medium", "high", "critical"}


class NucleiAdapter(Adapter):
    tool, stage = "nuclei", "nuclei"
    label = "Template-based vulnerability checks"
    target_kind = "url"
    traffic_note = "Sends template requests to each authorised URL; intrusive, DoS, fuzz and brute-force tags are excluded."

    def build_commands(self, ctx: StageContext) -> list[list[str]]:
        lst = ctx.write_list("nuclei-input.txt", ctx.targets)
        sev = [s for s in ctx.options.get("nuclei_severity", []) if s in SEV_OK] or ["low", "medium", "high", "critical"]
        argv = [ctx.binary, "-l", str(lst), "-jsonl", "-silent", "-nc", "-duc", "-ni", "-irr",
                "-severity", ",".join(sev), "-etags", EXCLUDED_TAGS,
                "-rl", str(ctx.rate.rps), "-c", str(max(1, min(ctx.rate.threads, 5))), "-bs", "2",
                "-timeout", "10", "-retries", "1", "-mhe", "10"]
        tags = validate_ident_list(ctx.options.get("nuclei_tags", ""), "nuclei tags")
        if tags:
            argv += ["-tags", tags]
        return [argv]

    def parse(self, ctx: StageContext, argv: list[str], stdout: str) -> ParseResult:
        res = ParseResult()
        for obj in iter_jsonl(stdout):
            info = obj.get("info") or {}
            matched = str(obj.get("matched-at") or obj.get("url") or obj.get("host") or "")
            asset = host_of(matched) or str(obj.get("host", "")).split(":")[0].lower()
            if not asset or not ctx.scope.host_allowed(asset)[0]:
                res.warnings.append(f"dropped out-of-scope finding at {matched!r}")
                continue
            sev = str(info.get("severity", "info")).lower()
            extracted = obj.get("extracted-results") or []
            cls = info.get("classification") or {}
            cves = cls.get("cve-id") or []
            desc = str(info.get("description") or "")
            if cves:
                desc += f"\nCVE: {', '.join(cves)}"
            evidence = f"Matched at: {matched}"
            if obj.get("matcher-name"):
                evidence += f"\nMatcher: {obj['matcher-name']}"
            if extracted:
                evidence += "\nExtracted: " + ", ".join(map(str, extracted))[:1000]
            details = ""
            if obj.get("request"):
                details += "--- request ---\n" + str(obj["request"])[:4000]
            if obj.get("response"):
                details += "\n--- response ---\n" + str(obj["response"])[:4000]
            refs = info.get("reference") or []
            res.findings.append(FindingRecord(
                title=str(info.get("name") or obj.get("template-id") or "Nuclei match"), asset=asset, source="nuclei",
                template_id=str(obj.get("template-id", "unknown")), severity=sev if sev in SEV_OK else "info",
                confidence="medium" if extracted else "low", description=desc, url=matched, evidence=evidence,
                details=details, dedupe_extra=str(obj.get("matcher-name", "")),
                references=[refs] if isinstance(refs, str) else list(refs)[:10],
                template_version=ctx.extras.get("template_version")))
        res.output = {"findings": len(res.findings)}
        return res


async def template_version(binary: str) -> str | None:
    """Best effort: `nuclei -templates-version` prints the installed template pack version."""
    r = await run_process([binary, "-templates-version", "-duc"], timeout=20, max_output_bytes=50_000)
    m = re.search(r"templates version:\s*v?([\w.\-]+)", r.stdout + r.stderr, re.I)
    return m.group(1) if m else None
