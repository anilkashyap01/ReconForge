"""HTML and JSON scan reports. HTML is rendered by Jinja2 with autoescape; the JSON export is machine-readable."""
from __future__ import annotations

import csv
import io
import json
import os
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..config import get_settings, redact
from ..database import now, q, q1
from ..database import db
from ..models import StageStatus
from . import store

TEMPLATES = Path(__file__).resolve().parent.parent / "templates"
STATEMENT = ("Findings in this report are detections reported by automated scanners (for example Nuclei template matches). "
             "They are potential findings unless their validation status says an analyst confirmed them. A scanner match is not proof "
             "of exploitability. Cached discovery results, where used, show what was known at the time and say nothing about current safety.")
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _uniq(items: list[dict], key) -> list[dict]:
    seen, out = set(), []
    for i in items:
        k = key(i)
        if k not in seen:
            seen.add(k)
            out.append(i)
    return out


def build_report(scan_id: int) -> dict[str, Any]:
    with db() as c:
        scan = q1(c, "SELECT * FROM scans WHERE id=?", (scan_id,))
        if not scan:
            raise KeyError(scan_id)
        project = q1(c, "SELECT id,name,description FROM projects WHERE id=?", (scan["project_id"],))
        stages = q(c, "SELECT * FROM scan_stages WHERE scan_id=? ORDER BY position", (scan_id,))
        runs = q(c, "SELECT tool,version FROM tool_runs WHERE scan_id=? GROUP BY tool,version", (scan_id,))
        assets = q(c, "SELECT a.kind,a.value,a.sources,a.first_seen,a.last_seen,(a.first_scan_id=?) AS new_in_this_scan,"
                      " GROUP_CONCAT(DISTINCT s.source) AS seen_via FROM asset_scans s JOIN assets a ON a.id=s.asset_id WHERE s.scan_id=?"
                      " GROUP BY a.id ORDER BY a.kind,a.value", (scan_id, scan_id))
        findings = q(c, "SELECT f.id,f.title,f.description,f.asset,f.url,f.severity,f.confidence,f.source,f.template_id,f.evidence,f.details,"
                        "f.refs,f.tool_version,f.template_version,f.validation_status,f.analyst_notes,f.first_seen,f.last_seen"
                        " FROM finding_scans s JOIN findings f ON f.id=s.finding_id WHERE s.scan_id=?", (scan_id,))
    agg_dns, agg_ports, agg_eps = [], [], []
    stage_out = []
    for st in stages:
        if st["status"] in StageStatus.DONE and st["output_json"]:
            pr = store.result_from_json(st["output_json"])
            agg_dns += [d.__dict__ for d in pr.dns]
            agg_ports += [p.__dict__ for p in pr.ports]
            agg_eps += [e.__dict__ for e in pr.endpoints]
        stage_out.append({k: st[k] for k in ("position", "name", "tool", "label", "status", "touches_target", "traffic_note", "started_at",
                                              "finished_at", "items", "input_count", "attempts", "message", "cached_from_scan", "cached_at")})
    for f in findings:
        f["refs"] = json.loads(f.pop("refs") or "[]")
        f["label"] = ("Confirmed by analyst" if f["validation_status"] == "confirmed" else
                      "Potential finding (scanner detection, not validated)" if f["validation_status"] == "unvalidated" else
                      f"Analyst status: {f['validation_status'].replace('_', ' ')}")
    findings.sort(key=lambda f: (SEV_ORDER.get(f["severity"], 9), f["asset"]))
    cfg = json.loads(scan["config_json"])
    problems = [s for s in stage_out if s["status"] in ("failed", "partial", "missing_tool", "cancelled", "skipped")]
    sev: dict[str, int] = {}
    for f in findings:
        sev[f["severity"]] = sev.get(f["severity"], 0) + 1
    return {
        "generated_at": now(), "reconforge_report_version": 1, "statement": STATEMENT,
        "project": project, "scan": {"id": scan["id"], "profile": scan["profile"], "status": scan["status"], "created_at": scan["created_at"],
                                       "started_at": scan["started_at"], "completed_at": scan["completed_at"], "error": scan["error"],
                                       "authorization_confirmed": bool(scan["authorization_confirmed"]),
                                       "active_testing_confirmed": bool(scan["active_testing_confirmed"])},
        "scope": {"include": json.loads(scan["scope_json"]), "exclude": json.loads(scan["exclusions_json"])},
        "options": cfg["options"], "limits": cfg["limits"], "tools": runs, "stages": stage_out, "failed_or_incomplete_stages": problems,
        "assets": assets, "dns_records": _uniq(agg_dns, lambda d: (d["host"], d["rtype"], d["value"])),
        "ports": _uniq(agg_ports, lambda p: (p["host"], p["ip"], p["port"], p["protocol"])),
        "endpoints": _uniq(agg_eps, lambda e: e["url"]), "findings": findings, "findings_by_severity": sev,
        "summary": json.loads(scan["summary_json"] or "{}"),
    }


def render_html(report: dict[str, Any]) -> str:
    env = Environment(loader=FileSystemLoader(str(TEMPLATES)), autoescape=select_autoescape(["html"]))
    return env.get_template("report.html").render(r=report, sev_order=list(SEV_ORDER))


def render_csv(report: dict[str, Any]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "severity", "title", "asset", "url", "confidence",
        "validation_status", "source", "template_id", "first_seen", "last_seen"
    ])
    for f in report.get("findings", []):
        writer.writerow([
            f.get("severity", ""),
            f.get("title", ""),
            f.get("asset", ""),
            f.get("url", ""),
            f.get("confidence", ""),
            f.get("validation_status", ""),
            f.get("source", ""),
            f.get("template_id", ""),
            f.get("first_seen", ""),
            f.get("last_seen", ""),
        ])
    return buf.getvalue()


def write_reports(scan_id: int) -> dict[str, Path]:
    rep = build_report(scan_id)
    d = get_settings().reports_dir
    d.mkdir(parents=True, exist_ok=True)
    paths = {
        "json": d / f"scan-{scan_id}.json",
        "html": d / f"scan-{scan_id}.html",
        "csv": d / f"scan-{scan_id}.csv",
    }
    paths["json"].write_text(redact(json.dumps(rep, indent=2, default=str)))
    paths["html"].write_text(redact(render_html(rep)))
    paths["csv"].write_text(redact(render_csv(rep)))
    for p in paths.values():
        os.chmod(p, 0o600)
    return paths
