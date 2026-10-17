"""Persistence helpers: deduplicating upserts with first/last seen, scan links, comparisons, logging."""
from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import asdict
from typing import Any

from ..config import redact
from ..database import now, q, q1
from ..models import DnsRecord, EndpointRecord, FindingRecord, ParseResult, PortRecord


# ------------------------------------------------------------------ ParseResult <-> JSON (stage snapshots)
def result_to_json(pr: ParseResult) -> str:
    return json.dumps({"hosts": pr.hosts, "dns": [asdict(d) for d in pr.dns], "ports": [asdict(p) for p in pr.ports],
                       "endpoints": [asdict(e) for e in pr.endpoints], "output": pr.output, "warnings": pr.warnings})


def result_from_json(text: str | None) -> ParseResult:
    d = json.loads(text) if text else {}
    return ParseResult(hosts=[tuple(h) for h in d.get("hosts", [])], dns=[DnsRecord(**x) for x in d.get("dns", [])],
                       ports=[PortRecord(**x) for x in d.get("ports", [])],
                       endpoints=[EndpointRecord(**x) for x in d.get("endpoints", [])],
                       output=d.get("output", {}), warnings=d.get("warnings", []))


# ------------------------------------------------------------------ logging
def log(conn: sqlite3.Connection, scan_id: int, level: str, message: str) -> None:
    conn.execute("INSERT INTO scan_logs(scan_id,ts,level,message) VALUES(?,?,?,?)", (scan_id, now(), level, redact(message)[:2000]))


# ------------------------------------------------------------------ upserts
def _merge_sources(old: str, new: str) -> str:
    return ",".join(sorted({s for s in (old.split(",") + [new]) if s}))


def upsert_asset(conn, pid: int, kind: str, value: str, source: str, scan_id: int, cached: bool = False) -> tuple[int, bool]:
    ts = now()
    row = q1(conn, "SELECT id,sources FROM assets WHERE project_id=? AND kind=? AND value=?", (pid, kind, value))
    if row:
        if not cached:   # cached results are carried over but never refresh last_seen
            conn.execute("UPDATE assets SET last_seen=?, last_scan_id=?, sources=? WHERE id=?",
                         (ts, scan_id, _merge_sources(row["sources"], source), row["id"]))
        aid, new = row["id"], False
    else:
        aid = conn.execute("INSERT INTO assets(project_id,kind,value,sources,first_seen,last_seen,first_scan_id,last_scan_id)"
                           " VALUES(?,?,?,?,?,?,?,?)", (pid, kind, value, source, ts, ts, scan_id, scan_id)).lastrowid
        new = True
    conn.execute("INSERT OR IGNORE INTO asset_scans(scan_id,asset_id,source) VALUES(?,?,?)",
                 (scan_id, aid, f"cached:{source}" if cached else source))
    return aid, new


def upsert_dns(conn, pid: int, r: DnsRecord, scan_id: int) -> None:
    ts = now()
    conn.execute("INSERT INTO dns_records(project_id,host,rtype,value,first_seen,last_seen,last_scan_id) VALUES(?,?,?,?,?,?,?)"
                 " ON CONFLICT(project_id,host,rtype,value) DO UPDATE SET last_seen=excluded.last_seen,last_scan_id=excluded.last_scan_id",
                 (pid, r.host, r.rtype, r.value, ts, ts, scan_id))


def upsert_port(conn, pid: int, r: PortRecord, scan_id: int) -> None:
    ts = now()
    conn.execute(
        "INSERT INTO ports(project_id,host,ip,port,protocol,service,product,version,source,first_seen,last_seen,last_scan_id)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(project_id,host,ip,port,protocol) DO UPDATE SET last_seen=excluded.last_seen,"
        " last_scan_id=excluded.last_scan_id, service=COALESCE(excluded.service,service),"
        " product=COALESCE(excluded.product,product), version=COALESCE(excluded.version,version)",
        (pid, r.host, r.ip or "", r.port, r.protocol, r.service, r.product, r.version, r.source, ts, ts, scan_id))


def upsert_endpoint(conn, pid: int, r: EndpointRecord, scan_id: int) -> None:
    ts = now()
    conn.execute(
        "INSERT INTO endpoints(project_id,url,host,status_code,title,webserver,technologies,content_length,kind,source,first_seen,last_seen,last_scan_id)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(project_id,url) DO UPDATE SET last_seen=excluded.last_seen,"
        " last_scan_id=excluded.last_scan_id, status_code=COALESCE(excluded.status_code,status_code), title=COALESCE(excluded.title,title),"
        " webserver=COALESCE(excluded.webserver,webserver), content_length=COALESCE(excluded.content_length,content_length),"
        " technologies=CASE WHEN excluded.technologies!='[]' THEN excluded.technologies ELSE technologies END",
        (pid, r.url, r.host, r.status_code, r.title, r.webserver, json.dumps(r.technologies), r.content_length, r.kind, r.source, ts, ts, scan_id))


def finding_fingerprint(r: FindingRecord) -> str:
    key = "\x1f".join([r.source, r.template_id, r.asset.lower(), r.url, r.dedupe_extra])
    return hashlib.sha256(key.encode()).hexdigest()[:32]


def upsert_finding(conn, pid: int, r: FindingRecord, scan_id: int, tool_version: str | None) -> tuple[int, bool]:
    ts, fp = now(), finding_fingerprint(r)
    row = q1(conn, "SELECT id,validation_status,analyst_notes FROM findings WHERE project_id=? AND fingerprint=?", (pid, fp))
    if row:
        status, notes = row["validation_status"], row["analyst_notes"]
        if status == "fixed":   # detected again after being marked fixed
            status, notes = "unvalidated", (notes + f"\n[auto] Re-detected in scan {scan_id} after being marked fixed.").strip()
        conn.execute("UPDATE findings SET last_seen=?, last_scan_id=?, severity=?, evidence=?, details=?, tool_version=?,"
                     " template_version=COALESCE(?,template_version), validation_status=?, analyst_notes=? WHERE id=?",
                     (ts, scan_id, r.severity, r.evidence, r.details, tool_version, r.template_version, status, notes, row["id"]))
        fid, new = row["id"], False
    else:
        fid = conn.execute(
            "INSERT INTO findings(project_id,fingerprint,title,description,asset,url,severity,confidence,source,template_id,evidence,details,refs,"
            "tool_version,template_version,first_seen,last_seen,first_scan_id,last_scan_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (pid, fp, r.title, r.description, r.asset, r.url, r.severity, r.confidence, r.source, r.template_id, r.evidence, r.details,
             json.dumps(r.references), tool_version, r.template_version, ts, ts, scan_id, scan_id)).lastrowid
        new = True
    conn.execute("INSERT OR IGNORE INTO finding_scans(scan_id,finding_id) VALUES(?,?)", (scan_id, fid))
    return fid, new


# ------------------------------------------------------------------ comparison
def compare_scans(conn, older_id: int, newer_id: int) -> dict[str, Any]:
    def assets(sid: int) -> dict[tuple[str, str], str]:
        return {(r["kind"], r["value"]): r["source"] for r in q(
            conn, "SELECT a.kind,a.value,GROUP_CONCAT(s.source) source FROM asset_scans s JOIN assets a ON a.id=s.asset_id WHERE s.scan_id=? GROUP BY a.id", (sid,))}

    def findings(sid: int) -> dict[int, dict]:
        return {r["id"]: r for r in q(conn, "SELECT f.id,f.title,f.asset,f.severity,f.validation_status FROM finding_scans s JOIN findings f ON f.id=s.finding_id WHERE s.scan_id=?", (sid,))}

    a_old, a_new, f_old, f_new = assets(older_id), assets(newer_id), findings(older_id), findings(newer_id)
    s_old, s_new = q1(conn, "SELECT profile,status FROM scans WHERE id=?", (older_id,)), q1(conn, "SELECT profile,status FROM scans WHERE id=?", (newer_id,))
    comparable = bool(s_old and s_new and s_old["profile"] == s_new["profile"])
    return {
        "older_scan": older_id, "newer_scan": newer_id, "comparable": comparable,
        "note": "" if comparable else "These scans used different profiles; 'disappeared' items may simply not have been checked.",
        "assets_new": [{"kind": k[0], "value": k[1]} for k in sorted(set(a_new) - set(a_old))],
        "assets_disappeared": [{"kind": k[0], "value": k[1]} for k in sorted(set(a_old) - set(a_new))],
        "assets_unchanged": len(set(a_new) & set(a_old)),
        "findings_new": [f_new[i] for i in sorted(set(f_new) - set(f_old))],
        "findings_not_detected": [f_old[i] for i in sorted(set(f_old) - set(f_new))],
        "findings_unchanged": len(set(f_new) & set(f_old)),
    }
