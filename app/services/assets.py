"""Persistence with deduplication (first_seen / last_seen), scan comparison and prioritisation."""
from __future__ import annotations

import hashlib
import json
import sqlite3
from typing import Any

from ..database import now, q, q1
from ..models import FindingRecord, OPEN_VALIDATION, ParseResult, SEVERITIES, SEVERITY_RANK
from ..scope import Scope

PRIORITY_WORDS = ("admin", "login", "auth", "sso", "vpn", "staging", "stage", "dev", "test", "internal", "jenkins",
                  "gitlab", "grafana", "kibana", "api", "portal", "backup", "beta", "old", "uat", "git")
RISKY_PORTS = {21, 22, 23, 25, 445, 1433, 1521, 2375, 3306, 3389, 5432, 5900, 6379, 9200, 11211, 27017}


def asset_priority(host: str, ports: list[int] | None = None, is_new: bool = False) -> tuple[int, list[str]]:
    """Transparent heuristic used to order work and the asset table. Returns (score, reasons)."""
    score, why = 0, []
    labels = host.lower().replace("-", ".").split(".")
    hit = [w for w in PRIORITY_WORDS if w in labels]
    if hit:
        score += 3
        why.append("name suggests " + "/".join(hit))
    risky = sorted(set(ports or []) & RISKY_PORTS)
    if risky:
        score += 3
        why.append("exposed ports " + ",".join(map(str, risky)))
    if is_new:
        score += 4
        why.append("new since earlier scans")
    return score, why


def upsert_asset(conn: sqlite3.Connection, project_id: int, scan_id: int, kind: str, value: str, source: str) -> bool:
    ts = now()
    row = q1(conn, "SELECT id, sources FROM assets WHERE project_id=? AND kind=? AND value=?", (project_id, kind, value))
    if row:
        srcs = set(filter(None, row["sources"].split(",")))
        srcs.add(source)
        conn.execute("UPDATE assets SET last_seen=?, last_scan_id=?, sources=? WHERE id=?",
                     (ts, scan_id, ",".join(sorted(srcs)), row["id"]))
        asset_id, is_new = row["id"], False
    else:
        cur = conn.execute("INSERT INTO assets(project_id,kind,value,sources,first_seen,last_seen,first_scan_id,last_scan_id) "
                           "VALUES(?,?,?,?,?,?,?,?)", (project_id, kind, value, source, ts, ts, scan_id, scan_id))
        asset_id, is_new = cur.lastrowid, True
    conn.execute("INSERT OR IGNORE INTO asset_scans(scan_id,asset_id,source) VALUES(?,?,?)", (scan_id, asset_id, source))
    return is_new


def finding_fingerprint(f: FindingRecord) -> str:
    raw = "\x1f".join([f.source, f.template_id, f.asset.lower(), f.url.split("#")[0], f.dedupe_extra])
    return hashlib.sha256(raw.encode()).hexdigest()[:40]


def upsert_finding(conn: sqlite3.Connection, project_id: int, scan_id: int, f: FindingRecord, tool_version: str | None) -> bool:
    ts, fp = now(), finding_fingerprint(f)
    row = q1(conn, "SELECT id FROM findings WHERE project_id=? AND fingerprint=?", (project_id, fp))
    if row:
        conn.execute("""UPDATE findings SET last_seen=?, last_scan_id=?, severity=?, confidence=?, evidence=?, details=?,
                        tool_version=?, template_version=COALESCE(?, template_version),
                        validation_status=CASE WHEN validation_status='fixed' THEN 'unvalidated' ELSE validation_status END
                        WHERE id=?""", (ts, scan_id, f.severity, f.confidence, f.evidence, f.details, tool_version,
                                        f.template_version, row["id"]))
        fid, is_new = row["id"], False
    else:
        cur = conn.execute("""INSERT INTO findings(project_id,fingerprint,title,description,asset,url,severity,confidence,source,
                              template_id,evidence,details,refs,tool_version,template_version,first_seen,last_seen,first_scan_id,last_scan_id)
                              VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                           (project_id, fp, f.title, f.description, f.asset, f.url, f.severity, f.confidence, f.source,
                            f.template_id, f.evidence, f.details, json.dumps(f.references), tool_version, f.template_version,
                            ts, ts, scan_id, scan_id))
        fid, is_new = cur.lastrowid, True
    conn.execute("INSERT OR IGNORE INTO finding_scans(scan_id,finding_id) VALUES(?,?)", (scan_id, fid))
    return is_new


def scope_filter(scope: Scope, res: ParseResult) -> int:
    """Final defensive filter: nothing outside the authorised scope is ever persisted. Returns the number dropped."""
    before = res.item_count
    res.hosts = [(h, s) for h, s in res.hosts if scope.host_allowed(h)[0]]
    res.dns = [d for d in res.dns if scope.host_allowed(d.host)[0]]
    res.ports = [p for p in res.ports if scope.host_allowed(p.host)[0]]
    res.endpoints = [e for e in res.endpoints if scope.url_allowed(e.url)[0]]
    res.findings = [f for f in res.findings if scope.host_allowed(f.asset)[0]]
    return before - res.item_count


def persist_result(conn: sqlite3.Connection, project_id: int, scan_id: int, res: ParseResult,
                   tool_version: str | None, max_assets: int) -> dict[str, int]:
    ts = now()
    counts = {"new_assets": 0, "assets": 0, "ports": 0, "endpoints": 0, "findings": 0, "new_findings": 0, "dns": 0}
    seen_hosts: set[str] = set()
    for host, source in res.hosts:
        if host in seen_hosts and source in ("dnsx", "httpx"):
            continue
        if len(seen_hosts) >= max_assets and host not in seen_hosts:
            continue
        seen_hosts.add(host)
        kind = "ip" if host.replace(".", "").isdigit() or ":" in host else "domain"
        counts["new_assets"] += upsert_asset(conn, project_id, scan_id, kind, host, source)
    counts["assets"] = len(seen_hosts)
    for d in res.dns:
        conn.execute("""INSERT INTO dns_records(project_id,host,rtype,value,first_seen,last_seen,last_scan_id) VALUES(?,?,?,?,?,?,?)
                        ON CONFLICT(project_id,host,rtype,value) DO UPDATE SET last_seen=excluded.last_seen, last_scan_id=excluded.last_scan_id""",
                     (project_id, d.host, d.rtype, d.value, ts, ts, scan_id))
        counts["dns"] += 1
    for p in res.ports:
        conn.execute("""INSERT INTO ports(project_id,host,ip,port,protocol,service,product,version,source,first_seen,last_seen,last_scan_id)
                        VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                        ON CONFLICT(project_id,host,port,protocol) DO UPDATE SET last_seen=excluded.last_seen, last_scan_id=excluded.last_scan_id,
                          ip=COALESCE(excluded.ip, ip), service=COALESCE(excluded.service, service), product=COALESCE(excluded.product, product),
                          version=COALESCE(excluded.version, version),
                          source=CASE WHEN instr(source, excluded.source)>0 THEN source ELSE source||','||excluded.source END""",
                     (project_id, p.host, p.ip, p.port, p.protocol, p.service, p.product, p.version, p.source, ts, ts, scan_id))
        counts["ports"] += 1
    for e in res.endpoints:
        conn.execute("""INSERT INTO endpoints(project_id,url,host,status_code,title,webserver,technologies,content_length,kind,source,first_seen,last_seen,last_scan_id)
                        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
                        ON CONFLICT(project_id,url) DO UPDATE SET last_seen=excluded.last_seen, last_scan_id=excluded.last_scan_id,
                          status_code=COALESCE(excluded.status_code, status_code), title=COALESCE(excluded.title, title),
                          webserver=COALESCE(excluded.webserver, webserver), content_length=COALESCE(excluded.content_length, content_length),
                          technologies=CASE WHEN excluded.technologies!='[]' THEN excluded.technologies ELSE technologies END,
                          kind=CASE WHEN excluded.kind='http' THEN 'http' ELSE kind END""",
                     (project_id, e.url, e.host, e.status_code, e.title, e.webserver, json.dumps(e.technologies),
                      e.content_length, e.kind, e.source, ts, ts, scan_id))
        counts["endpoints"] += 1
    for f in res.findings:
        counts["new_findings"] += upsert_finding(conn, project_id, scan_id, f, tool_version)
        counts["findings"] += 1
    return counts


# ------------------------------------------------------------------ comparison & stats
def seen_before(conn: sqlite3.Connection, project_id: int, scan_id: int) -> set[str]:
    """Domain assets that existed before this scan started (used to flag and prioritise new ones)."""
    rows = q(conn, "SELECT value FROM assets WHERE project_id=? AND kind='domain' AND first_scan_id < ?", (project_id, scan_id))
    return {r["value"] for r in rows}


def compare_scans(conn: sqlite3.Connection, project_id: int, older: int, newer: int) -> dict[str, Any]:
    def assets(sid: int) -> dict[str, str]:
        return {r["value"]: r["kind"] for r in q(conn, "SELECT DISTINCT a.value, a.kind FROM asset_scans s JOIN assets a ON a.id=s.asset_id "
                                                  "WHERE s.scan_id=? AND a.project_id=?", (sid, project_id))}

    def findings(sid: int) -> dict[int, dict]:
        return {r["id"]: r for r in q(conn, "SELECT f.id, f.title, f.severity, f.asset, f.url FROM finding_scans s JOIN findings f ON f.id=s.finding_id "
                                            "WHERE s.scan_id=? AND f.project_id=?", (sid, project_id))}

    a_old, a_new, f_old, f_new = assets(older), assets(newer), findings(older), findings(newer)
    by_sev = lambda d: sorted(d, key=lambda r: -SEVERITY_RANK.get(r["severity"], 0))
    return {
        "older": older, "newer": newer,
        "assets_new": sorted(set(a_new) - set(a_old)), "assets_gone": sorted(set(a_old) - set(a_new)),
        "assets_unchanged": len(set(a_new) & set(a_old)),
        "findings_new": by_sev([f_new[i] for i in set(f_new) - set(f_old)]),
        "findings_gone": by_sev([f_old[i] for i in set(f_old) - set(f_new)]),
        "findings_unchanged": len(set(f_new) & set(f_old)),
    }


def dashboard_stats(conn: sqlite3.Connection) -> dict[str, Any]:
    sev = {s: 0 for s in SEVERITIES}
    ph = ",".join("?" * len(OPEN_VALIDATION))
    for r in q(conn, f"SELECT severity, COUNT(*) c FROM findings WHERE validation_status IN ({ph}) GROUP BY severity", OPEN_VALIDATION):
        sev[r["severity"]] = r["c"]
    return {
        "projects": q1(conn, "SELECT COUNT(*) c FROM projects")["c"],
        "assets": q1(conn, "SELECT COUNT(*) c FROM assets")["c"],
        "endpoints": q1(conn, "SELECT COUNT(*) c FROM endpoints")["c"],
        "ports": q1(conn, "SELECT COUNT(*) c FROM ports")["c"],
        "open_findings": sum(sev.values()), "severity": sev,
        "running": q1(conn, "SELECT COUNT(*) c FROM scans WHERE status IN ('queued','running','paused')")["c"],
        "recent_scans": q(conn, "SELECT s.id, s.profile, s.status, s.created_at, s.completed_at, p.name AS project FROM scans s "
                                "JOIN projects p ON p.id=s.project_id ORDER BY s.id DESC LIMIT 8"),
    }
