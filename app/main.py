"""ReconForge web application: pages, JSON API and security middleware."""
from __future__ import annotations

import json
import sqlite3
from contextlib import asynccontextmanager
from dataclasses import asdict, fields
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .config import HARD_MAX, Limits, SecretStore, effective_limits, get_settings
from .database import get_setting, init_db, now, q, q1, set_setting
from .database import db
from .models import (PROFILES, FindingUpdate, IntegrationUpdate, LimitsUpdate, ProjectCreate, ScanCreate, ScanStatus, ScopeAdd)
from .scheduler import Scheduler
from .scope import Scope, ScopeError, parse_scope_entry, safe_path_under, validate_ident_list, validate_port_spec
from .services import providers, reports, store
from .services.pipeline import create_scan, validate_request
from .services.tools import detect_all

APP_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(APP_DIR / "templates"))
CSP = "default-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
REPORT_CSP = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'"
SEV_SQL = "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END"


def saved_limits(conn: sqlite3.Connection | None = None) -> dict[str, Any]:
    if conn is not None:
        return get_setting(conn, "limits", {}) or {}
    with db() as c:
        return get_setting(c, "limits", {}) or {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    app.state.sched = Scheduler(effective_limits(saved_limits()))
    await app.state.sched.start()
    yield
    await app.state.sched.stop()


app = FastAPI(title="ReconForge", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(APP_DIR / "static")), name="static")


@app.middleware("http")
async def guard(request: Request, call_next):
    """Host allow-list (DNS-rebinding defence) and CSRF defence for state-changing requests."""
    allowed = get_settings().allowed_hosts
    host = (request.headers.get("host") or "").rsplit(":", 1)[0].strip("[]").lower() if not (request.headers.get("host") or "").startswith("[") else "::1"
    if host not in allowed:
        return JSONResponse({"detail": "Host header not allowed. Use http://127.0.0.1:8000"}, status_code=400)
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        origin = request.headers.get("origin")
        if request.headers.get("x-reconforge") != "1" or (origin and (urlsplit(origin).hostname or "").lower() not in allowed):
            return JSONResponse({"detail": "Cross-site or malformed request rejected."}, status_code=403)
    resp = await call_next(request)
    resp.headers.setdefault("Content-Security-Policy", CSP)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("Cache-Control", "no-store")
    return resp


@app.exception_handler(ScopeError)
async def scope_error(_: Request, exc: ScopeError):
    return JSONResponse({"detail": str(exc)}, status_code=400)


def need(row: Any, what: str = "Not found") -> Any:
    if not row:
        raise HTTPException(404, what)
    return row


# ------------------------------------------------------------------ pages (data is loaded by /static/app.js)
def page(name: str, title: str):
    async def view(request: Request, pid: int | None = None, sid: int | None = None):
        return templates.TemplateResponse(request, "shell.html", {"page": name, "title": title, "pid": pid, "sid": sid})
    return view


for path, name, title in [("/", "overview", "Overview"), ("/projects", "projects", "Projects"), ("/projects/{pid}", "project", "Project"),
                          ("/projects/{pid}/scan", "wizard", "New scan"), ("/scans", "scans", "Scan history"), ("/scans/{sid}", "scan", "Scan"),
                          ("/assets", "assets", "Assets"), ("/findings", "findings", "Findings"), ("/tools", "tools", "Tool health"),
                          ("/settings", "settings", "Settings")]:
    app.add_api_route(path, page(name, title), methods=["GET"], include_in_schema=False)


# ------------------------------------------------------------------ overview and projects
@app.get("/api/overview")
def overview():
    with db() as c:
        sev = {r["severity"]: r["n"] for r in q(c, "SELECT severity, COUNT(*) n FROM findings WHERE validation_status IN ('unvalidated','confirmed') GROUP BY severity")}
        recent = q(c, "SELECT s.id,s.profile,s.status,s.created_at,s.completed_at,s.summary_json,p.name project, p.id project_id FROM scans s JOIN projects p ON p.id=s.project_id ORDER BY s.id DESC LIMIT 8")
        for r in recent:
            r["summary"] = json.loads(r.pop("summary_json") or "{}")
        return {"projects": q1(c, "SELECT COUNT(*) n FROM projects")["n"], "assets": q1(c, "SELECT COUNT(*) n FROM assets")["n"],
                "endpoints": q1(c, "SELECT COUNT(*) n FROM endpoints")["n"],
                "open_findings": sum(sev.values()), "findings_by_severity": sev, "recent_scans": recent,
                "active_scans": q1(c, "SELECT COUNT(*) n FROM scans WHERE status IN ('queued','running','paused')")["n"]}


@app.get("/api/projects")
def list_projects():
    with db() as c:
        return q(c, "SELECT p.*, (SELECT COUNT(*) FROM assets a WHERE a.project_id=p.id) assets,"
                    " (SELECT COUNT(*) FROM findings f WHERE f.project_id=p.id AND f.validation_status IN ('unvalidated','confirmed')) open_findings,"
                    " (SELECT COUNT(*) FROM scans s WHERE s.project_id=p.id) scans,"
                    " (SELECT COUNT(*) FROM scope_entries e WHERE e.project_id=p.id AND e.excluded=0) scope_entries FROM projects p ORDER BY p.id DESC")


def _add_scope(c: sqlite3.Connection, pid: int, entries: list[str], excluded: bool, confirmed: bool, note: str) -> None:
    parsed = [parse_scope_entry(e) for e in entries]
    if parsed and not excluded and not confirmed:
        raise ScopeError("Confirm that you are authorised to test these targets before adding them to the scope.")
    for e in parsed:
        c.execute("INSERT OR IGNORE INTO scope_entries(project_id,kind,value,excluded,authorization_note,authorized_at,created_at) VALUES(?,?,?,?,?,?,?)",
                  (pid, e.kind, e.value, int(excluded), note, None if excluded else now(), now()))


@app.post("/api/projects")
def create_project(body: ProjectCreate):
    with db() as c:
        if q1(c, "SELECT id FROM projects WHERE name=?", (body.name,)):
            raise ScopeError("A project with that name already exists.")
        pid = c.execute("INSERT INTO projects(name,description,created_at) VALUES(?,?,?)", (body.name, body.description, now())).lastrowid
        _add_scope(c, pid, body.scope, False, body.authorization_confirmed, body.authorization_note)   # a ScopeError rolls everything back
        _add_scope(c, pid, body.exclusions, True, True, "")
        return {"id": pid}


@app.get("/api/projects/{pid}")
def get_project(pid: int):
    with db() as c:
        p = need(q1(c, "SELECT * FROM projects WHERE id=?", (pid,)))
        entries = q(c, "SELECT * FROM scope_entries WHERE project_id=? ORDER BY excluded, id", (pid,))
        from .scope import ScopeEntry
        for e in entries:
            e["display"] = ScopeEntry(e["kind"], e["value"]).display()
        scans = q(c, "SELECT id,profile,status,created_at,completed_at,summary_json FROM scans WHERE project_id=? ORDER BY id DESC", (pid,))
        for s in scans:
            s["summary"] = json.loads(s.pop("summary_json") or "{}")
        return {**p, "scope": entries, "scans": scans}


@app.post("/api/projects/{pid}/scope")
def add_scope(pid: int, body: ScopeAdd):
    with db() as c:
        need(q1(c, "SELECT id FROM projects WHERE id=?", (pid,)))
        _add_scope(c, pid, body.entries, body.excluded, body.authorization_confirmed, body.authorization_note)
    return {"ok": True}


@app.delete("/api/projects/{pid}/scope/{eid}")
def delete_scope(pid: int, eid: int):
    with db() as c:
        c.execute("DELETE FROM scope_entries WHERE id=? AND project_id=?", (eid, pid))
    return {"ok": True}


@app.delete("/api/projects/{pid}")
def delete_project(pid: int):
    with db() as c:
        if q1(c, "SELECT id FROM scans WHERE project_id=? AND status IN ('queued','running','paused')", (pid,)):
            raise ScopeError("Cancel the project's active scans first.")
        c.execute("DELETE FROM projects WHERE id=?", (pid,))
    return {"ok": True}


# ------------------------------------------------------------------ scans
@app.post("/api/projects/{pid}/scans")
async def start_scan(pid: int, body: ScanCreate, request: Request):
    from .scope import ScopeEntry
    o = body.options
    validate_port_spec(o.ports)
    validate_ident_list(o.nuclei_tags, "nuclei tags")
    if o.enable_ffuf:
        safe_path_under(o.ffuf_wordlist, get_settings().wordlist_dirs)
    with db() as c:
        project = need(q1(c, "SELECT * FROM projects WHERE id=?", (pid,)))
        rows = q(c, "SELECT * FROM scope_entries WHERE project_id=?", (pid,))
        chosen = [r for r in rows if not r["excluded"] and r["id"] in body.scope_entry_ids and r["authorized_at"]]
        if not chosen:
            raise ScopeError("Select at least one authorised scope entry for this scan.")
        include = [ScopeEntry(r["kind"], r["value"]).display() for r in chosen]
        exclude = [ScopeEntry(r["kind"], r["value"]).display() for r in rows if r["excluded"]]
        exclude += [parse_scope_entry(x).display() for x in body.extra_exclusions]
        Scope.from_strings(include, exclude)                         # raises ScopeError if anything is malformed
        validate_request(body.profile, body.authorization_confirmed, body.active_testing_confirmed, o)
        sid = create_scan(c, project, body.profile, include, exclude, o, saved_limits(c), body.authorization_confirmed, body.active_testing_confirmed)
    request.app.state.sched.enqueue(sid)
    return {"id": sid}


@app.get("/api/scans")
def list_scans(project_id: int | None = None):
    with db() as c:
        rows = q(c, "SELECT s.id,s.project_id,s.profile,s.status,s.created_at,s.started_at,s.completed_at,s.summary_json,p.name project FROM scans s"
                    " JOIN projects p ON p.id=s.project_id WHERE (? IS NULL OR s.project_id=?) ORDER BY s.id DESC LIMIT 200", (project_id, project_id))
    for r in rows:
        r["summary"] = json.loads(r.pop("summary_json") or "{}")
    return rows


@app.get("/api/scans/{sid}")
def get_scan(sid: int):
    with db() as c:
        s = need(q1(c, "SELECT s.*, p.name project FROM scans s JOIN projects p ON p.id=s.project_id WHERE s.id=?", (sid,)))
        stages = q(c, "SELECT id,position,name,tool,label,touches_target,traffic_note,status,started_at,finished_at,items,input_count,attempts,message,cached_from_scan,cached_at FROM scan_stages WHERE scan_id=? ORDER BY position", (sid,))
        logs = q(c, "SELECT id,ts,level,message FROM scan_logs WHERE scan_id=? ORDER BY id DESC LIMIT 200", (sid,))[::-1]
        runs = q(c, "SELECT stage_name,tool,version,exit_code,status,timed_out,truncated FROM tool_runs WHERE scan_id=? ORDER BY id", (sid,))
    cfg = json.loads(s.pop("config_json"))
    s["options"], s["limits"] = cfg["options"], cfg["limits"]
    s["scope"], s["exclusions"], s["summary"] = json.loads(s.pop("scope_json")), json.loads(s.pop("exclusions_json")), json.loads(s.pop("summary_json") or "{}")
    return {**s, "stages": stages, "logs": logs, "tool_runs": runs}


@app.get("/api/scans/{sid}/runs")
def scan_runs(sid: int):
    """Exact commands and captured output of every tool run, for debugging a failed or surprising stage."""
    with db() as c:
        need(q1(c, "SELECT id FROM scans WHERE id=?", (sid,)))
        rows = q(c, "SELECT id,stage_name,tool,version,argv_json,started_at,finished_at,exit_code,status,timed_out,truncated,stdout_bytes,stderr_tail,error,stdout_head FROM tool_runs WHERE scan_id=? ORDER BY id", (sid,))
    for r in rows:
        r["argv"] = json.loads(r.pop("argv_json"))
    return rows


@app.get("/api/scans/{sid}/logs")
def scan_logs(sid: int, after: int = 0):
    with db() as c:
        return q(c, "SELECT id,ts,level,message FROM scan_logs WHERE scan_id=? AND id>? ORDER BY id LIMIT 500", (sid, after))


@app.post("/api/scans/{sid}/cancel")
def cancel_scan(sid: int, request: Request):
    with db() as c:
        s = need(q1(c, "SELECT status FROM scans WHERE id=?", (sid,)))
    if s["status"] not in ScanStatus.ACTIVE:
        raise ScopeError("This scan is not active.")
    request.app.state.sched.cancel(sid)
    return {"ok": True}


@app.post("/api/scans/{sid}/pause")
def pause_scan(sid: int, request: Request):
    request.app.state.sched.set_pause(sid, True)
    return {"ok": True, "note": "Pausing takes effect between stages; a running tool is not interrupted."}


@app.post("/api/scans/{sid}/resume")
def resume_scan(sid: int, request: Request):
    request.app.state.sched.set_pause(sid, False)
    return {"ok": True}


@app.post("/api/scans/{sid}/retry")
def retry_scan(sid: int, request: Request):
    with db() as c:
        s = need(q1(c, "SELECT status FROM scans WHERE id=?", (sid,)))
        if s["status"] in ScanStatus.ACTIVE:
            raise ScopeError("This scan is still active.")
        c.execute("UPDATE scan_stages SET status='pending', message=NULL, error=NULL, started_at=NULL, finished_at=NULL WHERE scan_id=?"
                  " AND status NOT IN ('completed','empty','cached') AND NOT (status='partial' AND items>0)", (sid,))
        store.log(c, sid, "info", "Retry requested: unfinished stages will run again; completed stages are kept")
    request.app.state.sched.enqueue(sid)
    return {"ok": True}


@app.get("/api/scans/{sid}/compare")
def compare(sid: int, other: int | None = None):
    with db() as c:
        s = need(q1(c, "SELECT project_id,profile FROM scans WHERE id=?", (sid,)))
        if other is None:
            prev = q1(c, "SELECT id FROM scans WHERE project_id=? AND id<? AND status IN ('completed','completed_with_issues') ORDER BY (profile=?) DESC, id DESC LIMIT 1",
                      (s["project_id"], sid, s["profile"]))
            if not prev:
                raise ScopeError("There is no earlier completed scan in this project to compare with.")
            other = prev["id"]
        need(q1(c, "SELECT id FROM scans WHERE id=? AND project_id=?", (other, s["project_id"])), "The other scan is not in the same project")
        return store.compare_scans(c, min(sid, other), max(sid, other))


@app.post("/api/scans/{sid}/report")
def make_report(sid: int):
    try:
        paths = reports.write_reports(sid)
    except KeyError:
        raise HTTPException(404, "Scan not found")
    return {"html": f"/scans/{sid}/report.html", "json": f"/api/scans/{sid}/report.json", "files": {k: str(v) for k, v in paths.items()}}


@app.get("/api/scans/{sid}/report.json")
def report_json(sid: int):
    try:
        paths = reports.write_reports(sid)
    except KeyError:
        raise HTTPException(404, "Scan not found")
    return FileResponse(paths["json"], media_type="application/json", filename=f"reconforge-scan-{sid}.json")


@app.get("/scans/{sid}/report.html", include_in_schema=False)
def report_html(sid: int):
    try:
        paths = reports.write_reports(sid)
    except KeyError:
        raise HTTPException(404, "Scan not found")
    return Response(paths["html"].read_text(), media_type="text/html", headers={"Content-Security-Policy": REPORT_CSP})


# ------------------------------------------------------------------ assets and findings
@app.get("/api/assets")
def list_assets(project_id: int | None = None, q_: str = Query("", alias="q"), kind: str = "", sort: str = "value", order: str = "asc", limit: int = 500):
    return _assets(project_id, q_, kind, sort, order, limit)


def _assets(project_id, text, kind, sort, order, limit):
    col = {"value": "a.value", "kind": "a.kind", "first_seen": "a.first_seen", "last_seen": "a.last_seen", "findings": "findings", "ports": "ports"}.get(sort, "a.value")
    direction = "DESC" if order == "desc" else "ASC"
    with db() as c:
        return q(c, f"SELECT a.*, p.name project,"
                    " (SELECT COUNT(DISTINCT x.port) FROM ports x WHERE x.project_id=a.project_id AND x.host=a.value) ports,"
                    " (SELECT COUNT(*) FROM endpoints e WHERE e.project_id=a.project_id AND e.host=a.value) endpoints,"
                    " (SELECT COUNT(*) FROM findings f WHERE f.project_id=a.project_id AND f.asset=a.value AND f.validation_status IN ('unvalidated','confirmed')) findings,"
                    " (SELECT GROUP_CONCAT(DISTINCT d.value) FROM dns_records d WHERE d.project_id=a.project_id AND d.host=a.value AND d.rtype IN ('A','AAAA')) ips"
                    " FROM assets a JOIN projects p ON p.id=a.project_id WHERE (? IS NULL OR a.project_id=?) AND (?='' OR a.kind=?)"
                    " AND (?='' OR a.value LIKE '%'||?||'%') ORDER BY " + col + " " + direction + " LIMIT ?",
                 (project_id, project_id, kind, kind, text, text, min(max(limit, 1), 2000)))


@app.get("/api/assets/{aid}")
def asset_detail(aid: int):
    with db() as c:
        a = need(q1(c, "SELECT * FROM assets WHERE id=?", (aid,)))
        pid, v = a["project_id"], a["value"]
        dns = q(c, "SELECT rtype,value,first_seen,last_seen FROM dns_records WHERE project_id=? AND host=? ORDER BY rtype,value", (pid, v))
        ips = [d["value"] for d in dns if d["rtype"] in ("A", "AAAA")]
        marks = ",".join("?" * (len(ips) + 1))
        return {**a, "dns": dns,
                "ports": q(c, "SELECT port,protocol,ip,service,product,version,source,last_seen FROM ports WHERE project_id=? AND host=? ORDER BY port", (pid, v)),
                "endpoints": q(c, "SELECT url,status_code,title,webserver,technologies,kind,source,last_seen FROM endpoints WHERE project_id=? AND host=? ORDER BY url LIMIT 300", (pid, v)),
                "findings": q(c, f"SELECT id,title,severity,validation_status,source,last_seen FROM findings WHERE project_id=? AND asset=? ORDER BY {SEV_SQL}", (pid, v)),
                "intel": [{**r, "payload": json.loads(r.pop("payload_json"))} for r in
                          q(c, f"SELECT provider,subject,payload_json,fetched_at FROM integration_results WHERE project_id=? AND subject IN ({marks})", (pid, v, *ips))]}


@app.get("/api/findings")
def list_findings(project_id: int | None = None, scan_id: int | None = None, severity: str = "", status: str = "", text: str = "", limit: int = 1000):
    with db() as c:
        rows = q(c, f"SELECT f.id,f.project_id,p.name project,f.title,f.asset,f.url,f.severity,f.confidence,f.source,f.template_id,f.validation_status,f.first_seen,f.last_seen"
                    " FROM findings f JOIN projects p ON p.id=f.project_id WHERE (? IS NULL OR f.project_id=?) AND (? IS NULL OR f.id IN (SELECT finding_id FROM finding_scans WHERE scan_id=?)) AND (?='' OR f.severity=?)"
                    " AND (?='' OR f.validation_status=?) AND (?='' OR f.title LIKE '%'||?||'%' OR f.asset LIKE '%'||?||'%' OR f.template_id LIKE '%'||?||'%')"
                    f" ORDER BY {SEV_SQL.replace('severity', 'f.severity')}, f.last_seen DESC LIMIT ?",
                 (project_id, project_id, scan_id, scan_id, severity, severity, status, status, text, text, text, text, min(max(limit, 1), 5000)))
    return rows


@app.get("/api/findings/{fid}")
def finding_detail(fid: int):
    with db() as c:
        f = need(q1(c, "SELECT * FROM findings WHERE id=?", (fid,)))
        f["refs"] = json.loads(f.pop("refs") or "[]")
        f["scans"] = [r["scan_id"] for r in q(c, "SELECT scan_id FROM finding_scans WHERE finding_id=? ORDER BY scan_id", (fid,))]
    f["potential"] = f["validation_status"] == "unvalidated"
    return f


@app.patch("/api/findings/{fid}")
def update_finding(fid: int, body: FindingUpdate):
    with db() as c:
        need(q1(c, "SELECT id FROM findings WHERE id=?", (fid,)))
        if body.validation_status is not None:
            c.execute("UPDATE findings SET validation_status=? WHERE id=?", (body.validation_status, fid))
            if body.validation_status == "confirmed":
                c.execute("UPDATE findings SET confidence='high' WHERE id=?", (fid,))
        if body.analyst_notes is not None:
            c.execute("UPDATE findings SET analyst_notes=? WHERE id=?", (body.analyst_notes, fid))
    return {"ok": True}


# ------------------------------------------------------------------ tools and settings
@app.get("/api/tools")
async def tools(refresh: int = 0):
    found = await detect_all(force=bool(refresh))
    return [t.to_dict() for t in found.values()]


@app.get("/api/settings")
def get_settings_api():
    s = get_settings()
    with db() as c:
        saved = saved_limits(c)
    return {"limits": asdict(effective_limits(saved)), "defaults": asdict(Limits()), "hard_max": HARD_MAX, "integrations": providers.state(),
            "wordlist_dirs": [str(p) for p in s.wordlist_dirs], "bind": f"{s.host}:{s.port}", "profiles": PROFILES}


@app.put("/api/settings/limits")
def put_limits(body: LimitsUpdate):
    names = {f.name for f in fields(Limits)}
    bad = [k for k in body.limits if k not in names]
    if bad:
        raise ScopeError(f"Unknown limit(s): {', '.join(bad)}")
    with db() as c:
        merged = {**saved_limits(c), **body.limits}
        eff = effective_limits(merged)
        set_setting(c, "limits", {k: v for k, v in asdict(eff).items()})
    return {"limits": asdict(eff), "note": "Concurrency limits apply after the server restarts. Rate and timeout limits apply to new scans."}


@app.put("/api/integrations/{name}")
def put_integration(name: str, body: IntegrationUpdate):
    if name not in providers.PROVIDERS:
        raise HTTPException(404, "Unknown integration")
    secret = providers.PROVIDERS[name]["secrets"][0]
    if body.api_key is not None:
        (SecretStore().set(secret, body.api_key.strip()) if body.api_key.strip() else SecretStore().delete(secret))
    with db() as c:
        c.execute("INSERT OR IGNORE INTO integrations(name) VALUES(?)", (name,))
        if body.enabled is not None:
            c.execute("UPDATE integrations SET enabled=?, updated_at=? WHERE name=?", (int(body.enabled), now(), name))
    return next(s for s in providers.state() if s["name"] == name)


@app.post("/api/integrations/{name}/test")
async def test_integration(name: str):
    if name not in providers.PROVIDERS:
        raise HTTPException(404, "Unknown integration")
    return await providers.test(name)
