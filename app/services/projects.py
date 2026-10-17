"""Projects, authorised scope entries and scan creation. All rules here are enforced server-side."""
from __future__ import annotations

import json
import sqlite3
from typing import Any

from ..config import effective_limits, get_settings
from ..database import get_setting, now, q, q1
from ..models import ProjectCreate, ScanCreate, ScopeAdd
from ..scope import Scope, ScopeError, parse_scope_entry, safe_path_under, validate_ident_list, validate_port_spec
from ..adapters import ADAPTERS

ACTIVE_PROFILES = ("vulnerability", "web")


class RequestRejected(ValueError):
    """A request violated a safety rule (HTTP 400)."""


def add_scope_entries(conn: sqlite3.Connection, project_id: int, entries: list[str], excluded: bool,
                      confirmed: bool, note: str) -> list[dict]:
    if not excluded and not confirmed:
        raise RequestRejected("Confirm that you are authorised to test these targets before adding them to scope.")
    parsed = [parse_scope_entry(e) for e in entries]          # ScopeError on any invalid entry
    out = []
    for e in parsed:
        conn.execute("""INSERT OR IGNORE INTO scope_entries(project_id,kind,value,excluded,authorization_note,authorized_at,created_at)
                        VALUES(?,?,?,?,?,?,?)""", (project_id, e.kind, e.value, int(excluded), note, None if excluded else now(), now()))
        out.append({"kind": e.kind, "value": e.display(), "excluded": excluded})
    return out


def create_project(conn: sqlite3.Connection, req: ProjectCreate) -> int:
    if q1(conn, "SELECT 1 FROM projects WHERE name=?", (req.name.strip(),)):
        raise RequestRejected("A project with that name already exists.")
    [parse_scope_entry(e) for e in req.scope + req.exclusions]   # validate everything before writing anything
    cur = conn.execute("INSERT INTO projects(name,description,created_at) VALUES(?,?,?)", (req.name.strip(), req.description, now()))
    pid = cur.lastrowid
    if req.scope:
        add_scope_entries(conn, pid, req.scope, False, req.authorization_confirmed, req.authorization_note)
    if req.exclusions:
        add_scope_entries(conn, pid, req.exclusions, True, True, "")
    return pid


def plan_stages(profile: str, o: dict[str, Any]) -> list[str]:
    stages = ["subfinder"]
    if o.get("enable_gau"):
        stages.append("gau")
    if profile != "passive":
        stages += ["dnsx"]
        if o.get("enable_enrichment"):
            stages.append("enrichment")
        stages += ["naabu", "httpx"]
        if profile == "web":
            stages.append("katana")
        if o.get("enable_nmap"):
            stages.append("nmap")
        if o.get("enable_testssl"):
            stages.append("testssl")
        if profile == "web" and o.get("enable_ffuf"):
            stages.append("ffuf")
        if profile in ACTIVE_PROFILES:
            stages.append("nuclei")
        if profile == "web" and o.get("enable_zap"):
            stages.append("zap")
    elif o.get("enable_enrichment"):
        stages.append("enrichment")
    return stages


def stage_meta(name: str) -> tuple[str, str, bool, str]:
    if name == "enrichment":
        return ("enrichment", "Public-source enrichment (opt-in providers)", False,
                "Sends in-scope domains/IPs to the providers you enabled. Nothing is sent to the target.")
    a = ADAPTERS[name]
    return (a.tool, a.label, a.touches_target, a.traffic_note)


def create_scan(conn: sqlite3.Connection, project_id: int, req: ScanCreate) -> int:
    if not q1(conn, "SELECT 1 FROM projects WHERE id=?", (project_id,)):
        raise RequestRejected("Project not found.")
    if not req.authorization_confirmed:
        raise RequestRejected("Confirm that you have permission to test the selected scope before creating a scan.")
    if req.profile in ACTIVE_PROFILES and not req.active_testing_confirmed:
        raise RequestRejected("This profile performs active vulnerability testing. Confirm active testing explicitly.")
    o = req.options
    if req.profile == "passive" and (o.enable_nmap or o.enable_testssl or o.enable_ffuf or o.enable_zap):
        raise RequestRejected("The passive profile cannot enable modules that contact the target.")
    if (o.enable_ffuf or o.enable_zap) and (req.profile != "web" or not req.active_testing_confirmed):
        raise RequestRejected("ffuf and ZAP are only available in the Web Assessment profile with active testing confirmed.")

    rows = q(conn, "SELECT * FROM scope_entries WHERE project_id=? AND excluded=0", (project_id,))
    if req.scope_entry_ids:
        rows = [r for r in rows if r["id"] in set(req.scope_entry_ids)]
        if len(rows) != len(set(req.scope_entry_ids)):
            raise RequestRejected("Some selected scope entries do not belong to this project.")
    if not rows:
        raise RequestRejected("The project has no authorised scope entries. Add scope before scanning.")
    includes = [(f"*.{r['value']}" if r["kind"] == "wildcard" else r["value"]) for r in rows]
    excl = [(f"*.{r['value']}" if r["kind"] == "wildcard" else r["value"])
            for r in q(conn, "SELECT * FROM scope_entries WHERE project_id=? AND excluded=1", (project_id,))]
    excl += req.extra_exclusions
    scope = Scope.from_strings(includes, excl)                 # raises ScopeError on malformed entries

    opts = o.model_dump()
    opts["ports"] = validate_port_spec(o.ports)
    opts["nuclei_tags"] = validate_ident_list(o.nuclei_tags, "nuclei tags")
    if o.enable_ffuf:
        opts["ffuf_wordlist"] = str(safe_path_under(o.ffuf_wordlist, get_settings().wordlist_dirs))
    limits = effective_limits({**(get_setting(conn, "limits", {}) or {}), **{k: v for k, v in opts.items() if v is not None}})
    opts["_effective_limits"] = limits.__dict__

    cur = conn.execute("""INSERT INTO scans(project_id,profile,status,config_json,scope_json,exclusions_json,authorization_confirmed,
                          active_testing_confirmed,created_at) VALUES(?,?,?,?,?,?,?,?,?)""",
                       (project_id, req.profile, "draft", json.dumps(opts), json.dumps([e.display() for e in scope.include]),
                        json.dumps([e.display() for e in scope.exclude]), 1, int(req.active_testing_confirmed), now()))
    sid = cur.lastrowid
    for pos, name in enumerate(plan_stages(req.profile, opts)):
        tool, label, touches, note = stage_meta(name)
        conn.execute("INSERT INTO scan_stages(scan_id,position,name,tool,label,touches_target,traffic_note) VALUES(?,?,?,?,?,?,?)",
                     (sid, pos, name, tool, label, int(touches), note))
    return sid


def reset_for_retry(conn: sqlite3.Connection, scan_id: int) -> None:
    """Re-queue only the stages that did not finish; completed/empty/partial/cached stages keep their stored output."""
    conn.execute("""UPDATE scan_stages SET status='pending', error=NULL, message=NULL, finished_at=NULL
                    WHERE scan_id=? AND status IN ('failed','missing_tool','skipped','cancelled','pending','running')""", (scan_id,))
    conn.execute("UPDATE scans SET error=NULL, completed_at=NULL, cancel_requested=0, pause_requested=0 WHERE id=?", (scan_id,))
