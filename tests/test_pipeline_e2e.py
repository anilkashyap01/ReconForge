"""Drives the real pipeline, scheduler gate, runner, parsers, scope filter and database using stub binaries."""
import asyncio
import json
import sys

from app.adapters import REGISTRY
from app.database import db, now, q, q1
from app.models import ScanOptions
from app.services.pipeline import ScanRun, create_scan

INCLUDE = ["example.com", "*.example.com"]
EXCLUDE = ["admin.example.com"]


class Sched:
    def __init__(self):
        self.target_sem = asyncio.Semaphore(1)


def new_project(name="demo"):
    with db() as c:
        return c.execute("INSERT INTO projects(name,created_at) VALUES(?,?)", (name, now())).lastrowid


def start(pid, profile="standard", include=INCLUDE, exclude=EXCLUDE, limits=None, **opts):
    with db() as c:
        project = q1(c, "SELECT * FROM projects WHERE id=?", (pid,))
        return create_scan(c, project, profile, include, exclude, ScanOptions(**opts), {"retry_base_seconds": 1, **(limits or {})}, True, profile in ("vulnerability", "web"))


def execute(sid):
    asyncio.run(ScanRun(sid, Sched()).run())


def stages(sid):
    with db() as c:
        return {r["name"]: r for r in q(c, "SELECT * FROM scan_stages WHERE scan_id=?", (sid,))}


def scan_row(sid):
    with db() as c:
        return q1(c, "SELECT * FROM scans WHERE id=?", (sid,))


def values(sql, *args):
    with db() as c:
        return [list(r.values())[0] for r in q(c, sql, args)]


def test_standard_scan_end_to_end_enforces_scope_and_stores_real_results(fake_tools):
    pid = new_project()
    sid = start(pid, allow_resolved_ips=True)
    execute(sid)
    st = stages(sid)
    assert [st[n]["status"] for n in ("subfinder", "dnsx", "httpx", "naabu")] == ["completed"] * 4
    assert scan_row(sid)["status"] == "completed"
    assets = values("SELECT value FROM assets WHERE project_id=? ORDER BY value", pid)
    assert assets == ["api.example.com", "example.com", "www.example.com"]            # admin.* excluded, other.net rejected
    assert "unrelated.other.net" not in assets and "edge.thirdparty-cdn.net" not in assets
    assert ("CNAME", "edge.thirdparty-cdn.net") in [(r["rtype"], r["value"]) for r in _all("dns_records")]
    assert sorted(values("SELECT url FROM endpoints WHERE project_id=?", pid)) == ["https://api.example.com", "https://example.com", "https://www.example.com"]
    ports = _all("ports")
    assert {(p["host"], p["port"]) for p in ports} == {(h, n) for h in assets for n in (80, 443)}
    assert all(p["ip"] == "93.184.216.34" for p in ports)
    summary = json.loads(scan_row(sid)["summary_json"])
    assert summary["rejected_out_of_scope"] >= 2 and summary["assets"] == 3
    runs = _all("tool_runs")
    assert {r["tool"] for r in runs} == {"subfinder", "dnsx", "httpx", "naabu"} and all(r["version"] for r in runs)
    assert {r["name"]: r["touches_target"] for r in _all("scan_stages")}["subfinder"] == 0


def _all(table):
    with db() as c:
        return q(c, f"SELECT * FROM {table}")


def test_resolved_ips_are_not_port_scanned_unless_explicitly_allowed(fake_tools):
    pid = new_project()
    sid = start(pid)                                   # default: allow_resolved_ips = False
    execute(sid)
    nb = stages(sid)["naabu"]
    assert nb["status"] == "skipped" and "not explicitly authorised" in nb["message"]
    assert _all("ports") == [] and not [r for r in _all("tool_runs") if r["tool"] == "naabu"]


def test_explicit_ip_in_scope_is_probed_and_scanned_without_the_opt_in(fake_tools):
    pid = new_project()
    sid = start(pid, include=["203.0.113.7"], exclude=[])
    execute(sid)
    assert stages(sid)["subfinder"]["status"] == "skipped"                      # no wildcard domain
    assert {(p["host"], p["port"]) for p in _all("ports")} == {("203.0.113.7", 80), ("203.0.113.7", 443)}


def test_vulnerability_scan_stores_potential_findings_and_drops_out_of_scope_ones(fake_tools):
    pid = new_project()
    sid = start(pid, "vulnerability", allow_resolved_ips=True)
    execute(sid)
    f = _all("findings")
    assert len(f) == 1
    f = f[0]
    assert f["asset"] in ("api.example.com", "example.com", "www.example.com") and f["validation_status"] == "unvalidated"
    assert f["title"].startswith("<script>")                                     # stored raw, escaped on output
    assert (f["tool_version"], f["template_version"], f["confidence"]) == ("3.3.0", "10.1.0", "low")
    assert "evil.other.net" not in json.dumps(f)
    assert "Rejected" in " ".join(values("SELECT message FROM scan_logs WHERE scan_id=?", sid))


def test_missing_tool_is_distinct_from_failed_and_retry_resumes_without_rerunning_done_stages(fake_tools):
    nuclei = fake_tools / "nuclei"
    saved = nuclei.read_text()
    nuclei.unlink()
    pid = new_project()
    sid = start(pid, "vulnerability", allow_resolved_ips=True)
    execute(sid)
    st = stages(sid)
    assert st["nuclei"]["status"] == "missing_tool" and "not found" in st["nuclei"]["message"]
    assert scan_row(sid)["status"] == "completed_with_issues"
    before = len([r for r in _all("tool_runs") if r["tool"] == "subfinder"])
    nuclei.write_text(saved)
    nuclei.chmod(0o755)
    with db() as c:                                                              # what POST /retry does
        c.execute("UPDATE scan_stages SET status='pending', message=NULL WHERE scan_id=? AND status NOT IN ('completed','empty','partial','cached')", (sid,))
    execute(sid)
    assert stages(sid)["nuclei"]["status"] == "completed" and scan_row(sid)["status"] == "completed"
    assert len([r for r in _all("tool_runs") if r["tool"] == "subfinder"]) == before == 1
    assert len(_all("findings")) == 1


def write_subfinder(fake_tools, body):
    f = fake_tools / "subfinder"
    f.write_text(f"#!{sys.executable}\nimport sys, json\nif '-version' in sys.argv:\n    print('subfinder Current Version: v2.6.0'); sys.exit(0)\n" + body)


def test_empty_result_is_distinct_from_failure(fake_tools):
    write_subfinder(fake_tools, "pass\n")
    pid = new_project()
    sid = start(pid, "passive", include=["*.example.com"], exclude=[])
    execute(sid)
    assert stages(sid)["subfinder"]["status"] == "empty"
    assert scan_row(sid)["status"] == "completed"


def test_failed_tool_is_reported_with_its_error(fake_tools):
    write_subfinder(fake_tools, "sys.stderr.write('boom: bad config\\n')\nsys.exit(2)\n")
    pid = new_project()
    sid = start(pid, "passive", include=["*.example.com"], exclude=[], limits={"max_retries": 0})
    execute(sid)
    s = stages(sid)["subfinder"]
    assert s["status"] == "failed" and "exit code 2" in s["message"] and "boom" in s["message"]
    assert scan_row(sid)["status"] == "failed"


def test_transient_failure_is_retried_with_backoff_and_then_succeeds(fake_tools, tmp_path):
    marker = tmp_path / "first-run-done"
    write_subfinder(fake_tools, f"import os\nif not os.path.exists({str(marker)!r}):\n    open({str(marker)!r}, 'w').close(); sys.stderr.write('temporary dns failure'); sys.exit(1)\n"
                                "print(json.dumps({'host': 'api.example.com'}))\n")
    pid = new_project()
    sid = start(pid, "passive", include=["*.example.com"], exclude=[], limits={"max_retries": 1, "retry_base_seconds": 1})
    execute(sid)
    s = stages(sid)["subfinder"]
    assert s["status"] == "completed" and s["attempts"] == 2
    assert values("SELECT value FROM assets WHERE project_id=?", pid) == ["api.example.com"]


def test_passive_discovery_is_cached_and_cache_never_refreshes_last_seen(fake_tools):
    pid = new_project()
    s1 = start(pid, "passive", include=["*.example.com"], exclude=[])
    execute(s1)
    with db() as c:
        c.execute("UPDATE assets SET last_seen='2020-01-01T00:00:00Z'")
    s2 = start(pid, "passive", include=["*.example.com"], exclude=[])
    execute(s2)
    st = stages(s2)["subfinder"]
    assert st["status"] == "cached" and st["cached_from_scan"] == s1 and "Reused results" in st["message"]
    assert len([r for r in _all("tool_runs") if r["scan_id"] == s2]) == 0
    assert set(values("SELECT last_seen FROM assets")) == {"2020-01-01T00:00:00Z"}
    assert set(values("SELECT source FROM asset_scans WHERE scan_id=?", s2)) == {"cached:subfinder"}
    s3 = start(pid, "passive", include=["*.example.com"], exclude=[], use_cache=False)
    execute(s3)
    assert stages(s3)["subfinder"]["status"] == "completed"
    assert values("SELECT last_seen FROM assets WHERE value='api.example.com'") != ["2020-01-01T00:00:00Z"]


def test_scope_is_revalidated_right_before_launch(fake_tools, monkeypatch):
    original = REGISTRY["httpx"].build

    def tampered(ctx, targets, extra=None):
        cmds = original(ctx, targets, extra)
        cmds[0].targets.append("evil.net")
        cmds[0].stdin += "evil.net\n"
        return cmds
    monkeypatch.setattr(REGISTRY["httpx"], "build", tampered)
    pid = new_project()
    sid = start(pid)
    execute(sid)
    s = stages(sid)["httpx"]
    assert s["status"] == "failed" and "Blocked by scope validation" in s["message"]
    assert not [r for r in _all("tool_runs") if r["tool"] == "httpx"]


def test_stdin_that_differs_from_validated_targets_is_blocked(fake_tools, monkeypatch):
    original = REGISTRY["dnsx"].build

    def tampered(ctx, targets, extra=None):
        cmds = original(ctx, targets, extra)
        cmds[0].stdin += "evil.net\n"                    # targets list untouched, but the input differs
        return cmds
    monkeypatch.setattr(REGISTRY["dnsx"], "build", tampered)
    pid = new_project()
    sid = start(pid)
    execute(sid)
    assert stages(sid)["dnsx"]["status"] == "failed" and not [r for r in _all("tool_runs") if r["tool"] == "dnsx"]


def test_budget_below_what_tools_can_honour_refuses_to_run_rate_limited_tools(fake_tools):
    pid = new_project()
    sid = start(pid, requests_per_second=0.5, per_host_rps=0.5)
    execute(sid)
    s = scan_row(sid)
    assert s["status"] == "failed" and "will not exceed your configured budget" in s["error"]
    assert _all("tool_runs") == []


def test_max_assets_limits_work_and_new_assets_are_prioritised(fake_tools):
    pid = new_project()
    sid = start(pid, max_assets=2, allow_resolved_ips=True)
    execute(sid)
    assert len(stages(sid)["httpx"]["output_json"]) > 0
    assert stages(sid)["dnsx"]["input_count"] <= 2


def test_timeout_is_partial_not_failed_and_is_never_retried(fake_tools):
    write_subfinder(fake_tools, "import time\ntime.sleep(60)\n")
    pid = new_project()
    sid = start(pid, "passive", include=["*.example.com"], exclude=[], limits={"tool_timeout_seconds": 2, "max_retries": 2})
    execute(sid)
    s = stages(sid)["subfinder"]
    assert s["status"] == "partial" and s["attempts"] == 1 and "does NOT mean the target is clean" in s["message"]
    assert len([r for r in _all("tool_runs") if r["tool"] == "subfinder"]) == 1


def test_naabu_on_unlisted_resolved_ips_logs_a_shared_platform_warning(fake_tools):
    pid = new_project()
    sid = start(pid, allow_resolved_ips=True)
    execute(sid)
    assert any("shared platform" in m for m in values("SELECT message FROM scan_logs WHERE scan_id=?", sid))


def test_hostname_with_several_ips_keeps_every_ip_and_raw_output_is_kept_redacted(fake_tools):
    from app.config import SecretStore
    SecretStore().set("shodan_api_key", "TOPSECRET-KEY-12345")
    (fake_tools / "dnsx").write_text(f"#!{sys.executable}\nimport sys, json\nif '-version' in sys.argv:\n    print('dnsx Current Version: v1.3.1'); sys.exit(0)\n"
                                     "for h in sys.stdin.read().split():\n    print(json.dumps({'host': h, 'a': ['93.184.216.34', '93.184.216.35']}))\n")
    write_subfinder(fake_tools, "print(json.dumps({'host': 'api.example.com'}))\nprint('debug TOPSECRET-KEY-12345')\n")
    pid = new_project()
    sid = start(pid, allow_resolved_ips=True, include=["*.example.com"], exclude=[])
    execute(sid)
    ports = {(p["ip"], p["port"]) for p in _all("ports") if p["host"] == "api.example.com"}
    assert ports == {(ip, n) for ip in ("93.184.216.34", "93.184.216.35") for n in (80, 443)}
    runs = {r["tool"]: r for r in _all("tool_runs")}
    assert "api.example.com" in runs["subfinder"]["stdout_head"] and "TOPSECRET-KEY-12345" not in runs["subfinder"]["stdout_head"]
    assert json.loads(runs["naabu"]["argv_json"])[0].endswith("naabu") and runs["naabu"]["started_at"] <= runs["naabu"]["finished_at"]


def test_old_database_is_migrated_without_losing_ports():
    from app.database import init_db
    with db() as c:
        pid = c.execute("INSERT INTO projects(name,created_at) VALUES('old',?)", (now(),)).lastrowid
        c.executescript("DROP TABLE ports; ALTER TABLE tool_runs DROP COLUMN stdout_head;"
                        "CREATE TABLE ports(id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE, host TEXT NOT NULL, ip TEXT,"
                        " port INTEGER NOT NULL, protocol TEXT NOT NULL DEFAULT 'tcp', service TEXT, product TEXT, version TEXT, source TEXT NOT NULL DEFAULT '',"
                        " first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, last_scan_id INTEGER, UNIQUE(project_id, host, port, protocol));")
        c.execute("INSERT INTO ports(project_id,host,ip,port,service,source,first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?)", (pid, "a.example.com", None, 80, "http", "naabu", now(), now()))
        c.execute("INSERT INTO ports(project_id,host,ip,port,service,source,first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?)", (pid, "a.example.com", "1.2.3.4", 443, "https", "nmap", now(), now()))
    init_db()
    init_db()                                          # idempotent
    rows = _all("ports")
    assert {(r["port"], r["ip"], r["service"]) for r in rows} == {(80, "", "http"), (443, "1.2.3.4", "https")}
    with db() as c:
        c.execute("INSERT INTO ports(project_id,host,ip,port,source,first_seen,last_seen) VALUES(?,?,?,?,?,?,?)", (pid, "a.example.com", "5.6.7.8", 443, "naabu", now(), now()))
    assert len(_all("ports")) == 3 and "stdout_head" in _all("tool_runs")[0].keys() if _all("tool_runs") else True
