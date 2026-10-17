import json

from app.database import db, now, q, q1
from app.models import FindingRecord
from app.services import reports, store


def project(c):
    pid = c.execute("INSERT INTO projects(name,created_at) VALUES('p',?)", (now(),)).lastrowid
    return pid


def scan(c, pid, profile="vulnerability"):
    return c.execute("INSERT INTO scans(project_id,profile,status,config_json,scope_json,exclusions_json,created_at) VALUES(?,?,?,?,?,?,?)",
                     (pid, profile, "completed", json.dumps({"options": {}, "limits": {"requests_per_second": 2.0}}), json.dumps(["*.example.com"]), "[]", now())).lastrowid


def rec(**kw):
    base = dict(title="Panel", asset="a.example.com", source="nuclei", template_id="t1", severity="high", url="https://a.example.com/p", evidence="e")
    base.update(kw)
    return FindingRecord(**base)


def test_assets_are_deduplicated_and_first_seen_is_kept():
    with db() as c:
        pid = project(c)
        s1, s2 = scan(c, pid), scan(c, pid)
        a1, new1 = store.upsert_asset(c, pid, "domain", "a.example.com", "subfinder", s1)
        c.execute("UPDATE assets SET first_seen='2020-01-01T00:00:00Z', last_seen='2020-01-01T00:00:00Z' WHERE id=?", (a1,))
        a2, new2 = store.upsert_asset(c, pid, "domain", "a.example.com", "dnsx", s2)
        row = q1(c, "SELECT * FROM assets WHERE id=?", (a1,))
        assert (a1, new1, new2) == (a2, True, False)
        assert q1(c, "SELECT COUNT(*) n FROM assets")["n"] == 1
        assert row["first_seen"] == "2020-01-01T00:00:00Z" and row["last_seen"] != row["first_seen"]
        assert row["first_scan_id"] == s1 and row["last_scan_id"] == s2 and row["sources"] == "dnsx,subfinder"


def test_cached_results_never_refresh_last_seen():
    with db() as c:
        pid = project(c)
        s1, s2 = scan(c, pid), scan(c, pid)
        aid, _ = store.upsert_asset(c, pid, "domain", "a.example.com", "subfinder", s1)
        c.execute("UPDATE assets SET last_seen='2020-01-01T00:00:00Z' WHERE id=?", (aid,))
        store.upsert_asset(c, pid, "domain", "a.example.com", "subfinder", s2, cached=True)
        assert q1(c, "SELECT last_seen FROM assets WHERE id=?", (aid,))["last_seen"] == "2020-01-01T00:00:00Z"
        assert q1(c, "SELECT source FROM asset_scans WHERE scan_id=?", (s2,))["source"] == "cached:subfinder"


def test_findings_dedupe_across_scans_and_keep_analyst_state():
    with db() as c:
        pid = project(c)
        s1, s2 = scan(c, pid), scan(c, pid)
        f1, new1 = store.upsert_finding(c, pid, rec(), s1, "3.0")
        c.execute("UPDATE findings SET validation_status='confirmed', analyst_notes='checked manually' WHERE id=?", (f1,))
        f2, new2 = store.upsert_finding(c, pid, rec(evidence="newer"), s2, "3.1")
        row = q1(c, "SELECT * FROM findings WHERE id=?", (f1,))
        assert (f1, new1, new2) == (f2, True, False) and q1(c, "SELECT COUNT(*) n FROM findings")["n"] == 1
        assert row["validation_status"] == "confirmed" and row["analyst_notes"] == "checked manually"
        assert (row["first_scan_id"], row["last_scan_id"], row["evidence"], row["tool_version"]) == (s1, s2, "newer", "3.1")
        assert q1(c, "SELECT COUNT(*) n FROM finding_scans")["n"] == 2


def test_different_matcher_or_url_is_a_different_finding_and_fixed_findings_reopen():
    with db() as c:
        pid = project(c)
        s1, s2 = scan(c, pid), scan(c, pid)
        a, _ = store.upsert_finding(c, pid, rec(), s1, None)
        b, nb = store.upsert_finding(c, pid, rec(url="https://a.example.com/other"), s1, None)
        assert a != b and nb
        c.execute("UPDATE findings SET validation_status='fixed' WHERE id=?", (a,))
        store.upsert_finding(c, pid, rec(), s2, None)
        row = q1(c, "SELECT validation_status, analyst_notes FROM findings WHERE id=?", (a,))
        assert row["validation_status"] == "unvalidated" and "Re-detected" in row["analyst_notes"]


def test_scan_comparison_reports_new_and_disappeared():
    with db() as c:
        pid = project(c)
        s1, s2 = scan(c, pid), scan(c, pid)
        store.upsert_asset(c, pid, "domain", "old.example.com", "x", s1)
        store.upsert_asset(c, pid, "domain", "both.example.com", "x", s1)
        store.upsert_asset(c, pid, "domain", "both.example.com", "x", s2)
        store.upsert_asset(c, pid, "domain", "new.example.com", "x", s2)
        store.upsert_finding(c, pid, rec(), s2, None)
        d = store.compare_scans(c, s1, s2)
    assert [a["value"] for a in d["assets_new"]] == ["new.example.com"]
    assert [a["value"] for a in d["assets_disappeared"]] == ["old.example.com"]
    assert d["assets_unchanged"] == 1 and len(d["findings_new"]) == 1 and d["comparable"]


def test_report_contains_required_sections_and_distinguishes_detections_from_validation():
    with db() as c:
        pid = project(c)
        sid = scan(c, pid)
        store.upsert_asset(c, pid, "domain", "a.example.com", "subfinder", sid)
        store.upsert_finding(c, pid, rec(), sid, "3.3.0")
        c.execute("INSERT INTO scan_stages(scan_id,position,name,tool,label,status,message) VALUES(?,?,?,?,?,?,?)", (sid, 0, "nuclei", "nuclei", "Vulnerability checks", "failed", "boom"))
        c.execute("INSERT INTO tool_runs(scan_id,stage_name,tool,version,argv_json,started_at,status) VALUES(?,?,?,?,?,?,?)", (sid, "nuclei", "nuclei", "3.3.0", "[]", now(), "completed"))
    rep = reports.build_report(sid)
    assert rep["scope"]["include"] == ["*.example.com"] and rep["limits"]["requests_per_second"] == 2.0
    assert rep["tools"] == [{"tool": "nuclei", "version": "3.3.0"}]
    assert rep["failed_or_incomplete_stages"][0]["name"] == "nuclei"
    assert rep["findings"][0]["label"].startswith("Potential finding")
    assert "not proof" in rep["statement"] and rep["assets"][0]["value"] == "a.example.com"


def test_html_report_escapes_untrusted_content_and_files_are_private():
    evil = "<script>alert(1)</script>"
    with db() as c:
        pid = project(c)
        sid = scan(c, pid)
        store.upsert_finding(c, pid, rec(title=evil, evidence=evil, asset="a.example.com"), sid, None)
        c.execute("UPDATE findings SET analyst_notes=?", (evil,))
    paths = reports.write_reports(sid)
    html = paths["html"].read_text()
    assert evil not in html and "&lt;script&gt;" in html
    assert json.loads(paths["json"].read_text())["findings"][0]["title"] == evil     # JSON keeps the raw value
    assert oct(paths["html"].stat().st_mode & 0o777) == "0o600"
