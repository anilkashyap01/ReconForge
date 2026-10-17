import json
import time

import pytest
from fastapi.testclient import TestClient

from app.main import app

H = {"X-ReconForge": "1"}


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def make_project(client, scope=("*.example.com",), confirmed=True, name="demo"):
    r = client.post("/api/projects", json={"name": name, "scope": list(scope), "authorization_confirmed": confirmed}, headers=H)
    return r


def wait_done(client, sid, timeout=40):
    end = time.time() + timeout
    while time.time() < end:
        s = client.get(f"/api/scans/{sid}").json()
        if s["status"] not in ("queued", "running", "paused"):
            return s
        time.sleep(0.2)
    raise AssertionError("scan did not finish")


def test_every_page_renders_without_data(client):
    for path in ("/", "/projects", "/scans", "/assets", "/findings", "/tools", "/settings"):
        r = client.get(path)
        assert r.status_code == 200 and "ReconForge" in r.text and "/static/app.js" in r.text
    assert client.get("/static/app.js").status_code == 200
    ov = client.get("/api/overview").json()
    assert ov["projects"] == 0 and ov["assets"] == 0 and ov["open_findings"] == 0 and ov["recent_scans"] == []   # real, empty values


def test_unexpected_host_header_is_rejected(client):
    assert client.get("/", headers={"host": "evil.example"}).status_code == 400
    assert client.get("/api/overview", headers={"host": "attacker.com:8000"}).status_code == 400


def test_state_changing_requests_need_the_custom_header(client):
    assert client.post("/api/projects", json={"name": "x"}).status_code == 403
    assert client.post("/api/projects", json={"name": "x"}, headers={**H, "origin": "https://evil.example"}).status_code == 403
    assert client.post("/api/projects", json={"name": "x"}, headers={**H, "origin": "http://127.0.0.1:8000"}).status_code == 200


def test_scope_requires_permission_confirmation_and_valid_entries(client):
    assert make_project(client, confirmed=False).status_code == 400
    assert client.get("/api/projects").json() == []                      # nothing half-created
    for bad in ("example.com; id", "$(whoami).com", "0.0.0.0/0"):
        assert make_project(client, scope=(bad,)).status_code == 400
    assert make_project(client).status_code == 200
    assert make_project(client).status_code == 400                       # duplicate name


def test_active_profiles_need_separate_confirmation_and_server_checks_everything(client):
    pid = make_project(client).json()["id"]
    sid_entry = client.get(f"/api/projects/{pid}").json()["scope"][0]["id"]
    base = {"scope_entry_ids": [sid_entry], "authorization_confirmed": True}
    assert client.post(f"/api/projects/{pid}/scans", json={**base, "profile": "vulnerability"}, headers=H).status_code == 400
    assert client.post(f"/api/projects/{pid}/scans", json={**base, "profile": "web"}, headers=H).status_code == 400
    assert client.post(f"/api/projects/{pid}/scans", json={**base, "authorization_confirmed": False, "profile": "passive"}, headers=H).status_code == 400
    assert client.post(f"/api/projects/{pid}/scans", json={**base, "profile": "passive", "options": {"enable_nmap": True}}, headers=H).status_code == 400
    assert client.post(f"/api/projects/{pid}/scans", json={**base, "profile": "standard", "options": {"enable_zap": True}}, headers=H).status_code == 400
    assert client.post(f"/api/projects/{pid}/scans", json={**base, "profile": "standard", "options": {"ports": "80;id"}}, headers=H).status_code == 400
    assert client.post(f"/api/projects/{pid}/scans", json={**base, "profile": "standard", "extra_exclusions": ["bad entry!"]}, headers=H).status_code == 400
    assert client.post(f"/api/projects/{pid}/scans", json={"profile": "passive", "scope_entry_ids": [], "authorization_confirmed": True}, headers=H).status_code == 400
    assert client.post(f"/api/projects/{pid}/scans", json={**base, "profile": "web", "active_testing_confirmed": True, "options": {"enable_ffuf": True, "ffuf_wordlist": "/etc/passwd"}}, headers=H).status_code == 400
    assert client.get("/api/scans").json() == []


def test_full_scan_through_api_scheduler_and_reports(client, fake_tools):
    pid = make_project(client, scope=("*.example.com", "example.com")).json()["id"]
    client.post(f"/api/projects/{pid}/scope", json={"entries": ["admin.example.com"], "excluded": True}, headers=H)
    entries = [e for e in client.get(f"/api/projects/{pid}").json()["scope"] if not e["excluded"]]
    r = client.post(f"/api/projects/{pid}/scans", headers=H, json={"profile": "vulnerability", "scope_entry_ids": [e["id"] for e in entries], "authorization_confirmed": True,
                                                                  "active_testing_confirmed": True, "options": {"allow_resolved_ips": True}})
    assert r.status_code == 200
    scan = wait_done(client, r.json()["id"])
    assert scan["status"] == "completed", scan["error"] or [s["message"] for s in scan["stages"]]
    assert scan["exclusions"] == ["admin.example.com"] and "example.com" in scan["scope"]
    assert [s["status"] for s in scan["stages"]] == ["completed"] * 5
    assets = client.get("/api/assets", params={"project_id": pid}).json()
    assert sorted(a["value"] for a in assets) == ["api.example.com", "example.com", "www.example.com"]
    assert client.get("/api/assets", params={"q": "api"}).json()[0]["value"] == "api.example.com"
    detail = client.get(f"/api/assets/{assets[0]['id']}").json()
    assert detail["dns"] and detail["ports"] and detail["endpoints"]
    findings = client.get("/api/findings", params={"severity": "high"}).json()
    assert len(findings) == 1 and findings[0]["validation_status"] == "unvalidated"
    fid = findings[0]["id"]
    assert client.get("/api/findings", params={"scan_id": scan["id"]}).json()[0]["id"] == fid
    assert client.get("/api/findings", params={"scan_id": 9999}).json() == []
    assert client.patch(f"/api/findings/{fid}", json={"validation_status": "confirmed", "analyst_notes": "reproduced by hand"}, headers=H).status_code == 200
    d = client.get(f"/api/findings/{fid}").json()
    assert d["validation_status"] == "confirmed" and d["confidence"] == "high" and d["potential"] is False
    html = client.get(f"/scans/{scan['id']}/report.html")
    assert html.status_code == 200 and "<script>alert(1)" not in html.text and "&lt;script&gt;" in html.text
    assert "default-src 'none'" in html.headers["content-security-policy"] and "Confirmed by analyst" in html.text
    j = client.get(f"/api/scans/{scan['id']}/report.json").json()
    assert j["scope"]["exclude"] == ["admin.example.com"] and j["findings"][0]["validation_status"] == "confirmed" and j["tools"]
    assert client.get("/api/scans/999/report.json").status_code == 404
    assert client.get(f"/api/overview").json()["open_findings"] == 1
    # a second scan can be compared with the first
    r2 = client.post(f"/api/projects/{pid}/scans", headers=H, json={"profile": "passive", "scope_entry_ids": [e["id"] for e in entries], "authorization_confirmed": True})
    s2 = wait_done(client, r2.json()["id"])
    cmp = client.get(f"/api/scans/{s2['id']}/compare").json()
    assert cmp["older_scan"] == scan["id"] and cmp["comparable"] is False and cmp["note"]


def test_scan_with_no_tools_installed_reports_missing_tools_not_success(client, monkeypatch):
    monkeypatch.setenv("PATH", "/nonexistent")
    pid = make_project(client).json()["id"]
    eid = client.get(f"/api/projects/{pid}").json()["scope"][0]["id"]
    sid = client.post(f"/api/projects/{pid}/scans", headers=H, json={"profile": "standard", "scope_entry_ids": [eid], "authorization_confirmed": True}).json()["id"]
    scan = wait_done(client, sid)
    assert scan["status"] == "failed"
    assert {s["name"]: s["status"] for s in scan["stages"]}["subfinder"] == "missing_tool"
    assert "not usable" in scan["stages"][0]["message"]


def test_tool_health_lists_all_tools_with_versions_or_missing(client, fake_tools):
    tools = {t["name"]: t for t in client.get("/api/tools?refresh=1").json()}
    assert len(tools) == 11 and tools["subfinder"]["installed"] and tools["subfinder"]["version"] == "2.6.0"
    assert tools["nuclei"]["template_version"] == "10.1.0"
    assert not tools["nmap"]["installed"] and tools["nmap"]["problem"] == "not found on PATH"
    assert all(t["kali_package"] and t["install_url"].startswith("https://") for t in tools.values())


def test_settings_are_clamped_and_api_keys_never_leave_the_server(client, tmp_path):
    r = client.put("/api/settings/limits", json={"limits": {"requests_per_second": 99999, "max_assets": 10}}, headers=H).json()["limits"]
    assert r["requests_per_second"] <= 50 and r["max_assets"] == 10
    assert client.put("/api/settings/limits", json={"limits": {"bogus": 1}}, headers=H).status_code == 400
    secret = "super-secret-key-abc123"
    assert client.put("/api/integrations/shodan", json={"api_key": secret, "enabled": True}, headers=H).status_code == 200
    state = client.get("/api/settings")
    assert secret not in state.text and secret not in client.get("/settings").text and secret not in client.get("/static/app.js").text
    shodan = [i for i in state.json()["integrations"] if i["name"] == "shodan"][0]
    assert shodan["configured"] and shodan["enabled"]
    path = tmp_path / "data" / "secrets.json"
    assert oct(path.stat().st_mode & 0o777) == "0o600" and secret in path.read_text()
    assert client.put("/api/integrations/shodan", json={"api_key": ""}, headers=H).json()["configured"] is False
    assert client.put("/api/integrations/nope", json={"enabled": True}, headers=H).status_code == 404


def test_scan_runs_endpoint_exposes_exact_commands_and_output(client, fake_tools):
    pid = make_project(client).json()["id"]
    eid = client.get(f"/api/projects/{pid}").json()["scope"][0]["id"]
    sid = client.post(f"/api/projects/{pid}/scans", headers=H, json={"profile": "passive", "scope_entry_ids": [eid], "authorization_confirmed": True}).json()["id"]
    wait_done(client, sid)
    runs = client.get(f"/api/scans/{sid}/runs").json()
    assert runs[0]["tool"] == "subfinder" and runs[0]["argv"][0].endswith("subfinder") and "-d" in runs[0]["argv"]
    assert "api.example.com" in runs[0]["stdout_head"] and runs[0]["exit_code"] == 0
    assert client.get("/api/scans/9999/runs").status_code == 404
