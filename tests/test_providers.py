import asyncio
import json
import urllib.error
import urllib.request

import pytest

from app.config import SecretStore
from app.database import db, now, q
from app.rate_limiter import TokenBucket
from app.services import providers

KEY = "KEY-123456-secret"


@pytest.fixture(autouse=True)
def fast_buckets(monkeypatch):
    monkeypatch.setattr(providers, "_bucket", lambda name: TokenBucket(1000, 1000))


@pytest.fixture
def calls(monkeypatch):
    seen = []
    script = {"responses": []}

    def fake(url, headers, timeout=20.0):
        seen.append((url, headers))
        status, hdrs, body = script["responses"].pop(0) if script["responses"] else (200, {}, {})
        return status, hdrs, json.dumps(body).encode()
    monkeypatch.setattr(providers, "_fetch", fake)
    seen_holder = type("Calls", (list,), {})(seen)
    seen_holder.script = script
    seen_holder._real = seen
    return seen_holder


def n(calls):
    return len(calls._real)


def configure(name="shodan", enabled=True):
    SecretStore().set(providers.PROVIDERS[name]["secrets"][0], KEY)
    with db() as c:
        c.execute("INSERT OR REPLACE INTO integrations(name,enabled) VALUES(?,?)", (name, int(enabled)))


def project():
    with db() as c:
        return c.execute("INSERT INTO projects(name,created_at) VALUES('p',?)", (now(),)).lastrowid


def test_nothing_is_configured_or_enabled_by_default():
    assert all(not s["configured"] and not s["enabled"] for s in providers.state())


def test_shodan_credential_test_records_provider_reported_usage_only(calls):
    configure()
    calls.script["responses"].append((200, {}, {"plan": "dev", "query_credits": 100, "scan_credits": 5, "other": "ignored"}))
    r = asyncio.run(providers.test("shodan"))
    assert r["ok"] and r["usage"] == {"plan": "dev", "scan_credits": 5, "query_credits": 100}
    s = [x for x in providers.state() if x["name"] == "shodan"][0]
    assert s["last_success"] and s["usage"]["plan"] == "dev" and s["last_error"] is None


def test_urlscan_usage_comes_from_rate_limit_headers_not_hardcoded_quotas(calls):
    configure("urlscan")
    calls.script["responses"].append((200, {"x-rate-limit-remaining": "41", "x-rate-limit-limit": "60", "content-type": "x"}, {"results": []}))
    r = asyncio.run(providers.test("urlscan"))
    assert r["usage"] == {"x-rate-limit-remaining": "41", "x-rate-limit-limit": "60"}


def test_rate_limit_response_triggers_backoff_and_never_rotates_or_retries(calls):
    configure()
    calls.script["responses"].append((429, {"retry-after": "120"}, {"error": "slow down"}))
    pid = project()
    ok, msgs, errs = asyncio.run(providers.enrich(pid, 1, [], ["203.0.113.5", "203.0.113.6", "203.0.113.7"], asyncio.Event()))
    assert ok == 0 and n(calls) == 1 and any("backing off" in e for e in errs)
    s = [x for x in providers.state() if x["name"] == "shodan"][0]
    assert s["backoff_until"] and "quota or rate limit" in s["last_error"]
    ok2, _, errs2 = asyncio.run(providers.enrich(pid, 1, [], ["203.0.113.5"], asyncio.Event()))
    assert n(calls) == 1 and ok2 == 0 and errs2                       # still backing off: no request sent at all


def test_rejected_credentials_stop_further_lookups(calls):
    configure()
    calls.script["responses"].append((401, {}, {"error": "Invalid API key"}))
    _, _, errs = asyncio.run(providers.enrich(project(), 1, [], ["203.0.113.5", "203.0.113.6"], asyncio.Event()))
    assert n(calls) == 1 and "credential rejected" in errs[0]


def test_disabled_providers_send_nothing(calls):
    configure(enabled=False)
    ok, msgs, errs = asyncio.run(providers.enrich(project(), 1, ["a.example.com"], ["203.0.113.5"], asyncio.Event()))
    assert ok == 0 and n(calls) == 0 and len(msgs) == 2


def test_only_supplied_subjects_are_looked_up_and_results_are_stored_as_reported(calls):
    configure()
    configure("urlscan")
    calls.script["responses"] += [(200, {}, {"ip_str": "203.0.113.5", "ports": [80], "org": "Example"}),
                                  (200, {}, {"results": [{"page": {"url": "https://a.example.com/", "ip": "203.0.113.5"}, "task": {"time": "t"}, "result": "https://urlscan.io/r"}], "total": 1})]
    pid = project()
    ok, _, errs = asyncio.run(providers.enrich(pid, 7, ["a.example.com"], ["203.0.113.5"], asyncio.Event()))
    assert ok == 2 and not errs and n(calls) == 2
    assert "203.0.113.5" in calls._real[0][0] and "domain%3Aa.example.com" in calls._real[1][0]
    with db() as c:
        rows = {r["provider"]: json.loads(r["payload_json"]) for r in q(c, "SELECT * FROM integration_results")}
    assert rows["shodan"]["ports"] == [80] and rows["urlscan"]["results"][0]["url"] == "https://a.example.com/"


def test_lookups_per_provider_are_capped(calls):
    configure()
    ips = [f"203.0.113.{i}" for i in range(1, 60)]
    asyncio.run(providers.enrich(project(), 1, [], ips, asyncio.Event()))
    assert n(calls) == providers.MAX_LOOKUPS_PER_PROVIDER


def test_network_errors_never_leak_the_api_key(monkeypatch):
    configure()

    def boom(req, timeout=None):
        raise urllib.error.URLError(f"cannot reach {req.full_url}")
    monkeypatch.setattr(urllib.request, "urlopen", boom)
    r = asyncio.run(providers.test("shodan"))
    assert not r["ok"] and KEY not in r["error"]
    assert all(KEY not in json.dumps(s) for s in providers.state())
