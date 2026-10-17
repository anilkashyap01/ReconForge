"""Optional third-party intelligence providers (Shodan, urlscan.io). Documented endpoints only; opt-in; read-only lookups.

Only in-scope hostnames/IP addresses are ever sent. Nothing is submitted for scanning, and no evidence leaves the machine.
Keys are read from the local secret store and never reach templates, reports, logs or the browser.
"""
from __future__ import annotations

import asyncio
import json
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any

from ..config import SecretStore, redact
from ..database import db, now, parse_ts, q, q1
from ..rate_limiter import TokenBucket, parse_retry_after

PROVIDERS: dict[str, dict[str, Any]] = {
    "shodan": {"label": "Shodan", "secrets": ["shodan_api_key"], "docs": "https://developer.shodan.io/api",
               "sends": "IP addresses (host lookup)"},
    "urlscan": {"label": "urlscan.io", "secrets": ["urlscan_api_key"], "docs": "https://urlscan.io/docs/api/",
                "sends": "hostnames (search of existing public scans; nothing is submitted for scanning)"},
}
_buckets: dict[str, TokenBucket] = {}
MAX_LOOKUPS_PER_PROVIDER = 25


class ProviderError(Exception):
    pass


class ProviderBackoff(ProviderError):
    pass


def _bucket(name: str) -> TokenBucket:
    return _buckets.setdefault(name, TokenBucket(1.0, 1.0))


def _fetch(url: str, headers: dict[str, str], timeout: float = 20.0) -> tuple[int, dict[str, str], bytes]:
    req = urllib.request.Request(url, headers={"User-Agent": "ReconForge/1.0", **headers})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:   # noqa: S310 (https URLs built below)
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read(2_000_000)
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read(200_000)
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise ProviderError(redact(f"network error: {e}")) from e


def _set_state(name: str, **fields: Any) -> None:
    with db() as c:
        c.execute("INSERT OR IGNORE INTO integrations(name) VALUES(?)", (name,))
        sets = ", ".join(f"{k}=?" for k in fields) + ", updated_at=?"
        c.execute(f"UPDATE integrations SET {sets} WHERE name=?", (*fields.values(), now(), name))


def _key(name: str) -> str:
    key = SecretStore().get(PROVIDERS[name]["secrets"][0])
    if not key:
        raise ProviderError("no API key configured")
    return key


async def _call(name: str, url_for_key, headers_for_key) -> tuple[int, dict[str, str], Any]:
    with db() as c:
        row = q1(c, "SELECT backoff_until FROM integrations WHERE name=?", (name,))
    until = parse_ts(row["backoff_until"]) if row else None
    if until and until > datetime.now(timezone.utc):
        raise ProviderBackoff(f"backing off until {row['backoff_until']}")
    key = _key(name)
    await _bucket(name).acquire()
    status, headers, body = await asyncio.to_thread(_fetch, url_for_key(key), headers_for_key(key))
    if status in (429, 503) or (status == 402):
        delay = parse_retry_after(headers.get("retry-after")) or 60.0
        _bucket(name).penalize(delay)
        until_s = (datetime.now(timezone.utc) + timedelta(seconds=delay)).strftime("%Y-%m-%dT%H:%M:%SZ")
        _set_state(name, backoff_until=until_s, last_error=f"HTTP {status}: quota or rate limit reached")
        raise ProviderBackoff(f"HTTP {status}; backing off {int(delay)}s (no key rotation is attempted)")
    if status in (401, 403):
        _set_state(name, last_error=f"HTTP {status}: credential rejected")
        raise ProviderError(f"HTTP {status}: credential rejected")
    try:
        data = json.loads(body.decode("utf-8", "replace")) if body else {}
    except json.JSONDecodeError:
        data = {}
    return status, headers, data


def _usage(headers: dict[str, str]) -> dict[str, str]:
    return {k: v for k, v in headers.items() if k.startswith("x-rate-limit")}


async def test(name: str) -> dict[str, Any]:
    """Credential/usage check. Shodan: documented /api-info. urlscan: one small search; rate-limit headers are recorded."""
    try:
        if name == "shodan":
            status, h, d = await _call(name, lambda k: "https://api.shodan.io/api-info?" + urllib.parse.urlencode({"key": k}), lambda k: {})
            if status != 200:
                raise ProviderError(f"HTTP {status}")
            usage = {k: d.get(k) for k in ("plan", "scan_credits", "query_credits") if k in d}
        else:
            status, h, d = await _call(name, lambda k: "https://urlscan.io/api/v1/search/?q=domain%3Aexample.com&size=1", lambda k: {"API-Key": k})
            if status != 200:
                raise ProviderError(f"HTTP {status}")
            usage = _usage(h)
        _set_state(name, last_success=now(), last_error=None, backoff_until=None, usage_json=json.dumps(usage))
        return {"ok": True, "usage": usage}
    except ProviderError as e:
        _set_state(name, last_error=redact(str(e)))
        return {"ok": False, "error": redact(str(e))}


def state() -> list[dict[str, Any]]:
    store = SecretStore()
    with db() as c:
        rows = {r["name"]: r for r in q(c, "SELECT * FROM integrations")}
    out = []
    for n, meta in PROVIDERS.items():
        r = rows.get(n, {})
        out.append({"name": n, "label": meta["label"], "docs": meta["docs"], "sends": meta["sends"],
                    "configured": all(store.configured(s) for s in meta["secrets"]), "enabled": bool(r.get("enabled")),
                    "last_success": r.get("last_success"), "last_error": r.get("last_error"), "backoff_until": r.get("backoff_until"),
                    "usage": json.loads(r.get("usage_json") or "{}")})
    return out


def ready(name: str) -> bool:
    s = next(x for x in state() if x["name"] == name)
    return s["configured"] and s["enabled"]


async def enrich(pid: int, scan_id: int, hostnames: list[str], ips: list[str], cancel: asyncio.Event) -> tuple[int, list[str], list[str]]:
    """Returns (successful lookups, informational messages, errors)."""
    ok, msgs, errs = 0, [], []
    plans = {"shodan": ips, "urlscan": hostnames}
    for name, subjects in plans.items():
        if not ready(name):
            msgs.append(f"{PROVIDERS[name]['label']}: skipped (not configured and enabled)")
            continue
        for subject in subjects[:MAX_LOOKUPS_PER_PROVIDER]:
            if cancel.is_set():
                return ok, msgs, errs
            try:
                if name == "shodan":
                    status, h, d = await _call(name, lambda k, s=subject: f"https://api.shodan.io/shodan/host/{urllib.parse.quote(s, safe='')}?" + urllib.parse.urlencode({"key": k}), lambda k: {})
                    payload = {} if status == 404 else {k: d.get(k) for k in ("ip_str", "org", "isp", "os", "ports", "hostnames", "domains", "last_update", "vulns")}
                else:
                    status, h, d = await _call(name, lambda k, s=subject: "https://urlscan.io/api/v1/search/?" + urllib.parse.urlencode({"q": f"domain:{s}", "size": 20}), lambda k: {"API-Key": k})
                    payload = {"results": [{"url": (r.get("page") or {}).get("url"), "ip": (r.get("page") or {}).get("ip"),
                                            "server": (r.get("page") or {}).get("server"), "time": (r.get("task") or {}).get("time"),
                                            "result": r.get("result")} for r in d.get("results", [])[:20]], "total": d.get("total")}
                    _set_state(name, usage_json=json.dumps(_usage(h)))
                if status not in (200, 404):
                    raise ProviderError(f"HTTP {status}")
                with db() as c:
                    c.execute("INSERT INTO integration_results(project_id,scan_id,provider,subject,payload_json,fetched_at) VALUES(?,?,?,?,?,?)"
                              " ON CONFLICT(project_id,provider,subject) DO UPDATE SET payload_json=excluded.payload_json,"
                              "fetched_at=excluded.fetched_at,scan_id=excluded.scan_id", (pid, scan_id, name, subject, json.dumps(payload), now()))
                _set_state(name, last_success=now(), last_error=None)
                ok += 1
            except ProviderBackoff as e:
                errs.append(f"{PROVIDERS[name]['label']}: {e}")
                break
            except ProviderError as e:
                errs.append(f"{PROVIDERS[name]['label']} {subject}: {e}")
                _set_state(name, last_error=redact(str(e)))
                if "credential" in str(e):
                    break
    return ok, msgs, errs
