"""Optional third-party asset-intelligence providers (Shodan, urlscan.io, Censys Platform).

* Disabled by default; a provider needs both `enabled` and a configured credential.
* Only lookups (reads) are implemented. Nothing is ever submitted for scanning and no evidence is uploaded.
* Keys are sent in headers where the provider allows it and are redacted from every stored error.
* HTTP 429/503 + Retry-After put the provider into a visible backoff window.
"""
from __future__ import annotations

import asyncio
import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from ..config import SecretStore, redact
from ..database import db, now, parse_ts, q1
from ..models import EndpointRecord, ParseResult
from ..rate_limiter import TokenBucket, parse_retry_after
from ..scope import Scope
from ..adapters.base import host_of


class ProviderError(Exception):
    pass


class RateLimited(ProviderError):
    def __init__(self, delay: float) -> None:
        super().__init__(f"rate limited by provider; backing off for {delay:.0f}s")
        self.delay = delay


@dataclass
class HttpResult:
    status: int
    headers: dict[str, str]
    body: Any
    text: str


def _fetch(url: str, headers: dict[str, str], timeout: float = 20.0) -> HttpResult:
    req = urllib.request.Request(url, headers={"User-Agent": "ReconForge/1.0", **headers})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:       # noqa: S310 (https URLs built from constants)
            raw, status, hdrs = resp.read(2_000_000), resp.status, dict(resp.headers.items())
    except urllib.error.HTTPError as exc:
        raw, status, hdrs = exc.read(200_000), exc.code, dict(exc.headers.items())
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ProviderError(f"network error: {type(exc).__name__}") from None   # never echo the URL (may hold a key)
    text = raw.decode("utf-8", "replace")
    try:
        body = json.loads(text)
    except json.JSONDecodeError:
        body = None
    return HttpResult(status, {k.lower(): v for k, v in hdrs.items()}, body, text)


async def http_get(url: str, headers: dict[str, str] | None = None) -> HttpResult:
    return await asyncio.to_thread(_fetch, url, headers or {})


def _check(res: HttpResult, allow_404: bool = False) -> None:
    if res.status in (429, 503):
        raise RateLimited(parse_retry_after(res.headers.get("retry-after")) or 60.0)
    if res.status in (401, 403):
        raise ProviderError(f"credential rejected or plan does not include this endpoint (HTTP {res.status})")
    if res.status == 404 and allow_404:
        return
    if not 200 <= res.status < 300:
        raise ProviderError(f"unexpected HTTP {res.status}")


class Provider:
    name = ""
    label = ""
    docs_url = ""
    secret_names: tuple[str, ...] = ()
    min_interval = 1.0
    has_usage = False

    def __init__(self) -> None:
        self.secrets = SecretStore()
        self.bucket = TokenBucket(1.0 / self.min_interval, capacity=1.0)

    @property
    def credential_configured(self) -> bool:
        return bool(self.secrets.get(self.secret_names[0]))

    async def usage(self) -> dict[str, Any]:
        raise ProviderError("this provider has no usage endpoint in the adapter")

    async def lookup_ip(self, ip: str) -> dict[str, Any]:
        raise ProviderError("IP lookup not supported")

    async def search_domain(self, domain: str) -> dict[str, Any]:
        raise ProviderError("domain search not supported")


class Shodan(Provider):
    name, label, docs_url = "shodan", "Shodan", "https://developer.shodan.io/api"
    secret_names, min_interval, has_usage = ("shodan_api_key",), 1.0, True
    base = "https://api.shodan.io"

    def _key(self) -> str:
        return urllib.parse.quote(self.secrets.get("shodan_api_key") or "")

    async def usage(self) -> dict[str, Any]:
        res = await http_get(f"{self.base}/api-info?key={self._key()}")
        _check(res)
        b = res.body or {}
        return {k: b.get(k) for k in ("plan", "query_credits", "scan_credits", "monitored_ips") if k in b}

    async def lookup_ip(self, ip: str) -> dict[str, Any]:
        res = await http_get(f"{self.base}/shodan/host/{urllib.parse.quote(ip)}?key={self._key()}")
        _check(res, allow_404=True)
        if res.status == 404:
            return {"found": False}
        b = res.body or {}
        return {"found": True, "ports": b.get("ports", []), "hostnames": b.get("hostnames", []), "org": b.get("org"),
                "os": b.get("os"), "last_update": b.get("last_update"),
                "services": [{"port": d.get("port"), "product": d.get("product"), "version": d.get("version")}
                             for d in (b.get("data") or [])[:30]]}


class Urlscan(Provider):
    name, label, docs_url = "urlscan", "urlscan.io", "https://urlscan.io/docs/api/"
    secret_names, min_interval, has_usage = ("urlscan_api_key",), 2.0, True
    base = "https://urlscan.io/api/v1"

    def _headers(self) -> dict[str, str]:
        key = self.secrets.get("urlscan_api_key")
        return {"API-Key": key} if key else {}

    async def usage(self) -> dict[str, Any]:
        res = await http_get(f"{self.base}/quotas", self._headers())
        _check(res)
        return res.body if isinstance(res.body, dict) else {}

    async def search_domain(self, domain: str) -> dict[str, Any]:
        q = urllib.parse.quote(f"domain:{domain}")
        res = await http_get(f"{self.base}/search/?q={q}&size=100", self._headers())
        _check(res)
        results = (res.body or {}).get("results", [])
        rate = {k: v for k, v in res.headers.items() if k.startswith("x-rate-limit")}
        return {"total": (res.body or {}).get("total"), "rate_headers": rate,
                "pages": [{"url": (r.get("page") or {}).get("url"), "domain": (r.get("page") or {}).get("domain"),
                           "ip": (r.get("page") or {}).get("ip"), "time": (r.get("task") or {}).get("time")} for r in results]}


class Censys(Provider):
    name, label, docs_url = "censys", "Censys Platform", "https://docs.censys.com/reference/get-started"
    secret_names, min_interval = ("censys_api_key", "censys_org_id"), 2.0
    base = "https://api.platform.censys.io/v3/global/asset/host"

    async def lookup_ip(self, ip: str) -> dict[str, Any]:
        org = self.secrets.get("censys_org_id")
        url = f"{self.base}/{urllib.parse.quote(ip)}" + (f"?organization_id={urllib.parse.quote(org)}" if org else "")
        res = await http_get(url, {"Authorization": f"Bearer {self.secrets.get('censys_api_key')}",
                                   "Accept": "application/vnd.censys.api.v3.host.v1+json"})
        _check(res, allow_404=True)
        if res.status == 404:
            return {"found": False}
        resource = ((res.body or {}).get("result") or {}).get("resource") or {}
        services = resource.get("services") or []
        return {"found": True, "ports": sorted({s.get("port") for s in services if isinstance(s, dict) and s.get("port")}),
                "raw_keys": sorted(resource)[:20]}


PROVIDERS: dict[str, type[Provider]] = {c.name: c for c in (Shodan, Urlscan, Censys)}


def provider_rows() -> list[dict[str, Any]]:
    out = []
    with db() as conn:
        for name, cls in PROVIDERS.items():
            p = cls()
            st = q1(conn, "SELECT * FROM integrations WHERE name=?", (name,)) or {}
            backoff = parse_ts(st.get("backoff_until"))
            out.append({"name": name, "label": p.label, "docs_url": p.docs_url, "has_usage": p.has_usage,
                        "credential_configured": p.credential_configured, "enabled": bool(st.get("enabled")),
                        "last_success": st.get("last_success"), "last_error": st.get("last_error"),
                        "backoff_active": bool(backoff and backoff > datetime.now(timezone.utc)),
                        "backoff_until": st.get("backoff_until"), "usage": json.loads(st.get("usage_json") or "{}"),
                        "needs_org": name == "censys", "org_configured": p.secrets.configured("censys_org_id")})
    return out


def set_enabled(name: str, enabled: bool) -> None:
    with db() as conn:
        conn.execute("""INSERT INTO integrations(name,enabled,updated_at) VALUES(?,?,?)
                        ON CONFLICT(name) DO UPDATE SET enabled=excluded.enabled, updated_at=excluded.updated_at""", (name, int(enabled), now()))


async def guarded(name: str, fn, *args) -> Any:
    """Run one provider call with enablement, backoff, pacing and redacted error recording."""
    p = PROVIDERS[name]()
    with db() as conn:
        st = q1(conn, "SELECT * FROM integrations WHERE name=?", (name,)) or {}
    if not st.get("enabled"):
        raise ProviderError("integration is not enabled")
    if not p.credential_configured and name != "urlscan":
        raise ProviderError("no credential configured")
    backoff = parse_ts(st.get("backoff_until"))
    if backoff and backoff > datetime.now(timezone.utc):
        raise ProviderError(f"in backoff until {st['backoff_until']}")
    await p.bucket.acquire()
    try:
        result = await getattr(p, fn)(*args)
    except RateLimited as exc:
        until = (datetime.now(timezone.utc) + timedelta(seconds=exc.delay)).strftime("%Y-%m-%dT%H:%M:%SZ")
        with db() as conn:
            conn.execute("UPDATE integrations SET last_error=?, backoff_until=?, updated_at=? WHERE name=?", (str(exc), until, now(), name))
        raise
    except ProviderError as exc:
        with db() as conn:
            conn.execute("UPDATE integrations SET last_error=?, updated_at=? WHERE name=?", (redact(str(exc)), now(), name))
        raise
    with db() as conn:
        conn.execute("UPDATE integrations SET last_success=?, last_error=NULL, backoff_until=NULL, updated_at=? WHERE name=?", (now(), now(), name))
    return result


async def test_provider(name: str) -> dict[str, Any]:
    p = PROVIDERS[name]()
    if not p.has_usage:
        raise ProviderError("this provider has no documented usage endpoint to test with; run a scan with enrichment to verify")
    usage = await guarded(name, "usage")
    with db() as conn:
        conn.execute("UPDATE integrations SET usage_json=? WHERE name=?", (json.dumps(usage), name))
    return usage


async def enrich(project_id: int, scan_id: int, scope: Scope, roots: list[str], ips: list[str], log, max_lookups: int = 50) -> tuple[ParseResult, list[str]]:
    """Run enabled providers over in-scope domains/IPs only. Returns discoveries and per-provider status lines."""
    res, status = ParseResult(), []
    rows = {r["name"]: r for r in provider_rows()}
    lookups = 0
    for name in PROVIDERS:
        row = rows[name]
        if not (row["enabled"] and (row["credential_configured"] or name == "urlscan")):
            continue
        try:
            if name == "urlscan":
                for d in roots[:10]:
                    data = await guarded(name, "search_domain", d)
                    lookups += 1
                    for pg in data["pages"]:
                        if pg.get("domain") and scope.host_allowed(pg["domain"])[0]:
                            res.hosts.append((pg["domain"].lower(), "urlscan"))
                        if pg.get("url") and scope.url_allowed(pg["url"])[0]:
                            res.endpoints.append(EndpointRecord(url=pg["url"], host=host_of(pg["url"]), kind="historical", source="urlscan"))
                    _store(project_id, scan_id, name, d, data)
                status.append(f"urlscan: searched {min(len(roots), 10)} domain(s)")
            else:
                n = 0
                for ip in ips[:max_lookups]:
                    if not scope.ip_scannable(ip, True)[0] and not scope.ip_allowed(ip)[0]:
                        continue
                    data = await guarded(name, "lookup_ip", ip)
                    _store(project_id, scan_id, name, ip, data)
                    n += 1
                status.append(f"{name}: looked up {n} IP(s)")
        except ProviderError as exc:
            status.append(f"{name}: {redact(str(exc))}")
            log("warning", f"integration {name}: {redact(str(exc))}")
    res.output = {"hosts": sorted({h for h, _ in res.hosts})}
    return res, status


def _store(project_id: int, scan_id: int, provider: str, subject: str, payload: dict) -> None:
    with db() as conn:
        conn.execute("""INSERT INTO integration_results(project_id,scan_id,provider,subject,payload_json,fetched_at) VALUES(?,?,?,?,?,?)
                        ON CONFLICT(project_id,provider,subject) DO UPDATE SET payload_json=excluded.payload_json, scan_id=excluded.scan_id, fetched_at=excluded.fetched_at""",
                     (project_id, scan_id, provider, subject, json.dumps(payload)[:50_000], now()))
