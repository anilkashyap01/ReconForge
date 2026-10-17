"""Scope parsing and enforcement. Every scanner launch is re-validated through this module."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from urllib.parse import urlsplit


class ScopeError(ValueError):
    """Invalid scope input."""


class ScopeViolation(ScopeError):
    """A target is outside the authorised scope."""


_LABEL = r"(?!-)[a-z0-9-]{1,63}(?<!-)"
_TLD = r"(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})"
HOST_RE = re.compile(rf"^(?:{_LABEL}\.)+{_TLD}$")
FORBIDDEN_CHARS = set(" \t\r\n\0/\\@:?#;&|`$<>\"'(){}[]!*,%=+~^")
PUBLIC_SUFFIXES = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.in", "net.in", "co.jp",
                   "com.br", "com.cn", "co.nz", "co.za", "com.mx", "com.tr", "com.sg", "co.kr", "gov.in", "ac.in"}
MIN_V4_PREFIX = 16
MIN_V6_PREFIX = 48
PORT_SPEC_RE = re.compile(r"^(top100|top1000|\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*)$")
IDENT_LIST_RE = re.compile(r"^[a-z0-9_,-]{0,200}$")


@dataclass(frozen=True)
class ScopeEntry:
    kind: str    # domain | wildcard | ip | cidr
    value: str

    def display(self) -> str:
        return f"*.{self.value}" if self.kind == "wildcard" else self.value


def normalize_domain(value: str) -> str:
    v = value.strip().lower().rstrip(".")
    if not v or len(v) > 253:
        raise ScopeError(f"invalid domain: {value!r}")
    if any(c in FORBIDDEN_CHARS for c in v):
        raise ScopeError(f"domain contains forbidden characters: {value!r}")
    try:
        v = v.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ScopeError(f"invalid domain: {value!r}") from exc
    if not HOST_RE.match(v):
        raise ScopeError(f"invalid domain name: {value!r}")
    return v


def parse_scope_entry(raw: str) -> ScopeEntry:
    s = (raw or "").strip()
    if not s:
        raise ScopeError("empty scope entry")
    if s.lower().startswith(("http://", "https://")):
        parts = urlsplit(s)
        if parts.path not in ("", "/") or parts.query or parts.fragment or not parts.hostname:
            raise ScopeError(f"enter a hostname, not a URL with a path: {raw!r}")
        s = parts.hostname
    if s.startswith("*."):
        base = normalize_domain(s[2:])
        if base in PUBLIC_SUFFIXES:
            raise ScopeError(f"wildcard on a public suffix is not allowed: {raw!r}")
        return ScopeEntry("wildcard", base)
    try:
        return ScopeEntry("ip", str(ipaddress.ip_address(s)))
    except ValueError:
        pass
    if "/" in s:
        try:
            net = ipaddress.ip_network(s, strict=True)
        except ValueError as exc:
            raise ScopeError(f"invalid CIDR: {raw!r}") from exc
        floor = MIN_V4_PREFIX if net.version == 4 else MIN_V6_PREFIX
        if net.prefixlen < floor:
            raise ScopeError(f"CIDR too broad (minimum /{floor}): {raw!r}")
        return ScopeEntry("cidr", str(net))
    return ScopeEntry("domain", normalize_domain(s))


def _host_matches(entry: ScopeEntry, host: str, subtree: bool) -> bool:
    if entry.kind == "domain":
        return host == entry.value or (subtree and host.endswith("." + entry.value))
    if entry.kind == "wildcard":
        return host.endswith("." + entry.value) or (subtree and host == entry.value)
    return False


def _ip_matches(entry: ScopeEntry, ip: ipaddress._BaseAddress) -> bool:
    if entry.kind == "ip":
        return ip == ipaddress.ip_address(entry.value)
    if entry.kind == "cidr":
        net = ipaddress.ip_network(entry.value)
        return ip.version == net.version and ip in net
    return False


def _as_ip(host: str):
    try:
        return ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return None


@dataclass(frozen=True)
class Scope:
    include: tuple[ScopeEntry, ...]
    exclude: tuple[ScopeEntry, ...] = ()

    @classmethod
    def from_strings(cls, include: Iterable[str], exclude: Iterable[str] = ()) -> "Scope":
        return cls(tuple(parse_scope_entry(s) for s in include), tuple(parse_scope_entry(s) for s in exclude))

    # ------------------------------------------------------------------ checks
    def host_allowed(self, host: str) -> tuple[bool, str]:
        h = (host or "").strip().lower().rstrip(".")
        ip = _as_ip(h)
        if ip is not None:
            return self.ip_allowed(str(ip))
        try:
            h = normalize_domain(h)
        except ScopeError:
            return False, "not a valid hostname"
        for ex in self.exclude:
            if _host_matches(ex, h, subtree=True):
                return False, f"excluded by {ex.display()}"
        for inc in self.include:
            if _host_matches(inc, h, subtree=False):
                return True, f"matches {inc.display()}"
        return False, "not in authorised scope"

    def ip_allowed(self, ip: str) -> tuple[bool, str]:
        try:
            addr = ipaddress.ip_address(ip.strip("[]"))
        except ValueError:
            return False, "not a valid IP address"
        for ex in self.exclude:
            if _ip_matches(ex, addr):
                return False, f"excluded by {ex.display()}"
        for inc in self.include:
            if _ip_matches(inc, addr):
                return True, f"matches {inc.display()}"
        return False, "IP not explicitly authorised"

    def ip_scannable(self, ip: str, allow_resolved: bool) -> tuple[bool, str]:
        """IPs learned from DNS are only port-scanned when explicitly authorised, or when the user opted in
        AND the address is globally routable and not excluded."""
        ok, why = self.ip_allowed(ip)
        if ok:
            return True, why
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False, "not a valid IP address"
        if any(_ip_matches(ex, addr) for ex in self.exclude):
            return False, "excluded"
        if allow_resolved and addr.is_global:
            return True, "resolved from an in-scope hostname (user opted in)"
        return False, "resolved IP is not explicitly authorised"

    def url_allowed(self, url: str) -> tuple[bool, str]:
        try:
            parts = urlsplit(url)
            host = parts.hostname
            parts.port  # noqa: B018  (raises ValueError on a bad port)
        except ValueError:
            return False, "malformed URL"
        if parts.scheme not in ("http", "https") or not host:
            return False, "only http/https URLs are accepted"
        if parts.username or parts.password:
            return False, "URLs with credentials are rejected"
        return self.host_allowed(host)

    def wildcard_roots(self) -> list[str]:
        roots = []
        for e in self.include:
            if e.kind == "wildcard" and self.host_allowed("probe." + e.value)[0] and e.value not in roots:
                roots.append(e.value)
        return roots

    def seed_domains(self) -> list[str]:
        return [e.value for e in self.include if e.kind == "domain" and self.host_allowed(e.value)[0]]

    def seed_ips(self, limit: int) -> list[str]:
        out: list[str] = []
        for e in self.include:
            if e.kind == "ip" and self.ip_allowed(e.value)[0]:
                out.append(e.value)
            elif e.kind == "cidr":
                net = ipaddress.ip_network(e.value)
                if net.num_addresses > limit:
                    raise ScopeError(f"CIDR {e.value} has {net.num_addresses} addresses, above the asset limit {limit}; narrow it")
                out += [str(a) for a in (net.hosts() if net.num_addresses > 2 else net) if self.ip_allowed(str(a))[0]]
        return out[:limit]

    def to_json(self) -> dict[str, list[str]]:
        return {"include": [e.display() for e in self.include], "exclude": [e.display() for e in self.exclude]}


def filter_hosts(scope: Scope, hosts: Iterable[str]) -> tuple[list[str], list[tuple[str, str]]]:
    allowed, rejected, seen = [], [], set()
    for h in hosts:
        hn = (h or "").strip().lower().rstrip(".")
        if hn in seen:
            continue
        seen.add(hn)
        ok, why = scope.host_allowed(hn)
        (allowed.append(hn) if ok else rejected.append((hn, why)))
    return allowed, rejected


def _check_public(scope: Scope, host: str, host_ips: dict[str, list[str]]) -> None:
    """A hostname that resolves to loopback/private/link-local space is only allowed if that IP is explicitly in scope."""
    for ip in host_ips.get(host, []):
        addr = _as_ip(ip)
        if addr is not None and not addr.is_global and not scope.ip_allowed(ip)[0]:
            raise ScopeViolation(f"{host} resolves to non-public address {ip} which is not explicitly authorised")


def revalidate_targets(scope: Scope, kind: str, targets: Iterable[str],
                       host_ips: dict[str, list[str]] | None = None, allow_resolved_ips: bool = False) -> None:
    """Called immediately before a scanner launches. Raises ScopeViolation on the first problem found.

    kinds: domain_root | host | url | hostport | port_host (host plus resolved-IP gating)
    """
    host_ips = host_ips or {}
    for t in targets:
        if not isinstance(t, str) or not t or t.startswith("-") or any(c in t for c in "\0\r\n \t"):
            raise ScopeViolation(f"unsafe target token rejected: {t!r}")
        if kind == "domain_root":
            if t not in scope.wildcard_roots():
                raise ScopeViolation(f"{t} is not a wildcard-authorised root domain")
        elif kind == "url":
            ok, why = scope.url_allowed(t)
            if not ok:
                raise ScopeViolation(f"{t}: {why}")
            _check_public(scope, urlsplit(t).hostname or "", host_ips)
        else:
            host = t
            if kind == "hostport" and t.count(":") == 1:      # bare hostnames/IPs are allowed too
                host, _, port = t.rpartition(":")
                if not port.isdigit() or not 0 < int(port) < 65536:
                    raise ScopeViolation(f"{t}: invalid port")
            ok, why = scope.host_allowed(host)
            if not ok:
                raise ScopeViolation(f"{host}: {why}")
            _check_public(scope, host, host_ips)
            if kind == "port_host" and _as_ip(host) is None:
                ips = host_ips.get(host)
                if not ips:
                    raise ScopeViolation(f"{host}: resolved IPs unknown; port scanning requires verified DNS data")
                for ip in ips:
                    ok, why = scope.ip_scannable(ip, allow_resolved_ips)
                    if not ok:
                        raise ScopeViolation(f"{host} -> {ip}: {why}")


def revalidate_ips(scope: Scope, ips: Iterable[str], allow_resolved_ips: bool = False) -> None:
    """Immediately-before-launch check for port scanners that receive raw IP addresses."""
    for ip in ips:
        if not isinstance(ip, str) or not ip or ip.startswith("-") or any(c in ip for c in "\0\r\n \t"):
            raise ScopeViolation(f"unsafe target token rejected: {ip!r}")
        ok, why = scope.ip_scannable(ip, allow_resolved_ips)
        if not ok:
            raise ScopeViolation(f"{ip}: {why}")


# ------------------------------------------------------------------ misc validators
def validate_port_spec(spec: str) -> str:
    s = (spec or "top100").strip().lower()
    if not PORT_SPEC_RE.match(s):
        raise ScopeError(f"invalid port specification: {spec!r}")
    for part in re.findall(r"\d+", s if not s.startswith("top") else ""):
        if not 0 < int(part) < 65536:
            raise ScopeError(f"port out of range: {part}")
    return s


def validate_ident_list(value: str, what: str) -> str:
    v = (value or "").strip().lower()
    if not IDENT_LIST_RE.match(v):
        raise ScopeError(f"{what} may contain only a-z, 0-9, '_', '-' and commas")
    return v


def safe_path_under(path: str, roots: Iterable[Path]) -> Path:
    """Resolve a user-supplied file path and require it to live under one of the allowed roots."""
    if not path or "\0" in path or path.startswith("-"):
        raise ScopeError("unsafe path")
    p = Path(path).expanduser().resolve()
    if not p.is_file():
        raise ScopeError(f"file not found: {path}")
    if not any(p == r or r in p.parents for r in roots):
        raise ScopeError("path is outside the allowed wordlist directories")
    return p
