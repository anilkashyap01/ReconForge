"""Shared constants, parse-result dataclasses and API request models."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import BaseModel, Field

SEVERITIES = ("info", "low", "medium", "high", "critical")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}
PROFILES = ("passive", "standard", "vulnerability", "web")
VALIDATION_STATUSES = ("unvalidated", "confirmed", "false_positive", "accepted_risk", "fixed")
OPEN_VALIDATION = ("unvalidated", "confirmed")


class StageStatus:
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"      # tool ran, produced results
    EMPTY = "empty"              # tool ran successfully, found nothing
    PARTIAL = "partial"          # timed out / hit output cap / some commands failed, results kept
    FAILED = "failed"            # tool ran and failed
    MISSING_TOOL = "missing_tool"
    SKIPPED = "skipped"
    CACHED = "cached"
    CANCELLED = "cancelled"
    DONE = (COMPLETED, EMPTY, PARTIAL, CACHED)   # statuses that are not re-run on resume


class ScanStatus:
    DRAFT = "draft"
    QUEUED = "queued"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    COMPLETED_WITH_ISSUES = "completed_with_issues"
    FAILED = "failed"
    CANCELLED = "cancelled"
    ACTIVE = (QUEUED, RUNNING, PAUSED)


@dataclass
class DnsRecord:
    host: str
    rtype: str
    value: str


@dataclass
class PortRecord:
    host: str
    port: int
    ip: str | None = None
    protocol: str = "tcp"
    service: str | None = None
    product: str | None = None
    version: str | None = None
    source: str = ""


@dataclass
class EndpointRecord:
    url: str
    host: str
    status_code: int | None = None
    title: str | None = None
    webserver: str | None = None
    technologies: list[str] = field(default_factory=list)
    content_length: int | None = None
    kind: str = "http"           # http | crawl | historical | bruteforce
    source: str = ""


@dataclass
class FindingRecord:
    title: str
    asset: str
    source: str
    template_id: str
    severity: str = "info"
    confidence: str = "low"      # scanner detections default to low until validated
    description: str = ""
    url: str = ""
    evidence: str = ""
    details: str = ""            # truncated request/response context
    dedupe_extra: str = ""
    references: list[str] = field(default_factory=list)
    template_version: str | None = None


@dataclass
class ParseResult:
    hosts: list[tuple[str, str]] = field(default_factory=list)   # (hostname, source)
    dns: list[DnsRecord] = field(default_factory=list)
    ports: list[PortRecord] = field(default_factory=list)
    endpoints: list[EndpointRecord] = field(default_factory=list)
    findings: list[FindingRecord] = field(default_factory=list)
    output: dict[str, Any] = field(default_factory=dict)         # data later stages consume
    warnings: list[str] = field(default_factory=list)

    def merge(self, other: "ParseResult") -> None:
        self.hosts += other.hosts
        self.dns += other.dns
        self.ports += other.ports
        self.endpoints += other.endpoints
        self.findings += other.findings
        self.warnings += other.warnings
        for k, v in other.output.items():
            if isinstance(v, list):
                self.output.setdefault(k, [])
                self.output[k] += v
            elif isinstance(v, dict):
                self.output.setdefault(k, {})
                self.output[k].update(v)
            else:
                self.output[k] = v

    @property
    def item_count(self) -> int:
        return len(self.hosts) + len(self.dns) + len(self.ports) + len(self.endpoints) + len(self.findings)


# --------------------------------------------------------------------------- API models
class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    description: str = Field(default="", max_length=2000)
    scope: list[str] = Field(default_factory=list, max_length=200)
    exclusions: list[str] = Field(default_factory=list, max_length=200)
    authorization_confirmed: bool = False
    authorization_note: str = Field(default="", max_length=500)


class ScopeAdd(BaseModel):
    entries: list[str] = Field(min_length=1, max_length=200)
    excluded: bool = False
    authorization_confirmed: bool = False
    authorization_note: str = Field(default="", max_length=500)


class ScanOptions(BaseModel):
    requests_per_second: float | None = None
    per_host_rps: float | None = None
    max_concurrent_target_jobs: int | None = None
    max_assets: int | None = None
    max_scan_seconds: int | None = None
    tool_timeout_seconds: int | None = None
    max_retries: int | None = None
    port_scan_pps: int | None = None
    cache_ttl_hours: int | None = None
    ports: str = "top100"
    use_cache: bool = True
    allow_resolved_ips: bool = False
    nuclei_severity: list[Literal["info", "low", "medium", "high", "critical"]] = Field(default_factory=lambda: ["low", "medium", "high", "critical"])
    nuclei_tags: str = ""
    crawl_depth: int = Field(default=2, ge=1, le=5)
    enable_gau: bool = False
    enable_nmap: bool = False
    enable_testssl: bool = False
    enable_ffuf: bool = False
    ffuf_wordlist: str = ""
    enable_zap: bool = False
    enable_enrichment: bool = False


class ScanCreate(BaseModel):
    profile: Literal["passive", "standard", "vulnerability", "web"] = "passive"
    scope_entry_ids: list[int] = Field(default_factory=list)
    extra_exclusions: list[str] = Field(default_factory=list, max_length=200)
    authorization_confirmed: bool = False
    active_testing_confirmed: bool = False
    options: ScanOptions = Field(default_factory=ScanOptions)


class FindingUpdate(BaseModel):
    validation_status: Literal["unvalidated", "confirmed", "false_positive", "accepted_risk", "fixed"] | None = None
    analyst_notes: str | None = Field(default=None, max_length=5000)


class LimitsUpdate(BaseModel):
    limits: dict[str, float | int]


class IntegrationUpdate(BaseModel):
    enabled: bool | None = None
    api_key: str | None = Field(default=None, max_length=500)
    org_id: str | None = Field(default=None, max_length=200)
