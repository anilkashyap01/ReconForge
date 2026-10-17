"""Central rate-limit planning.

What is enforced, honestly:
* Scanner binaries are third-party processes. We cannot meter their packets, so we (a) serialise
  target-touching stages with a semaphore, (b) derive each tool's own rate flag from the combined
  budget divided by the number of tools allowed to run at once, and (c) cap that by the per-host budget.
* Requests made by ReconForge itself (provider APIs) go through TokenBucket / HostBudgets and honour
  HTTP 429 + Retry-After.
"""
from __future__ import annotations

import asyncio
import email.utils
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Awaitable, Callable

from .config import Limits


class TokenBucket:
    def __init__(self, rate: float, capacity: float | None = None,
                 clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], Awaitable[None]] = asyncio.sleep) -> None:
        if rate <= 0:
            raise ValueError("rate must be positive")
        self.rate = rate
        self.capacity = capacity if capacity is not None else max(1.0, rate)
        self._clock, self._sleep = clock, sleep
        self._tokens = self.capacity
        self._last = clock()
        self._blocked_until = 0.0

    def _refill(self) -> None:
        now = self._clock()
        self._tokens = min(self.capacity, self._tokens + (now - self._last) * self.rate)
        self._last = now

    def try_acquire(self, n: float = 1.0) -> float:
        """Return 0.0 if `n` tokens were taken, otherwise the seconds to wait."""
        self._refill()
        now = self._clock()
        if now < self._blocked_until:
            return self._blocked_until - now
        if self._tokens >= n:
            self._tokens -= n
            return 0.0
        return (n - self._tokens) / self.rate

    async def acquire(self, n: float = 1.0) -> None:
        while (wait := self.try_acquire(n)) > 0:
            await self._sleep(wait)

    def penalize(self, seconds: float) -> None:
        """Block all acquisitions for `seconds` (used for 429 / Retry-After)."""
        self._blocked_until = max(self._blocked_until, self._clock() + max(0.0, seconds))
        self._tokens = 0.0


class HostBudgets:
    """Per-origin budgets plus an optional global ceiling for requests this process sends itself."""

    def __init__(self, per_host_rps: float, global_rps: float | None = None, **kw) -> None:
        self._per_host, self._kw = per_host_rps, kw
        self._hosts: dict[str, TokenBucket] = {}
        self._global = TokenBucket(global_rps, **kw) if global_rps else None

    def bucket(self, host: str) -> TokenBucket:
        return self._hosts.setdefault(host.lower(), TokenBucket(self._per_host, **self._kw))

    async def acquire(self, host: str) -> None:
        await self.bucket(host).acquire()
        if self._global:
            await self._global.acquire()

    def note_response(self, host: str, status: int, retry_after: str | None) -> float:
        """Apply backoff after HTTP 429/503. Returns the penalty applied in seconds (0 if none)."""
        if status not in (429, 503):
            return 0.0
        delay = parse_retry_after(retry_after) or 30.0
        self.bucket(host).penalize(delay)
        return delay


def parse_retry_after(value: str | None, now: datetime | None = None) -> float | None:
    if not value:
        return None
    value = value.strip()
    if value.isdigit():
        return float(value)
    try:
        when = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return max(0.0, (when - (now or datetime.now(timezone.utc))).total_seconds())


@dataclass(frozen=True)
class RetryPolicy:
    max_retries: int = 2
    base_seconds: float = 5.0
    factor: float = 2.0
    max_delay: float = 300.0

    def delay(self, attempt: int) -> float:
        return min(self.max_delay, self.base_seconds * (self.factor ** attempt))

    @classmethod
    def from_limits(cls, limits: Limits) -> "RetryPolicy":
        return cls(limits.max_retries, limits.retry_base_seconds)


@dataclass(frozen=True)
class ToolRate:
    rps: int            # value passed to the tool's own rate flag (integer >= 1)
    threads: int
    pps: int            # packets/second for port discovery
    dns_qps: int
    clamped: bool = False
    note: str = ""

    def halved(self) -> "ToolRate":
        return ToolRate(max(1, self.rps // 2), max(1, self.threads // 2), max(10, self.pps // 2),
                        max(5, self.dns_qps // 2), self.clamped, self.note)


def plan_tool_rate(limits: Limits, concurrent_target_jobs: int | None = None) -> ToolRate:
    """Combined budget / concurrent target-touching tools, capped by the per-host budget.

    Tools only accept integer rates >= 1, so a configured budget below 1 rps is clamped upward and flagged.
    """
    n = max(1, concurrent_target_jobs or limits.max_concurrent_target_jobs)
    wanted = min(limits.requests_per_second / n, limits.per_host_rps)
    rps = max(1, int(wanted))
    clamped = rps > wanted
    note = (f"configured budget {wanted:.2f} rps is below the 1 rps minimum the tools accept; using 1 rps"
            if clamped else "")
    return ToolRate(rps=rps, threads=max(1, min(rps, 10)), pps=limits.port_scan_pps, dns_qps=limits.dns_qps,
                    clamped=clamped, note=note)
