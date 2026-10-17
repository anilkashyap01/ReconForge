import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from app.config import Limits, effective_limits
from app.rate_limiter import HostBudgets, RetryPolicy, TokenBucket, parse_retry_after, plan_tool_rate


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


def test_token_bucket_spends_burst_then_waits():
    c = Clock()
    b = TokenBucket(2, 2, clock=c)
    assert b.try_acquire() == 0 and b.try_acquire() == 0
    assert b.try_acquire() == pytest.approx(0.5)
    c.t += 0.5
    assert b.try_acquire() == 0


def test_penalty_blocks_until_expiry():
    c = Clock()
    b = TokenBucket(10, 10, clock=c)
    b.penalize(30)
    assert b.try_acquire() == pytest.approx(30)
    c.t += 31
    assert b.try_acquire() == 0


def test_retry_after_parsing():
    assert parse_retry_after("120") == 120
    assert parse_retry_after(None) is None and parse_retry_after("soon") is None
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    http_date = (now + timedelta(seconds=90)).strftime("%a, %d %b %Y %H:%M:%S GMT")
    assert parse_retry_after(http_date, now) == pytest.approx(90)


def test_host_budget_backoff_on_429_only_affects_that_host():
    c = Clock()
    hb = HostBudgets(5, clock=c)
    assert hb.note_response("a.example.com", 200, None) == 0
    assert hb.note_response("a.example.com", 429, "40") == 40
    assert hb.bucket("a.example.com").try_acquire() > 0
    assert hb.bucket("b.example.com").try_acquire() == 0


def test_host_budget_global_ceiling_is_applied():
    async def run():
        c, slept = Clock(), []

        async def sleep(s):
            slept.append(s)
            c.t += s
        hb = HostBudgets(100, global_rps=1, clock=c, sleep=sleep)
        for _ in range(3):
            await hb.acquire("a.example.com")
        return slept
    assert sum(asyncio.run(run())) >= 2


def test_retry_policy_is_exponential_and_capped():
    p = RetryPolicy(3, 5, 2, 60)
    assert [p.delay(i) for i in range(5)] == [5, 10, 20, 40, 60]


def test_default_rate_is_conservative():
    r = plan_tool_rate(Limits())
    assert r.rps == 2 and not r.clamped
    assert Limits().max_concurrent_target_jobs == 1


def test_budget_is_divided_across_concurrent_tools_and_capped_per_host():
    assert plan_tool_rate(effective_limits({"requests_per_second": 8, "per_host_rps": 8}), 4).rps == 2
    assert plan_tool_rate(effective_limits({"requests_per_second": 20, "per_host_rps": 3}), 1).rps == 3


def test_sub_one_rps_is_clamped_and_flagged_not_silently_exceeded():
    r = plan_tool_rate(effective_limits({"requests_per_second": 0.5, "per_host_rps": 0.5}))
    assert r.rps == 1 and r.clamped and "1 rps" in r.note


def test_limits_cannot_exceed_hard_maximums():
    assert effective_limits({"requests_per_second": 10_000}).requests_per_second <= 50
    assert effective_limits({"max_concurrent_target_jobs": 99}).max_concurrent_target_jobs <= 4
