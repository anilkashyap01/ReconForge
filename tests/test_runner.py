import asyncio
import sys

from app.services.runner import run_command, safe_env


def run(**kw):
    return asyncio.run(run_command(**kw))


def test_timeout_kills_process_and_keeps_partial_output():
    r = run(argv=[sys.executable, "-c", "import sys,time; print('partial', flush=True); time.sleep(30)"], timeout=1.5, max_output=10_000)
    assert r.timed_out and not r.cancelled and "partial" in r.stdout


def test_cancellation_stops_process_quickly():
    async def go():
        ev = asyncio.Event()
        task = asyncio.create_task(run_command([sys.executable, "-c", "import time; time.sleep(30)"], timeout=60, max_output=1000, cancel=ev))
        await asyncio.sleep(0.5)
        ev.set()
        return await asyncio.wait_for(task, 10)
    assert asyncio.run(go()).cancelled


def test_output_is_capped_and_process_killed():
    r = run(argv=[sys.executable, "-c", "import sys\nwhile True: sys.stdout.write('x'*1000)"], timeout=20, max_output=5000)
    assert r.truncated and len(r.stdout) <= 5000


def test_stdin_is_delivered_and_nonzero_exit_reported():
    r = run(argv=[sys.executable, "-c", "import sys; print(sys.stdin.read().upper()); sys.exit(3)"], stdin_text="abc", timeout=10, max_output=1000)
    assert r.stdout.strip() == "ABC" and r.exit_code == 3 and not r.timed_out


def test_missing_binary_is_reported_not_raised():
    assert "could not start" in run(argv=["/nonexistent/tool"], timeout=5, max_output=100).error


def test_scanner_environment_contains_no_provider_secrets(monkeypatch):
    monkeypatch.setenv("RECONFORGE_SHODAN_API_KEY", "sekret-value-123")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "other")
    env = safe_env()
    assert "sekret-value-123" not in env.values() and "AWS_SECRET_ACCESS_KEY" not in env
    r = run(argv=[sys.executable, "-c", "import os; print(sorted(os.environ))"], timeout=10, max_output=1000)
    assert "RECONFORGE_SHODAN_API_KEY" not in r.stdout
