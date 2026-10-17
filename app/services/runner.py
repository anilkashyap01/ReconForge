"""Async subprocess execution: argument arrays only, timeouts, output caps, cancellation."""
from __future__ import annotations

import asyncio
import os
import signal
import sys
from collections import deque
from dataclasses import dataclass
from pathlib import Path

from ..config import BASE_DIR


def sanitized_path() -> str:
    """PATH without the virtualenv, so the Python `httpx` CLI can never shadow ProjectDiscovery's httpx."""
    venv_bins = {str(Path(sys.executable).parent), str(BASE_DIR / ".venv" / "bin")}
    parts = [p for p in os.environ.get("PATH", os.defpath).split(os.pathsep) if p and p not in venv_bins]
    return os.pathsep.join(parts)


def safe_env() -> dict[str, str]:
    """Minimal environment. Provider API keys and other RECONFORGE_* values are never passed to scanners."""
    env = {"PATH": sanitized_path(), "HOME": os.environ.get("HOME", "/tmp"), "LANG": "C.UTF-8"}
    for k in ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy"):
        if k in os.environ:
            env[k] = os.environ[k]
    return env


@dataclass
class RunResult:
    argv: list[str]
    exit_code: int | None = None
    stdout: str = ""
    stderr_tail: str = ""
    timed_out: bool = False
    truncated: bool = False
    cancelled: bool = False
    error: str | None = None
    stdout_bytes: int = 0


def check_argv(argv: list[str]) -> None:
    if not argv or not all(isinstance(a, str) and "\0" not in a for a in argv):
        raise ValueError("invalid argv")
    if not os.path.isabs(argv[0]):
        raise ValueError("binary must be an absolute path")


def _kill(proc: asyncio.subprocess.Process, sig: int) -> None:
    try:
        os.killpg(proc.pid, sig)
    except (ProcessLookupError, PermissionError):
        pass


async def run_command(argv: list[str], *, stdin_text: str | None = None, timeout: float, max_output: int,
                      cancel: asyncio.Event | None = None, cwd: Path | None = None) -> RunResult:
    check_argv(argv)
    res = RunResult(argv=list(argv))
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv, stdin=asyncio.subprocess.PIPE if stdin_text is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, cwd=str(cwd) if cwd else None,
            env=safe_env(), start_new_session=True)
    except (FileNotFoundError, PermissionError, OSError) as exc:
        res.error = f"could not start: {exc}"
        return res

    async def feed() -> None:
        try:
            proc.stdin.write(stdin_text.encode())
            await proc.stdin.drain()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            try:
                proc.stdin.close()
            except Exception:
                pass

    async def read_out() -> bytes:
        chunks, total = [], 0
        while data := await proc.stdout.read(65536):
            total += len(data)
            if total > max_output:
                keep = len(data) - (total - max_output)
                if keep > 0:
                    chunks.append(data[:keep])
                res.truncated = True
                _kill(proc, signal.SIGKILL)
                break
            chunks.append(data)
        res.stdout_bytes = min(total, max_output)
        return b"".join(chunks)

    async def read_err() -> bytes:
        tail: deque[bytes] = deque(maxlen=64)
        while data := await proc.stderr.read(4096):
            tail.append(data)
        return b"".join(tail)[-4000:]

    tasks = [asyncio.create_task(read_out()), asyncio.create_task(read_err())]
    if stdin_text is not None:
        tasks.append(asyncio.create_task(feed()))
    waiter = asyncio.create_task(proc.wait())
    watchers = {waiter} | ({asyncio.create_task(cancel.wait())} if cancel else set())
    done, _ = await asyncio.wait(watchers, timeout=timeout, return_when=asyncio.FIRST_COMPLETED)
    if waiter not in done:
        res.timed_out = not (cancel and cancel.is_set())
        res.cancelled = bool(cancel and cancel.is_set())
        _kill(proc, signal.SIGTERM)
        try:
            await asyncio.wait_for(proc.wait(), 3)
        except asyncio.TimeoutError:
            _kill(proc, signal.SIGKILL)
    for w in watchers:
        if not w.done():
            w.cancel()
    try:
        out_b, err_b, *_ = await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), 10)
    except asyncio.TimeoutError:
        out_b = err_b = b""
    res.stdout = out_b.decode("utf-8", "replace") if isinstance(out_b, bytes) else ""
    res.stderr_tail = err_b.decode("utf-8", "replace") if isinstance(err_b, bytes) else ""
    res.exit_code = proc.returncode
    return res
