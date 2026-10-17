"""Job queue and concurrency control shared by every scan."""
from __future__ import annotations

import asyncio
import traceback

from .config import Limits, redact
from .database import db, now, q
from .models import ScanStatus
from .services import store
from .services.pipeline import ScanRun


class Scheduler:
    """Scans run at most `max_concurrent_jobs` at a time. Stages that send traffic to targets additionally pass through
    `target_sem`, so by default only ONE target-touching tool process runs at any moment across all scans."""

    def __init__(self, limits: Limits) -> None:
        self.limits = limits
        self.queue: asyncio.Queue[int] = asyncio.Queue()
        self.target_sem = asyncio.Semaphore(limits.max_concurrent_target_jobs)
        self.runs: dict[int, ScanRun] = {}
        self.workers: list[asyncio.Task] = []

    def recover(self) -> None:
        with db() as c:
            for r in q(c, "SELECT id FROM scans WHERE status IN ('queued','running','paused')"):
                c.execute("UPDATE scans SET status=?, error=?, completed_at=? WHERE id=?",
                          (ScanStatus.FAILED, "Interrupted by a server restart. Use Retry to resume unfinished stages.", now(), r["id"]))
                c.execute("UPDATE scan_stages SET status='pending' WHERE scan_id=? AND status='running'", (r["id"],))

    async def start(self) -> None:
        self.recover()
        self.workers = [asyncio.create_task(self._worker()) for _ in range(self.limits.max_concurrent_jobs)]

    async def stop(self) -> None:
        for r in self.runs.values():
            r.cancel.set()
        for w in self.workers:
            w.cancel()
        await asyncio.gather(*self.workers, return_exceptions=True)

    def enqueue(self, scan_id: int) -> None:
        with db() as c:
            c.execute("UPDATE scans SET status=?, cancel_requested=0, pause_requested=0, error=NULL, completed_at=NULL WHERE id=?", (ScanStatus.QUEUED, scan_id))
        self.queue.put_nowait(scan_id)

    def cancel(self, scan_id: int) -> None:
        with db() as c:
            c.execute("UPDATE scans SET cancel_requested=1 WHERE id=?", (scan_id,))
            store.log(c, scan_id, "info", "Cancel requested")
        if run := self.runs.get(scan_id):
            run.cancel.set()

    def set_pause(self, scan_id: int, paused: bool) -> None:
        with db() as c:
            c.execute("UPDATE scans SET pause_requested=? WHERE id=?", (int(paused), scan_id))

    async def _worker(self) -> None:
        while True:
            sid = await self.queue.get()
            run = ScanRun(sid, self)
            self.runs[sid] = run
            try:
                await run.run()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                with db() as c:
                    store.log(c, sid, "error", redact(traceback.format_exc())[-1500:])
                    c.execute("UPDATE scans SET status=?, error=?, completed_at=? WHERE id=?",
                              (ScanStatus.FAILED, f"Internal error: {redact(str(exc))[:300]}", now(), sid))
            finally:
                self.runs.pop(sid, None)
                self.queue.task_done()
