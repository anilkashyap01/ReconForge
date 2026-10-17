"""Tool detection: resolve binaries, confirm identity and read versions. Nothing is assumed installed."""
from __future__ import annotations

import asyncio
import os
import re
import shutil
import time
from dataclasses import asdict, dataclass

from ..adapters import REGISTRY
from ..adapters.base import ToolSpec
from .runner import run_command, sanitized_path


@dataclass
class ToolStatus:
    name: str
    label: str
    core: bool
    installed: bool
    path: str | None
    version: str | None
    problem: str | None
    kali_package: str
    install_url: str
    touches_target: bool
    description: str
    template_version: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def resolve_binary(spec: ToolSpec) -> str | None:
    pinned = os.environ.get(f"RECONFORGE_TOOL_{spec.name.upper()}")
    if pinned:
        return pinned if os.path.isfile(pinned) and os.access(pinned, os.X_OK) else None
    for b in spec.binaries:
        p = shutil.which(b, path=sanitized_path())
        if p:
            return os.path.abspath(p)
    return None


async def detect_one(spec: ToolSpec) -> ToolStatus:
    base = dict(name=spec.name, label=spec.label, core=spec.core, kali_package=spec.kali_package,
                install_url=spec.install_url, touches_target=spec.touches_target, description=spec.description)
    path = resolve_binary(spec)
    if not path:
        return ToolStatus(installed=False, path=None, version=None, problem="not found on PATH", **base)
    r = await run_command([path, *spec.version_args], timeout=spec.version_timeout, max_output=100_000)
    text = f"{r.stdout}\n{r.stderr_tail}"
    if r.error:
        return ToolStatus(installed=False, path=path, version=None, problem=r.error, **base)
    if not re.search(spec.identity_re, text, re.I):
        return ToolStatus(installed=False, path=path, version=None,
                          problem=f"{path} does not look like {spec.label} (wrong program or version check failed)", **base)
    m = re.search(spec.version_re, text)
    st = ToolStatus(installed=True, path=path, version=m.group(1) if m else "unknown", problem=None, **base)
    if spec.name == "nuclei":
        t = await run_command([path, "-templates-version"], timeout=20, max_output=50_000)
        tm = re.search(r"templates version:?\s*v?(\d+\.\d+\.\d+)", f"{t.stdout}\n{t.stderr_tail}", re.I)
        st.template_version = tm.group(1) if tm else None
    return st


_cache: dict[str, object] = {"at": 0.0, "data": {}}


async def detect_all(force: bool = False, max_age: float = 30.0) -> dict[str, ToolStatus]:
    if not force and time.monotonic() - float(_cache["at"]) < max_age and _cache["data"]:
        return _cache["data"]  # type: ignore[return-value]
    results = await asyncio.gather(*(detect_one(a.spec) for a in REGISTRY.values()))
    _cache["data"] = {s.name: s for s in results}
    _cache["at"] = time.monotonic()
    return _cache["data"]  # type: ignore[return-value]
