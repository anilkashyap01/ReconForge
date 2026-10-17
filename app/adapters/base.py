"""Adapter base types. An adapter knows how to build argv arrays for one tool and parse its output."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator
from urllib.parse import urlsplit

from ..models import ParseResult, ScanOptions
from ..rate_limiter import ToolRate


@dataclass(frozen=True)
class ToolSpec:
    name: str
    label: str
    binaries: tuple[str, ...]
    version_args: tuple[str, ...]
    identity_re: str          # output must match, so a same-named but different program is rejected
    version_re: str
    core: bool
    kali_package: str
    install_url: str
    touches_target: bool
    description: str
    version_timeout: int = 20


@dataclass
class Command:
    argv: list[str]                 # argv[0] is the resolved binary; never passed through a shell
    targets: list[str]              # exactly what is re-validated against scope before launch
    target_kind: str                # domain_root | host | url | hostport | ip
    stdin: str | None = None
    out_file: Path | None = None
    label: str = ""


@dataclass
class BuildContext:
    binary: str
    rate: ToolRate
    opts: ScanOptions
    workdir: Path
    tool_version: str | None = None
    template_version: str | None = None
    allowed_wordlist_dirs: tuple[Path, ...] = ()


class Adapter:
    spec: ToolSpec

    def build(self, ctx: BuildContext, targets: list[str], extra: dict | None = None) -> list[Command]:
        raise NotImplementedError

    def parse(self, cmd: Command, stdout: str, file_text: str | None, ctx: BuildContext) -> ParseResult:
        raise NotImplementedError


def lines(targets: list[str]) -> str:
    return "\n".join(targets) + "\n"


def jsonl(text: str, warnings: list[str]) -> Iterator[dict]:
    bad = 0
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            bad += 1
            continue
        if isinstance(obj, dict):
            yield obj
    if bad:
        warnings.append(f"{bad} unparseable output line(s) skipped")


def host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def clip(text: object, limit: int) -> str:
    s = "" if text is None else str(text)
    return s if len(s) <= limit else s[:limit] + f"... [truncated {len(s) - limit} chars]"


TAG_RE = re.compile(r"<[^>]+>")
