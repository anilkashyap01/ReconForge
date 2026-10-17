"""Runtime configuration, execution limits and the local secret store."""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parent.parent
SECRET_NAMES = ("shodan_api_key", "urlscan_api_key", "censys_api_key", "censys_org_id")


def _load_dotenv(path: Path) -> None:
    if not path.is_file():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


_load_dotenv(BASE_DIR / ".env")


@dataclass(frozen=True)
class Settings:
    host: str
    port: int
    data_dir: Path
    wordlist_dirs: tuple[Path, ...]
    allowed_hosts: tuple[str, ...]

    @property
    def db_path(self) -> Path:
        return self.data_dir / "reconforge.db"

    @property
    def work_dir(self) -> Path:
        return self.data_dir / "work"

    @property
    def reports_dir(self) -> Path:
        return self.data_dir / "reports"

    @property
    def secrets_path(self) -> Path:
        return self.data_dir / "secrets.json"


def get_settings() -> Settings:
    """Read settings from the environment on each call so tests can override them."""
    data_dir = Path(os.environ.get("RECONFORGE_DATA_DIR", BASE_DIR / "data")).expanduser().resolve()
    wl = [Path("/usr/share/wordlists"), Path("/usr/share/seclists"), data_dir / "wordlists"]
    wl += [Path(p) for p in os.environ.get("RECONFORGE_WORDLIST_DIRS", "").split(":") if p]
    extra = tuple(h.strip().lower() for h in os.environ.get("RECONFORGE_ALLOWED_HOSTS", "").split(",") if h.strip())
    return Settings(
        host=os.environ.get("RECONFORGE_HOST", "127.0.0.1"),
        port=int(os.environ.get("RECONFORGE_PORT", "8000")),
        data_dir=data_dir,
        wordlist_dirs=tuple(p.resolve() for p in wl),
        allowed_hosts=("127.0.0.1", "localhost") + (("testserver",) if os.environ.get("RECONFORGE_TESTING") else ()) + extra,
    )


def ensure_dirs() -> None:
    s = get_settings()
    for d in (s.data_dir, s.work_dir, s.reports_dir):
        d.mkdir(parents=True, exist_ok=True)
    os.chmod(s.data_dir, 0o700)


# --------------------------------------------------------------------------- limits
@dataclass
class Limits:
    """Conservative defaults; see README 'Rate limiting' for what is and is not enforced."""

    max_concurrent_jobs: int = 2          # scans running in parallel
    max_concurrent_target_jobs: int = 1   # tool processes allowed to touch targets at once
    requests_per_second: float = 2.0      # combined HTTP budget against targets
    per_host_rps: float = 2.0             # ceiling per target host
    dns_qps: int = 50                     # DNS queries/second sent to resolvers
    port_scan_pps: int = 100              # packets/second for port discovery
    max_assets: int = 500
    max_scan_seconds: int = 3600
    tool_timeout_seconds: int = 900
    max_output_bytes: int = 20_000_000
    cache_ttl_hours: int = 24
    max_retries: int = 2
    retry_base_seconds: float = 5.0


HARD_MAX = Limits(
    max_concurrent_jobs=8, max_concurrent_target_jobs=4, requests_per_second=50.0, per_host_rps=50.0,
    dns_qps=500, port_scan_pps=2000, max_assets=5000, max_scan_seconds=86_400, tool_timeout_seconds=7200,
    max_output_bytes=100_000_000, cache_ttl_hours=24 * 30, max_retries=5, retry_base_seconds=300.0,
)


def effective_limits(overrides: dict[str, Any] | None = None) -> Limits:
    """Defaults + overrides, clamped to hard maximums. Unknown keys are ignored."""
    base = asdict(Limits())
    hard = asdict(HARD_MAX)
    for f in fields(Limits):
        if overrides and f.name in overrides and overrides[f.name] is not None:
            try:
                val = type(base[f.name])(overrides[f.name])
            except (TypeError, ValueError):
                continue
            floor = 0 if f.name == "max_retries" else (0.1 if isinstance(val, float) and "rps" in f.name else 1)
            base[f.name] = max(type(val)(floor), min(val, hard[f.name]))
    return Limits(**base)


# --------------------------------------------------------------------------- secrets
def redact(text: str, extra: list[str] | None = None) -> str:
    """Remove any configured secret value from text before it is logged, stored or shown."""
    values = [v for v in (SecretStore().values() + (extra or [])) if v and len(v) >= 6]
    for v in values:
        text = text.replace(v, "[redacted]")
    return text


class SecretStore:
    """JSON file with mode 0600 inside a 0700 directory. Never exposed to templates or the browser."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or get_settings().secrets_path

    def _read(self) -> dict[str, str]:
        if not self.path.is_file():
            return {}
        try:
            if self.path.stat().st_mode & 0o077:
                os.chmod(self.path, 0o600)
            data = json.loads(self.path.read_text())
            return {k: str(v) for k, v in data.items() if isinstance(k, str)}
        except (OSError, json.JSONDecodeError):
            return {}

    def _write(self, data: dict[str, str]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump(data, fh)
        os.replace(tmp, self.path)
        os.chmod(self.path, 0o600)

    def get(self, name: str) -> str | None:
        env = os.environ.get(f"RECONFORGE_{name.upper()}")
        return self._read().get(name) or env or None

    def set(self, name: str, value: str) -> None:
        if name not in SECRET_NAMES:
            raise ValueError(f"unknown secret {name!r}")
        data = self._read()
        data[name] = value.strip()
        self._write(data)

    def delete(self, name: str) -> None:
        data = self._read()
        data.pop(name, None)
        self._write(data)

    def configured(self, name: str) -> bool:
        return bool(self.get(name))

    def values(self) -> list[str]:
        vals = list(self._read().values())
        vals += [os.environ[f"RECONFORGE_{n.upper()}"] for n in SECRET_NAMES if os.environ.get(f"RECONFORGE_{n.upper()}")]
        return vals
