"""Start ReconForge: `python -m app`. Binds to 127.0.0.1 unless you deliberately override it."""
from __future__ import annotations

import ipaddress
import os
import sys

import uvicorn

from .config import get_settings


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def main() -> None:
    s = get_settings()
    if not is_loopback(s.host) and os.environ.get("RECONFORGE_ALLOW_REMOTE") != "1":
        sys.exit(f"Refusing to bind to {s.host}: ReconForge has no login and runs scanners. Use 127.0.0.1, "
                 "or set RECONFORGE_ALLOW_REMOTE=1 only if you put your own authentication in front of it.")
    print(f"ReconForge listening on http://{s.host}:{s.port}  (data: {s.data_dir})")
    uvicorn.run("app.main:app", host=s.host, port=s.port, log_level="info")


if __name__ == "__main__":
    main()
