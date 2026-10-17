from __future__ import annotations

from .assessment import Ffuf, Nmap, Nuclei, Testssl, Zap
from .base import Adapter, BuildContext, Command, ToolSpec
from .discovery import Dnsx, Gau, Httpx, Katana, Naabu, Subfinder

REGISTRY: dict[str, Adapter] = {a.spec.name: a for a in (
    Subfinder(), Dnsx(), Httpx(), Naabu(), Katana(), Nuclei(), Nmap(), Zap(), Ffuf(), Gau(), Testssl())}

__all__ = ["REGISTRY", "Adapter", "BuildContext", "Command", "ToolSpec"]
