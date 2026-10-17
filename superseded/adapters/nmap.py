from __future__ import annotations

import xml.etree.ElementTree as ET

from ..models import ParseResult, PortRecord
from .base import Adapter, StageContext


class NmapAdapter(Adapter):
    tool, stage = "nmap", "nmap"
    label = "Service and version detection"
    target_kind = "port_host"
    traffic_note = "Sends service probes to ports already found open. No NSE scripts are run."

    def build_commands(self, ctx: StageContext) -> list[list[str]]:
        by_host: dict[str, list[int]] = ctx.extras.get("ports_by_host", {})
        cmds = []
        for host in ctx.targets:
            ports = sorted(set(by_host.get(host, [])))[:100]
            if not ports:
                continue
            cmds.append([ctx.binary, "-sV", "--version-intensity", "2", "-Pn", "-p", ",".join(map(str, ports)),
                         "--max-retries", "1", "--host-timeout", "300s", "--max-rate", str(ctx.rate.pps),
                         "-oX", "-", host])
        return cmds

    def parse(self, ctx: StageContext, argv: list[str], stdout: str) -> ParseResult:
        res = ParseResult()
        if not stdout.strip():
            return res
        if "<!DOCTYPE" in stdout.upper().replace("<!DOCTYPE NMAPRUN", "") or "<!ENTITY" in stdout:
            res.warnings.append("nmap XML contained a custom DTD/entity; output rejected")
            return res
        try:
            root = ET.fromstring(stdout)
        except ET.ParseError as exc:
            res.warnings.append(f"could not parse nmap XML: {exc}")
            return res
        host = argv[-1]
        for port in root.iter("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            ver = " ".join(x for x in (svc.get("version") if svc is not None else None,
                                       svc.get("extrainfo") if svc is not None else None) if x) or None
            res.ports.append(PortRecord(host=host, port=int(port.get("portid", 0)), protocol=port.get("protocol", "tcp"),
                                        service=svc.get("name") if svc is not None else None,
                                        product=svc.get("product") if svc is not None else None,
                                        version=ver, source="nmap"))
        return res
