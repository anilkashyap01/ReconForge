from __future__ import annotations

from ..models import ParseResult, PortRecord
from .base import Adapter, StageContext, as_int, iter_jsonl


class NaabuAdapter(Adapter):
    tool, stage = "naabu", "naabu"
    label = "Port discovery"
    target_kind = "port_host"
    traffic_note = "Sends TCP connection attempts to the target (connect scan, no root needed)."

    def build_commands(self, ctx: StageContext) -> list[list[str]]:
        lst = ctx.write_list("naabu-input.txt", ctx.targets)
        spec = ctx.options.get("ports", "top100")
        port_args = ["-top-ports", spec[3:]] if spec.startswith("top") else ["-p", spec]
        return [[ctx.binary, "-list", str(lst), *port_args, "-rate", str(ctx.rate.pps), "-c", "10", "-timeout", "1500",
                 "-retries", "1", "-scan-type", "c", "-exclude-cdn", "-silent", "-json", "-nc", "-duc"]]

    def parse(self, ctx: StageContext, argv: list[str], stdout: str) -> ParseResult:
        res = ParseResult()
        ports = []
        for obj in iter_jsonl(stdout):
            port = as_int(obj.get("port"))
            host = str(obj.get("host") or obj.get("ip") or "").lower()
            if port and host:
                res.ports.append(PortRecord(host=host, ip=obj.get("ip"), port=port, source="naabu"))
                ports.append({"host": host, "ip": obj.get("ip"), "port": port})
        res.output = {"ports": ports}
        return res
