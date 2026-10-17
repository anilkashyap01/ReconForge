import json

from app.adapters import REGISTRY, BuildContext, Command
from app.config import Limits
from app.models import ScanOptions
from app.rate_limiter import plan_tool_rate


def parse(name, stdout="", file_text=None, targets=("x",), tmp=None):
    ctx = BuildContext("/bin/x", plan_tool_rate(Limits()), ScanOptions(), tmp, tool_version="1.0", template_version="9.9.9")
    return REGISTRY[name].parse(Command(["/bin/x"], list(targets), "host"), stdout, file_text, ctx)


def jl(*objs):
    return "\n".join(json.dumps(o) for o in objs) + "\n"


def test_subfinder_parses_json_and_plain_lines_and_skips_garbage():
    pr = parse("subfinder", jl({"host": "A.example.com", "source": ["crtsh"]}) + "plain.example.com\n{broken\n")
    assert [h for h, _ in pr.hosts] == ["a.example.com", "plain.example.com"]
    assert any("unparseable" in w for w in pr.warnings)


def test_dnsx_extracts_ips_cnames_and_marks_only_resolving_hosts():
    pr = parse("dnsx", jl({"host": "a.example.com", "a": ["1.2.3.4"], "cname": ["x.cdn.net."]}, {"host": "dead.example.com", "status_code": "NXDOMAIN"}))
    assert pr.output["resolved"] == ["a.example.com"]
    assert pr.output["host_ips"] == {"a.example.com": ["1.2.3.4"]}
    assert pr.output["cnames"] == {"a.example.com": ["x.cdn.net"]}
    assert {(d.rtype, d.value) for d in pr.dns} == {("A", "1.2.3.4"), ("CNAME", "x.cdn.net")}


def test_httpx_parses_fingerprints():
    pr = parse("httpx", jl({"url": "https://a.example.com", "status_code": 200, "title": "Hi", "webserver": "nginx", "tech": ["Nginx", "PHP"], "content_length": 5}))
    e = pr.endpoints[0]
    assert (e.host, e.status_code, e.technologies, e.source) == ("a.example.com", 200, ["Nginx", "PHP"], "httpx")
    assert pr.output["live_urls"] == ["https://a.example.com"]


def test_naabu_and_katana():
    assert [(p.ip, p.port) for p in parse("naabu", jl({"ip": "1.2.3.4", "port": 22}, {"ip": "1.2.3.4", "port": "bad"})).ports] == [("1.2.3.4", 22)]
    k = parse("katana", jl({"request": {"endpoint": "https://a.example.com/x?y=1"}, "response": {"status_code": 404}}, {"request": {"endpoint": "javascript:void(0)"}}))
    assert [e.url for e in k.endpoints] == ["https://a.example.com/x?y=1"] and k.endpoints[0].kind == "crawl"


def test_nuclei_finding_is_a_potential_low_confidence_detection():
    pr = parse("nuclei", jl({"template-id": "t-1", "info": {"name": "Thing", "severity": "critical", "reference": ["https://r"]}, "matched-at": "https://a.example.com/p",
                             "matcher-name": "m", "extracted-results": ["v1"], "request": "GET /", "response": "HTTP/1.1 200"}))
    f = pr.findings[0]
    assert (f.severity, f.asset, f.source, f.template_id, f.confidence) == ("critical", "a.example.com", "nuclei", "t-1", "low")
    assert f.template_version == "9.9.9" and "v1" in f.evidence and "GET /" in f.details and f.references == ["https://r"]


def test_nuclei_unknown_severity_becomes_info():
    assert parse("nuclei", jl({"template-id": "t", "info": {"severity": "unknown"}, "matched-at": "https://a.example.com"})).findings[0].severity == "info"


def test_nmap_xml():
    xml = ('<nmaprun><host><address addr="1.2.3.4"/><ports><port protocol="tcp" portid="443"><state state="open"/>'
           '<service name="https" product="nginx" version="1.25"/></port><port protocol="tcp" portid="81"><state state="closed"/></port></ports></host></nmaprun>')
    pr = parse("nmap", xml)
    assert [(p.ip, p.port, p.service, p.product, p.version) for p in pr.ports] == [("1.2.3.4", 443, "https", "nginx", "1.25")]
    assert parse("nmap", "not xml").warnings


def test_testssl_only_reports_problems():
    rows = [{"id": "SSLv3", "severity": "OK", "finding": "not offered"}, {"id": "TLS1", "severity": "LOW", "finding": "offered", "port": "443"},
            {"id": "heartbleed", "severity": "CRITICAL", "finding": "VULNERABLE", "port": "443"}]
    pr = parse("testssl", file_text=json.dumps(rows), targets=("a.example.com:443",))
    assert [(f.template_id, f.severity, f.asset) for f in pr.findings] == [("TLS1", "low", "a.example.com"), ("heartbleed", "critical", "a.example.com")]


def test_ffuf_and_zap_and_gau():
    ff = parse("ffuf", file_text=json.dumps({"results": [{"url": "https://a.example.com/admin", "status": 301, "length": 3}]}))
    assert ff.endpoints[0].kind == "content"
    zap = parse("zap", file_text=json.dumps({"site": [{"alerts": [{"alert": "X", "riskcode": "3", "desc": "<p>d</p>", "pluginid": "40012", "instances": [{"uri": "https://a.example.com/", "method": "GET"}]}]}]}),
                targets=("https://a.example.com",))
    assert zap.findings[0].severity == "high" and zap.findings[0].description == "d"
    gau = parse("gau", "https://a.example.com/old\nnot a url\n")
    assert [e.url for e in gau.endpoints] == ["https://a.example.com/old"]
