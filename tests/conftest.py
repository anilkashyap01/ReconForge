import os
import stat
import sys
import textwrap
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    """Every test gets its own data directory. No test ever performs a real scan."""
    monkeypatch.setenv("RECONFORGE_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("RECONFORGE_TESTING", "1")
    monkeypatch.setenv("RECONFORGE_WORDLIST_DIRS", str(tmp_path / "wordlists"))
    (tmp_path / "wordlists").mkdir()
    from app.database import init_db
    init_db()
    return tmp_path


FAKE = {
    "subfinder": '''
        import json, sys
        if "-version" in sys.argv: print("[INF] Current Version: v2.6.0 subfinder projectdiscovery"); sys.exit(0)
        d = sys.argv[sys.argv.index("-d") + 1]
        for h in (f"api.{d}", f"www.{d}", f"admin.{d}", "unrelated.other.net"):
            print(json.dumps({"host": h, "input": d, "source": ["fixture"]}))
    ''',
    "dnsx": '''
        import json, sys
        if "-version" in sys.argv: print("[INF] Current Version: v1.2.0 dnsx projectdiscovery"); sys.exit(0)
        for h in sys.stdin.read().split():
            rec = {"host": h, "a": ["93.184.216.34"], "status_code": "NOERROR"}
            if h.startswith("www."): rec["cname"] = ["edge.thirdparty-cdn.net"]
            print(json.dumps(rec))
    ''',
    "httpx-toolkit": '''
        import json, sys
        if "-version" in sys.argv: print("[INF] Current Version: v1.6.0 projectdiscovery"); sys.exit(0)
        for h in sys.stdin.read().split():
            print(json.dumps({"url": f"https://{h}", "input": h, "status_code": 200, "title": "<b>Welcome</b>", "webserver": "nginx", "tech": ["Nginx"], "content_length": 10}))
    ''',
    "naabu": '''
        import json, sys
        if "-version" in sys.argv: print("[INF] Current Version: v2.3.0 naabu projectdiscovery"); sys.exit(0)
        for ip in sys.stdin.read().split():
            for p in (80, 443): print(json.dumps({"ip": ip, "port": p, "protocol": "tcp"}))
    ''',
    "nuclei": '''
        import json, sys
        if "-version" in sys.argv: print("[INF] Nuclei Engine Version: v3.3.0 projectdiscovery"); sys.exit(0)
        if "-templates-version" in sys.argv: print("[INF] Public nuclei-templates version: v10.1.0 (/tmp)"); sys.exit(0)
        urls = sys.stdin.read().split()
        info = {"name": "<script>alert(1)</script> Exposed panel", "severity": "high", "description": "fixture"}
        print(json.dumps({"template-id": "fixture-panel", "info": info, "matched-at": urls[0], "host": urls[0], "type": "http"}))
        print(json.dumps({"template-id": "fixture-offscope", "info": info, "matched-at": "https://evil.other.net/x", "host": "evil.other.net"}))
    ''',
}


@pytest.fixture
def fake_tools(tmp_path, monkeypatch):
    """Stub scanner binaries that print fixture output. They exist only inside the test's temp directory."""
    d = tmp_path / "bin"
    d.mkdir()
    for name, body in FAKE.items():
        f = d / name
        f.write_text(f"#!{sys.executable}\n" + textwrap.dedent(body))
        f.chmod(f.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", str(d))
    return d
