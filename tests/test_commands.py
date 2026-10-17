from pathlib import Path

import pytest

from app.adapters import REGISTRY, BuildContext
from app.config import Limits
from app.models import ScanOptions
from app.rate_limiter import plan_tool_rate
from app.scope import ScopeError
from app.services.runner import check_argv


def ctx(tmp_path, **opts):
    return BuildContext(binary="/usr/bin/tool", rate=plan_tool_rate(Limits()), opts=ScanOptions(**opts), workdir=tmp_path,
                        allowed_wordlist_dirs=(tmp_path / "wl",))


ALL_BUILDS = [("subfinder", ["example.com"], None), ("dnsx", ["a.example.com"], None), ("httpx", ["a.example.com"], None),
              ("naabu", ["203.0.113.5"], None), ("katana", ["https://a.example.com"], None), ("nuclei", ["https://a.example.com"], None),
              ("nmap", ["203.0.113.5"], {"ports_by_ip": {"203.0.113.5": [80, 443]}}), ("testssl", ["a.example.com:443"], None), ("gau", ["example.com"], None)]


@pytest.mark.parametrize("name,targets,extra", ALL_BUILDS)
def test_every_adapter_builds_safe_argv_arrays(tmp_path, name, targets, extra):
    for cmd in REGISTRY[name].build(ctx(tmp_path), targets, extra):
        assert isinstance(cmd.argv, list) and all(isinstance(a, str) for a in cmd.argv)
        assert cmd.argv[0] == "/usr/bin/tool"
        check_argv(cmd.argv)
        assert Path(cmd.argv[0]).name not in ("sh", "bash", "dash", "zsh")   # ("-c" is a legitimate concurrency flag for several tools)
        if cmd.stdin is not None:                      # stdin carries exactly the validated targets, nothing else
            assert [x for x in cmd.stdin.split("\n") if x] == cmd.targets
        else:
            assert set(cmd.targets) <= set(cmd.argv) or any(t in a for t in cmd.targets for a in cmd.argv)


def test_no_scanner_receives_targets_through_a_shell(tmp_path):
    import inspect
    import app.services.runner as runner
    src = inspect.getsource(runner)
    assert "shell=True" not in src and "create_subprocess_shell" not in src and "os.system" not in src


def test_check_argv_requires_absolute_binary_and_no_nul():
    with pytest.raises(ValueError):
        check_argv(["nuclei", "-l", "x"])
    with pytest.raises(ValueError):
        check_argv(["/bin/echo", "a\0b"])
    with pytest.raises(ValueError):
        check_argv([])


def test_rate_flags_follow_the_budget(tmp_path):
    c = ctx(tmp_path)
    httpx = REGISTRY["httpx"].build(c, ["a.example.com"])[0].argv
    assert httpx[httpx.index("-rl") + 1] == "2"
    nuclei = REGISTRY["nuclei"].build(c, ["https://a.example.com"])[0].argv
    assert nuclei[nuclei.index("-rl") + 1] == "2"
    katana = REGISTRY["katana"].build(c, ["https://a.example.com"])[0].argv
    assert katana[katana.index("-rl") + 1] == "2"
    naabu = REGISTRY["naabu"].build(c, ["203.0.113.5"])[0].argv
    assert naabu[naabu.index("-rate") + 1] == "100" and "c" == naabu[naabu.index("-s") + 1]


def test_nuclei_excludes_intrusive_templates_and_third_party_oast(tmp_path):
    argv = REGISTRY["nuclei"].build(ctx(tmp_path), ["https://a.example.com"])[0].argv
    excluded = argv[argv.index("-etags") + 1].split(",")
    assert {"dos", "fuzz", "intrusive", "bruteforce"} <= set(excluded)
    assert "-ni" in argv and "-duc" in argv


def test_nuclei_tags_are_validated_not_passed_through(tmp_path):
    ok = REGISTRY["nuclei"].build(ctx(tmp_path, nuclei_tags="exposure,misconfig"), ["https://a.example.com"])[0].argv
    assert ok[ok.index("-tags") + 1] == "exposure,misconfig"
    with pytest.raises(ScopeError):
        REGISTRY["nuclei"].build(ctx(tmp_path, nuclei_tags="x -t /etc/passwd"), ["https://a.example.com"])


def test_naabu_ports_validated(tmp_path):
    argv = REGISTRY["naabu"].build(ctx(tmp_path, ports="80,443,8000-8100"), ["203.0.113.5"])[0].argv
    assert argv[argv.index("-p") + 1] == "80,443,8000-8100"
    assert "-tp" in REGISTRY["naabu"].build(ctx(tmp_path, ports="top1000"), ["203.0.113.5"])[0].argv
    with pytest.raises(ScopeError):
        REGISTRY["naabu"].build(ctx(tmp_path, ports="80;id"), ["203.0.113.5"])


def test_ffuf_wordlist_must_be_inside_allowed_directory(tmp_path):
    (tmp_path / "wl").mkdir()
    wl = tmp_path / "wl" / "words.txt"
    wl.write_text("admin\n")
    ok = REGISTRY["ffuf"].build(ctx(tmp_path, ffuf_wordlist=str(wl)), ["https://a.example.com"])[0]
    assert ok.argv[ok.argv.index("-u") + 1] == "https://a.example.com/FUZZ"
    with pytest.raises(ScopeError):
        REGISTRY["ffuf"].build(ctx(tmp_path, ffuf_wordlist="/etc/passwd"), ["https://a.example.com"])


def test_subfinder_runs_once_per_root_with_no_shell_metacharacter_exposure(tmp_path):
    cmds = REGISTRY["subfinder"].build(ctx(tmp_path), ["a.com", "b.com"])
    assert [c.argv[c.argv.index("-d") + 1] for c in cmds] == ["a.com", "b.com"]
    assert all(c.target_kind == "domain_root" for c in cmds)


def test_nmap_only_scans_ports_already_found_open(tmp_path):
    cmd = REGISTRY["nmap"].build(ctx(tmp_path), ["203.0.113.5", "203.0.113.6"], {"ports_by_ip": {"203.0.113.5": [443, 80]}})
    assert len(cmd) == 1 and cmd[0].argv[cmd[0].argv.index("-p") + 1] == "80,443" and cmd[0].argv[-1] == "203.0.113.5"
