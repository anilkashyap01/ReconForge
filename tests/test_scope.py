import pytest

from app.scope import (Scope, ScopeError, ScopeViolation, filter_hosts, parse_scope_entry, revalidate_ips, revalidate_targets,
                       safe_path_under, validate_ident_list, validate_port_spec)


def scope(inc, exc=()):
    return Scope.from_strings(inc, exc)


def test_exact_domain_does_not_include_subdomains():
    s = scope(["example.com"])
    assert s.host_allowed("example.com")[0]
    assert not s.host_allowed("api.example.com")[0]


def test_wildcard_covers_subdomains_but_not_apex_or_lookalikes():
    s = scope(["*.example.com"])
    assert s.host_allowed("api.example.com")[0] and s.host_allowed("a.b.example.com")[0]
    assert not s.host_allowed("example.com")[0]
    assert not s.host_allowed("example.com.evil.net")[0]
    assert not s.host_allowed("badexample.com")[0]


def test_exclusions_override_inclusions():
    s = scope(["*.example.com"], ["admin.example.com", "*.internal.example.com"])
    assert not s.host_allowed("admin.example.com")[0]
    assert not s.host_allowed("db.internal.example.com")[0]
    assert s.host_allowed("www.example.com")[0]


def test_ips_need_explicit_authorisation():
    s = scope(["203.0.113.0/30"])
    assert s.ip_allowed("203.0.113.2")[0]
    assert not s.ip_allowed("203.0.113.9")[0]
    assert not s.ip_allowed("8.8.8.8")[0]


def test_resolved_ips_blocked_unless_opted_in_and_never_private():
    s = scope(["*.example.com"])
    assert not s.ip_scannable("93.184.216.34", False)[0]
    assert s.ip_scannable("93.184.216.34", True)[0]
    for bad in ("127.0.0.1", "10.0.0.5", "169.254.169.254", "192.168.1.1", "::1"):
        assert not s.ip_scannable(bad, True)[0], bad


def test_url_scope_checks_host_and_scheme():
    s = scope(["*.example.com"])
    assert s.url_allowed("https://api.example.com/login?a=1")[0]
    assert not s.url_allowed("https://evil.net/")[0]
    assert not s.url_allowed("https://api.example.com@evil.net/")[0]
    assert not s.url_allowed("ftp://api.example.com/")[0]
    assert not s.url_allowed("javascript:alert(1)")[0]


@pytest.mark.parametrize("bad", ["", "   ", "exa mple.com", "example.com; rm -rf /", "$(id).example.com", "-oN.example.com", "ex`id`.com",
                                 "http://example.com/path?x=1", "*", "*.*.example.com", "a" * 300 + ".com", "example.com\nevil.com", "0.0.0.0/0", "10.0.0.0/8"])
def test_malformed_or_dangerous_entries_are_rejected(bad):
    with pytest.raises(ScopeError):
        parse_scope_entry(bad)


def test_filter_hosts_reports_rejections():
    s = scope(["*.example.com"], ["admin.example.com"])
    ok, rejected = filter_hosts(s, ["a.example.com", "admin.example.com", "evil.net", "A.EXAMPLE.COM"])
    assert ok == ["a.example.com"]
    assert {h for h, _ in rejected} == {"admin.example.com", "evil.net"}


def test_revalidate_blocks_out_of_scope_and_option_like_tokens():
    s = scope(["*.example.com"])
    revalidate_targets(s, "host", ["a.example.com"])
    with pytest.raises(ScopeViolation):
        revalidate_targets(s, "host", ["a.example.com", "evil.net"])
    with pytest.raises(ScopeViolation):
        revalidate_targets(s, "host", ["-iL"])
    with pytest.raises(ScopeViolation):
        revalidate_targets(s, "url", ["https://a.example.com/\nhttps://evil.net"])
    revalidate_targets(s, "domain_root", ["example.com"])          # root of the *.example.com entry
    with pytest.raises(ScopeViolation):
        revalidate_targets(scope(["example.com"]), "domain_root", ["example.com"])   # exact entry: no subdomain enumeration


def test_revalidate_ips():
    s = scope(["203.0.113.5"])
    revalidate_ips(s, ["203.0.113.5"])
    with pytest.raises(ScopeViolation):
        revalidate_ips(s, ["203.0.113.6"])
    with pytest.raises(ScopeViolation):
        revalidate_ips(s, ["--script"])


def test_port_spec_and_ident_validation():
    assert validate_port_spec("top100") and validate_port_spec("80,443,8000-8010")
    for bad in ("0", "70000", "80;id", "-p", "80,,443", "99999-1"):
        with pytest.raises(ScopeError):
            validate_port_spec(bad)
    assert validate_ident_list("exposure,misconfiguration", "tags") == "exposure,misconfiguration"
    with pytest.raises(ScopeError):
        validate_ident_list("cve,$(id)", "tags")


def test_safe_path_under(tmp_path):
    root = tmp_path / "w"
    root.mkdir()
    good = root / "list.txt"
    good.write_text("a")
    assert safe_path_under(str(good), (root,)) == good.resolve()
    (tmp_path / "secret.txt").write_text("x")
    for bad in (str(tmp_path / "secret.txt"), str(root / ".." / "secret.txt"), "/etc/passwd", ""):
        with pytest.raises(ScopeError):
            safe_path_under(bad, (root,))
    link = root / "link.txt"
    link.symlink_to(tmp_path / "secret.txt")
    with pytest.raises(ScopeError):
        safe_path_under(str(link), (root,))
