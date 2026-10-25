"""Hostname rules for entries.*.allow_hosts.

The grant command is stricter than a file the MCP already accepted: a human
types a hostname. Loading a file accepts what the MCP would use (a URL is the
hostname inside it) and reports what cannot take effect.
"""
import allow_hosts


def _ok(value: str, expected: str, *, strict: bool) -> None:
    verdict = allow_hosts.judge(value, strict=strict)
    assert verdict.problem is None, verdict.problem
    assert verdict.normalized == expected


def _bad(value: str, snippet: str, *, strict: bool) -> None:
    verdict = allow_hosts.judge(value, strict=strict)
    assert verdict.problem, value
    assert snippet in verdict.problem


def test_grant_normalises_case_trailing_dot_and_idna():
    _ok("API.Ledger.Example.", "api.ledger.example", strict=True)
    _ok("bücher.example", "xn--bcher-kva.example", strict=True)
    _ok("*.GHCR.IO.", "*.ghcr.io", strict=True)


def test_grant_accepts_a_leading_wildcard_and_refuses_any_other():
    _ok("*.ghcr.io", "*.ghcr.io", strict=True)
    _bad("*", "wildcard", strict=True)
    _bad("*.*.ghcr.io", "wildcard", strict=True)
    _bad("foo.*.ghcr.io", "wildcard", strict=True)
    _bad("*ghcr.io", "wildcard", strict=True)


def test_grant_refuses_scheme_path_and_port():
    for value in (
        "https://api.ledger.example/v1",
        "api.ledger.example/v1",
        "api.ledger.example:443",
        "//api.ledger.example",
    ):
        _bad(value, "hostname", strict=True)


def test_load_accepts_a_url_or_port_as_the_hostname_the_mcp_would_use():
    _ok("https://API.Ledger.Example:443/v1", "api.ledger.example", strict=False)
    _ok("api.ledger.example:443", "api.ledger.example", strict=False)
    _ok("*.GHCR.IO:443", "*.ghcr.io", strict=False)


def test_loopback_private_and_link_local_are_refused_on_grant_and_on_load():
    for value in ("127.0.0.1", "10.1.2.3", "169.254.169.254", "::1", "fe80::1", "localhost", "printer.local"):
        _bad(value, value, strict=True)
        _bad(value, value, strict=False)
    loopback = allow_hosts.judge("127.0.0.1", strict=True)
    assert "loopback" in loopback.problem
    private = allow_hosts.judge("192.168.1.1", strict=True)
    assert "private" in private.problem
    link_local = allow_hosts.judge("169.254.169.254", strict=True)
    assert "link-local" in link_local.problem


def test_a_public_ip_is_not_a_hostname_grant_but_a_file_may_already_contain_one():
    """The MCP matches a public IP literal exactly. The grant command does not write one."""
    _bad("8.8.8.8", "IP address", strict=True)
    _ok("8.8.8.8", "8.8.8.8", strict=False)


def test_bare_public_suffixes_are_refused():
    for value in ("com", "co.uk", "*.co.uk", "github.io", "*.github.io"):
        _bad(value, "public suffix", strict=True)
        _bad(value, "public suffix", strict=False)
    _ok("bank.co.uk", "bank.co.uk", strict=True)
    _ok("psam.github.io", "psam.github.io", strict=True)
    _ok("*.ghcr.io", "*.ghcr.io", strict=True)


def test_same_host_ignores_case_and_a_url_the_mcp_would_reduce():
    assert allow_hosts.same_host("API.Example.COM.", "api.example.com")
    assert allow_hosts.same_host("https://api.example.com/v1", "api.example.com")
    assert not allow_hosts.same_host("*.example.com", "example.com")
    assert allow_hosts.same_host("127.0.0.1", "127.0.0.1")
