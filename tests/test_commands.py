"""
Layer 2: CLI command tests using Typer's CliRunner.
Tests UX behaviour — help output, error messages, exit codes.
No real network calls or keychain access.
"""
import pytest
import typer
from unittest.mock import patch
from typer.testing import CliRunner

from main import app

runner = CliRunner()


@pytest.fixture(autouse=True)
def suppress_background_tasks():
    """
    Prevent the main callback from spawning update-check threads or
    reading the changelog / keychain on every invocation.
    """
    with patch("main.start_update_check"), \
         patch("main.check_and_show_upgrade_notice"), \
         patch("main.print_update_notice"):
        yield


# ── --help ────────────────────────────────────────────────────────────────────

def test_help_lists_all_command_groups():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for group in ("auth", "vault", "ak", "recovery", "browser", "changelog", "upgrade"):
        assert group in result.output


def test_help_mentions_zero_knowledge():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    # The help string explains the security model
    assert "plaintext" in result.output.lower() or "encrypted" in result.output.lower()


# ── --version ─────────────────────────────────────────────────────────────────

def test_version_flag_short():
    result = runner.invoke(app, ["-V"])
    assert result.exit_code == 0
    assert "psamvault" in result.output


def test_version_flag_long():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "psamvault" in result.output


# ── psamvault browser (no subcommand) ─────────────────────────────────────────

def test_browser_no_subcommand_shows_help_table():
    result = runner.invoke(app, ["browser"])
    assert result.exit_code == 0
    assert "psamvault browser" in result.output
    assert "open" in result.output


def test_browser_help_table_includes_flags():
    result = runner.invoke(app, ["browser"])
    assert result.exit_code == 0
    assert "--headless" in result.output
    assert "--no-submit" in result.output


# ── psamvault vault (no subcommand) ───────────────────────────────────────────

def test_vault_no_subcommand_shows_help_table():
    result = runner.invoke(app, ["vault"])
    assert result.exit_code == 0
    assert "psamvault vault" in result.output


def test_vault_help_lists_subcommands():
    result = runner.invoke(app, ["vault"])
    assert result.exit_code == 0
    for cmd in ("add", "get", "list", "update", "delete"):
        assert cmd in result.output


# ── vault commands without a session ──────────────────────────────────────────

def test_vault_add_without_session_exits_nonzero():
    with patch("command.vault_commands.load_session", side_effect=typer.Exit(code=1)):
        result = runner.invoke(app, ["add", "github.com", "--user", "me@test.com", "--pass", "secret"])
    assert result.exit_code != 0


def test_vault_get_without_session_exits_nonzero():
    with patch("command.vault_commands.load_session", side_effect=typer.Exit(code=1)):
        result = runner.invoke(app, ["get", "github.com"])
    assert result.exit_code != 0


def test_vault_list_without_session_exits_nonzero():
    with patch("command.vault_commands.load_session", side_effect=typer.Exit(code=1)):
        result = runner.invoke(app, ["list"])
    assert result.exit_code != 0


def test_vault_delete_without_session_exits_nonzero():
    with patch("command.vault_commands.load_session", side_effect=typer.Exit(code=1)):
        result = runner.invoke(app, ["delete", "github.com"])
    assert result.exit_code != 0


# ── _search_credentials helper ──────────────────────────────────────────────────


def _make_entry(site_name: str, username: str, password: str, notes: str = "", login_url: str = "") -> dict:
    """Helper: encrypt credentials and build a vault entry dict matching export_vault() format."""
    from crypto import encrypt_credentials
    blob, iv = encrypt_credentials(bytes(range(32)), username, password, notes)
    entry = {
        "site_name": site_name,
        "encrypted_blob": blob,
        "iv": iv,
        "login_url": login_url,
        "username_hint": username,
    }
    return entry


def test_search_finds_by_site_name():
    """Search matches site_name case-insensitively."""
    from command.vault_commands import _search_credentials
    vek = bytes(range(32))
    entries = [_make_entry("GitHub.com", "alice", "p4ss", "")]
    results = _search_credentials(vek, entries, "github")
    assert len(results) == 1
    assert results[0]["site_name"] == "GitHub.com"
    assert results[0]["username"] == "alice"


def test_search_finds_by_username():
    """Search matches decrypted username case-insensitively."""
    from command.vault_commands import _search_credentials
    vek = bytes(range(32))
    entries = [_make_entry("example.com", "Alice@Example.com", "s3cret", "")]
    results = _search_credentials(vek, entries, "alice@example")
    assert len(results) == 1
    assert results[0]["site_name"] == "example.com"


def test_search_finds_by_notes():
    """Search matches decrypted notes case-insensitively."""
    from command.vault_commands import _search_credentials
    vek = bytes(range(32))
    entries = [_make_entry("mysite.com", "bob", "p@ss", "2FA enabled on phone")]
    results = _search_credentials(vek, entries, "2fa")
    assert len(results) == 1
    assert results[0]["notes"] == "2FA enabled on phone"


def test_search_does_not_find_by_password():
    """Search does NOT match against the decrypted password field."""
    from command.vault_commands import _search_credentials
    vek = bytes(range(32))
    entries = [_make_entry("bank.com", "alice", "MySecretPass123", "")]
    results = _search_credentials(vek, entries, "SecretPass")
    assert len(results) == 0


def test_search_returns_multiple_matches():
    """Search returns all entries matching the query (multiple matches)."""
    from command.vault_commands import _search_credentials
    vek = bytes(range(32))
    entries = [
        _make_entry("github.com", "alice", "p4ss", "work account"),
        _make_entry("gitlab.com", "alice", "p4ss2", "personal"),
        _make_entry("example.com", "bob", "p4ss3", "work stuff"),
    ]
    results = _search_credentials(vek, entries, "alice")
    assert len(results) == 2


def test_search_returns_no_matches():
    """Search returns empty list when nothing matches."""
    from command.vault_commands import _search_credentials
    vek = bytes(range(32))
    entries = [_make_entry("github.com", "alice", "p4ss", "")]
    results = _search_credentials(vek, entries, "nonexistent")
    assert results == []


def test_search_empty_entries_returns_empty():
    """Search with empty entries list returns empty list."""
    from command.vault_commands import _search_credentials
    vek = bytes(range(32))
    results = _search_credentials(vek, [], "anything")
    assert results == []


def test_search_skips_corrupt_entries():
    """Corrupt entries that fail to decrypt are silently skipped."""
    from command.vault_commands import _search_credentials
    vek = bytes(range(32))
    good = _make_entry("good.com", "alice", "p4ss", "valid notes")
    bad = {
        "site_name": "bad.com",
        "encrypted_blob": "deadbeef" + "00" * 14,  # 16 bytes — enough for AES-GCM but wrong ciphertext
        "iv": "aa" * 12,  # valid 12-byte IV (24 hex chars) that won't match
        "login_url": "",
        "username_hint": "baduser",
    }
    results = _search_credentials(vek, [good, bad], "alice")
    assert len(results) == 1
    assert results[0]["site_name"] == "good.com"


def test_search_result_keys():
    """Each result dict has the expected keys: site_name, username, password, notes, login_url."""
    from command.vault_commands import _search_credentials
    vek = bytes(range(32))
    entries = [_make_entry("test.com", "alice", "p4ss", "my notes", "https://test.com/login")]
    results = _search_credentials(vek, entries, "alice")
    assert len(results) == 1
    result = results[0]
    assert set(result.keys()) == {"site_name", "username", "password", "notes", "login_url"}


def test_search_case_insensitive_site_name():
    """Site name matching is case-insensitive."""
    from command.vault_commands import _search_credentials
    vek = bytes(range(32))
    entries = [_make_entry("MySite.Com", "alice", "p4ss", "")]
    results = _search_credentials(vek, entries, "mysite")
    assert len(results) == 1


def test_search_case_insensitive_username():
    """Username matching is case-insensitive."""
    from command.vault_commands import _search_credentials
    vek = bytes(range(32))
    entries = [_make_entry("site.com", "Alice.Wonderland", "p4ss", "")]
    results = _search_credentials(vek, entries, "wonderland")
    assert len(results) == 1


def test_search_case_insensitive_notes():
    """Notes matching is case-insensitive."""
    from command.vault_commands import _search_credentials
    vek = bytes(range(32))
    entries = [_make_entry("site.com", "alice", "p4ss", "IMPORTANT: Review annually")]
    results = _search_credentials(vek, entries, "review")
    assert len(results) == 1


# ── _search_api_keys helper ────────────────────────────────────────────────────

TEST_VEK = bytes(range(32))


def _make_ak_entry(name: str, service: str, key: str, notes: str = "", hint: str = "") -> dict:
    """Helper: encrypt an API key and build an entry dict matching export_api_keys() format."""
    from crypto import encrypt_api_key
    blob, iv = encrypt_api_key(TEST_VEK, service, key, notes)
    entry = {
        "name": name,
        "encrypted_blob": blob,
        "iv": iv,
        "service_hint": hint or service,
    }
    return entry


def test_search_api_keys_finds_by_name():
    """Search matches entry name case-insensitively."""
    from command.api_key_commands import _search_api_keys
    entries = [_make_ak_entry("xai-prod", "XAI", "sk-mykey123")]
    results = _search_api_keys(TEST_VEK, entries, "xai")
    assert len(results) == 1
    assert results[0]["name"] == "xai-prod"
    assert results[0]["service"] == "XAI"


def test_search_api_keys_finds_by_service():
    """Search matches decrypted service case-insensitively."""
    from command.api_key_commands import _search_api_keys
    entries = [_make_ak_entry("stripe-test", "Stripe", "sk_test_abc")]
    results = _search_api_keys(TEST_VEK, entries, "stripe")
    assert len(results) == 1
    assert results[0]["service"] == "Stripe"


def test_search_api_keys_finds_by_notes():
    """Search matches decrypted notes case-insensitively."""
    from command.api_key_commands import _search_api_keys
    entries = [_make_ak_entry("gh-token", "GitHub", "ghp_xxxx", "read-only, expires 2025-12")]
    results = _search_api_keys(TEST_VEK, entries, "expires")
    assert len(results) == 1
    assert results[0]["notes"] == "read-only, expires 2025-12"


def test_search_api_keys_does_not_find_by_key():
    """Search does NOT match against the decrypted API key value."""
    from command.api_key_commands import _search_api_keys
    entries = [_make_ak_entry("prod", "OpenAI", "sk-secret999")]
    results = _search_api_keys(TEST_VEK, entries, "secret999")
    assert len(results) == 0


def test_search_api_keys_multiple_matches():
    """Search returns all entries matching the query."""
    from command.api_key_commands import _search_api_keys
    entries = [
        _make_ak_entry("gh-personal", "GitHub", "ghp_aaa", "personal token"),
        _make_ak_entry("gh-work", "GitHub", "ghp_bbb", "work token"),
        _make_ak_entry("xai-prod", "XAI", "sk_ccc", "production"),
    ]
    results = _search_api_keys(TEST_VEK, entries, "github")
    assert len(results) == 2


def test_search_api_keys_no_matches():
    """Search returns empty list when nothing matches."""
    from command.api_key_commands import _search_api_keys
    entries = [_make_ak_entry("mykey", "Service", "val")]
    results = _search_api_keys(TEST_VEK, entries, "nonexistent")
    assert results == []


def test_search_api_keys_empty_entries():
    """Search with empty entries list returns empty list."""
    from command.api_key_commands import _search_api_keys
    results = _search_api_keys(TEST_VEK, [], "anything")
    assert results == []


def test_search_api_keys_skips_corrupt_entries():
    """Corrupt entries that fail to decrypt are silently skipped."""
    from command.api_key_commands import _search_api_keys
    good = _make_ak_entry("good-key", "Valid", "sk-valid")
    bad_iv = {
        "name": "bad-iv",
        "encrypted_blob": "aabb" + "00" * 14,
        "iv": "zz",  # invalid hex — will raise ValueError from bytes.fromhex()
        "service_hint": "Bad",
    }
    bad_tag = {
        "name": "bad-tag",
        "encrypted_blob": "deadbeef" + "00" * 14,
        "iv": "aa" * 12,  # valid hex but wrong ciphertext -> InvalidTag
        "service_hint": "Bad",
    }
    results = _search_api_keys(TEST_VEK, [good, bad_iv, bad_tag], "valid")
    assert len(results) == 1
    assert results[0]["name"] == "good-key"


def test_search_api_keys_result_keys():
    """Each result dict has the expected keys: name, service, api_key, notes."""
    from command.api_key_commands import _search_api_keys
    entries = [_make_ak_entry("test-key", "TestSvc", "sk-value", "my notes")]
    results = _search_api_keys(TEST_VEK, entries, "test")
    assert len(results) == 1
    result = results[0]
    assert set(result.keys()) == {"name", "service", "api_key", "notes"}


def test_search_api_keys_case_insensitive_name():
    """Name matching is case-insensitive."""
    from command.api_key_commands import _search_api_keys
    entries = [_make_ak_entry("My-Prod-Key", "Service", "sk-val")]
    results = _search_api_keys(TEST_VEK, entries, "my-prod")
    assert len(results) == 1


def test_search_api_keys_case_insensitive_service():
    """Service matching is case-insensitive."""
    from command.api_key_commands import _search_api_keys
    entries = [_make_ak_entry("key1", "OpenAI", "sk-val")]
    results = _search_api_keys(TEST_VEK, entries, "openai")
    assert len(results) == 1


def test_search_api_keys_case_insensitive_notes():
    """Notes matching is case-insensitive."""
    from command.api_key_commands import _search_api_keys
    entries = [_make_ak_entry("key1", "Svc", "sk-val", "CONFIDENTIAL: Rotate monthly")]
    results = _search_api_keys(TEST_VEK, entries, "monthly")
    assert len(results) == 1


# ── search CLI command integration ──────────────────────────────────────────────


def test_search_command_registered():
    """The search command should be registered on the main app."""
    info = app.registered_commands
    names = [c.name for c in info]
    assert "search" in names


def test_search_command_requires_query():
    """Search without a query should fail with missing argument error."""
    result = runner.invoke(app, ["search"])
    assert result.exit_code != 0
    assert "Missing argument" in result.output
