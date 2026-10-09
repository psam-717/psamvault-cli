"""Namespaced API key names: project/.env/KEY can be listed, resolved, and addressed."""

from unittest.mock import patch

from typer.testing import CliRunner

from api_key_names import (
    AmbiguousApiKeyName,
    entry_name_error,
    is_stale_env_source,
    parse_api_key_name,
    prepare_list_items,
    resolve_api_key_name,
)
from errors import NotFoundError

runner = CliRunner()

STORED = "atlas054probe/.env/my_custom_key"
LIVE = "env/.env/openrouter_api_key"
BAK_A = "env/.env.bak-20260911t114609z/openrouter_api_key"
BAK_B = "env/.env.bak-20260926t091410z/openrouter_api_key"


def test_parse_splits_a_project_key_and_an_unscoped_backup():
    project = parse_api_key_name(STORED)
    assert project["project"] == "atlas054probe"
    assert project["display_project"] == "atlas054probe"
    assert project["key_name"] == "my_custom_key"
    assert project["source"] == ".env"
    assert project["stale"] is False

    backup = parse_api_key_name(BAK_A)
    assert backup["display_project"] == "(unscoped)"
    assert backup["source"] == ".env.bak-20260911t114609z"
    assert backup["stale"] is True


def test_standalone_name_is_not_treated_as_a_project():
    parsed = parse_api_key_name("openai-prod")
    assert parsed["namespaced"] is False
    assert parsed["key_name"] == "openai-prod"
    assert parsed["display_project"] is None


def test_live_env_variants_are_not_stale_backups():
    assert is_stale_env_source(".env") is False
    assert is_stale_env_source(".env.local") is False
    assert is_stale_env_source(".env.production") is False
    assert is_stale_env_source(".env.old") is True
    assert is_stale_env_source(".env.save") is True
    assert is_stale_env_source(".env.20260926") is True


def test_composed_name_is_allowed_and_a_bare_slash_is_not():
    assert entry_name_error(STORED) is None
    assert entry_name_error("openai-prod") is None
    error = entry_name_error("foo/bar")
    assert error is not None
    assert "'/'" in error
    assert entry_name_error("   ") is not None


def test_leaf_resolves_to_the_one_project_key():
    entries = [{"name": STORED}, {"name": "openai-prod"}]
    assert resolve_api_key_name("my_custom_key", entries) == STORED
    assert resolve_api_key_name(STORED.upper(), entries) == STORED


def test_leaf_prefers_the_live_file_when_backups_share_it():
    entries = [{"name": LIVE}, {"name": BAK_A}, {"name": BAK_B}]
    assert resolve_api_key_name("openrouter_api_key", entries) == LIVE


def test_two_live_rows_are_ambiguous():
    entries = [
        {"name": "atlas/.env/KEY"},
        {"name": "other/.env/KEY"},
    ]
    try:
        resolve_api_key_name("KEY", entries)
    except AmbiguousApiKeyName as exc:
        assert exc.matches == ["atlas/.env/KEY", "other/.env/KEY"]
    else:
        raise AssertionError("expected AmbiguousApiKeyName")


def test_unknown_leaf_is_not_found():
    try:
        resolve_api_key_name("missing", [{"name": STORED}])
    except NotFoundError as exc:
        assert "missing" in exc.message
    else:
        raise AssertionError("expected NotFoundError")


def test_list_folds_backup_copies_onto_the_live_row():
    prepared = prepare_list_items([
        {"name": BAK_A, "updated_at": "2026-09-11T00:00:00Z", "service_hint": "scan"},
        {"name": LIVE, "updated_at": "2026-09-26T00:00:00Z", "service_hint": "scan"},
        {"name": BAK_B, "updated_at": "2026-09-26T00:00:00Z", "service_hint": "scan"},
        {"name": STORED, "updated_at": "2026-09-26T00:00:00Z", "service_hint": "scan"},
        {"name": "openai-prod", "updated_at": "2026-09-01T00:00:00Z", "service_hint": "OpenAI", "notes": "n"},
    ])
    assert prepared["stored"] == 5
    assert prepared["shown"] == 3
    unscoped = prepared["projects"]["(unscoped)"]
    assert len(unscoped) == 1
    assert unscoped[0]["key_name"] == "openrouter_api_key"
    assert unscoped[0]["stale_count"] == 2
    assert prepared["projects"]["atlas054probe"][0]["key_name"] == "my_custom_key"
    assert prepared["standalone"][0]["key_name"] == "openai-prod"


def test_project_filter_matches_the_stored_project():
    prepared = prepare_list_items(
        [{"name": STORED, "updated_at": "2026-09-26"}, {"name": LIVE, "updated_at": "2026-09-26"}],
        project_name="atlas054probe",
    )
    assert prepared["stored"] == 1
    assert list(prepared["projects"]) == ["atlas054probe"]


def test_namespaced_url_keeps_the_slashes(monkeypatch):
    monkeypatch.setenv("PSAMVAULT_API_URL", "https://example.test")
    from api_client import api_key_item_url

    assert api_key_item_url(STORED) == f"https://example.test/apikeys/{STORED}"


def test_ak_delete_sends_the_stored_name_for_a_leaf(monkeypatch):
    from main import app

    deleted = {}

    def delete_entry(access_token, refresh_token, name):
        deleted["name"] = name
        return {"detail": "deleted"}

    fake_session = lambda: {
        "access_token": "x", "refresh_token": "x", "vek": "00" * 32,
    }
    monkeypatch.setattr("session.load_session", fake_session)
    # ``ak_delete`` re-reads the session after the list call through its own
    # module-level binding (``from session import load_session``), which
    # monkeypatching ``session.load_session`` does not reach. Without this the
    # command reads the real keychain and exits 1 wherever nobody is logged in
    # (CI), while passing on a machine that happens to hold a live session.
    monkeypatch.setattr("command.api_key_commands.load_session", fake_session)
    monkeypatch.setattr("api_client.list_api_key_entries", lambda **kwargs: {
        "entries": [{"name": STORED}], "total": 1,
    })
    monkeypatch.setattr("api_client.delete_api_key_entry", delete_entry)
    with patch("main.start_update_check"), \
         patch("main.check_and_show_upgrade_notice"), \
         patch("main.print_update_notice"):
        result = runner.invoke(app, ["ak-delete", "my_custom_key"], input="y\n")
    assert result.exit_code == 0, result.output
    assert deleted["name"] == STORED
    assert STORED in result.output


def test_ak_delete_refuses_a_slash_that_is_not_a_project_key():
    from main import app

    with patch("main.start_update_check"), \
         patch("main.check_and_show_upgrade_notice"), \
         patch("main.print_update_notice"):
        result = runner.invoke(app, ["ak-delete", "foo/bar"])
    assert result.exit_code != 0
    assert "invalid character" in result.output.lower()


def test_ak_get_full_name_is_accepted(monkeypatch):
    from crypto import encrypt_api_key
    from main import app

    blob, iv = encrypt_api_key(bytes(32), "scan", "sk-live", "")
    fetched = {}

    def get_entry(access_token, refresh_token, name):
        fetched["name"] = name
        return {"name": name, "encrypted_blob": blob, "iv": iv}

    monkeypatch.setattr("session.load_session", lambda: {
        "access_token": "x", "refresh_token": "x", "vek": bytes(32).hex(),
    })
    monkeypatch.setattr("api_client.get_api_key_entry", get_entry)
    monkeypatch.setattr("reveal_gate.require_reveal", lambda **kwargs: None)
    with patch("main.start_update_check"), \
         patch("main.check_and_show_upgrade_notice"), \
         patch("main.print_update_notice"):
        result = runner.invoke(app, ["ak-get", STORED])
    assert result.exit_code == 0, result.output
    assert fetched["name"] == STORED
    assert "sk-live" in result.output


def test_ak_list_prints_the_leaf_and_folds_stale_copies(monkeypatch):
    from main import app

    monkeypatch.setattr("session.load_session", lambda: {
        "access_token": "x", "refresh_token": "x", "vek": "00" * 32,
    })
    monkeypatch.setattr("api_client.list_api_key_entries", lambda **kwargs: {
        "entries": [
            {"name": LIVE, "service_hint": "scan", "updated_at": "2026-09-26T00:00:00Z"},
            {"name": BAK_A, "service_hint": "scan", "updated_at": "2026-09-11T00:00:00Z"},
            {"name": STORED, "service_hint": "scan", "updated_at": "2026-09-26T00:00:00Z"},
        ],
        "total": 3,
    })
    with patch("main.start_update_check"), \
         patch("main.check_and_show_upgrade_notice"), \
         patch("main.print_update_notice"):
        result = runner.invoke(app, ["ak-list"])
    assert result.exit_code == 0, result.output
    assert "Project: (unscoped)" in result.output
    assert "Project: atlas054probe" in result.output
    assert "openrouter_api_key" in result.output
    assert "(+1 stale)" in result.output
    assert "my_custom_key" in result.output
    assert BAK_A not in result.output
