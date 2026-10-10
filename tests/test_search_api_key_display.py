"""`psamvault search` names an API key the way `ak-list` does.

A match on a project-scoped key used to print the stored name verbatim
(`atlas054probe/.env/my_custom_key`) — the storage detail, not the entry. It now prints
the leaf name plus the project and source that identify the row, which is also what
`ak-get` and `ak-delete` accept.
"""

from unittest.mock import patch

from typer.testing import CliRunner

runner = CliRunner()

STORED = "atlas054probe/.env/my_custom_key"
STANDALONE = "github_token"
SESSION = {"access_token": "x", "refresh_token": "x", "vek": "00" * 32}


def _invoke(monkeypatch, api_key_rows, command):
    from main import app

    monkeypatch.setattr("command.vault_commands._get_session_and_key", lambda: (dict(SESSION), bytes(32)))
    monkeypatch.setattr("session.load_session", lambda: dict(SESSION))
    monkeypatch.setattr("command.vault_commands._search_credentials", lambda *a, **k: [])
    monkeypatch.setattr("command.vault_commands._search_notes", lambda *a, **k: [])
    monkeypatch.setattr("command.vault_commands._search_api_keys", lambda *a, **k: api_key_rows)
    monkeypatch.setattr("api_client.export_vault", lambda **k: [])
    monkeypatch.setattr("api_client.export_api_keys", lambda **k: [])
    monkeypatch.setattr("api_client.export_notes", lambda **k: [])
    with patch("main.start_update_check"), \
         patch("main.check_and_show_upgrade_notice"), \
         patch("main.print_update_notice"):
        return runner.invoke(app, command)


def test_search_names_a_project_key_by_its_leaf_and_project(monkeypatch):
    result = _invoke(monkeypatch, [
        {"name": STORED, "service": "scan", "api_key": "sk-live-value", "notes": None},
    ], ["search", "custom"])
    assert result.exit_code == 0, result.output

    assert STORED not in result.output, "the raw stored name is still printed"
    assert "Name:     my_custom_key" in result.output
    assert "Project:  atlas054probe" in result.output
    assert "Source:   .env" in result.output


def test_search_still_prints_the_key_value(monkeypatch):
    """The display change must not turn search into a lister."""
    result = _invoke(monkeypatch, [
        {"name": STORED, "service": "scan", "api_key": "sk-live-value", "notes": None},
    ], ["search", "custom"])
    assert "sk-live-value" in result.output


def test_search_leaves_a_standalone_key_alone(monkeypatch):
    result = _invoke(monkeypatch, [
        {"name": STANDALONE, "service": "Github", "api_key": "ghp_value", "notes": None},
    ], ["search", "github"])
    assert result.exit_code == 0, result.output
    assert "Name:     github_token" in result.output
    assert "Project:" not in result.output
    assert "Source:" not in result.output


def test_search_shows_an_unscoped_key_under_its_unscoped_project(monkeypatch):
    result = _invoke(monkeypatch, [
        {"name": "env/.env/resend_api_key", "service": "scan", "api_key": "re_live", "notes": None},
    ], ["search", "resend"])
    assert "Name:     resend_api_key" in result.output
    assert "Project:  (unscoped)" in result.output
    assert "env/.env/resend_api_key" not in result.output
