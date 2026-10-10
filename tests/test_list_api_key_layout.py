"""`psamvault list` presents API keys the way `ak-list` does.

The API KEYS section of the combined listing is a summary of the same data, not a
second, differently-shaped report: keys group by project, backup copies of a live
key fold onto the live row, and standalone names come last. A raw stored name
(`env/.env.bak-.../openrouter_api_key`) is a storage detail, not something to read.
"""

from unittest.mock import patch

from typer.testing import CliRunner

runner = CliRunner()

LIVE = "env/.env/openrouter_api_key"
BAK_A = "env/.env.bak-20260911t114609z/openrouter_api_key"
STORED = "atlas054probe/.env/my_custom_key"
STANDALONE = "github_token"

AK_ENTRIES = [
    {"name": LIVE, "service_hint": "scan", "updated_at": "2026-09-26T00:00:00Z"},
    {"name": BAK_A, "service_hint": "scan", "updated_at": "2026-09-11T00:00:00Z"},
    {"name": STORED, "service_hint": "scan", "updated_at": "2026-09-26T00:00:00Z"},
    {"name": STANDALONE, "service_hint": "Github", "updated_at": "2026-09-10T00:00:00Z"},
]

SITE = {"site_name": "postgresql", "username_hint": "psam", "updated_at": "2026-09-01T00:00:00Z"}
NOTE = {"title": "Recovery drill", "category": "ops", "updated_at": "2026-09-02T00:00:00Z"}

SESSION = {"access_token": "x", "refresh_token": "x", "vek": "00" * 32}


def _stub(monkeypatch):
    """A vault with one site, one note and four API key rows (one a backup copy)."""
    monkeypatch.setattr("api_client.ensure_session", lambda: dict(SESSION))
    monkeypatch.setattr("command.vault_commands.load_session", lambda: dict(SESSION))
    monkeypatch.setattr("session.load_session", lambda: dict(SESSION))
    monkeypatch.setattr("api_client.list_vault_entries", lambda **kwargs: {"entries": [SITE], "total": 1})
    monkeypatch.setattr(
        "api_client.list_api_key_entries",
        lambda **kwargs: {"entries": AK_ENTRIES, "total": len(AK_ENTRIES)},
    )
    monkeypatch.setattr("api_client.list_note_entries", lambda **kwargs: {"entries": [NOTE], "total": 1})


def _invoke(monkeypatch, command):
    from main import app

    _stub(monkeypatch)
    with patch("main.start_update_check"), \
         patch("main.check_and_show_upgrade_notice"), \
         patch("main.print_update_notice"):
        return runner.invoke(app, command)


def test_list_groups_project_api_keys_and_folds_backup_copies(monkeypatch):
    result = _invoke(monkeypatch, ["list"])
    assert result.exit_code == 0, result.output

    assert "Project: (unscoped)" in result.output
    assert "Project: atlas054probe" in result.output
    assert "openrouter_api_key" in result.output
    assert "my_custom_key" in result.output
    assert "(+1 stale)" in result.output


def test_list_never_prints_a_raw_stored_name(monkeypatch):
    result = _invoke(monkeypatch, ["list"])
    assert BAK_A not in result.output
    assert "env/.env.bak-20260911t114609z" not in result.output


def test_list_groups_standalone_keys_and_reports_the_folded_count(monkeypatch):
    result = _invoke(monkeypatch, ["list"])
    assert "Standalone Keys" in result.output
    assert STANDALONE in result.output
    assert "4 stored, 3 shown (stale copies folded)." in result.output


def test_list_renders_the_api_key_block_exactly_as_ak_list_does(monkeypatch):
    """Anti-drift: the two commands share one renderer, so their lines match verbatim.

    If someone changes the grouping, the column layout or the summary in one command
    only, this fails.
    """
    ak_output = _invoke(monkeypatch, ["ak-list"]).output
    list_output = _invoke(monkeypatch, ["list"]).output

    ak_lines = [line for line in ak_output.splitlines() if line.strip()]
    assert ak_lines, "ak-list printed nothing to compare"
    missing = [line for line in ak_lines if line not in list_output]
    assert not missing, f"list does not render these ak-list lines:\n" + "\n".join(repr(l) for l in missing)


def test_list_still_shows_site_credentials_and_notes(monkeypatch):
    result = _invoke(monkeypatch, ["list"])
    assert "SITE CREDENTIALS" in result.output
    assert "postgresql" in result.output
    assert "SECURE NOTES" in result.output
    assert "Recovery drill" in result.output


def test_a_long_source_label_does_not_break_the_columns(monkeypatch):
    """A backup-only row carries the longest source label in the list.

    `env/.env.bak-20260926t091411z/render_api_key` renders as
    `.env.bak-20260926t091411z (stale)` — wider than the default column. Every row of
    the table must still put the date in the same place.
    """
    from main import app
    import re

    backup_only = "env/.env.bak-20260926t091411z/render_api_key"
    monkeypatch.setattr("api_client.ensure_session", lambda: dict(SESSION))
    monkeypatch.setattr("command.vault_commands.load_session", lambda: dict(SESSION))
    monkeypatch.setattr("session.load_session", lambda: dict(SESSION))
    monkeypatch.setattr("api_client.list_vault_entries", lambda **kwargs: {"entries": [], "total": 0})
    monkeypatch.setattr(
        "api_client.list_api_key_entries",
        lambda **kwargs: {
            "entries": [
                {"name": LIVE, "service_hint": "scan", "updated_at": "2026-09-26T00:00:00Z"},
                {"name": backup_only, "service_hint": "scan", "updated_at": "2026-09-26T00:00:00Z"},
            ],
            "total": 2,
        },
    )
    monkeypatch.setattr("api_client.list_note_entries", lambda **kwargs: {"entries": [], "total": 0})

    with patch("main.start_update_check"), \
         patch("main.check_and_show_upgrade_notice"), \
         patch("main.print_update_notice"):
        result = runner.invoke(app, ["list"])
    assert result.exit_code == 0, result.output

    rows = [
        line for line in result.output.splitlines()
        if line.startswith("    ") and re.search(r"\d{4}-\d{2}-\d{2}$", line)
    ]
    assert len(rows) >= 2, result.output
    widths = {len(line) for line in rows}
    assert len(widths) == 1, "the date column is not aligned:\n" + "\n".join(repr(r) for r in rows)
