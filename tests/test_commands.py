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
