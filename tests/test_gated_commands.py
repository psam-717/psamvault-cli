"""The four gated commands, driven through the real CLI.

These tests run the actual Typer app with the actual classifier, policy loader,
gate and audit writer — only the session and the HTTP calls are faked. That is
the point: a unit-tested gate that no command calls would still leak.
"""
from unittest.mock import Mock, patch

import pytest
from typer.testing import CliRunner

import api_client
import audit
import session
from crypto import encrypt_api_key, encrypt_credentials, encrypt_note
from errors import NotFoundError
from main import app

runner = CliRunner()

VEK = bytes(range(32))
SITE_PASSWORD = "correct-horse-battery-staple"
API_KEY_VALUE = "sk-live-do-not-leak-me"
NOTE_BODY = "private-key-material-here"

FAKE_SESSION = {"access_token": "t", "refresh_token": "r", "vek": VEK.hex()}


def creds_entry():
    blob, iv = encrypt_credentials(VEK, "alice@example.com", SITE_PASSWORD, "")
    return {
        "site_name": "github.com",
        "encrypted_blob": blob,
        "iv": iv,
        "login_url": "",
        "username_hint": "alice@example.com",
    }


def ak_entry():
    blob, iv = encrypt_api_key(VEK, "GitHub", API_KEY_VALUE, "")
    return {"name": "github-prod", "encrypted_blob": blob, "iv": iv, "service_hint": "GitHub"}


def note_entry():
    blob, iv = encrypt_note(VEK, NOTE_BODY)
    return {"title": "ssh-key", "category": None, "encrypted_blob": blob, "iv": iv}


def as_agent(monkeypatch):
    """The signal a real agent runtime leaves behind."""
    monkeypatch.setenv("PSAMVAULT_AGENT", "1")


def last_audit_row():
    rows = audit.read(audit.AUDIT_FILE)
    assert rows, "the gate must record a decision"
    return rows[-1]


# ── get ───────────────────────────────────────────────────────────────────


def test_get_refuses_an_agent_and_keeps_the_secret_out_of_the_output(monkeypatch):
    as_agent(monkeypatch)
    with patch("api_client.ensure_session", return_value=FAKE_SESSION), \
         patch("api_client.get_vault_entry", return_value=creds_entry()):
        result = runner.invoke(app, ["get", "github.com"])

    assert result.exit_code == 1
    assert "blocked" in result.output
    assert "agent terminal detected" in result.output
    assert SITE_PASSWORD not in result.output
    row = last_audit_row()
    assert row["decision"] == "deny"
    assert row["command"] == "get"
    assert row["entry"] == "github.com"
    assert row["signals"] == ["explicit:PSAMVAULT_AGENT"]


def test_get_refusal_points_at_the_capability_alternatives(monkeypatch):
    as_agent(monkeypatch)
    with patch("api_client.ensure_session", return_value=FAKE_SESSION), \
         patch("api_client.get_vault_entry", return_value=creds_entry()):
        result = runner.invoke(app, ["get", "github.com"])

    assert "psamvault approve github.com --for-agent" in result.output
    assert "use_credential" in result.output
    assert "browser_login" in result.output


def test_get_still_works_for_a_clean_caller():
    """The default policy must not change what a human's machine does."""
    with patch("api_client.ensure_session", return_value=FAKE_SESSION), \
         patch("api_client.get_vault_entry", return_value=creds_entry()):
        result = runner.invoke(app, ["get", "github.com"])

    assert result.exit_code == 0
    assert SITE_PASSWORD in result.output
    assert last_audit_row()["decision"] == "allow"


def test_get_copy_is_gated_too(monkeypatch):
    """--copy is a reveal: the clipboard is readable by the agent."""
    as_agent(monkeypatch)
    with patch("api_client.ensure_session", return_value=FAKE_SESSION), \
         patch("api_client.get_vault_entry", return_value=creds_entry()), \
         patch("command.vault_commands.pyperclip") as clipboard:
        result = runner.invoke(app, ["get", "github.com", "--copy"])

    assert result.exit_code == 1
    assert not clipboard.copy.called, "the guardrail must cover --copy"


def test_get_with_a_live_approval_reveals_exactly_once(monkeypatch, fake_keychain):
    as_agent(monkeypatch)
    session.mint_approval("github.com", ttl_seconds=120)

    with patch("api_client.ensure_session", return_value=FAKE_SESSION), \
         patch("api_client.get_vault_entry", return_value=creds_entry()):
        first = runner.invoke(app, ["get", "github.com"])
        second = runner.invoke(app, ["get", "github.com"])

    assert first.exit_code == 0
    assert SITE_PASSWORD in first.output
    assert second.exit_code == 1
    assert SITE_PASSWORD not in second.output
    assert [r["decision"] for r in audit.read(audit.AUDIT_FILE)] == ["approved", "deny"]


def test_an_expired_approval_does_not_reveal(monkeypatch, fake_keychain):
    as_agent(monkeypatch)
    session.mint_approval("github.com", ttl_seconds=15, now=1000.0)

    with patch("api_client.ensure_session", return_value=FAKE_SESSION), \
         patch("api_client.get_vault_entry", return_value=creds_entry()):
        result = runner.invoke(app, ["get", "github.com"])

    assert result.exit_code == 1
    assert SITE_PASSWORD not in result.output


def test_a_failed_fetch_does_not_burn_the_approval(monkeypatch, fake_keychain):
    """The gate runs at the emit point, so a 404 must not consume the token."""
    as_agent(monkeypatch)
    session.mint_approval("github.com", ttl_seconds=120)

    with patch("api_client.ensure_session", return_value=FAKE_SESSION), \
         patch("api_client.get_vault_entry", side_effect=NotFoundError("nope")):
        miss = runner.invoke(app, ["get", "github.com"])
    assert miss.exit_code == 1

    with patch("api_client.ensure_session", return_value=FAKE_SESSION), \
         patch("api_client.get_vault_entry", return_value=creds_entry()):
        hit = runner.invoke(app, ["get", "github.com"])
    assert hit.exit_code == 0, "the approval should still be live after a failed fetch"
    assert SITE_PASSWORD in hit.output


# ── ak-get / note-get ─────────────────────────────────────────────────────


def test_ak_get_refuses_an_agent(monkeypatch):
    as_agent(monkeypatch)
    with patch("api_client.ensure_session", return_value=FAKE_SESSION), \
         patch("api_client.get_api_key_entry", return_value=ak_entry()):
        result = runner.invoke(app, ["ak-get", "github-prod"])

    assert result.exit_code == 1
    assert API_KEY_VALUE not in result.output
    assert last_audit_row()["command"] == "ak-get"


def test_ak_get_reveals_once_with_an_approval(monkeypatch, fake_keychain):
    as_agent(monkeypatch)
    session.mint_approval("github-prod", ttl_seconds=120)
    with patch("api_client.ensure_session", return_value=FAKE_SESSION), \
         patch("api_client.get_api_key_entry", return_value=ak_entry()):
        result = runner.invoke(app, ["ak-get", "github-prod"])

    assert result.exit_code == 0
    assert API_KEY_VALUE in result.output


def test_note_get_refuses_an_agent_and_keeps_the_body_out(monkeypatch):
    as_agent(monkeypatch)
    with patch("api_client.ensure_session", return_value=FAKE_SESSION), \
         patch("api_client.get_note_entry", return_value=note_entry()):
        result = runner.invoke(app, ["note-get", "ssh-key"])

    assert result.exit_code == 1
    assert NOTE_BODY not in result.output
    assert last_audit_row()["command"] == "note-get"


# ── discovery stays open ──────────────────────────────────────────────────


def test_discovery_is_never_gated(monkeypatch):
    """An agent must be able to learn WHAT exists, just not the values."""
    as_agent(monkeypatch)
    payload = {
        "entries": [
            {
                "site_name": "github.com",
                "username_hint": "alice@example.com",
                "updated_at": "2026-09-01T00:00:00Z",
            }
        ],
        "total": 1,
    }
    empty = {"entries": [], "total": 0}
    with patch("api_client.ensure_session", return_value=FAKE_SESSION), \
         patch("command.vault_commands.load_session", return_value=FAKE_SESSION), \
         patch("api_client.list_vault_entries", return_value=payload), \
         patch("api_client.list_api_key_entries", return_value=empty), \
         patch("api_client.list_note_entries", return_value=empty):
        result = runner.invoke(app, ["list"])

    assert result.exit_code == 0, result.output
    assert "github.com" in result.output


# ── export --plaintext ────────────────────────────────────────────────────


def test_plaintext_export_is_refused_for_an_agent_before_any_fetch(monkeypatch, tmp_path):
    as_agent(monkeypatch)
    export_vault = Mock()
    with patch("command.export_command.is_logged_in", return_value=True), \
         patch("api_client.ensure_session", return_value=FAKE_SESSION), \
         patch("api_client.export_vault", export_vault):
        result = runner.invoke(app, ["export", "--plaintext"])

    assert result.exit_code == 1
    assert "blocked" in result.output
    assert "whole-vault dump cannot be approved" in result.output
    assert not export_vault.called, "nothing should be read out of the vault for a refused dump"
    assert last_audit_row()["decision"] == "deny"


def test_plaintext_export_still_works_for_a_clean_caller(tmp_path):
    """A human (or their script) keeps the existing behaviour and confirmation."""
    with patch("command.export_command.is_logged_in", return_value=True), \
         patch("command.export_command._DESKTOP", tmp_path), \
         patch("api_client.ensure_session", return_value=FAKE_SESSION), \
         patch("command.export_command.load_session", return_value=FAKE_SESSION), \
         patch("api_client.export_vault", return_value=[creds_entry()]), \
         patch("api_client.export_api_keys", return_value=[ak_entry()]), \
         patch("api_client.export_notes", return_value=[note_entry()]):
        result = runner.invoke(app, ["export", "--plaintext"], input="y\n")

    assert result.exit_code == 0, result.output
    written = list(tmp_path.glob("psamvault-backup-plaintext-*.json"))
    assert written, "the plaintext backup should still be written"
    body = written[0].read_text(encoding="utf-8")
    assert SITE_PASSWORD in body
    assert "3 secret(s)" in result.output, "the confirmation must name how many secrets it exposes"
    assert last_audit_row()["decision"] == "allow"


def test_encrypted_export_is_never_gated(monkeypatch, tmp_path):
    """Only --plaintext reveals; the encrypted path is not a reveal at all."""
    as_agent(monkeypatch)
    with patch("command.export_command.is_logged_in", return_value=True), \
         patch("command.export_command._DESKTOP", tmp_path), \
         patch("api_client.ensure_session", return_value=FAKE_SESSION), \
         patch("command.export_command.load_session", return_value=FAKE_SESSION), \
         patch("api_client.export_vault", return_value=[creds_entry()]), \
         patch("api_client.export_api_keys", return_value=[]), \
         patch("api_client.export_notes", return_value=[]):
        result = runner.invoke(app, ["export"], input="Passphrase1\nPassphrase1\n")

    assert "blocked" not in result.output
    assert list(tmp_path.glob("psamvault-backup-2*.json")), "encrypted export should still write"
