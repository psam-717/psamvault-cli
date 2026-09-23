"""``psamvault approve`` — the human half of the handover.

Every test drives the real Typer command. The TTY gate is the interesting part:
``approve`` must be reachable from a human's terminal and unreachable from an
agent's shell, a pipe, or a script — that is what stops an agent approving
itself out of a refusal.
"""
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

import audit
import caller
import session
from main import app

runner = CliRunner()

FAKE_SESSION = {"access_token": "t", "refresh_token": "r", "vek": "00" * 32}

FOUND_SITE = {"site_name": "github.com", "encrypted_blob": "x", "iv": "y"}


def as_human_terminal(monkeypatch):
    monkeypatch.setattr(caller, "tty_present", lambda: True)


def confirm_yes(monkeypatch):
    monkeypatch.setattr("typer.confirm", lambda *a, **k: True)


def confirm_no(monkeypatch):
    monkeypatch.setattr("typer.confirm", lambda *a, **k: False)


def locate_site(monkeypatch):
    """Make the entry-existence check resolve to a site."""
    from errors import NotFoundError

    monkeypatch.setattr("api_client.ensure_session", lambda: FAKE_SESSION)
    monkeypatch.setattr("api_client.get_vault_entry", lambda **kwargs: FOUND_SITE)
    monkeypatch.setattr(
        "api_client.get_api_key_entry", lambda **kwargs: (_ for _ in ()).throw(NotFoundError("no"))
    )


# ── Deliberate friction ───────────────────────────────────────────────────


def test_for_agent_is_required(monkeypatch):
    as_human_terminal(monkeypatch)
    result = runner.invoke(app, ["approve", "github.com"])
    assert result.exit_code == 1
    assert "--for-agent" in result.output


def test_an_agent_or_pipe_cannot_mint_its_own_approval(monkeypatch, fake_keychain):
    """The TTY check is the mechanism that makes self-approval impossible."""
    monkeypatch.setattr(caller, "tty_present", lambda: False)
    with patch("api_client.ensure_session", return_value=FAKE_SESSION):
        result = runner.invoke(app, ["approve", "github.com", "--for-agent"])

    assert result.exit_code == 1
    assert "real terminal" in result.output
    assert session.list_approvals() == [], "no token may be minted without a terminal"


def test_cancelling_mints_nothing(monkeypatch, fake_keychain):
    as_human_terminal(monkeypatch)
    confirm_no(monkeypatch)
    locate_site(monkeypatch)
    result = runner.invoke(app, ["approve", "github.com", "--for-agent"])
    assert result.exit_code == 1
    assert "Cancelled" in result.output
    assert session.list_approvals() == []


# ── The mint ──────────────────────────────────────────────────────────────


def test_a_human_mints_a_one_time_approval(monkeypatch, fake_keychain):
    as_human_terminal(monkeypatch)
    confirm_yes(monkeypatch)
    locate_site(monkeypatch)

    result = runner.invoke(app, ["approve", "github.com", "--for-agent"])

    assert result.exit_code == 0, result.output
    assert "One-time reveal approved for site 'github.com'" in result.output
    assert "succeeds once" in result.output
    approvals = session.list_approvals()
    assert len(approvals) == 1
    assert approvals[0]["entry"] == "github.com"
    assert approvals[0]["single_use"] is True


def test_the_confirmation_names_the_entry_and_the_window(monkeypatch, fake_keychain):
    as_human_terminal(monkeypatch)
    locate_site(monkeypatch)
    seen = {}

    def capture(message, *args, **kwargs):
        seen["message"] = message
        return True

    monkeypatch.setattr("typer.confirm", capture)
    runner.invoke(app, ["approve", "github.com", "--for-agent", "--ttl", "60"])
    assert "'github.com'" in seen["message"]
    assert "60" in seen["message"]


def test_the_mint_is_written_to_the_trail(monkeypatch, fake_keychain):
    as_human_terminal(monkeypatch)
    confirm_yes(monkeypatch)
    locate_site(monkeypatch)
    runner.invoke(app, ["approve", "github.com", "--for-agent"])

    row = audit.read(audit.AUDIT_FILE)[-1]
    assert row["decision"] == "minted"
    assert row["command"] == "approve"
    assert row["caller"] == "human"
    assert row["token_id"]


def test_ttl_defaults_to_the_policy_and_is_clamped(monkeypatch, fake_keychain, tmp_path):
    import policy

    as_human_terminal(monkeypatch)
    confirm_yes(monkeypatch)
    locate_site(monkeypatch)
    monkeypatch.setattr(policy, "POLICY_FILE", tmp_path / "policy.json")
    (tmp_path / "policy.json").write_text('{"approval_ttl_seconds": 300}', encoding="utf-8")

    runner.invoke(app, ["approve", "github.com", "--for-agent"])
    assert session.list_approvals()[0]["expires_at"] - session.list_approvals()[0]["created_at"] == 300

    session.clear_approvals()
    result = runner.invoke(app, ["approve", "github.com", "--for-agent", "--ttl", "5"])
    assert "using 15s" in result.output
    approvals = session.list_approvals()
    assert approvals[0]["expires_at"] - approvals[0]["created_at"] == 15


# ── Entry resolution ──────────────────────────────────────────────────────


def test_an_api_key_name_resolves_and_is_named_in_the_confirmation(monkeypatch, fake_keychain):
    from errors import NotFoundError

    as_human_terminal(monkeypatch)
    confirm_yes(monkeypatch)
    monkeypatch.setattr("api_client.ensure_session", lambda: FAKE_SESSION)
    monkeypatch.setattr(
        "api_client.get_vault_entry", lambda **kwargs: (_ for _ in ()).throw(NotFoundError("no"))
    )
    monkeypatch.setattr("api_client.get_api_key_entry", lambda **kwargs: {"name": "openai-prod"})

    result = runner.invoke(app, ["approve", "openai-prod", "--for-agent"])
    assert result.exit_code == 0
    assert "API key 'openai-prod'" in result.output


def test_an_unknown_entry_is_refused_and_mints_nothing(monkeypatch, fake_keychain):
    from errors import NotFoundError

    as_human_terminal(monkeypatch)
    confirm_yes(monkeypatch)
    monkeypatch.setattr("api_client.ensure_session", lambda: FAKE_SESSION)
    for reader in ("get_vault_entry", "get_api_key_entry", "get_note_entry"):
        monkeypatch.setattr(
            f"api_client.{reader}", lambda **kwargs: (_ for _ in ()).throw(NotFoundError("no"))
        )

    result = runner.invoke(app, ["approve", "typo-name", "--for-agent"])
    assert result.exit_code == 1
    assert "No vault entry named 'typo-name'" in result.output
    assert "ak-list" in result.output
    assert session.list_approvals() == []


def test_a_session_failure_surfaces_as_a_typed_error(monkeypatch, fake_keychain):
    from errors import SessionExpiredError

    as_human_terminal(monkeypatch)
    confirm_yes(monkeypatch)
    monkeypatch.setattr(
        "api_client.ensure_session",
        lambda: (_ for _ in ()).throw(SessionExpiredError("Your session has expired", hint="log in again")),
    )
    result = runner.invoke(app, ["approve", "github.com", "--for-agent"])
    assert result.exit_code == 1
    assert "session has expired" in result.output
    assert session.list_approvals() == []


# ── Revocation ────────────────────────────────────────────────────────────


def test_logout_drops_pending_approvals(fake_keychain, tmp_path, monkeypatch):
    """An approval must not outlive the session it was minted for."""
    # clear_session() unlinks the presence marker — never the real one.
    monkeypatch.setattr(session, "SESSION_FILE", tmp_path / "session.json")
    session.mint_approval("github.com", ttl_seconds=120)
    assert session.list_approvals()
    session.clear_session()
    assert session.list_approvals() == []
