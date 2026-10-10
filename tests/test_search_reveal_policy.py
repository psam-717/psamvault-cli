"""`search` shows an agent what matched, never the secret.

The reveal gate refused `get`/`ak-get` while `search` printed the same decrypted values, so
the guardrail had a hole: one command away, no approval, nothing in the audit. Per the
decision on the hole, search stays usable as a *discovery* command — names, projects,
services, note titles — and the value itself needs the reveal path (`get`/`ak-get`/
`note-get`, or an approval), the same rule the policy engine already applies.

No approval token is spent by a search (an approval names one entry; a search covers many),
and the invocation writes exactly one audit row.
"""

from unittest.mock import patch

from typer.testing import CliRunner

import caller

runner = CliRunner()

AGENT = "1"
HUMAN = "0"
SECRET = "sk-live-value"
SITE_SECRET = "hunter2"
NOTE_BODY = "the recovery phrase is correct horse"

AK_ROWS = [{"name": "atlas054probe/.env/my_custom_key", "service": "scan",
            "api_key": SECRET, "notes": None}]
SITE_ROWS = [{"site_name": "postgresql", "username": "psam", "password": SITE_SECRET,
              "notes": None, "login_url": None}]
NOTE_ROWS = [{"title": "Recovery drill", "category": "ops", "content": NOTE_BODY}]

SESSION = {"access_token": "x", "refresh_token": "x", "vek": "00" * 32}


def _invoke(monkeypatch, psamvault_agent, audit_rows):
    from main import app

    real_classify = caller.classify
    monkeypatch.setattr("caller.classify",
                        lambda *a, **k: real_classify({"PSAMVAULT_AGENT": psamvault_agent}))
    monkeypatch.setattr("audit.record", lambda **kw: audit_rows.append(kw))
    monkeypatch.setattr("session.consume_approval",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("approval spent")))
    monkeypatch.setattr("command.vault_commands._get_session_and_key", lambda: (dict(SESSION), bytes(32)))
    # The name the command actually calls: vault_commands does
    # `from session import load_session`, so patching the session module is not enough.
    monkeypatch.setattr("command.vault_commands.load_session", lambda: dict(SESSION))
    monkeypatch.setattr("session.load_session", lambda: dict(SESSION))
    monkeypatch.setattr("command.vault_commands._search_credentials", lambda *a, **k: SITE_ROWS)
    monkeypatch.setattr("command.vault_commands._search_api_keys", lambda *a, **k: AK_ROWS)
    monkeypatch.setattr("command.vault_commands._search_notes", lambda *a, **k: NOTE_ROWS)
    monkeypatch.setattr("api_client.export_vault", lambda **k: [])
    monkeypatch.setattr("api_client.export_api_keys", lambda **k: [])
    monkeypatch.setattr("api_client.export_notes", lambda **k: [])
    with patch("main.start_update_check"), \
         patch("main.check_and_show_upgrade_notice"), \
         patch("main.print_update_notice"):
        result = runner.invoke(app, ["search", "e"])
    assert "not logged in" not in result.output.lower(), (
        "this harness reached the real session path - patch the name the command calls "
        "(command.vault_commands.load_session), not the defining module"
    )
    return result


def test_an_agent_sees_what_matched_but_no_values(monkeypatch):
    rows = []
    result = _invoke(monkeypatch, AGENT, rows)
    assert result.exit_code == 0, result.output

    # discovery still works
    assert "my_custom_key" in result.output
    assert "postgresql" in result.output
    assert "Recovery drill" in result.output

    # ...and no secret comes with it
    assert SECRET not in result.output
    assert SITE_SECRET not in result.output
    assert NOTE_BODY not in result.output


def test_an_agent_is_told_how_to_get_the_value(monkeypatch):
    rows = []
    result = _invoke(monkeypatch, AGENT, rows)
    assert "not displayed for this caller" in result.output
    assert "approve" in result.output


def test_the_invocation_writes_exactly_one_deny_row(monkeypatch):
    rows = []
    _invoke(monkeypatch, AGENT, rows)
    assert len(rows) == 1, rows
    row = rows[0]
    assert row["command"] == "search"
    assert row["decision"] == "deny"
    assert row["caller"] == "agent"


def test_a_human_still_gets_the_values_and_an_allow_row(monkeypatch):
    rows = []
    result = _invoke(monkeypatch, HUMAN, rows)
    assert result.exit_code == 0, result.output
    assert SECRET in result.output
    assert SITE_SECRET in result.output
    assert NOTE_BODY in result.output
    assert [r["decision"] for r in rows] == ["allow"]


def test_search_never_spends_an_approval_token(monkeypatch):
    """session.consume_approval raises in the harness, so reaching it fails this test."""
    rows = []
    result = _invoke(monkeypatch, AGENT, rows)
    assert result.exit_code == 0, result.output
