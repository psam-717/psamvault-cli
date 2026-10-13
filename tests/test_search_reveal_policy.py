"""`search` reveals nothing — to anybody.

Discovery and reveal are separate jobs. `search` matches many entries at once and has to
stay useful without their secrets, so it prints no value and no free-text field for any
caller under any policy mode. Every match names the command that reveals it (`get` /
`ak-get` / `note-get`), and THAT command is decided and audited per entry. The search
itself writes one audit row recording the caller.

What this replaced (measured 2026-10-12, 0.7.2): a human caller got every matched
password, key and note content, and an agent caller still got the site and API-key
`Notes:` field verbatim — the free text the query itself matches, which is where
break-glass codes and fallback tokens get written down.
"""

from unittest.mock import patch

from typer.testing import CliRunner

import caller

# Captured at import: a test that invokes the harness more than once would otherwise
# wrap the patched classifier around itself and lose the marker it was given.
_REAL_CLASSIFY = caller.classify

runner = CliRunner()

AGENT = "1"
NON_AGENT = "0"  # no TTY in the harness, so this classifies as `uncertain`
SECRET = "sk-live-EXAMPLEVALUE"
SITE_SECRET = "hunter2"
NOTE_BODY = "the recovery phrase is correct horse"
SITE_NOTES = "rotated 2026-09; break-glass code 8891-4420"
AK_NOTES = "scoped to repo x; fallback token 9931-xx"
STORED = "atlas054probe/.env/my_custom_key"

AK_ROWS = [{"name": STORED, "service": "scan", "api_key": SECRET, "notes": AK_NOTES}]
SITE_ROWS = [{"site_name": "postgresql", "username": "psam", "password": SITE_SECRET,
              "notes": SITE_NOTES, "login_url": None}]
NOTE_ROWS = [{"title": "Recovery drill", "category": "ops", "content": NOTE_BODY}]

SESSION = {"access_token": "x", "refresh_token": "x", "vek": "00" * 32}

EVERY_SECRET = (SECRET, SITE_SECRET, NOTE_BODY, SITE_NOTES, AK_NOTES)


def _invoke(monkeypatch, psamvault_agent, audit_rows, *, query="e", policy_path=None):
    from main import app

    monkeypatch.setattr("caller.classify",
                        lambda *a, **k: _REAL_CLASSIFY({"PSAMVAULT_AGENT": psamvault_agent}))
    monkeypatch.setattr("audit.record", lambda **kw: audit_rows.append(kw))
    monkeypatch.setattr("session.consume_approval",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("approval spent")))
    if policy_path is not None:
        monkeypatch.setattr("policy.POLICY_FILE", policy_path)
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
        result = runner.invoke(app, ["search", query])
    assert "not logged in" not in result.output.lower(), (
        "this harness reached the real session path - patch the name the command calls "
        "(command.vault_commands.load_session), not the defining module"
    )
    return result


def _assert_no_secret(result):
    for secret in EVERY_SECRET:
        assert secret not in result.output, f"leaked: {secret!r}"


def test_a_non_agent_gets_the_matches_but_no_values(monkeypatch):
    rows = []
    result = _invoke(monkeypatch, NON_AGENT, rows)
    assert result.exit_code == 0, result.output

    # discovery still works, in full
    assert "postgresql" in result.output
    assert "psam" in result.output
    assert "my_custom_key" in result.output
    assert "Project:  atlas054probe" in result.output
    assert "Recovery drill" in result.output
    assert "Category: ops" in result.output

    _assert_no_secret(result)


def test_an_agent_gets_the_matches_but_no_values(monkeypatch):
    rows = []
    result = _invoke(monkeypatch, AGENT, rows)
    assert result.exit_code == 0, result.output

    assert "postgresql" in result.output
    assert "my_custom_key" in result.output
    assert "Recovery drill" in result.output

    _assert_no_secret(result)


def test_free_text_fields_are_never_printed(monkeypatch):
    """A note is where a break-glass code gets written down — it is not a discovery fact."""
    for who in (NON_AGENT, AGENT):
        rows = []
        result = _invoke(monkeypatch, who, rows)
        assert SITE_NOTES not in result.output
        assert AK_NOTES not in result.output
        assert "Notes:" in result.output, "the field is still named, only its text is withheld"


def test_a_non_agent_is_told_the_command_that_reveals_each_match(monkeypatch):
    rows = []
    result = _invoke(monkeypatch, NON_AGENT, rows)

    assert "hidden — run  psamvault get postgresql" in result.output
    assert f"hidden — run  psamvault ak-get {STORED}" in result.output
    assert 'hidden — run  psamvault note-get "Recovery drill"' in result.output


def test_a_leaf_name_is_not_handed_to_ak_get_and_a_spaced_name_is_quoted(monkeypatch):
    """`ak-get` resolves a leaf only when it is unambiguous — the stored name always works."""
    rows = []
    result = _invoke(monkeypatch, NON_AGENT, rows)

    assert "ak-get my_custom_key" not in result.output
    assert "ak-get atlas054probe/.env/my_custom_key" in result.output
    # a name with a space must survive the shell
    assert 'note-get "Recovery drill"' in result.output


def test_an_agent_is_pointed_at_the_human_not_at_a_command_it_cannot_run(monkeypatch):
    rows = []
    result = _invoke(monkeypatch, AGENT, rows)

    assert "hidden — the human runs  psamvault get postgresql" in result.output
    assert "hidden — run  psamvault" not in result.output
    # ...and it keeps a way to finish the job without the value
    assert "use_credential" in result.output
    assert "run_with_credential" in result.output
    assert "browser_login" in result.output


def test_the_invocation_writes_exactly_one_discovery_row(monkeypatch):
    """One row per search, naming who asked — the row is not a reveal decision."""
    for who in (NON_AGENT, AGENT):
        rows = []
        _invoke(monkeypatch, who, rows)
        assert len(rows) == 1, rows
        row = rows[0]
        assert row["command"] == "search"
        assert row["decision"] == "discovery"
        assert row["entry"] is None
        # the harness has no TTY, so a non-agent caller is `uncertain` here
        assert row["caller"] == ("agent" if who == AGENT else "uncertain")


def test_the_open_policy_mode_does_not_restore_values(monkeypatch, tmp_path):
    """No policy mode makes a discovery command a reveal."""
    policy_file = tmp_path / "policy.json"
    policy_file.write_text('{"reveal": "open"}', encoding="utf-8")

    rows = []
    result = _invoke(monkeypatch, NON_AGENT, rows, policy_path=policy_file)

    assert result.exit_code == 0, result.output
    _assert_no_secret(result)


def test_search_never_spends_an_approval_token(monkeypatch):
    """session.consume_approval raises in the harness, so reaching it fails this test."""
    rows = []
    result = _invoke(monkeypatch, AGENT, rows)
    assert result.exit_code == 0, result.output
