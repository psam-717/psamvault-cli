"""psamvault generate: class guarantees, a hidden save, and the reveal gate.

The API and the keychain are fakes. Nothing here talks to a vault or reads a
real credential. The password under test is the one the command just drew.
"""
import string
from unittest.mock import patch

from typer.testing import CliRunner

import audit
import secrets
import session
from command.vault_commands import (
    SAFE_SYMBOLS,
    character_classes,
    generate_password,
    minimum_password_length,
)
from crypto import decrypt_credentials
from main import app

runner = CliRunner()

VEK = bytes(range(32))
FAKE_SESSION = {"access_token": "t", "refresh_token": "r", "vek": VEK.hex()}

# Characters the default symbol set must not contain. Quotes, backslash,
# backtick, dollar, percent, and space are the named exclusions. The rest
# split a shell word, a URL, or an HTML attribute.
EXCLUDED_SYMBOLS = set("\"'`\\$%&|;<>#?/~ ")


def as_agent(monkeypatch):
    monkeypatch.setenv("PSAMVAULT_AGENT", "1")


def last_audit_row():
    rows = audit.read(audit.AUDIT_FILE)
    assert rows, "the gate must record a decision"
    return rows[-1]


def saved_password(kwargs):
    creds = decrypt_credentials(VEK, kwargs["encrypted_blob"], kwargs["iv"])
    return creds["password"]


def test_minimum_length_keeps_the_stricter_floor():
    """8 stays the floor while it is higher than the class count."""
    assert minimum_password_length(1) == 8
    assert minimum_password_length(4) == 8
    assert minimum_password_length(9) == 9


def test_each_enabled_class_appears_and_symbols_stay_safe():
    classes = character_classes()
    for _ in range(200):
        password = generate_password(12, classes)
        assert len(password) == 12
        assert any(character.isupper() for character in password)
        assert any(character.islower() for character in password)
        assert any(character.isdigit() for character in password)
        symbols = [character for character in password if not character.isalnum()]
        assert symbols, password
        assert all(character in SAFE_SYMBOLS for character in symbols)
        assert not any(character in EXCLUDED_SYMBOLS for character in password)


def test_safe_symbol_set_is_the_documented_subset():
    assert SAFE_SYMBOLS == "!@^*()-_=+[]{}:,."
    assert set(SAFE_SYMBOLS) <= set(string.punctuation)
    assert set(SAFE_SYMBOLS).isdisjoint(EXCLUDED_SYMBOLS)


def test_disabled_class_is_absent_and_the_others_are_present():
    classes = character_classes(no_upper=True, no_symbols=True)
    assert [name for name, _alphabet in classes] == ["lower", "digits"]
    for _ in range(100):
        password = generate_password(16, classes)
        assert not any(character.isupper() for character in password)
        assert not any(character in string.punctuation for character in password)
        assert any(character.islower() for character in password)
        assert any(character.isdigit() for character in password)


def test_all_symbols_uses_the_full_punctuation_set():
    classes = character_classes(all_symbols=True)
    symbols = dict(classes)["symbols"]
    assert symbols == string.punctuation
    assert "$" in symbols and "%" in symbols and '"' in symbols


def test_guaranteed_characters_are_shuffled():
    """Length equal to the class count would leave class 0 in front without a shuffle."""
    classes = character_classes()
    firsts = {generate_password(len(classes), classes)[0] for _ in range(40)}
    assert any(character.islower() or character.isdigit() or character in SAFE_SYMBOLS for character in firsts)
    assert any(character.isupper() for character in firsts)


def test_shuffle_goes_through_systemrandom(monkeypatch):
    seen = []
    real = secrets.SystemRandom.shuffle

    def spy(self, values):
        seen.append(type(self))
        real(self, values)

    monkeypatch.setattr(secrets.SystemRandom, "shuffle", spy)
    generate_password(10, character_classes())
    assert seen
    assert issubclass(seen[0], secrets.SystemRandom)


def test_human_generate_still_prints_the_password():
    result = runner.invoke(app, ["generate", "--length", "20"])
    assert result.exit_code == 0, result.output
    line = next(line for line in result.output.splitlines() if "Generated password:" in line)
    password = line.split("Generated password:", 1)[1].strip()
    assert len(password) == 20
    assert last_audit_row()["decision"] == "allow"
    assert last_audit_row()["command"] == "generate"
    assert last_audit_row()["entry"] is None


def test_save_does_not_print_the_password():
    captured = {}

    def capture(**kwargs):
        captured.update(kwargs)

    with patch("api_client.ensure_session", return_value=FAKE_SESSION), \
         patch("api_client.add_vault_entry", side_effect=capture):
        result = runner.invoke(
            app, ["generate", "--save", "github.com", "--user", "me@example.com"]
        )

    assert result.exit_code == 0, result.output
    password = saved_password(captured)
    assert password not in result.output
    assert "Generated password:" not in result.output
    assert "github.com" in result.output
    assert "Length:" in result.output and "20" in result.output
    assert "Classes:" in result.output
    assert "upper" in result.output and "lower" in result.output
    assert "digits" in result.output and "symbols" in result.output
    assert audit.read(audit.AUDIT_FILE) == []


def test_save_show_prints_the_saved_password():
    captured = {}

    def capture(**kwargs):
        captured.update(kwargs)

    with patch("api_client.ensure_session", return_value=FAKE_SESSION), \
         patch("api_client.add_vault_entry", side_effect=capture):
        result = runner.invoke(
            app,
            ["generate", "--save", "github.com", "--user", "me@example.com", "--show", "--length", "24"],
        )

    assert result.exit_code == 0, result.output
    password = saved_password(captured)
    assert f"Generated password: {password}" in result.output
    assert "github.com" in result.output
    assert "24" in result.output
    assert last_audit_row()["decision"] == "allow"
    assert last_audit_row()["entry"] == "github.com"


def test_vault_generate_save_hides_the_password_too():
    captured = {}

    def capture(**kwargs):
        captured.update(kwargs)

    with patch("api_client.ensure_session", return_value=FAKE_SESSION), \
         patch("api_client.add_vault_entry", side_effect=capture):
        result = runner.invoke(
            app, ["vault", "generate", "--save", "github.com", "--user", "me@example.com", "--no-digits"]
        )

    assert result.exit_code == 0, result.output
    password = saved_password(captured)
    assert password not in result.output
    assert "digits" not in result.output
    assert "upper, lower, symbols" in result.output


def test_agent_generate_without_save_is_refused_and_draws_nothing(monkeypatch):
    as_agent(monkeypatch)
    with patch("command.vault_commands.generate_password") as draw, \
         patch("api_client.add_vault_entry") as store, \
         patch("api_client.ensure_session") as session_call:
        result = runner.invoke(app, ["generate"])

    assert result.exit_code == 1
    assert "blocked" in result.output
    assert "agent terminal detected" in result.output
    assert not draw.called
    assert not store.called
    assert not session_call.called
    row = last_audit_row()
    assert row["decision"] == "deny"
    assert row["command"] == "generate"
    assert row["entry"] is None
    assert row["signals"] == ["explicit:PSAMVAULT_AGENT"]


def test_agent_save_show_is_refused_before_anything_is_stored(monkeypatch):
    as_agent(monkeypatch)
    with patch("command.vault_commands.generate_password") as draw, \
         patch("api_client.add_vault_entry") as store, \
         patch("api_client.ensure_session") as session_call:
        result = runner.invoke(
            app,
            ["generate", "--save", "github.com", "--user", "me@example.com", "--show"],
        )

    assert result.exit_code == 1
    assert "blocked" in result.output
    assert "Generated password:" not in result.output
    assert not draw.called
    assert not store.called
    assert not session_call.called
    row = last_audit_row()
    assert row["decision"] == "deny"
    assert row["command"] == "generate"
    assert row["entry"] == "github.com"
    assert "psamvault approve github.com --for-agent" in result.output


def test_agent_save_without_show_stores_and_prints_no_value(monkeypatch):
    as_agent(monkeypatch)
    captured = {}

    def capture(**kwargs):
        captured.update(kwargs)

    with patch("api_client.ensure_session", return_value=FAKE_SESSION), \
         patch("api_client.add_vault_entry", side_effect=capture):
        result = runner.invoke(
            app, ["generate", "--save", "github.com", "--user", "me@example.com", "--length", "20"]
        )

    assert result.exit_code == 0, result.output
    password = saved_password(captured)
    assert password not in result.output
    assert "Generated password:" not in result.output
    assert "github.com" in result.output
    assert "20" in result.output
    assert audit.read(audit.AUDIT_FILE) == []


def test_agent_save_show_with_an_approval_prints_once(monkeypatch, fake_keychain):
    as_agent(monkeypatch)
    session.mint_approval("github.com", ttl_seconds=120)
    captured = {}

    def capture(**kwargs):
        captured.update(kwargs)

    with patch("api_client.ensure_session", return_value=FAKE_SESSION), \
         patch("api_client.add_vault_entry", side_effect=capture):
        allowed = runner.invoke(
            app, ["generate", "--save", "github.com", "--user", "me@example.com", "--show"]
        )
    assert allowed.exit_code == 0, allowed.output
    password = saved_password(captured)
    assert password in allowed.output

    with patch("command.vault_commands.generate_password") as draw, \
         patch("api_client.add_vault_entry") as store:
        refused = runner.invoke(
            app, ["generate", "--save", "github.com", "--user", "me@example.com", "--show"]
        )
    assert refused.exit_code == 1
    assert password not in refused.output
    assert not draw.called
    assert not store.called


def test_no_upper_and_no_lower_from_the_cli():
    upper = runner.invoke(app, ["generate", "--length", "32", "--no-upper"])
    assert upper.exit_code == 0, upper.output
    upper_password = _printed(upper.output)
    assert not any(character.isupper() for character in upper_password)
    assert any(character.islower() for character in upper_password)

    lower = runner.invoke(app, ["generate", "--length", "32", "--no-lower"])
    assert lower.exit_code == 0, lower.output
    lower_password = _printed(lower.output)
    assert not any(character.islower() for character in lower_password)
    assert any(character.isupper() for character in lower_password)


def test_every_class_disabled_is_refused():
    with patch("command.vault_commands.generate_password") as draw:
        result = runner.invoke(
            app, ["generate", "--no-upper", "--no-lower", "--no-digits", "--no-symbols"]
        )
    assert result.exit_code == 1
    assert "character class" in result.output
    assert not draw.called


def test_all_symbols_cannot_combine_with_no_symbols():
    result = runner.invoke(app, ["generate", "--all-symbols", "--no-symbols"])
    assert result.exit_code == 1
    assert "--all-symbols cannot be combined with --no-symbols" in result.output


def test_length_bounds():
    too_short = runner.invoke(app, ["generate", "--length", "7"])
    assert too_short.exit_code == 1
    assert "at least 8" in too_short.output
    assert "enabled character classes (4)" in too_short.output

    too_long = runner.invoke(app, ["generate", "--length", "129"])
    assert too_long.exit_code == 1
    assert "at most 128" in too_long.output

    floor = runner.invoke(app, ["generate", "--length", "8"])
    assert floor.exit_code == 0, floor.output
    assert len(_printed(floor.output)) == 8

    ceiling = runner.invoke(app, ["generate", "--length", "128"])
    assert ceiling.exit_code == 0, ceiling.output
    assert len(_printed(ceiling.output)) == 128


def test_length_must_cover_each_class_when_that_floor_is_higher(monkeypatch):
    """The helper's rule, driven through the command with a stand-in class list."""
    monkeypatch.setattr(
        "command.vault_commands.character_classes",
        lambda **kwargs: [("c", "a")] * 9,
    )
    result = runner.invoke(app, ["generate", "--length", "8"])
    assert result.exit_code == 1
    assert "at least 9" in result.output
    assert "enabled character classes (9)" in result.output


def test_invalid_site_name_is_refused_before_a_draw():
    with patch("command.vault_commands.generate_password") as draw, \
         patch("api_client.add_vault_entry") as store:
        result = runner.invoke(
            app, ["generate", "--save", "bad/name", "--user", "me@example.com"]
        )
    assert result.exit_code == 1
    assert "invalid character" in result.output
    assert not draw.called
    assert not store.called
    assert audit.read(audit.AUDIT_FILE) == []


def test_save_requires_a_user():
    result = runner.invoke(app, ["generate", "--save", "github.com"])
    assert result.exit_code == 1
    assert "--user is required when using --save" in result.output


def _printed(output: str) -> str:
    line = next(line for line in output.splitlines() if "Generated password:" in line)
    return line.split("Generated password:", 1)[1].strip()
