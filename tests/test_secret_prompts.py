"""Secret prompts: hidden by default, visible on request, never a silent block.

Issue #68, finding 2: every secret prompt hid its input, which has two costs. A
user cannot see a typo — and an invisible leading or trailing space is a
*different* password — and a prompt with no console to read from blocks for
ever printing nothing (observed here as CLI processes parked since Sep 25).

The contract these tests pin:

* hidden unless ``PSAMVAULT_SHOW_SECRETS`` says otherwise;
* when it is set, the same prompt is visible (login password, backup
  passphrase — every prompt that used to pass ``hide_input=True``);
* when it is not set and there is no console, the command fails immediately
  with a non-zero exit and a sentence saying the prompt cannot be answered.
"""

from contextlib import ExitStack
from unittest.mock import patch

import pytest
import typer
from typer.testing import CliRunner

import secret_prompt
from crypto import derive_key, derive_master_password, encrypt_vek
from main import app

runner = CliRunner()
PASSWORD = "Password1"
SALT = "ab" * 32
VEK = bytes(range(32))


def _login_payload() -> dict:
    key = bytes(derive_key(derive_master_password(PASSWORD), SALT))
    encrypted, iv = encrypt_vek(key, VEK)
    return {
        "access_token": "access-from-login",
        "refresh_token": "refresh-from-login",
        "kdf_salt": SALT,
        "encrypted_vek": encrypted,
        "vek_iv": iv,
        "has_recovery_codes": True,
    }


def _invoke_login(input=None, *, login_fn=None):
    """Drive `login` with everything outside the prompt faked out."""
    with ExitStack() as stack:
        stack.enter_context(patch("command.auth_commands.is_configured", return_value=True))
        stack.enter_context(patch("command.auth_commands.is_logged_in", return_value=False))
        stack.enter_context(patch("command.auth_commands.save_session"))
        stack.enter_context(patch("command.auth_commands._check_for_backup_after_login"))
        if login_fn is not None:
            stack.enter_context(patch("api_client.login", side_effect=login_fn))
        return runner.invoke(app, ["login"], input=input)


def _record_prompts(monkeypatch, answer: str = "typed-secret") -> list:
    """Replace typer.prompt with a recorder that answers without reading stdin."""
    seen: list = []

    def spy(text, **kwargs):
        seen.append((text, kwargs.get("hide_input")))
        return answer

    monkeypatch.setattr(typer, "prompt", spy)
    return seen


def _record_prompts_and_still_prompt(monkeypatch) -> list:
    """Record (text, hide_input) while still reading the real (piped) answer."""
    seen: list = []
    real_prompt = typer.prompt

    def spy(text, **kwargs):
        seen.append((text, kwargs.get("hide_input")))
        return real_prompt(text, **kwargs)

    monkeypatch.setattr(typer, "prompt", spy)
    return seen


# ── the default: hidden ───────────────────────────────────────────────────────


def test_secret_prompt_is_hidden_by_default(monkeypatch):
    monkeypatch.delenv(secret_prompt.SHOW_SECRETS_ENV, raising=False)
    monkeypatch.setattr(secret_prompt, "has_console", lambda: True)
    seen = _record_prompts(monkeypatch)

    assert secret_prompt.secret_prompt("Login password") == "typed-secret"
    assert seen == [("Login password", True)]


def test_the_login_password_prompt_is_hidden_by_default(monkeypatch):
    monkeypatch.delenv(secret_prompt.SHOW_SECRETS_ENV, raising=False)
    seen = _record_prompts_and_still_prompt(monkeypatch)

    result = _invoke_login(input=f"psam\n{PASSWORD}\n", login_fn=lambda u, m: _login_payload())

    assert result.exit_code == 0, result.output
    assert ("Login password", True) in seen


# ── the opt-in: visible ───────────────────────────────────────────────────────


def test_secret_prompt_is_visible_when_show_secrets_is_set(monkeypatch):
    monkeypatch.setenv(secret_prompt.SHOW_SECRETS_ENV, "1")
    # No console at all: a visible prompt must not need one.
    monkeypatch.setattr(secret_prompt, "has_console", lambda: False)
    seen = _record_prompts(monkeypatch)

    assert secret_prompt.secret_prompt("Login password") == "typed-secret"
    assert seen == [("Login password", False)]


def test_show_secrets_makes_the_login_password_prompt_visible(monkeypatch):
    monkeypatch.setenv(secret_prompt.SHOW_SECRETS_ENV, "1")
    seen = _record_prompts_and_still_prompt(monkeypatch)

    result = _invoke_login(input=f"psam\n{PASSWORD}\n", login_fn=lambda u, m: _login_payload())

    assert result.exit_code == 0, result.output
    assert ("Login password", False) in seen


def test_show_secrets_is_read_as_a_boolean(monkeypatch):
    monkeypatch.setenv(secret_prompt.SHOW_SECRETS_ENV, "1")
    assert secret_prompt.show_secrets() is True
    monkeypatch.setenv(secret_prompt.SHOW_SECRETS_ENV, "TRUE")
    assert secret_prompt.show_secrets() is True
    monkeypatch.setenv(secret_prompt.SHOW_SECRETS_ENV, "on")
    assert secret_prompt.show_secrets() is True
    monkeypatch.setenv(secret_prompt.SHOW_SECRETS_ENV, "0")
    assert secret_prompt.show_secrets() is False
    monkeypatch.setenv(secret_prompt.SHOW_SECRETS_ENV, "no")
    assert secret_prompt.show_secrets() is False
    monkeypatch.delenv(secret_prompt.SHOW_SECRETS_ENV, raising=False)
    assert secret_prompt.show_secrets() is False


# ── no console: fail, do not block ────────────────────────────────────────────


def test_secret_prompt_refuses_without_a_console(monkeypatch, capsys):
    monkeypatch.delenv(secret_prompt.SHOW_SECRETS_ENV, raising=False)
    monkeypatch.setattr(secret_prompt, "has_console", lambda: False)

    with pytest.raises(typer.Exit) as excinfo:
        secret_prompt.secret_prompt("Login password")

    assert excinfo.value.exit_code == 1
    err = capsys.readouterr().err
    assert "cannot be answered" in err
    assert secret_prompt.SHOW_SECRETS_ENV in err


def test_login_without_a_console_exits_instead_of_blocking(monkeypatch):
    monkeypatch.delenv(secret_prompt.SHOW_SECRETS_ENV, raising=False)
    monkeypatch.setattr(secret_prompt, "has_console", lambda: False)

    result = _invoke_login(input="psam\n")

    assert result.exit_code == 1
    assert "cannot be answered" in result.output


def test_login_without_a_console_makes_no_login_request(monkeypatch):
    monkeypatch.delenv(secret_prompt.SHOW_SECRETS_ENV, raising=False)
    monkeypatch.setattr(secret_prompt, "has_console", lambda: False)
    calls: list = []

    result = _invoke_login(input="psam\n", login_fn=lambda u, m: calls.append((u, m)))

    assert result.exit_code == 1
    assert calls == []
