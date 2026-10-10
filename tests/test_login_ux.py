"""`psamvault login` UX: the 401 hint, and what it does with a saved session.

Two defects from issue #68, both reproduced from real use:

* a 401 claimed the only possible cause was a NEW machine and told the user to run
  ``psamvault restore`` — which then refused because ``login`` had left a stale
  session behind, pointing at a way out (``--force``) that neither message named;
* ``login`` asked "log in as a different user?" whenever the presence marker
  existed, even when the session behind it could no longer refresh — and answering
  no printed nothing and exited 0, so it read as success.

``is_logged_in()`` is a file-existence check and stays one: the "is this session
usable?" question is asked on the login path only.
"""

import base64
import json
import time
from contextlib import ExitStack
from unittest.mock import patch

import pytest
import typer
from typer.testing import CliRunner

import api_client
from crypto import derive_key, derive_master_password, encrypt_vek
from errors import SessionExpiredError
from main import app

runner = CliRunner()
PASSWORD = "Password1"
SALT = "ab" * 32
VEK = bytes(range(32))
LIVE = "the saved session"  # what the refusal must say it kept


def _make_jwt(exp) -> str:
    """A JWT-shaped access token with a controllable exp claim."""
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).rstrip(b"=").decode()
    payload = {"sub": "u1", "type": "access", "exp": exp}
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"{header}.{body}.sig"


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


@pytest.fixture(autouse=True)
def no_background_tasks():
    with patch("main.start_update_check"), \
         patch("main.check_and_show_upgrade_notice"), \
         patch("main.print_update_notice"):
        yield


def _invoke_login(input=None, *, marker=False, saved=None, saved_error=None,
                  login_fn=None, refresh_fn=None, update_fn=None):
    """Drive `login` with everything outside the flow itself faked out."""
    with ExitStack() as stack:
        stack.enter_context(patch("command.auth_commands.is_configured", return_value=True))
        stack.enter_context(patch("command.auth_commands.is_logged_in", return_value=marker))
        stack.enter_context(patch("command.auth_commands.save_session"))
        stack.enter_context(patch("command.auth_commands._check_for_backup_after_login"))
        if saved_error is not None:
            stack.enter_context(
                patch("command.auth_commands.load_session", side_effect=saved_error)
            )
        elif saved is not None:
            stack.enter_context(
                patch("command.auth_commands.load_session", return_value=saved)
            )
        if login_fn is not None:
            stack.enter_context(patch("api_client.login", side_effect=login_fn))
        if refresh_fn is not None:
            stack.enter_context(patch("api_client.refresh_session_tokens", side_effect=refresh_fn))
        if update_fn is not None:
            stack.enter_context(patch("api_client.update_tokens", side_effect=update_fn))
        return runner.invoke(app, ["login"], input=input)


def _saved(access_token: str, refresh_token: str = "saved-refresh") -> dict:
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "kdf_salt": SALT,
        "vek": VEK.hex(),
        "encrypted_vek": "bb" * 48,
        "vek_iv": "cc" * 12,
    }


def _refuse(username, master):
    raise SessionExpiredError("Invalid username or password")


# ── the 401 hint ──────────────────────────────────────────────────────────────


def test_login_401_hint_stops_blaming_a_new_machine():
    result = _invoke_login(input=f"psam\n{PASSWORD}\n", login_fn=_refuse)

    assert result.exit_code == 1
    assert "NEW machine" not in result.output


def test_login_401_hint_names_the_real_causes():
    result = _invoke_login(input=f"psam\n{PASSWORD}\n", login_fn=_refuse)

    out = result.output
    assert "typo" in out
    assert "restore on another machine replaced the account password" in out
    assert "pepper changed" in out
    assert "psamvault configure" in out


def test_login_401_hint_names_the_space_pitfall():
    result = _invoke_login(input=f"psam\n{PASSWORD}\n", login_fn=_refuse)

    assert "space" in result.output


def test_login_401_hint_names_the_way_out_of_the_stale_session():
    """`login` says use `restore`, `restore` refuses without `--force` — so say it here."""
    result = _invoke_login(input=f"psam\n{PASSWORD}\n", login_fn=_refuse)

    out = result.output
    assert "psamvault restore --force" in out
    assert "psamvault logout" in out


# ── a saved session that cannot be used ───────────────────────────────────────


def test_login_with_a_dead_session_goes_straight_to_the_prompts():
    attempted = []

    def dead_refresh(refresh_token):
        attempted.append(refresh_token)
        raise SessionExpiredError("Refresh token is invalid or has expired")

    result = _invoke_login(
        input=f"psam\n{PASSWORD}\n",
        marker=True,
        saved=_saved(_make_jwt(time.time() - 60)),
        login_fn=lambda username, master: _login_payload(),
        refresh_fn=dead_refresh,
    )

    assert result.exit_code == 0, result.output
    assert attempted == ["saved-refresh"]  # the session really was tested
    assert "different user" not in result.output
    assert "Username" in result.output
    assert "Logged in as psam" in result.output


def test_login_with_a_marker_but_no_session_data_goes_straight_to_the_prompts():
    result = _invoke_login(
        input=f"psam\n{PASSWORD}\n",
        marker=True,
        saved_error=typer.Exit(code=1),
        login_fn=lambda username, master: _login_payload(),
    )

    assert result.exit_code == 0, result.output
    assert "different user" not in result.output
    assert "Username" in result.output


def test_login_renews_an_expired_access_token_before_calling_the_session_dead():
    """A refreshable session is usable — and the rotation it costs must be persisted."""
    persisted = []

    result = _invoke_login(
        input="n\n",
        marker=True,
        saved=_saved(_make_jwt(time.time() - 60)),
        refresh_fn=lambda refresh_token: ("fresh-access", "fresh-refresh"),
        update_fn=lambda access, refresh: persisted.append((access, refresh)),
    )

    assert result.exit_code == 0, result.output
    assert persisted == [("fresh-access", "fresh-refresh")]
    assert "signing in again will replace it" in result.output
    assert "Kept the saved session" in result.output


# ── a saved session that still works ──────────────────────────────────────────


def test_login_asks_before_replacing_a_usable_session():
    def must_not_refresh(refresh_token):
        raise AssertionError("a live session must not be refreshed just to ask a question")

    result = _invoke_login(
        input="y\npsam\n" + PASSWORD + "\n",
        marker=True,
        saved=_saved(_make_jwt(time.time() + 7200)),
        login_fn=lambda username, master: _login_payload(),
        refresh_fn=must_not_refresh,
    )

    assert result.exit_code == 0, result.output
    assert "signing in again will replace it" in result.output
    assert "Logged in as psam" in result.output


def test_login_keeps_a_usable_session_when_the_user_declines():
    result = _invoke_login(
        input="n\n",
        marker=True,
        saved=_saved(_make_jwt(time.time() + 7200)),
    )

    assert result.exit_code == 0, result.output
    out = result.output
    # An explanation, not a silent success: what was kept, and how to drop it.
    assert "Kept the saved session" in out
    assert "psamvault logout" in out
    assert out.strip()
    # ...and it stopped there, instead of going on to ask for a password.
    assert "Login password" not in out
