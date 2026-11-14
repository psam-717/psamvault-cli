"""Recovery codes go through the reveal gate before they exist.

An agent (or, under ``strict``, an uncertain caller) is refused before any
prompt and before the call that stores or replaces codes. A human still sees
today's prompts, the codes, and an allow row. Nothing here uses a real vault
or a real credential: the session, the API, and the keychain are fakes.
"""

from __future__ import annotations

import re
from unittest.mock import Mock, patch

import pytest
from typer.testing import CliRunner

import account_flows
import api_client
import audit
import caller
import dashboard.cache as dash_cache
import reveal_gate
import session
from crypto import derive_key, derive_master_password, encrypt_vek, wrap_vek_with_passphrase
from main import app
from tests.conftest import TEST_VEK
from tests.test_dashboard import (
    _DASHBOARD_ORIGIN,
    _bootstrap,
    _build_dashboard_app,
    _csrf,
    _exchange,
)
from tests.test_restore import NEW_PASSWORD, PASSPHRASE, _invoke, _mock_the_restore_network

runner = CliRunner()
BASE = "https://test.example.com"

LOGIN_PASSWORD = "Password1"
SALT = "ab" * 32
CODE_RE = re.compile(r"[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}")


def _login_session(password: str = LOGIN_PASSWORD) -> dict:
    master = derive_master_password(password)
    key = derive_key(master, SALT)
    encrypted, iv = encrypt_vek(bytes(key), TEST_VEK)
    return {
        "access_token": "t",
        "refresh_token": "r",
        "kdf_salt": SALT,
        "encrypted_vek": encrypted,
        "vek_iv": iv,
        "vek": TEST_VEK.hex(),
    }


def _codes_in(text: str) -> list[str]:
    return CODE_RE.findall(text)


def _last_row() -> dict:
    rows = audit.read()
    assert rows, "the gate must record a decision"
    return rows[-1]


def _as_agent(monkeypatch) -> None:
    monkeypatch.setenv("PSAMVAULT_AGENT", "1")


def _as_human(monkeypatch) -> None:
    """A real terminal: both ends are TTYs, and no agent marker is set."""
    monkeypatch.setattr(caller, "tty_present", lambda: True)


def _watch_gate(monkeypatch, events: list[str]):
    real = reveal_gate.require_reveal

    def wrapped(*args, **kwargs):
        events.append("gate")
        return real(*args, **kwargs)

    monkeypatch.setattr(reveal_gate, "require_reveal", wrapped)


# ── CLI generate-codes ────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "argv",
    [
        ["generate-codes"],
        ["recovery", "generate-codes"],
    ],
)
def test_agent_generate_codes_is_refused_before_any_prompt_or_api(monkeypatch, argv):
    _as_agent(monkeypatch)
    events: list[str] = []
    store = Mock(side_effect=AssertionError("the code API must not be called"))
    session_touch = Mock(side_effect=AssertionError("the session must not be touched"))

    def confirm(*_args, **_kwargs):
        events.append("confirm")
        return True

    def prompt(*_args, **_kwargs):
        events.append("prompt")
        return LOGIN_PASSWORD

    with patch("command.recovery_commands.is_logged_in", return_value=True), \
         patch("api_client.ensure_session", session_touch), \
         patch("api_client.generate_recovery_codes_api", store), \
         patch("command.recovery_commands.typer.confirm", confirm), \
         patch("command.recovery_commands.secret_prompt", prompt):
        result = runner.invoke(app, argv, input="y\nPassword1\n")

    assert result.exit_code == 1
    assert events == []
    assert not store.called
    assert not session_touch.called
    assert "Continue?" not in result.output
    assert "YOUR RECOVERY CODES" not in result.output
    assert LOGIN_PASSWORD not in result.output
    row = _last_row()
    assert row["decision"] == "deny"
    assert row["command"] == "generate-codes"
    assert row["entry"] is None
    assert row["caller"] == "agent"
    assert "Password1" not in str(row)


def test_human_generate_codes_shows_the_codes_and_writes_an_allow_row(monkeypatch):
    _as_human(monkeypatch)
    events: list[str] = []
    _watch_gate(monkeypatch, events)

    def confirm(*_args, **_kwargs):
        events.append("confirm")
        return True

    def prompt(*_args, **_kwargs):
        events.append("prompt")
        return LOGIN_PASSWORD

    def store(**kwargs):
        events.append("api")
        assert len(kwargs["codes"]) == 8
        return {"detail": "ok", "remaining_codes": 8}

    with patch("command.recovery_commands.is_logged_in", return_value=True), \
         patch("api_client.ensure_session", return_value=_login_session()), \
         patch("api_client.generate_recovery_codes_api", store), \
         patch("command.recovery_commands.typer.confirm", confirm), \
         patch("command.recovery_commands.secret_prompt", prompt):
        result = runner.invoke(app, ["generate-codes"])

    assert result.exit_code == 0, result.output
    assert events == ["gate", "confirm", "prompt", "api"]
    codes = _codes_in(result.output)
    assert len(codes) == 8
    assert "YOUR RECOVERY CODES" in result.output
    row = _last_row()
    assert row["decision"] == "allow"
    assert row["command"] == "generate-codes"
    assert row["entry"] is None
    assert row["caller"] == "human"
    assert LOGIN_PASSWORD not in str(row)
    assert codes[0] not in str(row)


def test_an_entry_approval_does_not_cover_recovery_codes(monkeypatch, fake_keychain):
    _as_agent(monkeypatch)
    session.mint_approval("github.com", ttl_seconds=120)
    store = Mock(side_effect=AssertionError("the code API must not be called"))

    with patch("command.recovery_commands.is_logged_in", return_value=True), \
         patch("api_client.generate_recovery_codes_api", store):
        result = runner.invoke(app, ["generate-codes"])

    assert result.exit_code == 1
    assert not store.called
    assert _last_row()["decision"] == "deny"
    assert session.live_approval_for("github.com") is not None


def test_strict_mode_refuses_an_uncertain_caller_before_the_api(monkeypatch, tmp_path):
    """CliRunner has no TTY, so the caller is uncertain. ``strict`` refuses that."""
    (tmp_path / "policy.json").write_text('{"reveal": "strict"}\n', encoding="utf-8")
    store = Mock(side_effect=AssertionError("the code API must not be called"))
    prompt = Mock(return_value=LOGIN_PASSWORD)

    with patch("command.recovery_commands.is_logged_in", return_value=True), \
         patch("api_client.generate_recovery_codes_api", store), \
         patch("command.recovery_commands.secret_prompt", prompt):
        result = runner.invoke(app, ["generate-codes"], input="y\nPassword1\n")

    assert result.exit_code == 1
    assert not store.called
    assert not prompt.called
    row = _last_row()
    assert row["decision"] == "deny"
    assert row["caller"] == "uncertain"
    assert row["command"] == "generate-codes"
    assert row["entry"] is None


# ── CLI restore ───────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["--from-kit", "kit.json"],
    ],
)
def test_agent_restore_is_refused_before_it_starts(monkeypatch, httpx_mock, argv, tmp_path):
    """The kit file is never opened: the refusal happens before that read.

    Passing a kit path that does not exist is the point. A gate that ran after
    the file was parsed would fail on the missing file instead of the reveal.
    """
    if argv:
        argv = ["--from-kit", str(tmp_path / "kit.json")]
    _as_agent(monkeypatch)
    prompts: list[str] = []

    def prompt(*_args, **_kwargs):
        prompts.append("prompt")
        return "should-not-be-read"

    monkeypatch.setattr("command.restore_command.secret_prompt", prompt)
    result, _save = _invoke(argv, input=f"psam\n{PASSPHRASE}\n{NEW_PASSWORD}\n{NEW_PASSWORD}\ny\n")

    assert result.exit_code == 1
    assert "blocked" in result.output
    assert prompts == []
    assert httpx_mock.get_requests() == []
    assert "Username" not in result.output
    assert "psamvault vault restore" not in result.output
    assert "could not read" not in result.output
    assert "YOUR RECOVERY CODES" not in result.output
    row = _last_row()
    assert row["decision"] == "deny"
    assert row["command"] == "restore-codes"
    assert row["entry"] is None
    assert row["caller"] == "agent"


def test_backup_restore_alias_refuses_an_agent_before_prompts(monkeypatch):
    _as_agent(monkeypatch)
    prompts: list[str] = []
    monkeypatch.setattr(
        "command.restore_command.secret_prompt",
        lambda *_a, **_k: prompts.append("prompt"),
    )
    with patch("command.restore_command.is_configured", return_value=True), \
         patch("command.restore_command.is_logged_in", return_value=False):
        result = runner.invoke(app, ["backup", "restore"])

    assert result.exit_code == 1
    assert prompts == []
    assert "blocked" in result.output
    assert _last_row()["command"] == "restore-codes"
    assert _last_row()["decision"] == "deny"


def test_human_restore_shows_codes_and_the_gate_runs_first(monkeypatch, httpx_mock):
    _as_human(monkeypatch)
    events: list[str] = []
    _watch_gate(monkeypatch, events)

    import secret_prompt

    real_prompt = secret_prompt.secret_prompt

    def prompting(text, **kwargs):
        events.append("prompt")
        return real_prompt(text, **kwargs)

    monkeypatch.setattr("command.restore_command.secret_prompt", prompting)
    _mock_the_restore_network(httpx_mock)
    httpx_mock.add_response(
        method="POST",
        url=f"{BASE}/auth/recovery/generate",
        json={"detail": "ok", "remaining_codes": 8},
        status_code=200,
    )

    result, _save = _invoke(
        [],
        input=f"psam\n{PASSPHRASE}\n{NEW_PASSWORD}\n{NEW_PASSWORD}\ny\n",
    )

    assert result.exit_code == 0, result.output
    assert events[0] == "gate"
    assert "prompt" in events
    assert events.index("prompt") > 0
    codes = _codes_in(result.output)
    assert len(codes) == 8
    assert "YOUR RECOVERY CODES" in result.output
    generate = [r for r in httpx_mock.get_requests() if r.url.path.endswith("/recovery/generate")]
    assert len(generate) == 1
    row = _last_row()
    assert row["decision"] == "allow"
    assert row["command"] == "restore-codes"
    assert row["entry"] is None
    assert row["caller"] == "human"
    assert PASSPHRASE not in str(row)
    assert codes[0] not in str(row)


def test_restore_no_codes_is_not_gated_for_an_agent(monkeypatch, httpx_mock):
    """``--no-codes`` never shows codes, so an agent may restore without a reveal."""
    _as_agent(monkeypatch)
    _mock_the_restore_network(httpx_mock)
    result, _save = _invoke(
        ["--no-codes"],
        input=f"psam\n{PASSPHRASE}\n{NEW_PASSWORD}\n{NEW_PASSWORD}\n",
    )

    assert result.exit_code == 0, result.output
    assert "blocked" not in result.output
    assert "YOUR RECOVERY CODES" not in result.output
    assert httpx_mock.get_requests(), "the restore itself still runs"
    assert not [r for r in httpx_mock.get_requests() if "recovery" in r.url.path]
    assert all(row["command"] != "restore-codes" for row in audit.read())


# ── Dashboard ─────────────────────────────────────────────────────────────


def _dashboard(
    monkeypatch,
    tmp_path,
    fake_keychain,
    *,
    agent=False,
    human=False,
    login_password: str | None = None,
):
    if agent:
        _as_agent(monkeypatch)
    if human:
        _as_human(monkeypatch)
    app, _calls, _gets, _stored = _build_dashboard_app(monkeypatch, tmp_path, fake_keychain)
    # The builder writes a ciphertext that no password opens. A test that
    # really checks the login password replaces it before the first read.
    if login_password is not None:
        _install_login_wrap(fake_keychain, login_password)
    raw = app.test_client()
    opened = _exchange(raw, dash_cache.CACHE.launch_token)
    assert opened.status_code == 200, opened.data
    _response, body = _bootstrap(raw, headers={"Origin": _DASHBOARD_ORIGIN})
    return raw, body


def _install_login_wrap(fake_keychain, password: str = LOGIN_PASSWORD) -> None:
    record = _login_session(password)
    for field, value in record.items():
        fake_keychain.set_password("psamvault", f"session.{field}", value)


def test_dashboard_agent_cannot_issue_codes_and_a_missing_csrf_is_not_audited(
    monkeypatch, tmp_path, fake_keychain
):
    raw, body = _dashboard(monkeypatch, tmp_path, fake_keychain, agent=True)
    issued = {"n": 0}

    def forbid(*_args, **_kwargs):
        issued["n"] += 1
        raise AssertionError("recovery codes must not be issued")

    monkeypatch.setattr(account_flows, "issue_recovery_codes", forbid)
    monkeypatch.setattr(api_client, "generate_recovery_codes_api", forbid)

    missing = raw.post(
        "/api/auth/recovery-codes",
        json={"password": LOGIN_PASSWORD},
        headers={"Origin": _DASHBOARD_ORIGIN},
    )
    assert missing.status_code == 403
    assert audit.read() == []
    assert issued["n"] == 0

    refused = raw.post(
        "/api/auth/recovery-codes",
        json={"password": LOGIN_PASSWORD},
        headers={**_csrf(body), "Origin": _DASHBOARD_ORIGIN},
    )
    assert refused.status_code == 403
    text = refused.get_data(as_text=True)
    assert "blocked" in refused.get_json()["error"]
    assert LOGIN_PASSWORD not in text
    assert issued["n"] == 0
    row = _last_row()
    assert row["decision"] == "deny"
    assert row["command"] == "generate-codes"
    assert row["entry"] is None
    assert row["caller"] == "agent"


def test_dashboard_human_issue_shows_codes_and_the_gate_runs_first(
    monkeypatch, tmp_path, fake_keychain
):
    events: list[str] = []
    _watch_gate(monkeypatch, events)
    raw, body = _dashboard(
        monkeypatch, tmp_path, fake_keychain, human=True, login_password=LOGIN_PASSWORD
    )

    def store(**_kwargs):
        events.append("api")
        return {"ok": True}

    monkeypatch.setattr(api_client, "generate_recovery_codes_api", store)
    issued = raw.post(
        "/api/auth/recovery-codes",
        json={"password": LOGIN_PASSWORD},
        headers={**_csrf(body), "Origin": _DASHBOARD_ORIGIN},
    )
    assert issued.status_code == 200, issued.data
    codes = issued.get_json()["codes"]
    assert len(codes) == 8
    assert all(CODE_RE.fullmatch(code) for code in codes)
    assert events == ["gate", "api"]
    assert LOGIN_PASSWORD not in issued.get_data(as_text=True)
    row = _last_row()
    assert row["decision"] == "allow"
    assert row["command"] == "generate-codes"
    assert row["entry"] is None
    assert row["caller"] == "human"
    assert codes[0] not in str(row)


def test_dashboard_agent_restore_with_codes_does_not_start(
    monkeypatch, tmp_path, fake_keychain
):
    raw, body = _dashboard(monkeypatch, tmp_path, fake_keychain, agent=True)
    started = {"n": 0}

    def forbid(*_args, **_kwargs):
        started["n"] += 1
        raise AssertionError("restore must not start")

    monkeypatch.setattr(account_flows, "restore_account", forbid)
    monkeypatch.setattr(api_client, "begin_key_envelope_restore", forbid)
    monkeypatch.setattr(api_client, "restore_vault_key", forbid)
    monkeypatch.setattr(api_client, "generate_recovery_codes_api", forbid)

    refused = raw.post(
        "/api/auth/restore",
        json={
            "username": "psam",
            "passphrase": PASSPHRASE,
            "new_password": NEW_PASSWORD,
            "confirm": NEW_PASSWORD,
            "generate_codes": True,
            "replace_session": True,
        },
        headers={**_csrf(body), "Origin": _DASHBOARD_ORIGIN},
    )
    assert refused.status_code == 403
    text = refused.get_data(as_text=True)
    assert "blocked" in refused.get_json()["error"]
    assert PASSPHRASE not in text
    assert NEW_PASSWORD not in text
    assert started["n"] == 0
    row = _last_row()
    assert row["decision"] == "deny"
    assert row["command"] == "restore-codes"
    assert row["entry"] is None
    assert row["caller"] == "agent"


def test_dashboard_human_restore_with_codes_gates_before_the_restore(
    monkeypatch, tmp_path, fake_keychain
):
    events: list[str] = []
    _watch_gate(monkeypatch, events)
    raw, body = _dashboard(monkeypatch, tmp_path, fake_keychain, human=True)

    wrapped, iv, slot_salt = wrap_vek_with_passphrase(PASSPHRASE, TEST_VEK)

    def begin(_username, _passphrase):
        events.append("begin")
        return {
            "wrapped_vek": wrapped,
            "iv": iv,
            "kdf_salt": slot_salt,
            "slot_id": "slot-1",
            "account_kdf_salt": SALT,
        }

    def store(access_token, codes):
        events.append("api")
        assert access_token
        assert len(codes) == 8
        return {"ok": True}

    def login(_username, _master):
        master = derive_master_password(NEW_PASSWORD)
        key = derive_key(master, SALT)
        encrypted, vek_iv = encrypt_vek(bytes(key), TEST_VEK)
        return {
            "access_token": "access-from-login",
            "refresh_token": "refresh-from-login",
            "kdf_salt": SALT,
            "encrypted_vek": encrypted,
            "vek_iv": vek_iv,
            "has_recovery_codes": False,
        }

    monkeypatch.setattr(api_client, "begin_key_envelope_restore", begin)
    monkeypatch.setattr(api_client, "restore_vault_key", lambda **_kwargs: {"ok": True})
    monkeypatch.setattr(api_client, "login", login)
    monkeypatch.setattr(api_client, "generate_recovery_codes_api", store)

    restored = raw.post(
        "/api/auth/restore",
        json={
            "username": "psam",
            "passphrase": PASSPHRASE,
            "new_password": NEW_PASSWORD,
            "confirm": NEW_PASSWORD,
            "generate_codes": True,
            "replace_session": True,
        },
        headers={**_csrf(body), "Origin": _DASHBOARD_ORIGIN},
    )
    assert restored.status_code == 200, restored.data
    codes = restored.get_json()["recovery_codes"]
    assert len(codes) == 8
    assert all(CODE_RE.fullmatch(code) for code in codes)
    assert events[0] == "gate"
    assert events.index("begin") > 0
    assert events.index("api") > events.index("begin")
    assert PASSPHRASE not in restored.get_data(as_text=True)
    row = _last_row()
    assert row["decision"] == "allow"
    assert row["command"] == "restore-codes"
    assert row["entry"] is None
    assert row["caller"] == "human"
    assert codes[0] not in str(row)


def test_dashboard_restore_without_codes_is_not_a_reveal(monkeypatch, tmp_path, fake_keychain):
    raw, body = _dashboard(monkeypatch, tmp_path, fake_keychain, agent=True)
    seen = {}

    def fake_restore(*_args, **kwargs):
        seen["generate_codes"] = kwargs.get("generate_codes")
        return {
            "username": "psam",
            "has_recovery_codes": True,
            "proof": "empty vault",
            "warning": None,
            "recovery_codes": None,
        }

    monkeypatch.setattr(account_flows, "restore_account", fake_restore)
    restored = raw.post(
        "/api/auth/restore",
        json={
            "username": "psam",
            "passphrase": PASSPHRASE,
            "new_password": NEW_PASSWORD,
            "confirm": NEW_PASSWORD,
            "generate_codes": False,
            "replace_session": True,
        },
        headers={**_csrf(body), "Origin": _DASHBOARD_ORIGIN},
    )
    assert restored.status_code == 200, restored.data
    assert restored.get_json()["recovery_codes"] is None
    assert seen["generate_codes"] is False
    assert audit.read() == []
    assert PASSPHRASE not in restored.get_data(as_text=True)
