"""Account flows used by the dashboard.

These tests check the same crypto the terminal uses, and that the returned
status never carries the vault key, a token, or the password.
"""

from __future__ import annotations

import json

import pytest
from cryptography.exceptions import InvalidTag

import account_flows
import api_client
import session
from crypto import (
    decrypt_vek,
    derive_key,
    derive_master_password,
    encrypt_credentials,
    encrypt_master_with_code,
    encrypt_vek,
    wrap_vek_with_passphrase,
    build_kit,
)
from errors import SessionExpiredError
from tests.conftest import TEST_VEK

PASSWORD = "Password1"
NEW_PASSWORD = "NewPassword1"
USERNAME = "psam"
SALT = "ab" * 32
CODE = "ABCD-EF01-2345"
PASSPHRASE = "backup-passphrase-1"


def _login_payload(password: str = PASSWORD, *, codes: bool = True) -> dict:
    master = derive_master_password(password)
    key = derive_key(master, SALT)
    encrypted, iv = encrypt_vek(bytes(key), TEST_VEK)
    return {
        "access_token": "access-from-login",
        "refresh_token": "refresh-from-login",
        "kdf_salt": SALT,
        "encrypted_vek": encrypted,
        "vek_iv": iv,
        "has_recovery_codes": codes,
    }


@pytest.fixture
def isolated_session(monkeypatch, tmp_path, fake_keychain):
    monkeypatch.setattr(session, "SESSION_FILE", tmp_path / "session.json")
    monkeypatch.setattr(account_flows, "is_configured", lambda: True)
    return fake_keychain


def _saved_vek() -> bytes:
    return bytes.fromhex(session.load_session()["vek"])


def test_login_stores_the_vault_key_and_returns_no_secrets(isolated_session, monkeypatch):
    monkeypatch.setattr(api_client, "login", lambda username, master: _login_payload())
    status = account_flows.login_account(USERNAME, PASSWORD)
    assert status == {"username": USERNAME, "has_recovery_codes": True}
    assert _saved_vek() == TEST_VEK
    assert "access-from-login" == session.load_session()["access_token"]
    dumped = json.dumps(status)
    assert PASSWORD not in dumped
    assert TEST_VEK.hex() not in dumped


def test_login_wrong_password_does_not_write_a_session(isolated_session, monkeypatch):
    def reject(username, master):
        raise SessionExpiredError("nope")

    monkeypatch.setattr(api_client, "login", reject)
    with pytest.raises(account_flows.AccountFlowError, match="Wrong username or password"):
        account_flows.login_account(USERNAME, PASSWORD)
    assert session.is_logged_in() is False


def test_recover_rewraps_the_same_vault_key(isolated_session, monkeypatch):
    encrypted, iv, code_salt = encrypt_master_with_code(CODE, TEST_VEK.hex())
    seen = {}

    def recover(username, code):
        assert code == CODE
        return {
            "encrypted_master": encrypted,
            "iv": iv,
            "code_kdf_salt": code_salt,
            "kdf_salt": SALT,
        }

    def reset(**kwargs):
        seen["reset"] = kwargs
        return {"remaining_codes": 7}

    monkeypatch.setattr(api_client, "recover_with_code", recover)
    monkeypatch.setattr(api_client, "reset_password_api", reset)
    monkeypatch.setattr(api_client, "login", lambda username, master: _login_payload(NEW_PASSWORD))

    status = account_flows.recover_account(USERNAME, CODE, NEW_PASSWORD, NEW_PASSWORD)
    assert status["username"] == USERNAME
    assert _saved_vek() == TEST_VEK
    login_key = derive_key(derive_master_password(NEW_PASSWORD), SALT)
    assert decrypt_vek(login_key, seen["reset"]["new_encrypted_vek"], seen["reset"]["new_vek_iv"]) == TEST_VEK
    assert NEW_PASSWORD not in json.dumps(status)


def test_recover_rejects_a_bad_code_before_reset(isolated_session, monkeypatch):
    encrypted, iv, code_salt = encrypt_master_with_code("FFFF-FFFF-FFFF", TEST_VEK.hex())
    monkeypatch.setattr(
        api_client,
        "recover_with_code",
        lambda username, code: {
            "encrypted_master": encrypted,
            "iv": iv,
            "code_kdf_salt": code_salt,
            "kdf_salt": SALT,
        },
    )

    def reset(**kwargs):
        raise AssertionError("reset must not run")

    monkeypatch.setattr(api_client, "reset_password_api", reset)
    with pytest.raises(account_flows.AccountFlowError, match="incorrect"):
        account_flows.recover_account(USERNAME, CODE, NEW_PASSWORD, NEW_PASSWORD)


def test_restore_with_passphrase_proves_an_entry_and_can_return_codes(isolated_session, monkeypatch):
    wrapped, iv, slot_salt = wrap_vek_with_passphrase(PASSPHRASE, TEST_VEK)
    blob, entry_iv = encrypt_credentials(TEST_VEK, "alice", "s3cr3t-Password1")
    issued = {}

    monkeypatch.setattr(
        api_client,
        "begin_key_envelope_restore",
        lambda username, passphrase: {
            "wrapped_vek": wrapped,
            "iv": iv,
            "kdf_salt": slot_salt,
            "slot_id": "slot-1",
            "account_kdf_salt": SALT,
        },
    )
    monkeypatch.setattr(api_client, "restore_vault_key", lambda **kwargs: {"ok": True})
    monkeypatch.setattr(api_client, "login", lambda username, master: _login_payload(NEW_PASSWORD, codes=False))
    monkeypatch.setattr(
        api_client,
        "list_vault_entries",
        lambda access, refresh: {"entries": [{"site_name": "GitHub"}]},
    )
    monkeypatch.setattr(
        api_client,
        "get_vault_entry",
        lambda access, refresh, site: {"site_name": site, "encrypted_blob": blob, "iv": entry_iv},
    )

    def store(access_token, codes):
        issued["n"] = len(codes)
        return {"ok": True}

    monkeypatch.setattr(api_client, "generate_recovery_codes_api", store)
    status = account_flows.restore_account(
        USERNAME, PASSPHRASE, NEW_PASSWORD, NEW_PASSWORD, generate_codes=True
    )
    assert status["proof"] == "GitHub"
    assert status["username"] == USERNAME
    assert len(status["recovery_codes"]) == 8
    assert issued["n"] == 8
    assert _saved_vek() == TEST_VEK
    dumped = json.dumps({key: value for key, value in status.items() if key != "recovery_codes"})
    assert PASSPHRASE not in dumped
    assert TEST_VEK.hex() not in dumped


def test_restore_from_kit_uses_the_account_inside_the_file(isolated_session, monkeypatch):
    wrapped, iv, slot_salt = wrap_vek_with_passphrase(PASSPHRASE, TEST_VEK)
    kit = build_kit(
        account="from-kit",
        wrapped_vek=wrapped,
        iv=iv,
        salt=slot_salt,
        slot_id="slot-1",
        account_kdf_salt=SALT,
    )
    monkeypatch.setattr(
        api_client,
        "validate_key_envelope_slot",
        lambda slot_id: {"exists": True, "revoked": False},
    )
    monkeypatch.setattr(api_client, "restore_vault_key", lambda **kwargs: {"ok": True})
    monkeypatch.setattr(api_client, "login", lambda username, master: _login_payload(NEW_PASSWORD))
    monkeypatch.setattr(api_client, "list_vault_entries", lambda access, refresh: {"entries": []})
    status = account_flows.restore_account(
        "", PASSPHRASE, NEW_PASSWORD, NEW_PASSWORD, kit_text=json.dumps(kit)
    )
    assert status["username"] == "from-kit"
    assert status["proof"] == "empty vault"
    assert status["recovery_codes"] is None


def test_issue_codes_requires_the_login_password(isolated_session, monkeypatch):
    payload = _login_payload()
    session.save_session(
        access_token=payload["access_token"],
        refresh_token=payload["refresh_token"],
        kdf_salt=payload["kdf_salt"],
        vek=TEST_VEK.hex(),
        encrypted_vek=payload["encrypted_vek"],
        vek_iv=payload["vek_iv"],
    )
    stored = session.load_session()
    monkeypatch.setattr(api_client, "generate_recovery_codes_api", lambda **kwargs: {"ok": True})
    codes = account_flows.issue_recovery_codes(PASSWORD, stored)
    assert len(codes) == 8
    with pytest.raises(account_flows.AccountFlowError, match="incorrect"):
        account_flows.issue_recovery_codes("WrongPassword1", stored)


def test_logout_clears_the_session_when_the_server_revoke_fails(isolated_session, monkeypatch):
    payload = _login_payload()
    session.save_session(
        access_token=payload["access_token"],
        refresh_token=payload["refresh_token"],
        kdf_salt=payload["kdf_salt"],
        vek=TEST_VEK.hex(),
        encrypted_vek=payload["encrypted_vek"],
        vek_iv=payload["vek_iv"],
    )

    def explode(access_token, refresh_token):
        raise ConnectionError("offline")

    monkeypatch.setattr(api_client, "logout", explode)
    account_flows.logout_account(payload["access_token"], payload["refresh_token"])
    assert session.is_logged_in() is False


def test_bad_code_decrypt_is_invalid_tag():
    """The recovery helper really raises InvalidTag for a mismatched code."""
    encrypted, iv, code_salt = encrypt_master_with_code(CODE, TEST_VEK.hex())
    with pytest.raises(InvalidTag):
        from crypto import decrypt_master_with_code

        decrypt_master_with_code("FFFF-FFFF-FFFF", encrypted, iv, code_salt)
