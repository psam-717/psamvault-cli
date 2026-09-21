"""Tests for `psamvault restore` — the session-less machine-loss recovery flow.

The point of these tests: a restore must (a) work without any session, (b) end with the
VEK wrapped under a login key derived *on this machine*, and (c) prove itself by opening
a real entry rather than trusting an HTTP status code.
"""
import json
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

import api_client
from crypto import (
    decrypt_credentials,
    decrypt_vek,
    derive_key,
    derive_master_password,
    encrypt_credentials,
    wrap_vek_with_passphrase,
)

from main import app

runner = CliRunner()
BASE = "https://test.example.com"

VEK = bytes(range(32))
PASSPHRASE = "backup-passphrase-1"
NEW_PASSWORD = "NewPassword1"
SLOT_ID = "11111111-2222-3333-4444-555555555555"
ACCOUNT_SALT = "aa" * 32

SESSION = {
    "access_token": "tok",
    "refresh_token": "ref",
    "kdf_salt": ACCOUNT_SALT,
    "vek": VEK.hex(),
    "encrypted_vek": "bb" * 48,
    "vek_iv": "cc" * 12,
}


@pytest.fixture(autouse=True)
def no_background_tasks():
    with patch("main.start_update_check"), \
         patch("main.check_and_show_upgrade_notice"), \
         patch("main.print_update_notice"):
        yield


def _invoke(args, input=None, configured=True, logged_in=False):
    """Invoke `restore` with config/login/session state faked out."""
    with patch("command.restore_command.is_configured", return_value=configured), \
         patch("command.restore_command.is_logged_in", return_value=logged_in), \
         patch("command.restore_command.save_session") as mock_save, \
         patch("command.restore_command.load_session", return_value=SESSION):
        result = runner.invoke(app, ["restore", *args], input=input)
    return result, mock_save


def _entry_for(site: str, username: str, password: str) -> dict:
    blob, iv = encrypt_credentials(VEK, username, password)
    return {
        "site_name": site,
        "encrypted_blob": blob,
        "iv": iv,
        "username_hint": username,
        "login_url": "",
        "created_at": "2026-09-18T22:00:00Z",
        "updated_at": "2026-09-18T22:00:00Z",
    }


def _kit(tmp_path, *, slot_id=SLOT_ID, account_kdf_salt=ACCOUNT_SALT):
    wrapped, iv, salt = wrap_vek_with_passphrase(PASSPHRASE, VEK)
    kit = {
        "kind": "psamvault-key-envelope",
        "format": 1,
        "account": "psam",
        "slot_id": slot_id,
        "kdf": {"algo": "pbkdf2-hmac-sha256", "iterations": 600_000, "salt": salt},
        "account_kdf_salt": account_kdf_salt,
        "wrapped_vek": wrapped,
        "iv": iv,
        "created_at": "2026-09-18T22:00:00Z",
    }
    path = tmp_path / "kit.json"
    path.write_text(json.dumps(kit), encoding="utf-8")
    return path


# ── guards ────────────────────────────────────────────────────────────────────


def test_restore_requires_configuration():
    result, _ = _invoke([], configured=False)
    assert result.exit_code == 1
    assert "not configured" in result.output
    assert "psamvault configure" in result.output


def test_restore_refuses_when_a_session_already_exists():
    result, _ = _invoke([], logged_in=True)
    assert result.exit_code == 1
    assert "already has a session" in result.output
    assert "--force" in result.output


# ── the path that matters: passphrase -> working vault ────────────────────────


def test_restore_rewraps_the_vek_under_a_login_key_derived_here(httpx_mock):
    wrapped, iv, salt = wrap_vek_with_passphrase(PASSPHRASE, VEK)
    httpx_mock.add_response(
        method="POST", url=f"{BASE}/auth/key-envelope/begin",
        json={
            "slot_id": SLOT_ID, "wrapped_vek": wrapped, "iv": iv,
            "kdf_salt": salt, "account_kdf_salt": ACCOUNT_SALT,
        },
        status_code=200,
    )
    httpx_mock.add_response(
        method="POST", url=f"{BASE}/auth/key-envelope/restore",
        json={"detail": "Vault access restored", "slot_id": SLOT_ID, "active_slots": 1},
        status_code=200,
    )
    httpx_mock.add_response(
        method="POST", url=f"{BASE}/auth/login",
        json={
            "access_token": "new_tok", "refresh_token": "new_ref", "token_type": "bearer",
            "kdf_salt": ACCOUNT_SALT, "encrypted_vek": "dd" * 48, "vek_iv": "ee" * 12,
            "has_recovery_codes": False,
        },
        status_code=200,
    )
    entry = _entry_for("github.com", "alice", "hunter2")
    httpx_mock.add_response(
        method="GET", url=f"{BASE}/vault",
        json={"entries": [entry], "total": 1}, status_code=200,
    )
    httpx_mock.add_response(
        method="GET", url=f"{BASE}/vault/github.com", json=entry, status_code=200,
    )

    result, mock_save = _invoke(
        [],
        input=f"psam\n{PASSPHRASE}\n{NEW_PASSWORD}\n{NEW_PASSWORD}\nn\n",
    )

    assert result.exit_code == 0, result.output

    # The restore call must carry the VEK wrapped under a login key derived on THIS
    # machine from the new password + the account salt.
    restore_requests = [
        r for r in httpx_mock.get_requests() if r.url.path.endswith("/key-envelope/restore")
    ]
    assert len(restore_requests) == 1
    body = json.loads(restore_requests[0].content)
    master = derive_master_password(NEW_PASSWORD)
    assert body["new_login_password"] == master
    login_key = derive_key(master, ACCOUNT_SALT)
    assert decrypt_vek(login_key, body["new_encrypted_vek"], body["new_vek_iv"]) == VEK
    # The passphrase itself authenticates the request (the server Argon2-verifies it, the
    # same way it verifies a recovery code). The VEK hex must never cross the wire.
    assert body["passphrase"] == PASSPHRASE
    assert VEK.hex() not in restore_requests[0].content.decode()

    # The session on this machine now holds the recovered VEK
    assert mock_save.called
    kwargs = mock_save.call_args.kwargs
    assert kwargs["vek"] == VEK.hex()
    assert kwargs["kdf_salt"] == ACCOUNT_SALT

    assert "Restored and logged in as psam" in result.output
    assert "Decrypted 'github.com' with the recovered key" in result.output
    assert "nothing was re-encrypted or moved" in result.output


def test_restore_rejects_a_wrong_passphrase(httpx_mock):
    httpx_mock.add_response(
        method="POST", url=f"{BASE}/auth/key-envelope/begin",
        json={"detail": "That passphrase does not match any backup slot for this account"},
        status_code=401,
    )

    result, _ = _invoke([], input="psam\nwrong-passphrase-1\n")

    assert result.exit_code == 1
    assert "does not match any backup slot" in result.output
    assert "--from-kit" in result.output


def test_restore_fails_loudly_when_the_key_cannot_open_an_entry(httpx_mock):
    wrapped, iv, salt = wrap_vek_with_passphrase(PASSPHRASE, VEK)
    httpx_mock.add_response(
        method="POST", url=f"{BASE}/auth/key-envelope/begin",
        json={
            "slot_id": SLOT_ID, "wrapped_vek": wrapped, "iv": iv,
            "kdf_salt": salt, "account_kdf_salt": ACCOUNT_SALT,
        },
        status_code=200,
    )
    httpx_mock.add_response(
        method="POST", url=f"{BASE}/auth/key-envelope/restore",
        json={"detail": "Vault access restored", "slot_id": SLOT_ID, "active_slots": 1},
        status_code=200,
    )
    httpx_mock.add_response(
        method="POST", url=f"{BASE}/auth/login",
        json={
            "access_token": "t", "refresh_token": "r", "token_type": "bearer",
            "kdf_salt": ACCOUNT_SALT, "encrypted_vek": "dd" * 48, "vek_iv": "ee" * 12,
            "has_recovery_codes": True,
        },
        status_code=200,
    )
    # An entry encrypted under a DIFFERENT key than the one we recovered
    wrong_blob, wrong_iv = encrypt_credentials(bytes(reversed(range(32))), "alice", "hunter2")
    httpx_mock.add_response(
        method="GET", url=f"{BASE}/vault",
        json={"entries": [{"site_name": "github.com", "encrypted_blob": wrong_blob,
                           "iv": wrong_iv, "username_hint": "alice"}], "total": 1},
        status_code=200,
    )
    httpx_mock.add_response(
        method="GET", url=f"{BASE}/vault/github.com",
        json={"site_name": "github.com", "encrypted_blob": wrong_blob, "iv": wrong_iv},
        status_code=200,
    )

    result, _ = _invoke([], input=f"psam\n{PASSPHRASE}\n{NEW_PASSWORD}\n{NEW_PASSWORD}\nn\n")

    assert result.exit_code == 1
    assert "could not be decrypted" in result.output
    assert "entries are untouched" in result.output


def test_restore_offers_fresh_recovery_codes(httpx_mock):
    wrapped, iv, salt = wrap_vek_with_passphrase(PASSPHRASE, VEK)
    httpx_mock.add_response(
        method="POST", url=f"{BASE}/auth/key-envelope/begin",
        json={
            "slot_id": SLOT_ID, "wrapped_vek": wrapped, "iv": iv,
            "kdf_salt": salt, "account_kdf_salt": ACCOUNT_SALT,
        },
        status_code=200,
    )
    httpx_mock.add_response(
        method="POST", url=f"{BASE}/auth/key-envelope/restore",
        json={"detail": "ok", "slot_id": SLOT_ID, "active_slots": 1}, status_code=200,
    )
    httpx_mock.add_response(
        method="POST", url=f"{BASE}/auth/login",
        json={
            "access_token": "t", "refresh_token": "r", "token_type": "bearer",
            "kdf_salt": ACCOUNT_SALT, "encrypted_vek": "dd" * 48, "vek_iv": "ee" * 12,
            "has_recovery_codes": False,
        },
        status_code=200,
    )
    entry = _entry_for("github.com", "alice", "hunter2")
    httpx_mock.add_response(
        method="GET", url=f"{BASE}/vault", json={"entries": [entry], "total": 1}, status_code=200,
    )
    httpx_mock.add_response(
        method="GET", url=f"{BASE}/vault/github.com", json=entry, status_code=200,
    )
    httpx_mock.add_response(
        method="POST", url=f"{BASE}/auth/recovery/generate",
        json={"detail": "Recovery codes generated successfully", "remaining_codes": 8},
        status_code=200,
    )

    result, _ = _invoke([], input=f"psam\n{PASSPHRASE}\n{NEW_PASSWORD}\n{NEW_PASSWORD}\ny\n")

    assert result.exit_code == 0, result.output
    assert "8 fresh recovery codes stored" in result.output
    generate = [r for r in httpx_mock.get_requests() if r.url.path.endswith("/recovery/generate")]
    assert len(generate) == 1
    # The codes wrap the recovered VEK — not some other key
    payload = json.loads(generate[0].content)
    assert payload["codes"][0]["code_hash"].startswith("$argon2")


# ── the kit path ──────────────────────────────────────────────────────────────


def test_restore_from_kit_works_without_the_server_slot(httpx_mock, tmp_path):
    kit_path = _kit(tmp_path)
    httpx_mock.add_response(
        method="POST", url=f"{BASE}/auth/key-envelope/validate",
        json={"exists": True, "revoked": False, "kind": "passphrase"}, status_code=200,
    )
    httpx_mock.add_response(
        method="POST", url=f"{BASE}/auth/key-envelope/restore",
        json={"detail": "ok", "slot_id": SLOT_ID, "active_slots": 1}, status_code=200,
    )
    httpx_mock.add_response(
        method="POST", url=f"{BASE}/auth/login",
        json={
            "access_token": "t", "refresh_token": "r", "token_type": "bearer",
            "kdf_salt": ACCOUNT_SALT, "encrypted_vek": "dd" * 48, "vek_iv": "ee" * 12,
            "has_recovery_codes": True,
        },
        status_code=200,
    )
    entry = _entry_for("github.com", "alice", "hunter2")
    httpx_mock.add_response(
        method="GET", url=f"{BASE}/vault", json={"entries": [entry], "total": 1}, status_code=200,
    )
    httpx_mock.add_response(
        method="GET", url=f"{BASE}/vault/github.com", json=entry, status_code=200,
    )

    result, mock_save = _invoke(
        ["--from-kit", str(kit_path)],
        input=f"{PASSPHRASE}\n{NEW_PASSWORD}\n{NEW_PASSWORD}\nn\n",
    )

    assert result.exit_code == 0, result.output
    paths = [r.url.path for r in httpx_mock.get_requests()]
    assert "/auth/key-envelope/validate" in paths
    assert "/auth/key-envelope/begin" not in paths  # the kit already carries the key
    assert mock_save.call_args.kwargs["vek"] == VEK.hex()
    assert "Restored and logged in as psam" in result.output


def test_restore_from_kit_refuses_a_revoked_slot(httpx_mock, tmp_path):
    """The refusal must STOP the flow — not print a message and carry on restoring."""
    kit_path = _kit(tmp_path)
    httpx_mock.add_response(
        method="POST", url=f"{BASE}/auth/key-envelope/validate",
        json={"exists": True, "revoked": True, "kind": "passphrase"}, status_code=200,
    )

    result, mock_save = _invoke(["--from-kit", str(kit_path)], input=f"{PASSPHRASE}\n")

    assert result.exit_code == 1
    assert "was revoked" in result.output
    # No continuation: no "could not check" fallback, no new-password prompt, no restore call
    assert "could not check the kit" not in result.output
    assert "Set a new login password" not in result.output
    assert not [r for r in httpx_mock.get_requests() if r.url.path.endswith("/restore")]
    assert not mock_save.called


def test_restore_from_kit_needs_the_account_salt(tmp_path):
    kit_path = _kit(tmp_path, account_kdf_salt=None)

    result, _ = _invoke(["--from-kit", str(kit_path)])

    assert result.exit_code == 1
    assert "no account salt" in result.output


def test_restore_from_kit_continues_when_the_server_cannot_be_reached(httpx_mock, tmp_path):
    """A self-contained kit must still work offline — the slot check is a courtesy."""
    import httpx

    kit_path = _kit(tmp_path)
    httpx_mock.add_exception(
        httpx.ConnectError("no route to host"),
        method="POST", url=f"{BASE}/auth/key-envelope/validate",
    )
    httpx_mock.add_response(
        method="POST", url=f"{BASE}/auth/key-envelope/restore",
        json={"detail": "ok", "slot_id": SLOT_ID, "active_slots": 1}, status_code=200,
    )
    httpx_mock.add_response(
        method="POST", url=f"{BASE}/auth/login",
        json={
            "access_token": "t", "refresh_token": "r", "token_type": "bearer",
            "kdf_salt": ACCOUNT_SALT, "encrypted_vek": "dd" * 48, "vek_iv": "ee" * 12,
            "has_recovery_codes": True,
        },
        status_code=200,
    )
    entry = _entry_for("github.com", "alice", "hunter2")
    httpx_mock.add_response(
        method="GET", url=f"{BASE}/vault", json={"entries": [entry], "total": 1}, status_code=200,
    )
    httpx_mock.add_response(
        method="GET", url=f"{BASE}/vault/github.com", json=entry, status_code=200,
    )

    result, mock_save = _invoke(
        ["--from-kit", str(kit_path)],
        input=f"{PASSPHRASE}\n{NEW_PASSWORD}\n{NEW_PASSWORD}\nn\n",
    )

    assert result.exit_code == 0, result.output
    assert "could not check the kit" in result.output
    assert mock_save.call_args.kwargs["vek"] == VEK.hex()


def test_restore_from_kit_rejects_a_wrong_passphrase(httpx_mock, tmp_path):
    kit_path = _kit(tmp_path)
    httpx_mock.add_response(
        method="POST", url=f"{BASE}/auth/key-envelope/validate",
        json={"exists": True, "revoked": False, "kind": "passphrase"}, status_code=200,
    )

    result, _ = _invoke(["--from-kit", str(kit_path)], input="not-the-passphrase\n")

    assert result.exit_code == 1
    assert "does not open this kit" in result.output


def test_restore_from_a_file_that_is_not_a_kit(tmp_path):
    other = tmp_path / "random.json"
    other.write_text('{"hello": 1}', encoding="utf-8")

    result, _ = _invoke(["--from-kit", str(other)])

    assert result.exit_code == 1
    assert "not a psamvault recovery kit" in result.output
