"""Tests for the vault key backup feature — `psamvault backup ...` plus the wire
shape of the key-envelope endpoints.

Layer 2 (CLI commands) + Layer 3 (HTTP client) in one file because the two are a single
feature here: what matters is that the secret never crosses the wire and that the kit
that lands on disk contains key material only.
"""
import json
import os
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

import api_client
import errors
from crypto import unwrap_vek_with_passphrase, wrap_vek_with_passphrase

from main import app

runner = CliRunner()
BASE = "https://test.example.com"

VEK = bytes(range(32))
PASSPHRASE = "backup-passphrase-1"
SLOT_ID = "11111111-2222-3333-4444-555555555555"
OTHER_VEK = bytes(reversed(range(32)))

SESSION = {
    "access_token": "tok",
    "refresh_token": "ref",
    "kdf_salt": "aa" * 32,
    "vek": VEK.hex(),
    "encrypted_vek": "bb" * 48,
    "vek_iv": "cc" * 12,
}

PROFILE = {"user_id": "1", "username": "psam", "email": "psam@example.com"}


@pytest.fixture(autouse=True)
def no_background_tasks():
    """Stop the root callback from doing update checks / keychain reads."""
    with patch("main.start_update_check"), \
         patch("main.check_and_show_upgrade_notice"), \
         patch("main.print_update_notice"):
        yield


def _invoke(args, input=None, logged_in=True, session=None):
    """Invoke the CLI with a faked session and login state."""
    fake = session or SESSION
    with patch("command.backup_commands.is_logged_in", return_value=logged_in), \
         patch("command.backup_commands.load_session", return_value=fake), \
         patch("session.load_session", return_value=fake):
        return runner.invoke(app, args, input=input)


def _slot_response(**overrides):
    payload = {
        "detail": "Backup slot stored",
        "slot_id": SLOT_ID,
        "kind": "passphrase",
        "created_at": "2026-09-18T22:00:00Z",
        "active_slots": 1,
    }
    payload.update(overrides)
    return payload


# ── backup create ─────────────────────────────────────────────────────────────


def test_create_stores_slot_and_writes_a_secret_free_kit(httpx_mock, tmp_path):
    httpx_mock.add_response(method="GET", url=f"{BASE}/auth/me", json=PROFILE, status_code=200)
    httpx_mock.add_response(
        method="POST", url=f"{BASE}/auth/key-envelope/create",
        json=_slot_response(), status_code=200,
    )
    kit_path = tmp_path / "kit.json"

    result = _invoke(
        ["backup", "create", "--out", str(kit_path)],
        input=f"{PASSPHRASE}\n{PASSPHRASE}\n",
    )

    assert result.exit_code == 0, result.output

    # ── what went over the wire ──
    create_requests = [r for r in httpx_mock.get_requests() if r.url.path.endswith("/create")]
    assert len(create_requests) == 1
    body = json.loads(create_requests[0].content)
    assert body["kind"] == "passphrase"
    assert body["passphrase_hash"].startswith("$argon2")
    assert len(body["wrapped_vek"]) == 96  # 32-byte VEK + 16-byte GCM tag, hex
    assert len(body["iv"]) == 24
    assert len(body["kdf_salt"]) == 32
    wire = create_requests[0].content.decode()
    assert PASSPHRASE not in wire
    assert VEK.hex() not in wire

    # ── what landed on disk ──
    kit = json.loads(kit_path.read_text(encoding="utf-8"))
    assert kit["kind"] == "psamvault-key-envelope"
    assert kit["format"] == 1
    assert kit["account"] == "psam"
    assert kit["slot_id"] == SLOT_ID
    assert kit["account_kdf_salt"] == SESSION["kdf_salt"]
    recovered = unwrap_vek_with_passphrase(
        PASSPHRASE, kit["wrapped_vek"], kit["iv"], kit["kdf"]["salt"]
    )
    assert recovered == VEK

    text = kit_path.read_text(encoding="utf-8")
    assert VEK.hex() not in text
    assert PASSPHRASE not in text
    assert "pepper" not in text.lower()
    if os.name != "nt":
        assert (kit_path.stat().st_mode & 0o777) == 0o600

    assert "Backup slot stored" in result.output
    assert "backup verify" in result.output


def test_create_no_upload_skips_the_server_and_writes_a_local_kit(httpx_mock, tmp_path):
    httpx_mock.add_response(method="GET", url=f"{BASE}/auth/me", json=PROFILE, status_code=200)
    kit_path = tmp_path / "kit.json"

    result = _invoke(
        ["backup", "create", "--no-upload", "--out", str(kit_path)],
        input=f"{PASSPHRASE}\n{PASSPHRASE}\n",
    )

    assert result.exit_code == 0, result.output
    assert not [r for r in httpx_mock.get_requests() if r.url.path.endswith("/create")]
    kit = json.loads(kit_path.read_text(encoding="utf-8"))
    assert kit["slot_id"] is None
    assert "Skipping the server copy" in result.output


def test_create_rejects_a_short_passphrase_then_accepts(httpx_mock, tmp_path):
    httpx_mock.add_response(method="GET", url=f"{BASE}/auth/me", json=PROFILE, status_code=200)
    httpx_mock.add_response(
        method="POST", url=f"{BASE}/auth/key-envelope/create",
        json=_slot_response(), status_code=200,
    )
    kit_path = tmp_path / "kit.json"

    result = _invoke(
        ["backup", "create", "--out", str(kit_path)],
        input=f"tooshort\n{PASSPHRASE}\n{PASSPHRASE}\n",
    )

    assert result.exit_code == 0, result.output
    assert "at least 12 characters" in result.output


def test_create_rejects_mismatched_confirmation(httpx_mock, tmp_path):
    httpx_mock.add_response(method="GET", url=f"{BASE}/auth/me", json=PROFILE, status_code=200)
    httpx_mock.add_response(
        method="POST", url=f"{BASE}/auth/key-envelope/create",
        json=_slot_response(), status_code=200,
    )
    kit_path = tmp_path / "kit.json"

    result = _invoke(
        ["backup", "create", "--out", str(kit_path)],
        input=f"{PASSPHRASE}\nnope-not-the-same\n{PASSPHRASE}\n{PASSPHRASE}\n",
    )

    assert result.exit_code == 0, result.output
    assert "do not match" in result.output


def test_create_requires_login():
    result = _invoke(["backup", "create"], logged_in=False)
    assert result.exit_code == 1
    assert "not logged in" in result.output.lower()


def test_create_reports_slot_limit_conflict(httpx_mock, tmp_path):
    # No /auth/me mock: the flow fails at the create call, before it ever builds a kit.
    httpx_mock.add_response(
        method="POST", url=f"{BASE}/auth/key-envelope/create",
        json={"detail": "This account already has 5 active backup slots."},
        status_code=409,
    )

    result = _invoke(
        ["backup", "create", "--out", str(tmp_path / "kit.json")],
        input=f"{PASSPHRASE}\n{PASSPHRASE}\n",
    )

    assert result.exit_code == 1
    assert "5 active backup slots" in result.output


# ── backup verify ─────────────────────────────────────────────────────────────


def test_verify_confirms_a_working_server_slot(httpx_mock):
    wrapped, iv, salt = wrap_vek_with_passphrase(PASSPHRASE, VEK)
    httpx_mock.add_response(method="GET", url=f"{BASE}/auth/me", json=PROFILE, status_code=200)
    httpx_mock.add_response(
        method="POST", url=f"{BASE}/auth/key-envelope/begin",
        json={
            "slot_id": SLOT_ID, "wrapped_vek": wrapped, "iv": iv,
            "kdf_salt": salt, "account_kdf_salt": SESSION["kdf_salt"],
        },
        status_code=200,
    )

    result = _invoke(["backup", "verify"], input=f"{PASSPHRASE}\n")

    assert result.exit_code == 0, result.output
    assert "Verified" in result.output


def test_verify_rejects_a_wrong_passphrase(httpx_mock):
    httpx_mock.add_response(method="GET", url=f"{BASE}/auth/me", json=PROFILE, status_code=200)
    httpx_mock.add_response(
        method="POST", url=f"{BASE}/auth/key-envelope/begin",
        json={"detail": "That passphrase does not match any backup slot for this account"},
        status_code=401,
    )

    result = _invoke(["backup", "verify"], input="wrong-passphrase-1\n")

    assert result.exit_code == 1
    assert "does not match any stored backup slot" in result.output
    assert "backup status" in result.output


def test_verify_detects_a_backup_for_a_different_vault(httpx_mock):
    """A valid passphrase that unwraps to a different VEK must not be reported as OK."""
    wrapped, iv, salt = wrap_vek_with_passphrase(PASSPHRASE, OTHER_VEK)
    httpx_mock.add_response(method="GET", url=f"{BASE}/auth/me", json=PROFILE, status_code=200)
    httpx_mock.add_response(
        method="POST", url=f"{BASE}/auth/key-envelope/begin",
        json={
            "slot_id": SLOT_ID, "wrapped_vek": wrapped, "iv": iv,
            "kdf_salt": salt, "account_kdf_salt": SESSION["kdf_salt"],
        },
        status_code=200,
    )

    result = _invoke(["backup", "verify"], input=f"{PASSPHRASE}\n")

    assert result.exit_code == 1
    assert "DIFFERENT vault key" in result.output


def test_verify_from_a_kit_file(httpx_mock, tmp_path):
    wrapped, iv, salt = wrap_vek_with_passphrase(PASSPHRASE, VEK)
    kit_path = tmp_path / "kit.json"
    kit_path.write_text(
        json.dumps({
            "kind": "psamvault-key-envelope",
            "format": 1,
            "account": "psam",
            "slot_id": SLOT_ID,
            "kdf": {"algo": "pbkdf2-hmac-sha256", "iterations": 600_000, "salt": salt},
            "account_kdf_salt": SESSION["kdf_salt"],
            "wrapped_vek": wrapped,
            "iv": iv,
            "created_at": "2026-09-18T22:00:00Z",
        }),
        encoding="utf-8",
    )

    result = _invoke(["backup", "verify", "--kit", str(kit_path)], input=f"{PASSPHRASE}\n")

    assert result.exit_code == 0, result.output
    assert "Verified" in result.output
    assert not httpx_mock.get_requests()  # a kit check needs no network


def test_verify_from_a_kit_file_with_wrong_passphrase(httpx_mock, tmp_path):
    wrapped, iv, salt = wrap_vek_with_passphrase(PASSPHRASE, VEK)
    kit_path = tmp_path / "kit.json"
    kit_path.write_text(
        json.dumps({
            "kind": "psamvault-key-envelope",
            "format": 1,
            "account": "psam",
            "slot_id": SLOT_ID,
            "kdf": {"algo": "pbkdf2-hmac-sha256", "iterations": 600_000, "salt": salt},
            "account_kdf_salt": SESSION["kdf_salt"],
            "wrapped_vek": wrapped,
            "iv": iv,
        }),
        encoding="utf-8",
    )

    result = _invoke(["backup", "verify", "--kit", str(kit_path)], input="definitely-wrong-1\n")

    assert result.exit_code == 1
    assert "does not open this kit" in result.output


def test_verify_rejects_a_file_that_is_not_a_kit(tmp_path):
    not_a_kit = tmp_path / "notes.json"
    not_a_kit.write_text('{"hello": "world"}', encoding="utf-8")

    result = _invoke(["backup", "verify", "--kit", str(not_a_kit)])

    assert result.exit_code == 1
    assert "not a psamvault recovery kit" in result.output


# ── backup status ─────────────────────────────────────────────────────────────


def test_status_warns_when_there_are_no_slots(httpx_mock):
    httpx_mock.add_response(
        method="GET", url=f"{BASE}/auth/key-envelope/status",
        json={"active_slots": 0, "slots": []}, status_code=200,
    )
    httpx_mock.add_response(
        method="GET", url=f"{BASE}/auth/recovery/remaining",
        json={"detail": "8 recovery code(s) remaining", "remaining_codes": 8}, status_code=200,
    )

    result = _invoke(["backup", "status"])

    assert result.exit_code == 0, result.output
    assert "No backup slots" in result.output
    assert "backup create" in result.output


def test_status_lists_slots_and_recovery_codes(httpx_mock):
    httpx_mock.add_response(
        method="GET", url=f"{BASE}/auth/key-envelope/status",
        json={
            "active_slots": 2,
            "slots": [
                {
                    "slot_id": SLOT_ID, "kind": "passphrase",
                    "created_at": "2026-09-18T22:00:00Z",
                    "last_verified_at": "2026-09-18T22:05:00Z", "revoked": False,
                },
                {
                    "slot_id": "99999999-8888-7777-6666-555555555555", "kind": "passphrase",
                    "created_at": "2026-09-01T10:00:00Z",
                    "last_verified_at": None, "revoked": True,
                },
            ],
        },
        status_code=200,
    )
    httpx_mock.add_response(
        method="GET", url=f"{BASE}/auth/recovery/remaining",
        json={"detail": "2 recovery code(s) remaining", "remaining_codes": 2}, status_code=200,
    )

    result = _invoke(["backup", "status"])

    assert result.exit_code == 0, result.output
    assert "11111111" in result.output
    assert "active" in result.output
    assert "revoked" in result.output
    assert "Active backup slots : 2" in result.output
    assert "Recovery codes left : 2" in result.output
    assert "not backed up" in result.output


# ── backup rotate / revoke ────────────────────────────────────────────────────


def test_rotate_stores_a_new_slot_and_writes_a_new_kit(httpx_mock, tmp_path):
    httpx_mock.add_response(method="GET", url=f"{BASE}/auth/me", json=PROFILE, status_code=200)
    httpx_mock.add_response(
        method="POST", url=f"{BASE}/auth/key-envelope/rotate",
        json={
            "detail": "Backup passphrase rotated", "slot_id": "77777777-1111-2222-3333-444444444444",
            "revoked_slots": 2, "active_slots": 1,
        },
        status_code=200,
    )
    kit_path = tmp_path / "kit-new.json"

    result = _invoke(
        ["backup", "rotate", "--out", str(kit_path)],
        input=f"y\n{PASSPHRASE}\n{PASSPHRASE}\n",
    )

    assert result.exit_code == 0, result.output
    assert "2 old slot(s) revoked" in result.output
    kit = json.loads(kit_path.read_text(encoding="utf-8"))
    assert kit["slot_id"] == "77777777-1111-2222-3333-444444444444"
    assert unwrap_vek_with_passphrase(
        PASSPHRASE, kit["wrapped_vek"], kit["iv"], kit["kdf"]["salt"]
    ) == VEK


def test_rotate_can_be_cancelled(httpx_mock, tmp_path):
    result = _invoke(["backup", "rotate", "--out", str(tmp_path / "k.json")], input="n\n")
    assert result.exit_code == 0
    assert "Cancelled" in result.output
    assert not httpx_mock.get_requests()


def test_revoke_prints_the_response_warning(httpx_mock):
    httpx_mock.add_response(
        method="POST", url=f"{BASE}/auth/key-envelope/revoke",
        json={
            "detail": "Backup slot revoked", "slot_id": SLOT_ID, "active_slots": 0,
            "warning": "No backup slots remain.",
        },
        status_code=200,
    )

    result = _invoke(["backup", "revoke", SLOT_ID])

    assert result.exit_code == 0, result.output
    assert "revoked" in result.output
    assert "No backup slots remain." in result.output


def test_revoke_surfaces_a_not_found_error(httpx_mock):
    httpx_mock.add_response(
        method="POST", url=f"{BASE}/auth/key-envelope/revoke",
        json={"detail": "No such backup slot"}, status_code=404,
    )

    result = _invoke(["backup", "revoke", SLOT_ID])

    assert result.exit_code == 1
    assert "No such backup slot" in result.output


# ── help surface ──────────────────────────────────────────────────────────────


def test_backup_help_lists_every_subcommand():
    result = _invoke(["backup", "--help"])
    assert result.exit_code == 0
    for command in ("create", "verify", "status", "rotate", "revoke", "restore"):
        assert command in result.output


# ── api_client wire behaviour for the new endpoints ───────────────────────────


def test_create_key_envelope_maps_validation_error(httpx_mock):
    httpx_mock.add_response(
        method="POST", url=f"{BASE}/auth/key-envelope/create",
        json={"detail": [{"msg": "Value error, wrapped_vek must be 96 hex characters"}]},
        status_code=422,
    )
    with pytest.raises(errors.ValidationError):
        api_client.create_key_envelope("tok", "ref", "$argon2id$hash", "00" * 48, "00" * 12, "00" * 16)


def test_create_key_envelope_refreshes_then_retries_on_401(httpx_mock):
    httpx_mock.add_response(
        method="POST", url=f"{BASE}/auth/key-envelope/create",
        json={"detail": "Could not validate credentials"}, status_code=401,
    )
    httpx_mock.add_response(
        method="POST", url=f"{BASE}/auth/refresh",
        json={"access_token": "new", "refresh_token": "new_r", "token_type": "bearer"},
        status_code=200,
    )
    httpx_mock.add_response(
        method="POST", url=f"{BASE}/auth/key-envelope/create",
        json=_slot_response(), status_code=200,
    )

    with patch("api_client.update_tokens", lambda a, r: None):
        result = api_client.create_key_envelope("tok", "ref", "$argon2id$hash", "00" * 48, "00" * 12, "00" * 16)

    assert result["slot_id"] == SLOT_ID


def test_rotate_key_envelope_maps_conflict(httpx_mock):
    httpx_mock.add_response(
        method="POST", url=f"{BASE}/auth/key-envelope/rotate",
        json={"detail": "already revoking"}, status_code=409,
    )
    with pytest.raises(errors.ConflictError):
        api_client.rotate_key_envelope("tok", "ref", "$argon2id$hash", "00" * 48, "00" * 12, "00" * 16)


def test_status_endpoint_maps_server_error_with_raw_body(httpx_mock):
    httpx_mock.add_response(
        method="GET", url=f"{BASE}/auth/key-envelope/status",
        text="internal explosion", status_code=500,
    )
    with pytest.raises(errors.ApiError) as exc:
        api_client.get_key_envelope_status("tok", "ref")
    assert exc.value.response_text == "internal explosion"


def test_begin_restore_is_unauthenticated_and_maps_401(httpx_mock):
    httpx_mock.add_response(
        method="POST", url=f"{BASE}/auth/key-envelope/begin",
        json={"detail": "That passphrase does not match any backup slot for this account"},
        status_code=401,
    )
    with pytest.raises(errors.SessionExpiredError):
        api_client.begin_key_envelope_restore("psam", "wrong-passphrase")
    request = httpx_mock.get_requests()[0]
    assert "authorization" not in {k.lower() for k in request.headers}


def test_validate_slot_reports_revocation(httpx_mock):
    httpx_mock.add_response(
        method="POST", url=f"{BASE}/auth/key-envelope/validate",
        json={"exists": True, "revoked": True, "kind": "passphrase"}, status_code=200,
    )
    assert api_client.validate_key_envelope_slot(SLOT_ID)["revoked"] is True


def test_rate_limit_maps_to_a_wait_hint_not_a_retry(httpx_mock):
    """A 429 is the server deliberately capping passphrase attempts — not a glitch."""
    httpx_mock.add_response(
        method="POST", url=f"{BASE}/auth/key-envelope/begin",
        json={"error": "Rate limit exceeded: 5 per 1 hour"},
        status_code=429,
    )
    with pytest.raises(errors.RateLimitedError) as exc:
        api_client.begin_key_envelope_restore("psam", PASSPHRASE)
    assert "wait" in (exc.value.hint or "").lower()


def test_verify_surfaces_the_rate_limit_hint(httpx_mock):
    httpx_mock.add_response(method="GET", url=f"{BASE}/auth/me", json=PROFILE, status_code=200)
    httpx_mock.add_response(
        method="POST", url=f"{BASE}/auth/key-envelope/begin",
        json={"error": "Rate limit exceeded"}, status_code=429,
    )

    result = _invoke(["backup", "verify"], input=f"{PASSPHRASE}\n")

    assert result.exit_code == 1
    assert "Too many attempts" in result.output
    assert "Wait a few minutes" in result.output


# ── the kit stays separate from the data dump ─────────────────────────────────


def test_export_gains_no_kit_option(httpx_mock):
    """The dump must not become an account credential: no --include-kit/--include-envelope."""
    for flag in ("--include-kit", "--include-envelope"):
        result = _invoke(["export", flag])
        assert result.exit_code != 0
        assert "no such option" in result.output.lower() or "unexpected" in result.output.lower()


def test_exported_file_carries_no_envelope_fields(httpx_mock, tmp_path):
    """Decrypting an export must yield data keys only — never the wrapped vault key."""
    from crypto import encrypt_credentials, export_decrypt

    blob, iv = encrypt_credentials(VEK, "alice", "s3cr3t", "")
    export_path = tmp_path / "psamvault-backup-test.json"

    # export_command reads the session from its OWN module binding, so both the
    # module-level load_session and is_logged_in must be patched (otherwise the real
    # keychain session is used and every entry fails to decrypt).
    with patch("command.export_command._DESKTOP", tmp_path), \
         patch("command.export_command.is_logged_in", return_value=True), \
         patch("command.export_command.load_session", return_value=SESSION), \
         patch("api_client.export_vault", return_value=[{
             "site_name": "github.com", "encrypted_blob": blob, "iv": iv, "login_url": "",
         }]), \
         patch("api_client.export_api_keys", return_value=[]), \
         patch("api_client.export_notes", return_value=[]):
        result = _invoke(["export"], input="export-passphrase-1\nexport-passphrase-1\n")

    assert result.exit_code == 0, result.output
    written = list(tmp_path.glob("psamvault-backup-*.json"))
    assert written, "no backup file was written"
    text = written[0].read_text(encoding="utf-8")
    data = export_decrypt(text, "export-passphrase-1")

    assert "wrapped_vek" not in json.dumps(data)
    assert "kdf" not in data
    assert "psamvault-key-envelope" not in text
    # It is a data dump: the entries, encrypted with the export passphrase
    assert data["credentials"][0]["site_name"] == "github.com"


# ── uninstall must not silently destroy the last copy of the key ──────────────


def test_uninstall_warns_when_no_backup_slot_exists(capsys):
    from command.uninstall_command import _warn_if_account_deletion_is_unrecoverable

    with patch("api_client.get_key_envelope_status",
               return_value={"active_slots": 0, "slots": []}):
        _warn_if_account_deletion_is_unrecoverable(SESSION)
    out = capsys.readouterr().out
    assert "NO backup passphrase slot" in out
    assert "backup create" in out


def test_uninstall_stays_quiet_when_a_backup_slot_exists(capsys):
    from command.uninstall_command import _warn_if_account_deletion_is_unrecoverable

    with patch("api_client.get_key_envelope_status",
               return_value={"active_slots": 1, "slots": []}):
        _warn_if_account_deletion_is_unrecoverable(SESSION)
    assert capsys.readouterr().out == ""


def test_uninstall_never_blocks_on_a_failed_status_lookup(capsys):
    from command.uninstall_command import _warn_if_account_deletion_is_unrecoverable

    with patch("api_client.get_key_envelope_status", side_effect=RuntimeError("offline")):
        _warn_if_account_deletion_is_unrecoverable(SESSION)
    assert capsys.readouterr().out == ""
