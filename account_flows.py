"""Account sign-in, sign-out, recovery, and restore for non-CLI callers.

The dashboard posts the password to this machine only. These functions do the
same wrapping the terminal commands do, then store the session in the OS
keychain. Callers must return the small status dict and nothing else: the
vault key, tokens, and passphrase never go back to the browser.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidTag

import api_client
from config import is_configured
from crypto import (
    decrypt_credentials,
    decrypt_master_with_code,
    decrypt_vek,
    derive_key,
    derive_master_password,
    encrypt_master_with_code,
    encrypt_vek,
    generate_recovery_codes,
    hash_recovery_code,
    parse_kit,
    unwrap_vek_with_passphrase,
)
from errors import NetworkError, PsamVaultError, SessionExpiredError
from session import clear_session, is_logged_in, save_session

_KIT_LIMIT = 256_000


class AccountFlowError(Exception):
    """A failure the user can act on. ``message`` is safe to show."""

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


def password_problems(password: str) -> list[str]:
    """Same rules as signup, so a reset is never weaker than a new account."""
    problems = []
    if len(password) < 8:
        problems.append("at least 8 characters")
    if not any(character.isupper() for character in password):
        problems.append("at least one uppercase letter")
    if not any(character.isdigit() for character in password):
        problems.append("at least one digit")
    return problems


def _require_configured() -> None:
    if not is_configured():
        raise AccountFlowError(
            "psamvault is not configured on this machine. Run pv configure in the terminal, then try again."
        )


def _require_password(password: str, confirm: str | None = None) -> None:
    if confirm is not None and password != confirm:
        raise AccountFlowError("The passwords do not match.")
    problems = password_problems(password)
    if problems:
        raise AccountFlowError("Password must have: " + ", ".join(problems))


def _public_message(exc: BaseException) -> str:
    message = (getattr(exc, "message", None) or str(exc)).strip() or "Request failed"
    hint = getattr(exc, "hint", None)
    if hint and hint not in message:
        return f"{message} {hint}"
    return message


def _open_session(username: str, master: str, vek_hex: str, kdf_salt: str | None = None) -> dict:
    """Log in with an already-derived master password and store the session."""
    try:
        result = api_client.login(username, master)
    except SessionExpiredError as exc:
        raise AccountFlowError(
            "The password was changed, but signing in failed. Sign in with the new password."
        ) from exc
    except (NetworkError, PsamVaultError) as exc:
        raise AccountFlowError(_public_message(exc)) from exc
    salt = kdf_salt or result["kdf_salt"]
    save_session(
        access_token=result["access_token"],
        refresh_token=result["refresh_token"],
        kdf_salt=salt,
        vek=vek_hex,
        encrypted_vek=result["encrypted_vek"],
        vek_iv=result["vek_iv"],
    )
    return result


def login_account(username: str, password: str) -> dict:
    """Sign in and return only what the page needs to render."""
    _require_configured()
    username = username.strip()
    if not username or not password:
        raise AccountFlowError("Username and password are required.")
    master = derive_master_password(password)
    try:
        result = api_client.login(username, master)
    except SessionExpiredError as exc:
        raise AccountFlowError(
            "Wrong username or password. On a new machine the login password is not enough. "
            "Restore with your backup passphrase or a recovery kit."
        ) from exc
    except NetworkError as exc:
        raise AccountFlowError(
            _public_message(exc) or "Could not reach the psamvault server."
        ) from exc
    except PsamVaultError as exc:
        raise AccountFlowError(_public_message(exc)) from exc
    login_key = derive_key(master, result["kdf_salt"])
    try:
        vek = decrypt_vek(login_key, result["encrypted_vek"], result["vek_iv"])
    except InvalidTag as exc:
        raise AccountFlowError(
            "The server returned a vault key this password cannot open."
        ) from exc
    save_session(
        access_token=result["access_token"],
        refresh_token=result["refresh_token"],
        kdf_salt=result["kdf_salt"],
        vek=bytes(vek).hex(),
        encrypted_vek=result["encrypted_vek"],
        vek_iv=result["vek_iv"],
    )
    return {
        "username": username,
        "has_recovery_codes": bool(result.get("has_recovery_codes")),
    }


def recover_account(username: str, recovery_code: str, new_password: str, confirm: str) -> dict:
    """Reset a forgotten login password with one recovery code, then sign in.

    The code is consumed. Other codes stay valid. Entries are not re-encrypted.
    """
    _require_configured()
    username = username.strip()
    recovery_code = recovery_code.strip()
    if not username or not recovery_code:
        raise AccountFlowError("Username and recovery code are required.")
    _require_password(new_password, confirm)
    try:
        result = api_client.recover_with_code(username, recovery_code)
    except (NetworkError, PsamVaultError) as exc:
        raise AccountFlowError(_public_message(exc)) from exc
    try:
        vek_hex = decrypt_master_with_code(
            recovery_code=recovery_code,
            encrypted_master=result["encrypted_master"],
            iv=result["iv"],
            salt=result["code_kdf_salt"],
        )
    except InvalidTag as exc:
        raise AccountFlowError("That recovery code is incorrect or has been tampered with.") from exc
    new_master = derive_master_password(new_password)
    login_key = derive_key(new_master, result["kdf_salt"])
    new_encrypted_vek, new_vek_iv = encrypt_vek(login_key, bytes.fromhex(vek_hex))
    try:
        api_client.reset_password_api(
            username=username,
            recovery_code=recovery_code,
            new_login_password=new_master,
            new_encrypted_vek=new_encrypted_vek,
            new_vek_iv=new_vek_iv,
        )
    except (NetworkError, PsamVaultError) as exc:
        raise AccountFlowError(_public_message(exc)) from exc
    _open_session(username, new_master, vek_hex, result["kdf_salt"])
    return {"username": username, "has_recovery_codes": True}


def _unwrap_from_kit(kit_text: str, passphrase: str) -> tuple[str, bytes, str, str | None, str | None]:
    if len(kit_text) > _KIT_LIMIT:
        raise AccountFlowError("That kit file is too large.")
    try:
        kit = parse_kit(kit_text)
    except ValueError as exc:
        raise AccountFlowError(str(exc)) from exc
    username = str(kit.get("account") or "").strip()
    account_kdf_salt = kit.get("account_kdf_salt")
    if not username or not account_kdf_salt:
        raise AccountFlowError(
            "This kit has no account salt. Restore with your username and backup passphrase instead."
        )
    slot_id = kit.get("slot_id")
    warning = None
    if slot_id:
        try:
            check = api_client.validate_key_envelope_slot(slot_id)
        except (SessionExpiredError, PsamVaultError, NetworkError):
            warning = "The kit could not be checked with the server. Continuing with the key inside the file."
        else:
            if check.get("exists") and check.get("revoked"):
                raise AccountFlowError(
                    "That kit was revoked. Use the current backup passphrase, or a kit from the latest backup."
                )
            if not check.get("exists"):
                warning = "This kit's slot is no longer on the server. Continuing because the file still holds the key."
    try:
        vek = unwrap_vek_with_passphrase(
            passphrase,
            kit["wrapped_vek"],
            kit["iv"],
            kit["kdf"]["salt"],
            iterations=kit["kdf"].get("iterations", 600_000),
        )
    except Exception as exc:  # noqa: BLE001 - a bad passphrase is one error to the user
        raise AccountFlowError("That passphrase does not open this kit.") from exc
    return username, vek, account_kdf_salt, slot_id, warning


def _unwrap_from_slot(username: str, passphrase: str) -> tuple[bytes, str, str | None]:
    try:
        begun = api_client.begin_key_envelope_restore(username, passphrase)
    except SessionExpiredError as exc:
        raise AccountFlowError(
            "That passphrase does not match a backup for this account. "
            "Check the username and passphrase, or restore from a kit file."
        ) from exc
    except (NetworkError, PsamVaultError) as exc:
        raise AccountFlowError(_public_message(exc)) from exc
    try:
        vek = unwrap_vek_with_passphrase(
            passphrase, begun["wrapped_vek"], begun["iv"], begun["kdf_salt"]
        )
    except Exception as exc:  # noqa: BLE001
        raise AccountFlowError("The stored backup did not open with that passphrase.") from exc
    return vek, begun["account_kdf_salt"], begun.get("slot_id")


def _prove_vault(vek: bytes) -> str | None:
    """Decrypt one real entry. None means the restored key did not open the vault."""
    from session import load_session

    session = load_session()
    try:
        listing = api_client.list_vault_entries(session["access_token"], session["refresh_token"])
    except (PsamVaultError, NetworkError):
        return None
    entries = listing.get("entries") if isinstance(listing, dict) else listing
    if not entries:
        return "empty vault"
    site = entries[0].get("site_name") or ""
    try:
        entry = api_client.get_vault_entry(
            session["access_token"], session["refresh_token"], site
        )
        decrypt_credentials(vek, encrypted_blob=entry["encrypted_blob"], iv=entry["iv"])
    except Exception:  # noqa: BLE001 - any failure means this key is not the right one
        return None
    return site or None


def _store_codes(vek: bytes, access_token: str) -> list[str]:
    codes = generate_recovery_codes(8)
    payloads = []
    for code in codes:
        encrypted_vek_hex, iv, kdf_salt = encrypt_master_with_code(code, vek.hex())
        payloads.append(
            {
                "code_hash": hash_recovery_code(code),
                "encrypted_master": encrypted_vek_hex,
                "iv": iv,
                "kdf_salt": kdf_salt,
            }
        )
    api_client.generate_recovery_codes_api(access_token=access_token, codes=payloads)
    return codes


def restore_account(
    username: str,
    passphrase: str,
    new_password: str,
    confirm: str,
    kit_text: str | None = None,
    generate_codes: bool = False,
    replace_session: bool = False,
) -> dict:
    """Put a vault key back on this machine and sign in.

    A kit file supplies the account name. Without one, the server-side backup
    slot is opened with the username and backup passphrase. Entries stay as
    they are; only the login wrap is replaced.
    """
    _require_configured()
    if is_logged_in() and not replace_session:
        raise AccountFlowError(
            "This machine already has a session. Sign out first, or confirm that restore should replace it."
        )
    if not passphrase:
        raise AccountFlowError("The backup passphrase is required.")
    _require_password(new_password, confirm)
    warning = None
    if kit_text and kit_text.strip():
        username, vek, account_kdf_salt, slot_id, warning = _unwrap_from_kit(kit_text, passphrase)
    else:
        username = username.strip()
        if not username:
            raise AccountFlowError("Username is required when you are not using a kit file.")
        vek, account_kdf_salt, slot_id = _unwrap_from_slot(username, passphrase)
    master = derive_master_password(new_password)
    login_key = derive_key(master, account_kdf_salt)
    new_encrypted_vek, new_vek_iv = encrypt_vek(login_key, vek)
    try:
        api_client.restore_vault_key(
            username=username,
            passphrase=passphrase,
            new_login_password=master,
            new_encrypted_vek=new_encrypted_vek,
            new_vek_iv=new_vek_iv,
            slot_id=slot_id,
        )
    except (NetworkError, PsamVaultError) as exc:
        raise AccountFlowError(_public_message(exc)) from exc
    _open_session(username, master, vek.hex(), account_kdf_salt)
    proof = _prove_vault(vek)
    if proof is None:
        warning = (
            "Access was restored, but an entry could not be decrypted with that key. "
            "Your entries were not changed. Try again with a different backup."
        )
    codes = None
    if generate_codes and proof is not None:
        from session import load_session

        try:
            codes = _store_codes(vek, load_session()["access_token"])
        except (NetworkError, PsamVaultError) as exc:
            extra = "Recovery codes were not stored. " + _public_message(exc)
            warning = f"{warning} {extra}".strip() if warning else extra
    return {
        "username": username,
        "has_recovery_codes": True,
        "proof": proof,
        "warning": warning,
        "recovery_codes": codes,
    }


def logout_account(access_token: str, refresh_token: str) -> None:
    """Revoke the server session, then wipe the local one even if the server is down."""
    try:
        api_client.logout(access_token, refresh_token)
    except Exception:  # noqa: BLE001 - local sign-out must still finish
        pass
    clear_session()


def remaining_recovery_codes(access_token: str) -> int:
    try:
        result = api_client.get_remaining_codes(access_token)
    except (NetworkError, PsamVaultError) as exc:
        raise AccountFlowError(_public_message(exc)) from exc
    return int(result.get("remaining_codes") or 0)


def issue_recovery_codes(password: str, session: dict) -> list[str]:
    """Replace every recovery code. The password proves this is the account owner.

    The new codes are returned once. They are not written to the dashboard cache.
    """
    if not password:
        raise AccountFlowError("Your login password is required to replace recovery codes.")
    master = derive_master_password(password)
    login_key = derive_key(master, session["kdf_salt"])
    try:
        vek = decrypt_vek(login_key, session["encrypted_vek"], session["vek_iv"])
    except InvalidTag as exc:
        raise AccountFlowError(
            "That password is incorrect. Recovery codes were not changed."
        ) from exc
    try:
        return _store_codes(bytes(vek), session["access_token"])
    except (NetworkError, PsamVaultError) as exc:
        raise AccountFlowError(_public_message(exc)) from exc
