import json
import os
from pathlib import Path

import keyring
import keyring.errors

_SERVICE = "psamvault"

_SESSION_KEYS = [
    "session.access_token",
    "session.refresh_token",
    "session.kdf_salt",
    "session.vek",
    "session.encrypted_vek",
    "session.vek_iv",
]

# Session file lives at ~/.psamvault/session.json on the user's machine.
# After the keyring migration it holds only an empty presence marker {}.
SESSION_DIR = Path.home() / ".psamvault"
SESSION_FILE = SESSION_DIR / "session.json"


def save_session(
    access_token: str,
    refresh_token: str,
    kdf_salt: str,
    vek: str,
    encrypted_vek: str,
    vek_iv: str,
) -> None:
    """
    Persist the session to the OS keychain after a successful login.

    All sensitive values (tokens, VEK, kdf_salt) are stored in the OS
    keychain (macOS Keychain, Windows Credential Manager, or Linux Secret
    Service). The session.json file is kept only as an empty presence marker
    so that is_logged_in() can do a fast file check without a keychain call.

    Args:
        access_token:  Short-lived JWT from the server (15 min).
        refresh_token: Long-lived opaque token from the server (30 days).
        kdf_salt:      Hex string from the server used to derive the login key.
        vek:           Hex-encoded 32-byte Vault Encryption Key (decrypted locally).
        encrypted_vek: Hex-encoded server copy of the VEK (encrypted with login key).
        vek_iv:        Hex-encoded IV used when encrypting the VEK.
    """
    SESSION_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)

    values = {
        "session.access_token": access_token,
        "session.refresh_token": refresh_token,
        "session.kdf_salt": kdf_salt,
        "session.vek": vek,
        "session.encrypted_vek": encrypted_vek,
        "session.vek_iv": vek_iv,
    }
    for key, value in values.items():
        keyring.set_password(_SERVICE, key, value)

    # Empty presence marker — no secrets on disk
    SESSION_FILE.write_text("{}")
    os.chmod(SESSION_FILE, 0o600)



def load_session() -> dict:
    """
    Load the session from the OS keychain.

    Migrates automatically from the old plaintext JSON format on first run:
    if session.json contains sensitive fields, they are moved to the keychain
    and session.json is replaced with an empty marker.

    Returns:
        Dict with keys: access_token, refresh_token, kdf_salt, vek, encrypted_vek, vek_iv.

    Raises:
        SystemExit: If no session file exists, prompting the user to log in.
    """
    if not SESSION_FILE.exists():
        import typer
        typer.echo(
            "You are not logged in. Run psamvault login first",
            err=True
        )
        raise typer.Exit(code=1)

    # Migration: if session.json still has the old plaintext fields, move them
    # to the keychain and replace the file with an empty marker.
    raw = SESSION_FILE.read_text().strip()
    if raw and raw != "{}":
        try:
            old_data = json.loads(raw)
        except json.JSONDecodeError:
            old_data = {}
        if old_data:
            for key in _SESSION_KEYS:
                field = key.split(".", 1)[1]  # "session.access_token" → "access_token"
                if field in old_data:
                    keyring.set_password(_SERVICE, key, old_data[field])
            SESSION_FILE.write_text("{}")
            os.chmod(SESSION_FILE, 0o600)

    session = {}
    for key in _SESSION_KEYS:
        field = key.split(".", 1)[1]
        value = keyring.get_password(_SERVICE, key)
        if value is None:
            import typer
            typer.echo(
                "Session data missing from keychain. Please log in again.",
                err=True
            )
            raise typer.Exit(code=1)
        session[field] = value
    return session


def update_tokens(access_token: str, refresh_token: str) -> None:
    """
    Overwrite both access_token and refresh_token in the keychain.
    Called after a token rotation so the new refresh token is persisted —
    without this the old revoked refresh token gets reused on the next
    request, causing a permanent 401 loop.
    """
    keyring.set_password(_SERVICE, "session.access_token", access_token)
    keyring.set_password(_SERVICE, "session.refresh_token", refresh_token)



def update_access_token(access_token: str) -> None:
    """
    Overwrite just the access_token in the keychain.
    Called automatically after a successful token refresh so the user
    never notices their token silently renewed mid-session.

    Args:
        access_token: The new JWT returned by POST /auth/refresh.
    """
    keyring.set_password(_SERVICE, "session.access_token", access_token)


def clear_session() -> None:
    """
    Delete all session data from the keychain and remove the presence marker.
    The tokens and VEK are wiped immediately.
    """
    for key in _SESSION_KEYS:
        try:
            keyring.delete_password(_SERVICE, key)
        except keyring.errors.PasswordDeleteError:
            pass
    if SESSION_FILE.exists():
        SESSION_FILE.unlink()


def is_logged_in() -> bool:
    """Check whether a session file exists without raising an error"""
    return SESSION_FILE.exists()

