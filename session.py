import json
import os
from pathlib import Path

# Session file lives at ~/.psamvault/session.json on the user's machine.
# This folder is created automatically on first login.
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
    Persist the session to disk after a successful login.

    The vek stored here is the raw 32-byte Vault Encryption Key as a hex string,
    decrypted locally from the server's encrypted copy using the login-derived key.
    It is stored locally only and is never sent to the server. It is needed on
    every vault command to encrypt/decrypt entries without prompting each time.

    The encrypted_vek and vek_iv are stored so that recovery_commands can build
    code payloads without requiring the user to re-enter their password
    (they verify identity with the password, then decrypt from these stored values).

    The session folder is created with restricted permissions (700) so only
    the current OS user can enter it.

    Args:
        access_token:  Short-lived JWT from the server (15 min).
        refresh_token: Long-lived opaque token from the server (30 days).
        kdf_salt:      Hex string from the server used to derive the login key.
        vek:           Hex-encoded 32-byte Vault Encryption Key (decrypted locally).
        encrypted_vek: Hex-encoded server copy of the VEK (encrypted with login key).
        vek_iv:        Hex-encoded IV used when encrypting the VEK.
    """
    SESSION_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    
    session_data = {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "kdf_salt": kdf_salt,
        "vek": vek,
        "encrypted_vek": encrypted_vek,
        "vek_iv": vek_iv,
    }
    
    SESSION_FILE.write_text(json.dumps(session_data, indent=2))
    
    # Restrict file permissions to owner read/write only (600)
    os.chmod(SESSION_FILE, 0o600)
    


def load_session() -> dict:
    """
    Load the session from disk.
 
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
    
    return json.loads(SESSION_FILE.read_text())


def update_tokens(access_token: str, refresh_token: str) -> None:
    """
    Overwrite both access_token and refresh_token in the session file.
    Called after a token rotation so the new refresh token is persisted —
    without this the old revoked refresh token gets reused on the next
    request, causing a permanent 401 loop.
    """
    session = load_session()
    session["access_token"] = access_token
    session["refresh_token"] = refresh_token
    SESSION_FILE.write_text(json.dumps(session, indent=2))
    os.chmod(SESSION_FILE, 0o600)
    


def update_access_token(access_token: str) -> None:
    """
    Overwrite just the access_token in the existing session file.
    Called automatically after a successful token refresh so the user
    never notices their token silently renewed mid-session.
 
    Args:
        access_token: The new JWT returned by POST /auth/refresh.
    """
    
    session = load_session()
    session["access_token"] = access_token
    SESSION_FILE.write_text(json.dumps(session, indent=2))
    os.chmod(SESSION_FILE, 0o600)
    
def clear_session() -> None:
    """
    Delete the session file on logout.
    The master password and tokens are wiped from disk immediately.
    """
    if SESSION_FILE.exists():
        SESSION_FILE.unlink()
        

def is_logged_in() -> bool:
    """Check whether a session file exists without raising an error"""
    return SESSION_FILE.exists()
    
