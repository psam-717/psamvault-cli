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
    master_password: str
) -> None:
    """
    Persist the session to disk after a successful login.
 
    The master password stored here is NOT what the user typed. It is a
    64-character hex string derived from the login password via HMAC-SHA256
    in crypto.derive_master_password(). It is stored locally only and is
    never sent to the server. It is needed on every vault command to
    re-derive the AES encryption key without prompting the user each time.
 
    The session folder is created with restricted permissions (700) so only
    the current OS user can enter it.
 
    Args:
        access_token:    Short-lived JWT from the server (15 min).
        refresh_token:   Long-lived opaque token from the server (30 days).
        kdf_salt:        Hex string from the server used to derive the key.
        master_password: Raw master password typed by the user at login.
    """
    SESSION_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    
    session_data = {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "kdf_salt": kdf_salt,
        "master_password": master_password
    }
    
    SESSION_FILE.write_text(json.dumps(session_data, indent=2))
    
    # Restrict file permissions to owner read/write only (600)
    os.chmod(SESSION_FILE, 0o600)
    


def load_session() -> dict:
    """
    Load the session from disk.
 
    Returns:
        Dict with keys: access_token, refresh_token, kdf_salt, master_password.
 
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
    
