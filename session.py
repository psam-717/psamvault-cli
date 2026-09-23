import base64
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

    Pending approval tokens go with it: an approval that outlived the session it
    was minted for would be a standing reveal.
    """
    for key in _SESSION_KEYS:
        try:
            keyring.delete_password(_SERVICE, key)
        except keyring.errors.PasswordDeleteError:
            pass
    if SESSION_FILE.exists():
        SESSION_FILE.unlink()
    clear_approvals()


def is_logged_in() -> bool:
    """Check whether a session file exists without raising an error"""
    return SESSION_FILE.exists()


# ── Token expiry (proactive refresh) ─────────────────────────────────────────

# Refresh the access token when it expires within this many seconds.
REFRESH_THRESHOLD_SECONDS = 300


def get_access_token_expiry(access_token: str) -> "float | None":
    """Return the JWT's ``exp`` claim as unix-epoch seconds, or None.

    Returns None when the token is not a readable JWT or carries no ``exp``
    claim — callers then fall back to the existing lazy 401 refresh.
    """
    try:
        payload_b64 = access_token.split(".")[1]
        padding = "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + padding))
        exp = payload.get("exp")
        return float(exp) if exp is not None else None
    except Exception:
        return None


# ── Approval tokens (reveal guardrail) ────────────────────────────────────────
#
# `psamvault approve <entry> --for-agent` mints one of these from a real
# terminal; the reveal gate consumes it on the next reveal of that entry. Rows
# live in the same keychain service as the session, so a token cannot outlive a
# logout and no new store (or new file format) is introduced.
#
# A row holds only {entry, created_at, expires_at, single_use} — no secret. The
# index row lists the live token ids, because the OS keychain has no "list
# entries" API; it is pruned on every read.

_APPROVAL_INDEX_KEY = "approval.index"
_APPROVAL_PREFIX = "approval."
APPROVAL_TOKEN_BYTES = 8  # 16 hex chars — matches a terminal-wide handover


def _approval_index() -> list[str]:
    raw = keyring.get_password(_SERVICE, _APPROVAL_INDEX_KEY)
    if not raw:
        return []
    try:
        ids = json.loads(raw)
    except json.JSONDecodeError:
        return []
    return [str(i) for i in ids] if isinstance(ids, list) else []


def _save_approval_index(ids: list[str]) -> None:
    if ids:
        keyring.set_password(_SERVICE, _APPROVAL_INDEX_KEY, json.dumps(ids))
        return
    try:
        keyring.delete_password(_SERVICE, _APPROVAL_INDEX_KEY)
    except keyring.errors.PasswordDeleteError:
        pass


def _read_approval(token_id: str) -> "dict | None":
    raw = keyring.get_password(_SERVICE, _APPROVAL_PREFIX + token_id)
    if not raw:
        return None
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def _drop_approval(token_id: str) -> None:
    try:
        keyring.delete_password(_SERVICE, _APPROVAL_PREFIX + token_id)
    except keyring.errors.PasswordDeleteError:
        pass


def _live(token_id: str, now: float) -> "dict | None":
    """Payload for a token that has not expired, or None (expired rows are pruned)."""
    payload = _read_approval(token_id)
    if payload is None:
        return None
    try:
        expires_at = float(payload.get("expires_at", 0))
    except (TypeError, ValueError):
        expires_at = 0
    if expires_at <= now:
        _drop_approval(token_id)
        return None
    payload["token_id"] = token_id
    return payload


def mint_approval(entry: str, ttl_seconds: int, *, now: "float | None" = None) -> dict:
    """Mint a single-use approval for ``entry``. Returns the row (with token_id)."""
    import secrets
    import time

    created = time.time() if now is None else now
    token_id = secrets.token_hex(APPROVAL_TOKEN_BYTES)
    payload = {
        "entry": entry,
        "created_at": created,
        "expires_at": created + float(ttl_seconds),
        "single_use": True,
    }
    keyring.set_password(_SERVICE, _APPROVAL_PREFIX + token_id, json.dumps(payload))
    _save_approval_index(_approval_index() + [token_id])
    payload["token_id"] = token_id
    return payload


def live_approval_for(entry: str, *, now: "float | None" = None) -> "dict | None":
    """First unexpired approval covering ``entry`` (case-insensitive), or None.

    Also prunes expired rows from the index as a side effect — an approval that
    timed out is not merely ignored, it is gone.
    """
    import time

    moment = time.time() if now is None else now
    wanted = (entry or "").strip().casefold()
    live_ids: list[str] = []
    found: dict | None = None
    for token_id in _approval_index():
        payload = _live(token_id, moment)
        if payload is None:
            continue
        live_ids.append(token_id)
        if found is None and str(payload.get("entry", "")).strip().casefold() == wanted:
            found = payload
    _save_approval_index(live_ids)
    return found


def consume_approval(token_id: str) -> None:
    """Delete a token after a successful reveal — single use, enforced."""
    _drop_approval(token_id)
    _save_approval_index([i for i in _approval_index() if i != token_id])


def list_approvals(*, now: "float | None" = None) -> list[dict]:
    """Every live approval (used by tests and the audit-facing surfaces)."""
    import time

    moment = time.time() if now is None else now
    live: list[dict] = []
    for token_id in _approval_index():
        payload = _live(token_id, moment)
        if payload is not None:
            live.append(payload)
    _save_approval_index([p["token_id"] for p in live])
    return live


def clear_approvals() -> None:
    """Drop every approval — called on logout so a token never outlives a session."""
    for token_id in _approval_index():
        _drop_approval(token_id)
    _save_approval_index([])


# ── Version state ─────────────────────────────────────────────────────────────

_VERSION_FILE = SESSION_DIR / "last_seen_version"


def get_last_seen_version() -> "str | None":
    """
    Return the last version string written by set_last_seen_version(),
    or None if the file does not exist yet (first ever run).
    """
    try:
        if _VERSION_FILE.exists():
            return _VERSION_FILE.read_text().strip() or None
    except Exception:
        pass
    return None


def set_last_seen_version(version: str) -> None:
    """
    Persist the current installed version so the next run can detect upgrades.
    Creates ~/.psamvault/ if needed. Silently swallows any I/O errors.
    """
    try:
        SESSION_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
        _VERSION_FILE.write_text(version)
    except Exception:
        pass

