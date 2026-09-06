import os
import time

import httpx
import typer

from errors import (  # noqa: F401  (ApiError re-exported for back-compat: dashboard + old tests)
    ApiError,
    ConflictError,
    NetworkError,
    NotFoundError,
    PsamVaultError,
    SessionExpiredError,
    ValidationError,
)
from session import update_tokens


def _base_url() -> str:
    return os.getenv("PSAMVAULT_API_URL", "https://psam-vault-backend.onrender.com")

# internal helpers
def _auth_headers(access_token: str) -> dict:
    return {"Authorization": f"Bearer {access_token}"}


def _request(method: str, url: str, **kwargs) -> httpx.Response:
    """Run an HTTP request, translating transport failures into NetworkError.

    The CLI prints errors at the command layer only — no raw httpx exceptions
    and no echo here.
    """
    try:
        return httpx.request(method, url, **kwargs)
    except httpx.HTTPError as exc:
        raise NetworkError(
            "Could not reach the psamvault server",
            hint="Check your internet connection and PSAMVAULT_API_URL",
        ) from exc


def _get(url: str, **kwargs) -> httpx.Response:
    return _request("GET", url, **kwargs)


def _post(url: str, **kwargs) -> httpx.Response:
    return _request("POST", url, **kwargs)


def _put(url: str, **kwargs) -> httpx.Response:
    return _request("PUT", url, **kwargs)


def _delete(url: str, **kwargs) -> httpx.Response:
    return _request("DELETE", url, **kwargs)


def _handle_error(response: httpx.Response) -> None:
    """Raise a typed, user-facing error for non-2xx responses.

    Errors are raised (never echoed) so the command layer is the single print
    site — preventing double-printed messages and letting non-CLI consumers
    (dashboard, TUI, MCP) catch the typed exception themselves.
    """
    if response.status_code == 422:
        # Pydantic validation error — extract the human-readable messages
        # from FastAPI's error list: [{"msg": "...", "loc": [...], ...}, ...]
        details = []
        try:
            for err in response.json().get("detail", []):
                msg = err.get("msg", "")
                # FastAPI prefixes field_validator messages with "Value error, " — strip it
                msg = msg.removeprefix("Value error, ")
                if msg:
                    details.append(msg)
        except Exception:
            details = []
        raise ValidationError(
            "Validation failed",
            details=details,
            hint="Fix the highlighted fields and try again",
        )

    if response.status_code == 401:
        detail = response.json().get("detail", "") if response.content else ""
        raise SessionExpiredError(
            "Your session is invalid or has expired",
            hint="Run  psamvault list  to refresh your session, then try again",
        )

    if response.status_code == 404:
        detail = response.json().get("detail", "Entry not found.")
        raise NotFoundError(str(detail))

    if response.status_code == 409:
        detail = response.json().get("detail", "Conflict.")
        raise ConflictError(str(detail))

    if not response.is_success:
        err = ApiError(f"Server error ({response.status_code})", hint="Try again in a moment")
        err.response_text = response.text[:500]  # technical detail for --verbose
        raise err


def _refresh_and_retry(refresh_token: str, retry_fn):
    """Refresh the access token then retry the original request.

    Called automatically when a 401 is received mid-session. The refresh
    token itself may be dead (expired/revoked) — that is reported as a
    SessionExpiredError, never as a transport or "not found" failure.
    """
    try:
        new_access, new_refresh = refresh_access_token(refresh_token)
    except NetworkError:
        raise  # server unreachable — not a session problem
    except (ApiError, ValueError) as exc:
        raise SessionExpiredError(
            "Your session has expired",
            hint="Run  psamvault login  to sign in again",
        ) from exc

    update_tokens(new_access, new_refresh)
    result = retry_fn(new_access)
    if result is None:
        raise SessionExpiredError(
            "Your session has expired",
            hint="Run  psamvault login  to sign in again",
        )
    return result


def ensure_session() -> dict:
    """Load the session, refreshing the access token if it is expired or
    expiring within ``REFRESH_THRESHOLD_SECONDS``.

    This is the CLI session gate: every authed command calls it instead of
    ``load_session()`` so an expiring access token is renewed *before* the
    first request (no 401 round-trip) and a dead refresh token produces one
    clean message instead of a mid-command failure. Returns a session dict
    carrying fresh tokens (persisted to the keychain).
    """
    from error_ui import print_error
    from session import REFRESH_THRESHOLD_SECONDS, get_access_token_expiry, load_session

    session = load_session()
    exp = get_access_token_expiry(session.get("access_token", ""))
    if exp is not None and exp <= time.time() + REFRESH_THRESHOLD_SECONDS:
        try:
            new_access, new_refresh = refresh_access_token(session["refresh_token"])
        except SessionExpiredError:
            print_error(
                SessionExpiredError(
                    "Your session has expired",
                    hint="Run  psamvault login  to sign in again",
                )
            )
            raise typer.Exit(code=1)
        except PsamVaultError as exc:
            print_error(exc)
            raise typer.Exit(code=1)
        update_tokens(new_access, new_refresh)
        session["access_token"] = new_access
        session["refresh_token"] = new_refresh
    return session
    
    

# Auth endpoints
def signup(username: str, email: str, login_password: str, kdf_salt: str, encrypted_vek: str, vek_iv: str) -> dict:
    """POST /auth/signup"""
    response = _post(
        f"{_base_url()}/auth/signup",
        json={
            "username": username,
            "email": email,
            "login_password": login_password,
            "kdf_salt": kdf_salt,
            "encrypted_vek": encrypted_vek,
            "vek_iv": vek_iv,
        }
    )
    _handle_error(response)
    return response.json()


def login(username: str, login_password: str) -> dict:
    """POST /auth/login — returns access_token, refresh_token, kdf_salt."""
    response = _post(
        f"{_base_url()}/auth/login",
        json={
            "username": username,
            "login_password": login_password
        }
    )
    _handle_error(response)
    return response.json()


def migrate_password(username: str, old_login_password: str, new_master_password: str) -> dict:
    """POST /auth/migrate — swap old password hash for new master-password hash."""
    response = _post(
        f"{_base_url()}/auth/migrate",
        json={
            "username": username,
            "old_login_password": old_login_password,
            "new_master_password": new_master_password,
        }
    )
    _handle_error(response)
    return response.json()


def refresh_access_token(refresh_token: str) -> str:
    """POST /auth/refresh - returns a new access_token string"""
    response = _post(
        f"{_base_url()}/auth/refresh",
        json={"refresh_token": refresh_token}
    )
    _handle_error(response)
    data = response.json()
    return data["access_token"], data["refresh_token"]


def logout(access_token: str, refresh_token: str) -> None:
    """POST /auth/logout - revokes the refresh token on the server"""
    response = _post(
        f"{_base_url()}/auth/logout",
        headers=_auth_headers(access_token),
        json={"refresh_token": refresh_token}
    )
    _handle_error(response)
    
    
def me(access_token: str) -> dict:
    """GET /auth/me - return the current user's profile"""
    response = _get(
        f"{_base_url()}/auth/me",
        headers=_auth_headers(access_token)
    )
    _handle_error(response)
    return response.json()
    
    
    
    
# Vault endpoints
def add_vault_entry(
    access_token: str,
    refresh_token: str,
    site_name: str,
    encrypted_blob: str,
    iv: str,
    username_hint: str | None,
    login_url: str | None = None,
) -> dict:
    """POST /vault - store a new encrypted entry"""
    def _call(token: str) -> dict:
        response = _post(
            f"{_base_url()}/vault",
            headers=_auth_headers(token),
            json={
                "site_name": site_name,
                "encrypted_blob": encrypted_blob,
                "iv": iv,
                "username_hint": username_hint,
                "login_url": login_url,
            },
        )
        if response.status_code == 401:
            return None
        _handle_error(response)
        return response.json()
    
    result = _call(access_token)
    if result is None:
        return _refresh_and_retry(refresh_token, _call)
    return result


def get_vault_entry(
    access_token: str,
    refresh_token: str,
    site_name: str
) -> dict:
    """GET /vault/{site_name} — fetch a single encrypted entry."""
    def _call(token: str) -> dict:
        response = _get(
            f"{_base_url()}/vault/{site_name}",
            headers=_auth_headers(token)
        )
        if response.status_code == 401:
            return None
        _handle_error(response)
        return response.json()
    
    result = _call(access_token)
    if result is None:
        return _refresh_and_retry(refresh_token, _call)
    return result


def list_vault_entries(
    access_token: str,
    refresh_token: str
) -> dict:
    """GET /vault — fetch all entries as lightweight list items."""
    def _call(token: str) -> dict:
        response = _get(
            f"{_base_url()}/vault",
            headers=_auth_headers(token)
        )
        if response.status_code == 401:
            return None
        _handle_error(response)
        return response.json()
    
    result = _call(access_token)
    if result is None:
        return _refresh_and_retry(refresh_token, _call)
    return result


def update_vault_entry(
    access_token: str,
    refresh_token: str,
    site_name: str,
    encrypted_blob: str,
    iv: str,
    username_hint: str | None,
    login_url: str | None = None,
) -> dict:
    """PUT /vault/{site_name} — update an existing encrypted entry"""
    def _call(token: str) -> dict:
        response = _put(
            f"{_base_url()}/vault/{site_name}",
            headers=_auth_headers(token),
            json={
                "encrypted_blob": encrypted_blob,
                "iv": iv,
                "username_hint": username_hint,
                "login_url": login_url,
            }
        )
        if response.status_code == 401:
            return None
        _handle_error(response)
        return response.json()
    
    result = _call(access_token)
    if result is None:
        return _refresh_and_retry(refresh_token, _call)
    return result

def update_vault_entry_url(
    access_token: str,
    refresh_token: str,
    site_name: str,
    login_url: str,
) -> dict:
    """PUT /vault/{site_name} — update only the login_url field."""
    def _call(token: str) -> dict:
        response = _put(
            f"{_base_url()}/vault/{site_name}",
            headers=_auth_headers(token),
            json={"login_url": login_url},
        )
        if response.status_code == 401:
            return None
        _handle_error(response)
        return response.json()

    result = _call(access_token)
    if result is None:
        return _refresh_and_retry(refresh_token, _call)
    return result


def delete_vault_entry(
    access_token: str,
    refresh_token: str,
    site_name: str
) -> dict:
    """DELETE /vault/{site_name} — permanently remove an entry."""
    def _call(token: str) -> dict:
        response = _delete(
            f"{_base_url()}/vault/{site_name}",
            headers=_auth_headers(token)
        )
        if response.status_code == 401:
            return None
        _handle_error(response)
        return response.json()
    
    result = _call(access_token)
    if result is None:
        return _refresh_and_retry(refresh_token, _call)
    return result



# recovery endpoints
def generate_recovery_codes_api(
    access_token: str,
    codes: list[dict],
    
) -> dict:
    """POST /auth/recovery/generate — store a fresh set of recovery codes."""
    response = _post(
        f"{_base_url()}/auth/recovery/generate",
        headers=_auth_headers(access_token),
        json={"codes": codes}
    )
    _handle_error(response)
    return response.json()


def get_remaining_codes(access_token: str) -> dict:
    """GET /auth/recovery/remaining — check how many codes are left."""
    response = _get(
        f"{_base_url()}/auth/recovery/remaining",
        headers=_auth_headers(access_token)
    )
    _handle_error(response)
    return response.json()


def recover_with_code(username: str, recovery_code: str) -> dict:
    """
    POST /auth/recovery/recover — step 1 of recovery flow.
    Returns encrypted_master, iv, kdf_salt.
    """
    response = _post(
        f"{_base_url()}/auth/recovery/recover",
        json={
            "username": username,
            "recovery_code": recovery_code
        }
    )
    _handle_error(response)
    return response.json()


def reset_password_api(
    username: str,
    recovery_code: str,
    new_login_password: str,
    new_encrypted_vek: str,
    new_vek_iv: str,
) -> dict:
    """
    POST /auth/recovery/reset-password — step 2 of recovery flow.
    Sets the new login password and updates the encrypted VEK.
    Only the used code is consumed — remaining codes stay valid.
    Returns remaining_codes count.
    """
    response = _post(
        f"{_base_url()}/auth/recovery/reset-password",
        json={
            "username": username,
            "recovery_code": recovery_code,
            "new_login_password": new_login_password,
            "new_encrypted_vek": new_encrypted_vek,
            "new_vek_iv": new_vek_iv,
        }
    )
    _handle_error(response)
    return response.json()



def add_api_key_entry(
    access_token: str,
    refresh_token: str,
    name: str,
    service_hint: str,
    encrypted_blob: str,
    iv: str,
    notes: str | None = None,
) -> dict:
    """POST /apikeys - store a new encrypted API key entry"""
    def _call(token: str) -> dict:
        body: dict[str, str] = {
            "name": name,
            "service_hint": service_hint,
            "encrypted_blob": encrypted_blob,
            "iv": iv,
        }
        if notes is not None:
            body["notes"] = notes
        response = _post(
            f"{_base_url()}/apikeys",
            headers=_auth_headers(token),
            json=body,
        )
        if response.status_code == 401:
            return None
        _handle_error(response)
        return response.json()
    
    result = _call(access_token)
    if result is None:
        return _refresh_and_retry(refresh_token, _call)
    return result


def get_api_key_entry(
    access_token: str,
    refresh_token: str,
    name: str,
) -> dict:
    """GET /apikeys/{name} — fetch a single encrypted API key entry."""
    def _call(token: str) -> dict:
        response = _get(
            f"{_base_url()}/apikeys/{name}",
            headers=_auth_headers(token)
        )
        if response.status_code == 401:
            return None
        _handle_error(response)
        return response.json()
    
    result= _call(access_token)
    if result is None:
        return _refresh_and_retry(refresh_token, _call)
    
    return result


def list_api_key_entries(
    access_token: str,
    refresh_token: str,
) -> dict:
    """GET /apikeys — fetch all API key entries as lightweight list items."""
    def _call(token: str) -> dict:
        response = _get(
            f"{_base_url()}/apikeys",
            headers=_auth_headers(token),
        )
        if response.status_code == 401:
            return None
        _handle_error(response)
        return response.json()
 
    result = _call(access_token)
    if result is None:
        return _refresh_and_retry(refresh_token, _call)
    return result
 
 
def update_api_key_entry(
    access_token: str,
    refresh_token: str,
    name: str,
    service_hint: str,
    encrypted_blob: str,
    iv: str,
    notes: str | None = None,
) -> dict:
    """PUT /apikeys/{name} — update an existing API key entry."""
    def _call(token: str) -> dict:
        body: dict[str, str] = {
            "service_hint": service_hint,
            "encrypted_blob": encrypted_blob,
            "iv": iv,
        }
        if notes is not None:
            body["notes"] = notes
        response = _put(
            f"{_base_url()}/apikeys/{name}",
            headers=_auth_headers(token),
            json=body,
        )
        if response.status_code == 401:
            return None
        _handle_error(response)
        return response.json()
 
    result = _call(access_token)
    if result is None:
        return _refresh_and_retry(refresh_token, _call)
    return result
 
 
def delete_api_key_entry(
    access_token: str,
    refresh_token: str,
    name: str,
) -> dict:
    """DELETE /apikeys/{name} — permanently remove an API key entry."""
    def _call(token: str) -> dict:
        response = _delete(
            f"{_base_url()}/apikeys/{name}",
            headers=_auth_headers(token),
        )
        if response.status_code == 401:
            return None
        _handle_error(response)
        return response.json()

    result = _call(access_token)
    if result is None:
        return _refresh_and_retry(refresh_token, _call)
    return result


# ── Note endpoints ────────────────────────────────────────────────────────────


def add_note_entry(
    access_token: str,
    refresh_token: str,
    title: str,
    category: str | None,
    encrypted_blob: str,
    iv: str,
) -> dict:
    """POST /notes - store a new encrypted note entry."""
    def _call(token: str) -> dict:
        body: dict[str, str] = {
            "title": title,
            "encrypted_blob": encrypted_blob,
            "iv": iv,
        }
        if category is not None:
            body["category"] = category
        response = _post(
            f"{_base_url()}/notes",
            headers=_auth_headers(token),
            json=body,
        )
        if response.status_code == 401:
            return None
        _handle_error(response)
        return response.json()

    result = _call(access_token)
    if result is None:
        return _refresh_and_retry(refresh_token, _call)
    return result


def get_note_entry(
    access_token: str,
    refresh_token: str,
    title: str,
) -> dict:
    """GET /notes/{title} — fetch a single encrypted note entry."""
    def _call(token: str) -> dict:
        response = _get(
            f"{_base_url()}/notes/{title}",
            headers=_auth_headers(token),
        )
        if response.status_code == 401:
            return None
        _handle_error(response)
        return response.json()

    result = _call(access_token)
    if result is None:
        return _refresh_and_retry(refresh_token, _call)
    return result


def list_note_entries(
    access_token: str,
    refresh_token: str,
) -> dict:
    """GET /notes — fetch all note entries as lightweight list items."""
    def _call(token: str) -> dict:
        response = _get(
            f"{_base_url()}/notes",
            headers=_auth_headers(token),
        )
        if response.status_code == 401:
            return None
        _handle_error(response)
        return response.json()

    result = _call(access_token)
    if result is None:
        return _refresh_and_retry(refresh_token, _call)
    return result


def update_note_entry(
    access_token: str,
    refresh_token: str,
    title: str,
    category: str | None = None,
    encrypted_blob: str | None = None,
    iv: str | None = None,
    new_title: str | None = None,
) -> dict:
    """PUT /notes/{title} — update an existing note entry."""
    def _call(token: str) -> dict:
        body: dict[str, str] = {}
        if category is not None:
            body["category"] = category
        if encrypted_blob is not None:
            body["encrypted_blob"] = encrypted_blob
        if iv is not None:
            body["iv"] = iv
        if new_title is not None:
            body["title"] = new_title
        response = _put(
            f"{_base_url()}/notes/{title}",
            headers=_auth_headers(token),
            json=body,
        )
        if response.status_code == 401:
            return None
        _handle_error(response)
        return response.json()

    result = _call(access_token)
    if result is None:
        return _refresh_and_retry(refresh_token, _call)
    return result


def delete_note_entry(
    access_token: str,
    refresh_token: str,
    title: str,
) -> dict:
    """DELETE /notes/{title} — permanently remove a note entry."""
    def _call(token: str) -> dict:
        response = _delete(
            f"{_base_url()}/notes/{title}",
            headers=_auth_headers(token),
        )
        if response.status_code == 401:
            return None
        _handle_error(response)
        return response.json()

    result = _call(access_token)
    if result is None:
        return _refresh_and_retry(refresh_token, _call)
    return result


def export_notes(
    access_token: str,
    refresh_token: str,
) -> list[dict]:
    """GET /notes/export/all — return all note entries with full encrypted blobs."""
    def _call(token: str) -> list[dict]:
        response = _get(
            f"{_base_url()}/notes/export/all",
            headers=_auth_headers(token),
        )
        if response.status_code == 401:
            return None
        _handle_error(response)
        return response.json()

    result = _call(access_token)
    if result is None:
        return _refresh_and_retry(refresh_token, _call)
    return result


# ── Export / Account deletion ──────────────────────────────────────────────────


def export_vault(
    access_token: str,
    refresh_token: str,
) -> list[dict]:
    """GET /vault/export/all — return all vault entries with full encrypted blobs."""
    def _call(token: str) -> list[dict]:
        response = _get(
            f"{_base_url()}/vault/export/all",
            headers=_auth_headers(token),
        )
        if response.status_code == 401:
            return None
        _handle_error(response)
        return response.json()

    result = _call(access_token)
    if result is None:
        return _refresh_and_retry(refresh_token, _call)
    return result


def export_api_keys(
    access_token: str,
    refresh_token: str,
) -> list[dict]:
    """GET /apikeys/export/all — return all API key entries with full encrypted blobs."""
    def _call(token: str) -> list[dict]:
        response = _get(
            f"{_base_url()}/apikeys/export/all",
            headers=_auth_headers(token),
        )
        if response.status_code == 401:
            return None
        _handle_error(response)
        return response.json()

    result = _call(access_token)
    if result is None:
        return _refresh_and_retry(refresh_token, _call)
    return result


def delete_account(
    access_token: str,
    refresh_token: str,
) -> dict:
    """DELETE /auth/account — permanently delete the user's account and all data."""
    def _call(token: str) -> dict:
        response = _delete(
            f"{_base_url()}/auth/account",
            headers=_auth_headers(token),
        )
        if response.status_code == 401:
            return None
        _handle_error(response)
        return response.json()

    result = _call(access_token)
    if result is None:
        return _refresh_and_retry(refresh_token, _call)
    return result