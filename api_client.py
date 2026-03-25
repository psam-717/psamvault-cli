import os
import httpx
import typer
from dotenv import load_dotenv

from session import update_tokens


load_dotenv()

BASE_URL = os.getenv("PSAMVAULT_API_URL", "http://127.0.0.1:8000")

# internal helpers
def _auth_headers(access_token: str) -> dict:
    return {"Authorization": f"Bearer {access_token}"}

def _handle_error(response: httpx.Response) -> None:
    """
    Raise a clean typer error for non-2xx responses instead of letting
    httpx bubble up a raw exception.
    """
    if response.status_code == 401:
        typer.echo("Session expired or invalid. Please run  psamvault login  again.", err=True)
        raise typer.Exit(code=1)
 
    if response.status_code == 404:
        detail = response.json().get("detail", "Entry not found.")
        typer.echo(f"Error: {detail}", err=True)
        raise typer.Exit(code=1)
 
    if response.status_code == 409:
        detail = response.json().get("detail", "Conflict.")
        typer.echo(f"Error: {detail}", err=True)
        raise typer.Exit(code=1)
 
    if not response.is_success:
        typer.echo(f"Error {response.status_code}: {response.text}", err=True)
        raise typer.Exit(code=1)
    

def _refresh_and_retry(refresh_token: str, retry_fn):
    """
    Attempt to refresh the access token then retry the original request.
    Called automatically when a 401 is received mid-session.
    """
    try:
        new_access, new_refresh = refresh_access_token(refresh_token)
        update_tokens(new_access, new_refresh)
        return retry_fn(new_access)
    except Exception:
        typer.echo("Session expired. Please run psamvault login again", err=True)
        raise typer.Exit(code=1) # pylint: disable = raise-missing-from
    
    

# Auth endpoints
def signup(username: str, email: str, login_password: str) -> dict:
    """POST /auth/signup"""
    response = httpx.post(
        f"{BASE_URL}/auth/signup",
        json={
            "username": username,
            "email": email,
            "login_password": login_password
        }
    )
    _handle_error(response)
    return response.json()


def login(username: str, login_password: str) -> dict:
    """POST /auth/login — returns access_token, refresh_token, kdf_salt."""
    response = httpx.post(
        f"{BASE_URL}/auth/login",
        json={
            "username": username,
            "login_password": login_password
        }
    )
    _handle_error(response)
    return response.json()


def refresh_access_token(refresh_token: str) -> str:
    """POST /auth/refresh - returns a new access_token string"""
    response = httpx.post(
        f"{BASE_URL}/auth/refresh",
        json={"refresh_token": refresh_token}
    )
    _handle_error(response)
    data = response.json()
    return data["access_token"], data["refresh_token"]


def logout(access_token: str, refresh_token: str) -> None:
    """POST /auth/logout - revokes the refresh token on the server"""
    response = httpx.post(
        f"{BASE_URL}/auth/logout",
        headers=_auth_headers(access_token),
        json={"refresh_token": refresh_token}
    )
    _handle_error(response)
    
    
def me(access_token: str) -> dict:
    """GET /auth/me - return the current user's profile"""
    response = httpx.get(
        f"{BASE_URL}/auth/me",
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
    username_hint: str | None
) -> dict: 
    """POST /vault - store a new encrypted entry"""
    def _call(token: str) -> dict:
        response = httpx.post(
            f"{BASE_URL}/vault",
            headers=_auth_headers(token),
            json={
                "site_name": site_name,
                "encrypted_blob": encrypted_blob,
                "iv": iv,
                "username_hint": username_hint
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
        response = httpx.get(
            f"{BASE_URL}/vault/{site_name}",
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
        response = httpx.get(
            f"{BASE_URL}/vault",
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
    username_hint: str | None
) -> dict:
    """PUT /vault/{site_name} — update an existing encrypted entry"""
    def _call(token: str) -> dict:
        response = httpx.put(
            f"{BASE_URL}/vault/{site_name}",
            headers=_auth_headers(token),
            json={
                "encrypted_blob": encrypted_blob,
                "iv": iv,
                "username_hint": username_hint
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

def delete_vault_entry(
    access_token: str,
    refresh_token: str,
    site_name: str
) -> dict:
    """DELETE /vault/{site_name} — permanently remove an entry."""
    def _call(token: str) -> dict:
        response = httpx.delete(
            f"{BASE_URL}/vault/{site_name}",
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
    response = httpx.post(
        f"{BASE_URL}/auth/recovery/generate",
        headers=_auth_headers(access_token),
        json={"codes": codes}
    )
    _handle_error(response)
    return response.json()


def get_remaining_codes(access_token: str) -> dict:
    """GET /auth/recovery/remaining — check how many codes are left."""
    response = httpx.get(
        f"{BASE_URL}/auth/recovery/remaining",
        headers=_auth_headers(access_token)
    )
    _handle_error(response)
    return response.json()


def recover_with_code(username: str, recovery_code: str) -> dict:
    """
    POST /auth/recovery/recover — step 1 of recovery flow.
    Returns encrypted_master, iv, kdf_salt.
    """
    response = httpx.post(
        f"{BASE_URL}/auth/recovery/recover",
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
    new_login_password: str
) -> dict:
    """
    POST /auth/recovery/reset-password — step 2 of recovery flow.
    Sets the new login password. Only the used code is consumed —
    remaining codes stay valid. Returns remaining_codes count.
    """
    response = httpx.post(
        f"{BASE_URL}/auth/recovery/reset-password",
        json={
            "username": username,
            "recovery_code": recovery_code,
            "new_login_password": new_login_password
        }
    )
    _handle_error(response)
    return response.json()
    
    