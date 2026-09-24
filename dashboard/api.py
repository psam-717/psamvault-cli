"""JSON API for the local dashboard.

The browser never receives the VEK. Lists carry names and hints only.
Passwords and API keys are returned from the reveal POST, and nowhere else.
"""

from __future__ import annotations

import secrets
from concurrent.futures import ThreadPoolExecutor

from flask import Blueprint, jsonify, request

import api_client
from crypto import decrypt_api_key, decrypt_credentials, encrypt_api_key, encrypt_credentials
from dashboard.cache import (
    CACHE,
    ensure_auth,
    load_api_keys,
    load_entries,
    remember_api_keys,
    remember_entries,
)
import session as session_store
from errors import NotFoundError

bp = Blueprint("dashboard_api", __name__, url_prefix="/api")

_FORBIDDEN_SITE_CHARS = set('\\/"\'' " <>|?*&#%")
_ALLOWED_ORIGINS = {
    "http://127.0.0.1:8500",
    "http://localhost:8500",
    "http://[::1]:8500",
}


def _error(message: str, status: int):
    return jsonify({"error": message}), status


def _validate_site_name(site: str) -> str | None:
    if not site.strip():
        return "Site name cannot be blank"
    found = [char for char in site if char in _FORBIDDEN_SITE_CHARS]
    if found:
        unique = "".join(dict.fromkeys(found))
        chars = " ".join(repr(char) for char in unique)
        return f"Site name contains invalid character(s): {chars}"
    return None


def _validate_login_url(url: str) -> str | None:
    if url and not url.startswith(("http://", "https://")):
        return "Login URL must start with http:// or https://"
    return None


def _validate_password(password: str) -> str | None:
    errors = []
    if len(password) < 8:
        errors.append("at least 8 characters")
    if not any(char.isupper() for char in password):
        errors.append("at least one uppercase letter")
    if not any(char.isdigit() for char in password):
        errors.append("at least one digit")
    if errors:
        return "Password must have: " + ", ".join(errors)
    return None


def _public_entry(row: dict) -> dict:
    return {
        "site_name": row.get("site_name") or "",
        "username_hint": row.get("username_hint") or "—",
        "updated_at": (row.get("updated_at") or "")[:10],
        "login_url": row.get("login_url") or "",
    }


def _public_key(row: dict) -> dict:
    return {
        "name": row.get("name") or "",
        "service_hint": row.get("service_hint") or "—",
        "updated_at": (row.get("updated_at") or "")[:10],
    }


def _auth_or_response():
    auth = ensure_auth()
    if auth is None:
        return None, _error("not_logged_in", 401)
    return auth, None


def _csrf_or_response():
    auth, failure = _auth_or_response()
    if failure is not None:
        return None, failure
    origin = request.headers.get("Origin")
    if origin and origin not in _ALLOWED_ORIGINS:
        return None, _error("Bad origin", 403)
    sent = request.headers.get("X-CSRF-Token", "")
    if not sent or not secrets.compare_digest(sent, CACHE.csrf_token):
        return None, _error("Missing or invalid CSRF token", 403)
    return auth, None


def _tokens(auth: dict) -> tuple[str, str, bytes]:
    return auth["access_token"], auth["refresh_token"], bytes.fromhex(auth["vek"])


def _body() -> dict:
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


@bp.after_request
def _no_store(response):
    response.headers["Cache-Control"] = "no-store"
    return response


@bp.get("/bootstrap")
def bootstrap():
    auth, failure = _auth_or_response()
    if failure is not None:
        return failure
    refresh = request.args.get("refresh") == "1"
    with ThreadPoolExecutor(max_workers=2) as pool:
        entry_future = pool.submit(load_entries, refresh)
        key_future = pool.submit(load_api_keys, refresh)
        raw_entries, entries_error = entry_future.result()
        raw_keys, keys_error = key_future.result()
    entries = [_public_entry(row) for row in raw_entries] if raw_entries is not None else None
    api_keys = [_public_key(row) for row in raw_keys] if raw_keys is not None else None
    # Publish the stripped rows so later mutations update what the browser sees.
    if entries is not None:
        remember_entries(entries)
    if api_keys is not None:
        remember_api_keys(api_keys)
    return jsonify(
        {
            "username": CACHE.username,
            "csrf_token": CACHE.csrf_token,
            "entries": entries,
            "api_keys": api_keys,
            "entries_error": entries_error,
            "api_keys_error": keys_error,
        }
    )


@bp.post("/logout")
def logout():
    _auth, failure = _csrf_or_response()
    if failure is not None:
        return failure
    session_store.clear_session()
    CACHE.reset()
    return jsonify({"ok": True})


@bp.get("/entries/<path:site_name>")
def entry_detail(site_name: str):
    """Edit form payload. The password stays on the server."""
    auth, failure = _auth_or_response()
    if failure is not None:
        return failure
    token, refresh, vek = _tokens(auth)
    try:
        data = api_client.get_vault_entry(token, refresh, site_name)
        plain = decrypt_credentials(vek, data["encrypted_blob"], data["iv"])
    except NotFoundError as exc:
        return _error(str(exc), 404)
    except (Exception, SystemExit):
        return _error("Entry not found", 404)
    return jsonify(
        {
            "site_name": data.get("site_name", site_name),
            "username": plain.get("username", ""),
            "login_url": data.get("login_url") or "",
            "notes": plain.get("notes", ""),
        }
    )


@bp.post("/entries/<path:site_name>/reveal")
def entry_reveal(site_name: str):
    auth, failure = _csrf_or_response()
    if failure is not None:
        return failure
    token, refresh, vek = _tokens(auth)
    try:
        data = api_client.get_vault_entry(token, refresh, site_name)
        plain = decrypt_credentials(vek, data["encrypted_blob"], data["iv"])
    except (NotFoundError, Exception, SystemExit):
        return _error("Entry not found", 404)
    fields = _body().get("fields") or ["password", "notes"]
    allowed = {"password", "notes"}
    payload = {name: plain.get(name, "") for name in fields if name in allowed}
    return jsonify(payload)


@bp.post("/entries")
def entry_add():
    auth, failure = _csrf_or_response()
    if failure is not None:
        return failure
    body = _body()
    site_name = (body.get("site_name") or "").strip()
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    notes = body.get("notes") or ""
    login_url = (body.get("login_url") or "").strip()

    error = _validate_site_name(site_name) or (None if password else "Password is required")
    error = error or _validate_password(password) or _validate_login_url(login_url)
    if error:
        return _error(error, 400)

    token, refresh, vek = _tokens(auth)
    blob, iv = encrypt_credentials(vek, username, password, notes)
    try:
        api_client.add_vault_entry(
            token,
            refresh,
            site_name,
            blob,
            iv,
            username_hint=username,
            login_url=login_url or None,
        )
    except Exception as exc:
        return _error(str(exc) or "Failed to save", 400)

    row = _public_entry(
        {
            "site_name": site_name,
            "username_hint": username,
            "login_url": login_url,
            "updated_at": "",
        }
    )
    current = list(CACHE.entries or [])
    current = [item for item in current if item.get("site_name") != site_name]
    current.append(row)
    remember_entries(current)
    return jsonify(row), 201


@bp.patch("/entries/<path:site_name>")
def entry_update(site_name: str):
    auth, failure = _csrf_or_response()
    if failure is not None:
        return failure
    token, refresh, vek = _tokens(auth)
    try:
        data = api_client.get_vault_entry(token, refresh, site_name)
        current = decrypt_credentials(vek, data["encrypted_blob"], data["iv"])
    except (NotFoundError, Exception, SystemExit):
        return _error("Entry not found", 404)

    body = _body()
    username = (body.get("username") or "").strip() or current.get("username", "")
    password = body.get("password") or current.get("password", "")
    if "notes" in body:
        notes = body.get("notes") or ""
    else:
        notes = current.get("notes", "")
    if "login_url" in body and (body.get("login_url") or "").strip():
        login_url = body.get("login_url").strip()
    else:
        login_url = data.get("login_url") or ""

    error = _validate_login_url(login_url)
    if password != current.get("password"):
        error = error or _validate_password(password)
    if error:
        return _error(error, 400)

    blob, iv = encrypt_credentials(vek, username, password, notes)
    try:
        api_client.update_vault_entry(
            token,
            refresh,
            site_name,
            blob,
            iv,
            username_hint=username,
            login_url=login_url or None,
        )
    except NotFoundError as exc:
        return _error(str(exc), 404)
    except Exception as exc:
        return _error(str(exc) or "Failed to save", 400)

    row = _public_entry(
        {
            "site_name": site_name,
            "username_hint": username or "—",
            "login_url": login_url,
            "updated_at": data.get("updated_at") or "",
        }
    )
    current_rows = [row if item.get("site_name") == site_name else item for item in (CACHE.entries or [])]
    if not any(item.get("site_name") == site_name for item in current_rows):
        current_rows.append(row)
    remember_entries(current_rows)
    return jsonify(row)


@bp.delete("/entries/<path:site_name>")
def entry_delete(site_name: str):
    auth, failure = _csrf_or_response()
    if failure is not None:
        return failure
    token, refresh, _vek = _tokens(auth)
    try:
        api_client.delete_vault_entry(token, refresh, site_name)
    except Exception as exc:
        return _error(str(exc) or "Failed to delete", 400)
    remember_entries([item for item in (CACHE.entries or []) if item.get("site_name") != site_name])
    return jsonify({"ok": True})


@bp.get("/api-keys/<path:name>")
def api_key_detail(name: str):
    auth, failure = _auth_or_response()
    if failure is not None:
        return failure
    token, refresh, vek = _tokens(auth)
    try:
        data = api_client.get_api_key_entry(token, refresh, name)
        plain = decrypt_api_key(vek, data["encrypted_blob"], data["iv"])
    except (NotFoundError, Exception, SystemExit):
        return _error("API key not found", 404)
    return jsonify(
        {
            "name": data.get("name", name),
            "service": plain.get("service", ""),
            "notes": plain.get("notes", ""),
        }
    )


@bp.post("/api-keys/<path:name>/reveal")
def api_key_reveal(name: str):
    auth, failure = _csrf_or_response()
    if failure is not None:
        return failure
    token, refresh, vek = _tokens(auth)
    try:
        data = api_client.get_api_key_entry(token, refresh, name)
        plain = decrypt_api_key(vek, data["encrypted_blob"], data["iv"])
    except (NotFoundError, Exception, SystemExit):
        return _error("API key not found", 404)
    fields = _body().get("fields") or ["api_key", "notes"]
    allowed = {"api_key", "notes"}
    payload = {field: plain.get(field, "") for field in fields if field in allowed}
    return jsonify(payload)


@bp.post("/api-keys")
def api_key_add():
    auth, failure = _csrf_or_response()
    if failure is not None:
        return failure
    body = _body()
    name = (body.get("name") or "").strip()
    service = (body.get("service") or "").strip()
    api_key = body.get("api_key") or ""
    notes = body.get("notes") or ""
    error = _validate_site_name(name) or (None if api_key else "API key is required")
    if error:
        return _error(error, 400)
    token, refresh, vek = _tokens(auth)
    blob, iv = encrypt_api_key(vek, service, api_key, notes)
    try:
        api_client.add_api_key_entry(token, refresh, name, service, blob, iv)
    except Exception as exc:
        return _error(str(exc) or "Failed to save", 400)
    row = _public_key({"name": name, "service_hint": service or "—", "updated_at": ""})
    rows = [item for item in (CACHE.api_keys or []) if item.get("name") != name]
    rows.append(row)
    remember_api_keys(rows)
    return jsonify(row), 201


@bp.patch("/api-keys/<path:name>")
def api_key_update(name: str):
    auth, failure = _csrf_or_response()
    if failure is not None:
        return failure
    token, refresh, vek = _tokens(auth)
    try:
        data = api_client.get_api_key_entry(token, refresh, name)
        current = decrypt_api_key(vek, data["encrypted_blob"], data["iv"])
    except (NotFoundError, Exception, SystemExit):
        return _error("API key not found", 404)
    body = _body()
    service = (body.get("service") or "").strip() or current.get("service", "")
    api_key = body.get("api_key") or current.get("api_key", "")
    if "notes" in body:
        notes = body.get("notes") or ""
    else:
        notes = current.get("notes", "")
    blob, iv = encrypt_api_key(vek, service, api_key, notes)
    try:
        api_client.update_api_key_entry(token, refresh, name, service, blob, iv)
    except Exception as exc:
        return _error(str(exc) or "Failed to save", 400)
    row = _public_key(
        {
            "name": name,
            "service_hint": service or "—",
            "updated_at": data.get("updated_at") or "",
        }
    )
    rows = [row if item.get("name") == name else item for item in (CACHE.api_keys or [])]
    remember_api_keys(rows)
    return jsonify(row)


@bp.delete("/api-keys/<path:name>")
def api_key_delete(name: str):
    auth, failure = _csrf_or_response()
    if failure is not None:
        return failure
    token, refresh, _vek = _tokens(auth)
    try:
        api_client.delete_api_key_entry(token, refresh, name)
    except Exception as exc:
        return _error(str(exc) or "Failed to delete", 400)
    remember_api_keys([item for item in (CACHE.api_keys or []) if item.get("name") != name])
    return jsonify({"ok": True})
