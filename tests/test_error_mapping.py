"""
Mapping tests: HTTP failures -> typed exceptions in api_client.

Every failure class must raise the RIGHT exception with a clean user message
(no echo at origin, no raw httpx tracebacks, no misattribution). The command
layer is responsible for printing.
"""
import httpx
import pytest

import api_client
from errors import ApiError, ConflictError, NetworkError, NotFoundError, SessionExpiredError, ValidationError

BASE = "https://test.example.com"


def _session():
    return {"access_token": "tok", "refresh_token": "ref"}


# ── 404 -> NotFoundError ─────────────────────────────────────────────────────

def test_404_raises_not_found_with_clean_message(httpx_mock):
    httpx_mock.add_response(
        method="GET", url=f"{BASE}/vault/missing.com", status_code=404,
        json={"detail": "No entry found for 'missing.com'"},
    )
    with pytest.raises(NotFoundError) as ei:
        api_client.get_vault_entry(**_session(), site_name="missing.com")
    assert "No entry found for 'missing.com'" in ei.value.message
    assert not ei.value.hint or True  # hint optional for NotFound


# ── 401 (non-wrapped path, e.g. me) -> SessionExpiredError ──────────────────

def test_401_raises_session_expired_with_refresh_hint(httpx_mock):
    httpx_mock.add_response(
        method="GET", url=f"{BASE}/auth/me", status_code=401,
        json={"detail": "Could not validate credentials"},
    )
    with pytest.raises(SessionExpiredError) as ei:
        api_client.me(access_token="tok")
    assert "session" in ei.value.message.lower()
    assert ei.value.hint


# ── 422 -> ValidationError with details ─────────────────────────────────────

def test_422_raises_validation_with_field_details(httpx_mock):
    httpx_mock.add_response(
        method="POST", url=f"{BASE}/auth/signup", status_code=422,
        json={"detail": [
            {"msg": "Value error, Password too short", "loc": ["body", "login_password"]},
            {"msg": "Email invalid", "loc": ["body", "email"]},
        ]},
    )
    with pytest.raises(ValidationError) as ei:
        api_client.signup(username="a", email="bad", login_password="x", kdf_salt="s", encrypted_vek="v", vek_iv="iv")
    assert "Password too short" in ei.value.details
    assert "Email invalid" in ei.value.details


# ── 409 -> ConflictError ────────────────────────────────────────────────────

def test_409_raises_conflict(httpx_mock):
    httpx_mock.add_response(
        method="POST", url=f"{BASE}/vault", status_code=409,
        json={"detail": "Entry already exists"},
    )
    with pytest.raises(ConflictError):
        api_client.add_vault_entry(
            **_session(), site_name="github.com",
            encrypted_blob="aa", iv="bb", username_hint="alice",
        )


# ── 5xx -> generic ApiError, no raw body in message ─────────────────────────

def test_5xx_raises_generic_without_raw_body(httpx_mock):
    httpx_mock.add_response(
        method="GET", url=f"{BASE}/vault/x", status_code=500, text="<html>boom traceback</html>",
    )
    with pytest.raises(ApiError) as ei:
        api_client.get_vault_entry(**_session(), site_name="x")
    assert "<html>" not in ei.value.message
    assert ei.value.response_text  # raw detail kept for --verbose


# ── Network failure -> NetworkError ─────────────────────────────────────────

def test_transport_error_raises_network_error(httpx_mock):
    httpx_mock.add_exception(httpx.ConnectError("connection refused"))
    with pytest.raises(NetworkError) as ei:
        api_client.get_vault_entry(**_session(), site_name="github.com")
    assert "reach" in ei.value.message.lower()
    assert ei.value.hint


# ── Dead refresh token -> SessionExpiredError (login hint, not NotFound) ────

def test_dead_refresh_token_raises_session_expired(httpx_mock):
    httpx_mock.add_response(
        method="GET", url=f"{BASE}/vault/github.com", status_code=401,
        json={"detail": "Could not validate credentials"},
    )
    httpx_mock.add_response(
        method="POST", url=f"{BASE}/auth/refresh", status_code=401,
        json={"detail": "Invalid refresh token"},
    )
    with pytest.raises(SessionExpiredError) as ei:
        api_client.get_vault_entry(**_session(), site_name="github.com")
    assert "login" in ei.value.hint


# ── Network failure during refresh is NOT misreported as session expiry ─────

def test_network_error_during_refresh_stays_network_error(httpx_mock):
    httpx_mock.add_response(
        method="GET", url=f"{BASE}/vault/github.com", status_code=401,
        json={"detail": "Could not validate credentials"},
    )
    httpx_mock.add_exception(httpx.ConnectError("server down"))
    with pytest.raises(NetworkError):
        api_client.get_vault_entry(**_session(), site_name="github.com")
