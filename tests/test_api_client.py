"""
Layer 3: HTTP client tests for api_client.py.
Uses pytest-httpx to intercept httpx calls — no real network traffic.
"""
import pytest

import api_client

BASE = "https://test.example.com"


# ── get_vault_entry ───────────────────────────────────────────────────────────

def test_get_vault_entry_success(httpx_mock, mock_session):
    entry = {
        "id": "abc-123",
        "site_name": "github.com",
        "encrypted_blob": "aa" * 32,
        "iv": "bb" * 12,
        "username_hint": "alice",
        "login_url": "https://github.com/login",
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-01-01T00:00:00Z",
    }
    httpx_mock.add_response(
        method="GET",
        url=f"{BASE}/vault/github.com",
        json=entry,
        status_code=200,
    )

    result = api_client.get_vault_entry(
        access_token=mock_session["access_token"],
        refresh_token=mock_session["refresh_token"],
        site_name="github.com",
    )
    assert result["site_name"] == "github.com"
    assert result["encrypted_blob"] == "aa" * 32


def test_get_vault_entry_retries_after_401(httpx_mock, mock_session):
    entry = {
        "id": "abc-123",
        "site_name": "github.com",
        "encrypted_blob": "cc" * 32,
        "iv": "dd" * 12,
        "username_hint": None,
        "login_url": None,
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-01-01T00:00:00Z",
    }
    # First GET → 401 (expired token)
    httpx_mock.add_response(method="GET", url=f"{BASE}/vault/github.com", status_code=401, json={"detail": "Could not validate credentials"})
    # Refresh call → 200
    httpx_mock.add_response(method="POST", url=f"{BASE}/auth/refresh", json={"access_token": "new_token", "refresh_token": "new_refresh", "token_type": "bearer"}, status_code=200)
    # Retry GET → 200
    httpx_mock.add_response(method="GET", url=f"{BASE}/vault/github.com", json=entry, status_code=200)

    with pytest.MonkeyPatch().context() as mp:
        mp.setattr("api_client.update_tokens", lambda a, r: None)
        result = api_client.get_vault_entry(
            access_token=mock_session["access_token"],
            refresh_token=mock_session["refresh_token"],
            site_name="github.com",
        )
    assert result["encrypted_blob"] == "cc" * 32


def test_get_vault_entry_returns_none_on_persistent_401(httpx_mock, mock_session):
    """After refresh, if the retry GET still returns 401, _refresh_and_retry
    detects the None return and raises typer.Exit with a clear session-expired message."""
    httpx_mock.add_response(method="GET", url=f"{BASE}/vault/github.com", status_code=401, json={"detail": "Could not validate credentials"})
    httpx_mock.add_response(method="POST", url=f"{BASE}/auth/refresh", json={"access_token": "new", "refresh_token": "new_r", "token_type": "bearer"}, status_code=200)
    httpx_mock.add_response(method="GET", url=f"{BASE}/vault/github.com", status_code=401, json={"detail": "Could not validate credentials"})

    with pytest.MonkeyPatch().context() as mp:
        mp.setattr("api_client.update_tokens", lambda a, r: None)
        with pytest.raises(api_client.ApiError):
            api_client.get_vault_entry(
                access_token=mock_session["access_token"],
                refresh_token=mock_session["refresh_token"],
                site_name="github.com",
            )


def test_get_vault_entry_404_exits(httpx_mock, mock_session):
    httpx_mock.add_response(
        method="GET",
        url=f"{BASE}/vault/notasite.com",
        status_code=404,
        json={"detail": "No entry found for 'notasite.com'"},
    )
    with pytest.raises(api_client.ApiError):
        api_client.get_vault_entry(
            access_token=mock_session["access_token"],
            refresh_token=mock_session["refresh_token"],
            site_name="notasite.com",
        )


# ── add_vault_entry ───────────────────────────────────────────────────────────

def test_add_vault_entry_sends_correct_payload(httpx_mock, mock_session):
    response_body = {
        "id": "new-id",
        "site_name": "github.com",
        "encrypted_blob": "ee" * 32,
        "iv": "ff" * 12,
        "username_hint": "alice",
        "login_url": None,
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-01-01T00:00:00Z",
    }
    httpx_mock.add_response(method="POST", url=f"{BASE}/vault", json=response_body, status_code=201)

    result = api_client.add_vault_entry(
        access_token=mock_session["access_token"],
        refresh_token=mock_session["refresh_token"],
        site_name="github.com",
        encrypted_blob="ee" * 32,
        iv="ff" * 12,
        username_hint="alice",
        login_url=None,
    )
    assert result["site_name"] == "github.com"

    # Verify the request body contained the right fields
    sent = httpx_mock.get_request()
    import json
    body = json.loads(sent.content)
    assert body["site_name"] == "github.com"
    assert body["encrypted_blob"] == "ee" * 32
    assert body["username_hint"] == "alice"


# ── _handle_error — 422 validation messages ───────────────────────────────────

def test_handle_error_422_raises_exit(httpx_mock, mock_session):
    httpx_mock.add_response(
        method="GET",
        url=f"{BASE}/vault/badsite",
        status_code=422,
        json={
            "detail": [
                {"msg": "Value error, site_name too long", "loc": ["body", "site_name"]},
            ]
        },
    )
    with pytest.raises(api_client.ApiError):
        api_client.get_vault_entry(
            access_token=mock_session["access_token"],
            refresh_token=mock_session["refresh_token"],
            site_name="badsite",
        )


# ── refresh_access_token ──────────────────────────────────────────────────────

def test_refresh_access_token_returns_new_tokens(httpx_mock):
    httpx_mock.add_response(
        method="POST",
        url=f"{BASE}/auth/refresh",
        json={"access_token": "new_access", "refresh_token": "new_refresh", "token_type": "bearer"},
        status_code=200,
    )
    new_access, new_refresh = api_client.refresh_access_token("old_refresh_token")
    assert new_access == "new_access"
    assert new_refresh == "new_refresh"


def test_refresh_access_token_401_raises(httpx_mock):
    httpx_mock.add_response(
        method="POST",
        url=f"{BASE}/auth/refresh",
        status_code=401,
        json={"detail": "Refresh token is invalid or has expired"},
    )
    with pytest.raises(api_client.ApiError):
        api_client.refresh_access_token("expired_refresh_token")
