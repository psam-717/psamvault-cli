"""
Tests for proactive token refresh: JWT exp decoding (session.py) and
ensure_session() (api_client.py).

ensure_session must:
- refresh when the access token is expired or expiring within 300s
- NOT refresh when the token has plenty of life left
- NOT refresh when the token is not a readable JWT (falls back to lazy 401)
- print a clean login hint and exit when the refresh token is dead
"""
import base64
import json
import time

import pytest
import typer

import api_client
from session import REFRESH_THRESHOLD_SECONDS, get_access_token_expiry


# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_jwt(exp: float | None) -> str:
    """Build an unsigned-looking JWT with a controllable exp claim."""
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).rstrip(b"=").decode()
    payload = {"sub": "u1", "type": "access"}
    if exp is not None:
        payload["exp"] = exp
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"{header}.{body}.sig"


def _session_with(access_token: str) -> dict:
    return {"access_token": access_token, "refresh_token": "ref", "vek": "00" * 32}


# ── get_access_token_expiry ──────────────────────────────────────────────────

def test_expiry_reads_exp_claim():
    exp = time.time() + 3600
    assert get_access_token_expiry(_make_jwt(exp)) == pytest.approx(exp)


def test_expiry_none_when_no_exp_claim():
    assert get_access_token_expiry(_make_jwt(None)) is None


def test_expiry_none_on_garbage():
    assert get_access_token_expiry("not-a-jwt") is None
    assert get_access_token_expiry("a.b") is None


# ── ensure_session ───────────────────────────────────────────────────────────

def test_no_refresh_when_token_far_from_expiry(monkeypatch):
    future = _make_jwt(time.time() + 7200)
    monkeypatch.setattr("api_client.refresh_access_token", lambda r: (_ for _ in ()).throw(AssertionError("should not refresh")))
    monkeypatch.setattr("api_client.update_tokens", lambda a, r: None)
    monkeypatch.setattr("session.load_session", lambda: _session_with(future))

    result = api_client.ensure_session()
    assert result["access_token"] == future


def test_refreshes_when_token_expiring_soon(monkeypatch):
    near = _make_jwt(time.time() + REFRESH_THRESHOLD_SECONDS - 60)
    calls = []
    monkeypatch.setattr("api_client.refresh_access_token", lambda r: ("new_access", "new_refresh"))
    monkeypatch.setattr("api_client.update_tokens", lambda a, r: calls.append((a, r)))
    monkeypatch.setattr("session.load_session", lambda: _session_with(near))

    result = api_client.ensure_session()
    assert result["access_token"] == "new_access"
    assert calls == [("new_access", "new_refresh")]


def test_refreshes_when_token_already_expired(monkeypatch):
    past = _make_jwt(time.time() - 60)
    calls = []
    monkeypatch.setattr("api_client.refresh_access_token", lambda r: ("new_access", "new_refresh"))
    monkeypatch.setattr("api_client.update_tokens", lambda a, r: calls.append((a, r)))
    monkeypatch.setattr("session.load_session", lambda: _session_with(past))

    result = api_client.ensure_session()
    assert result["access_token"] == "new_access"
    assert calls


def test_no_refresh_when_token_unreadable(monkeypatch):
    # Malformed token -> fall back to the lazy 401 refresh path (no proactive call).
    monkeypatch.setattr("api_client.refresh_access_token", lambda r: (_ for _ in ()).throw(AssertionError("should not refresh")))
    monkeypatch.setattr("session.load_session", lambda: _session_with("garbage.token.value"))

    result = api_client.ensure_session()
    assert result["access_token"] == "garbage.token.value"


def test_dead_refresh_token_prints_clean_message_and_exits(monkeypatch, capsys):
    from errors import SessionExpiredError

    def _boom(_refresh):
        raise SessionExpiredError("Refresh token is invalid or has expired")

    past = _make_jwt(time.time() - 60)
    monkeypatch.setattr("api_client.refresh_access_token", _boom)
    monkeypatch.setattr("session.load_session", lambda: _session_with(past))

    with pytest.raises(typer.Exit) as ei:
        api_client.ensure_session()
    assert ei.value.exit_code == 1
    out = capsys.readouterr().err.lower()
    assert "session has expired" in out
    assert "login" in out
