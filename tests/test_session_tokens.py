"""
Tests for proactive token refresh: JWT exp decoding (session.py) and
ensure_session() (api_client.py).

ensure_session must:
- refresh when the access token is expired or expiring within 300s
- NOT refresh when the token has plenty of life left
- NOT refresh when the token is not a readable JWT (falls back to lazy 401)
- print a clean login hint and exit when the refresh token is dead
- re-read the store once and retry when another client rotated the token
  between our read and our request (single-use tokens, one shared store)
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

# ── rotation race: another client refreshed first ────────────────────────────

def _rotating_store(sessions):
    """Fake store: each load_session() call yields the next dict, repeating the last.

    Simulates a keychain entry rewritten by another client (CLI, MCP server or the
    dashboard) between our read and our refresh request.
    """
    queue = list(sessions)

    def _load():
        return queue.pop(0) if len(queue) > 1 else queue[0]

    return _load


def test_retries_with_the_rotated_token_when_the_store_changed(monkeypatch):
    from errors import SessionExpiredError

    past = _make_jwt(time.time() - 60)
    monkeypatch.setattr(
        "session.load_session",
        _rotating_store([
            _session_with(past),
            dict(_session_with(past), refresh_token="ref-rotated"),
        ]),
    )

    seen = []

    def _refresh(token):
        seen.append(token)
        if token == "ref":
            raise SessionExpiredError("Refresh token is invalid or has expired")
        return ("new_access", "new_refresh")

    calls = []
    monkeypatch.setattr("api_client.refresh_access_token", _refresh)
    monkeypatch.setattr("api_client.update_tokens", lambda a, r: calls.append((a, r)))

    result = api_client.ensure_session()

    assert seen == ["ref", "ref-rotated"]
    assert result["access_token"] == "new_access"
    assert calls == [("new_access", "new_refresh")]


def test_no_retry_when_the_store_still_holds_the_same_token(monkeypatch):
    from errors import SessionExpiredError

    past = _make_jwt(time.time() - 60)
    monkeypatch.setattr("session.load_session", lambda: _session_with(past))

    seen = []

    def _refresh(token):
        seen.append(token)
        raise SessionExpiredError("Refresh token is invalid or has expired")

    monkeypatch.setattr("api_client.refresh_access_token", _refresh)

    with pytest.raises(typer.Exit) as ei:
        api_client.ensure_session()

    assert ei.value.exit_code == 1
    assert seen == ["ref"]


def test_no_retry_when_the_store_lost_its_refresh_token(monkeypatch):
    from errors import SessionExpiredError

    past = _make_jwt(time.time() - 60)
    monkeypatch.setattr(
        "session.load_session",
        _rotating_store([_session_with(past), {"access_token": past}]),
    )

    seen = []

    def _refresh(token):
        seen.append(token)
        raise SessionExpiredError("Refresh token is invalid or has expired")

    monkeypatch.setattr("api_client.refresh_access_token", _refresh)

    with pytest.raises(typer.Exit):
        api_client.ensure_session()

    assert seen == ["ref"]


def test_refresh_session_tokens_returns_the_pair(monkeypatch):
    monkeypatch.setattr("session.load_session", lambda: _session_with("t"))
    monkeypatch.setattr("api_client.refresh_access_token", lambda r: ("a2", "r2"))

    assert api_client.refresh_session_tokens() == ("a2", "r2")


def test_refresh_session_tokens_uses_the_supplied_token(monkeypatch):
    monkeypatch.setattr(
        "session.load_session",
        lambda: (_ for _ in ()).throw(AssertionError("must not re-read when a token is given")),
    )
    seen = []
    monkeypatch.setattr("api_client.refresh_access_token", lambda r: (seen.append(r), ("a", "b"))[1])

    assert api_client.refresh_session_tokens("given") == ("a", "b")
    assert seen == ["given"]
