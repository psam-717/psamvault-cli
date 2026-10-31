"""Dashboard HTTP API.

The slowness on tab clicks came from work done on every request: six keychain
reads, GET /auth/me, then another list call. These tests pin the replacement:

- the keychain and the profile call happen once per process
- a second load reuses the lists until the TTL
- a failed list is an error, not an empty vault
- mutations do not fetch the lists again
- a detail read never includes the password; reveal is a separate POST
"""

from __future__ import annotations

import config
import pytest
import session
from cryptography.exceptions import InvalidTag
from flask.testing import FlaskClient

import api_client
import dashboard.cache as dash_cache
from crypto import encrypt_api_key, encrypt_credentials
from dashboard import create_app
from errors import NotFoundError
from tests.conftest import TEST_ACCESS_TOKEN, TEST_REFRESH_TOKEN, TEST_VEK


def _session_record() -> dict:
    return {
        "access_token": TEST_ACCESS_TOKEN,
        "refresh_token": TEST_REFRESH_TOKEN,
        "kdf_salt": "aa" * 32,
        "vek": TEST_VEK.hex(),
        "encrypted_vek": "bb" * 44,
        "vek_iv": "cc" * 12,
    }


def _build_dashboard_app(monkeypatch, tmp_path, fake_keychain):
    """A dashboard that cannot see the real keychain, home directory, or API."""
    monkeypatch.setattr(config, "keyring", fake_keychain)
    monkeypatch.setattr(config, "CONFIG_FILE", tmp_path / "config.env")
    monkeypatch.setenv("PSAMVAULT_DASHBOARD_STATE_DIR", str(tmp_path / "state"))

    session_file = tmp_path / "session.json"
    session_file.write_text("{}")
    monkeypatch.setattr(session, "SESSION_FILE", session_file)

    record = _session_record()
    for field, value in record.items():
        fake_keychain.set_password("psamvault", f"session.{field}", value)

    calls = {
        "me": 0,
        "list_entries": 0,
        "list_keys": 0,
        "get_entry": 0,
        "add_entry": 0,
        "keyring_gets_at_start": None,
    }
    gets = {"n": 0}
    original_get = fake_keychain.get_password

    def counting_get(service, key):
        gets["n"] += 1
        return original_get(service, key)

    fake_keychain.get_password = counting_get

    blob, iv = encrypt_credentials(TEST_VEK, "alice", "s3cr3t-Password1", "note text")
    key_blob, key_iv = encrypt_api_key(TEST_VEK, "OpenAI", "sk-test-secret", "key note")

    stored = {
        "entry": {
            "site_name": "GitHub",
            "username_hint": "alice",
            "updated_at": "2026-09-01T12:00:00Z",
            "login_url": "https://github.com/login",
            "encrypted_blob": blob,
            "iv": iv,
            "password": "s3cr3t-Password1",
        },
        "key": {
            "name": "OpenAI",
            "service_hint": "OpenAI",
            "updated_at": "2026-09-02T12:00:00Z",
            "encrypted_blob": key_blob,
            "iv": key_iv,
            "api_key": "sk-test-secret",
        },
    }

    def me(access_token):
        calls["me"] += 1
        assert access_token == dash_cache.CACHE.auth["access_token"]
        return {"username": "alice"}

    def list_entries(access_token, refresh_token):
        calls["list_entries"] += 1
        return [dict(stored["entry"])]

    def list_keys(access_token, refresh_token):
        calls["list_keys"] += 1
        return [dict(stored["key"])]

    def get_entry(access_token, refresh_token, site_name):
        calls["get_entry"] += 1
        if site_name != stored["entry"]["site_name"]:
            raise NotFoundError("Entry not found")
        return dict(stored["entry"])

    def get_key(access_token, refresh_token, name):
        if name != stored["key"]["name"]:
            raise NotFoundError("API key not found")
        return dict(stored["key"])

    def add_entry(*args, **kwargs):
        calls["add_entry"] += 1
        return {"ok": True}

    def update_entry(*args, **kwargs):
        return {"ok": True}

    def delete_entry(*args, **kwargs):
        stored["entry"] = None
        return {"ok": True}

    monkeypatch.setattr(api_client, "me", me)
    monkeypatch.setattr(api_client, "list_vault_entries", list_entries)
    monkeypatch.setattr(api_client, "list_api_key_entries", list_keys)
    monkeypatch.setattr(api_client, "get_vault_entry", get_entry)
    monkeypatch.setattr(api_client, "get_api_key_entry", get_key)
    monkeypatch.setattr(api_client, "add_vault_entry", add_entry)
    monkeypatch.setattr(api_client, "update_vault_entry", update_entry)
    monkeypatch.setattr(api_client, "delete_vault_entry", delete_entry)
    monkeypatch.setattr(api_client, "add_api_key_entry", lambda *a, **k: {"ok": True})
    monkeypatch.setattr(api_client, "update_api_key_entry", lambda *a, **k: {"ok": True})
    monkeypatch.setattr(api_client, "delete_api_key_entry", lambda *a, **k: {"ok": True})

    dash_cache.CACHE.reset()
    app = create_app()
    app.config["TESTING"] = True
    calls["keyring_gets_at_start"] = gets["n"]
    return app, calls, gets, stored


@pytest.fixture
def dashboard_app(monkeypatch, tmp_path, fake_keychain):
    return _build_dashboard_app(monkeypatch, tmp_path, fake_keychain)


class _DashboardClient(FlaskClient):
    """The page's own origin. A test that must omit it uses a plain test client."""

    def open(self, *args, **kwargs):
        headers = dict(kwargs.pop("headers", None) or {})
        headers.setdefault("Origin", "http://127.0.0.1:8500")
        kwargs["headers"] = headers
        return super().open(*args, **kwargs)


@pytest.fixture
def client(dashboard_app):
    app, calls, gets, stored = dashboard_app
    app.test_client_class = _DashboardClient
    with app.test_client() as test_client:
        opened = test_client.post("/session", json={"token": dash_cache.CACHE.launch_token})
        assert opened.status_code == 200, opened.data
        yield test_client, calls, gets, stored


def _bootstrap(test_client, **kwargs):
    response = test_client.get("/api/bootstrap", **kwargs)
    assert response.status_code == 200, response.data
    return response, response.get_json()


def _csrf(body: dict) -> dict:
    return {"X-CSRF-Token": body["csrf_token"]}


def test_built_ui_is_served_and_holds_no_secret(client):
    test_client, _calls, _gets, _stored = client
    page = test_client.get("/")
    assert page.status_code == 200, page.data
    html = page.get_data(as_text=True)
    assert 'id="root"' in html
    assert "s3cr3t-Password1" not in html
    src = html.split('src="', 1)[1].split('"', 1)[0]
    asset = test_client.get(src)
    assert asset.status_code == 200
    assert len(asset.data) > 1000


def test_second_load_does_not_touch_keychain_or_profile(client):
    test_client, calls, gets, _stored = client
    _bootstrap(test_client)
    gets_after_first = gets["n"]
    me_after_first = calls["me"]
    assert me_after_first == 1

    _bootstrap(test_client)

    assert gets["n"] == gets_after_first
    assert calls["me"] == me_after_first


def test_second_load_reuses_lists_until_the_ttl(client):
    test_client, calls, _gets, _stored = client
    _bootstrap(test_client)
    _bootstrap(test_client)
    assert calls["list_entries"] == 1
    assert calls["list_keys"] == 1


def test_expired_ttl_relists_without_another_profile_call(client, monkeypatch):
    test_client, calls, _gets, _stored = client
    _bootstrap(test_client)
    monkeypatch.setattr(dash_cache, "LIST_TTL_SECONDS", 0)
    _bootstrap(test_client)
    assert calls["list_entries"] == 2
    assert calls["list_keys"] == 2
    assert calls["me"] == 1


def test_bootstrap_strips_secrets_and_ciphertext(client):
    test_client, _calls, _gets, _stored = client
    response, body = _bootstrap(test_client)
    text = response.get_data(as_text=True)
    assert "s3cr3t-Password1" not in text
    assert "sk-test-secret" not in text
    assert "encrypted_blob" not in text
    assert body["entries"][0]["site_name"] == "GitHub"
    assert body["entries"][0]["username_hint"] == "alice"
    assert body["api_keys"][0]["name"] == "OpenAI"
    assert body["username"] == "alice"
    assert body["entries_error"] is None
    assert body["api_keys_error"] is None


def test_list_failure_is_an_error_not_an_empty_vault(client, monkeypatch):
    _test_client, _calls, _gets, _stored = client

    def boom(access_token, refresh_token):
        raise ConnectionError("backend down")

    monkeypatch.setattr(api_client, "list_vault_entries", boom)
    monkeypatch.setattr(dash_cache, "LIST_TTL_SECONDS", 0)
    dash_cache.CACHE.entries_at = 0
    response, body = _bootstrap(_test_client, query_string={"refresh": "1"})
    assert body["entries"] is None
    assert body["entries"] != []
    assert "backend down" in body["entries_error"]
    assert body["api_keys"] is not None


def test_logged_out_bootstrap_is_401_and_does_not_load_the_keychain(client, monkeypatch):
    test_client, calls, gets, _stored = client
    monkeypatch.setattr(session, "is_logged_in", lambda: False)
    dash_cache.CACHE.reset()
    before = gets["n"]
    response = test_client.get("/api/bootstrap")
    assert response.status_code == 401
    assert response.get_json()["error"] == "not_logged_in"
    assert gets["n"] == before
    assert calls["me"] == 0


def test_add_entry_does_not_reload_lists_and_rejects_a_bad_name(client):
    test_client, calls, _gets, _stored = client
    _response, body = _bootstrap(test_client)
    lists_before = calls["list_entries"]

    bad = test_client.post(
        "/api/entries",
        json={"site_name": "bad/name", "password": "Abcdefg1"},
        headers=_csrf(body),
    )
    assert bad.status_code == 400
    assert calls["add_entry"] == 0

    missing = test_client.post(
        "/api/entries",
        json={"site_name": "GitLab", "password": "Abcdefg1"},
    )
    assert missing.status_code == 403

    created = test_client.post(
        "/api/entries",
        json={
            "site_name": "GitLab",
            "username": "bob",
            "password": "Abcdefg1",
            "notes": "",
            "login_url": "https://gitlab.com",
        },
        headers=_csrf(body),
    )
    assert created.status_code == 201, created.data
    row = created.get_json()
    assert row["site_name"] == "GitLab"
    assert "password" not in row
    assert calls["add_entry"] == 1
    assert calls["list_entries"] == lists_before

    again, payload = _bootstrap(test_client)
    names = [entry["site_name"] for entry in payload["entries"]]
    assert "GitLab" in names
    assert calls["list_entries"] == lists_before


def test_patch_clears_notes_and_keeps_a_blank_password(client, monkeypatch):
    test_client, calls, _gets, stored = client
    _response, body = _bootstrap(test_client)
    seen = {}

    def update_entry(access_token, refresh_token, site_name, blob, iv, username_hint=None, login_url=None):
        from crypto import decrypt_credentials

        seen["plain"] = decrypt_credentials(TEST_VEK, blob, iv)
        seen["login_url"] = login_url
        seen["username_hint"] = username_hint
        return {"ok": True}

    monkeypatch.setattr(api_client, "update_vault_entry", update_entry)
    revealed = test_client.post("/api/entries/GitHub/notes", json={}, headers=_csrf(body))
    assert revealed.status_code == 200, revealed.data
    response = test_client.patch(
        "/api/entries/GitHub",
        json={"password": "", "notes": ""},
        headers=_csrf(body),
    )
    assert response.status_code == 200, response.data
    assert seen["plain"]["password"] == "s3cr3t-Password1"
    assert seen["plain"]["notes"] == ""
    assert calls["get_entry"] == 2
    assert "s3cr3t-Password1" not in response.get_data(as_text=True)


def test_patch_missing_entry_is_404_not_a_crash(client, monkeypatch):
    test_client, _calls, _gets, _stored = client
    _response, body = _bootstrap(test_client)

    def missing(*args, **kwargs):
        raise NotFoundError("Entry not found")

    monkeypatch.setattr(api_client, "get_vault_entry", missing)
    response = test_client.patch(
        "/api/entries/Missing",
        json={"notes": "x"},
        headers=_csrf(body),
    )
    assert response.status_code == 404
    assert response.get_json()["error"]


def test_get_entry_omits_the_password_and_reveal_is_not_cached(client):
    test_client, _calls, _gets, _stored = client
    _response, body = _bootstrap(test_client)
    detail = test_client.get("/api/entries/GitHub")
    assert detail.status_code == 200
    detail_body = detail.get_json()
    assert "password" not in detail_body
    assert "notes" not in detail_body
    assert detail_body["has_notes"] is True
    assert "note text" not in detail.get_data(as_text=True)
    assert detail_body["username"] == "alice"

    reveal = test_client.post("/api/entries/GitHub/reveal", json={"fields": ["password"]}, headers=_csrf(body))
    assert reveal.status_code == 200
    assert reveal.headers["Cache-Control"] == "no-store"
    assert reveal.get_json() == {"password": "s3cr3t-Password1"}
    assert "note text" not in reveal.get_data(as_text=True)


def test_bad_origin_is_rejected(client):
    test_client, _calls, _gets, _stored = client
    _response, body = _bootstrap(test_client)
    response = test_client.post(
        "/api/entries/GitHub/reveal",
        json={"fields": ["password"]},
        headers={**_csrf(body), "Origin": "http://evil.example"},
    )
    assert response.status_code == 403


def test_delete_updates_the_cached_list(client):
    test_client, calls, _gets, _stored = client
    _response, body = _bootstrap(test_client)
    response = test_client.delete("/api/entries/GitHub", headers=_csrf(body))
    assert response.status_code == 200
    _again, payload = _bootstrap(test_client)
    assert payload["entries"] == []
    assert calls["list_entries"] == 1


def test_api_key_reveal_is_separate_from_the_list(client):
    test_client, _calls, _gets, _stored = client
    _response, body = _bootstrap(test_client)
    detail = test_client.get("/api/api-keys/OpenAI")
    assert "api_key" not in detail.get_json()
    assert "notes" not in detail.get_json()
    assert detail.get_json()["has_notes"] is True
    assert "key note" not in detail.get_data(as_text=True)
    reveal = test_client.post(
        "/api/api-keys/OpenAI/reveal",
        json={"fields": ["api_key"]},
        headers=_csrf(body),
    )
    assert reveal.status_code == 200
    assert reveal.get_json() == {"api_key": "sk-test-secret"}
    assert reveal.headers["Cache-Control"] == "no-store"


def test_rotated_token_is_used_on_the_next_call(client, monkeypatch):
    test_client, calls, _gets, _stored = client

    def list_entries(access_token, refresh_token):
        calls["list_entries"] += 1
        calls.setdefault("tokens", []).append(access_token)
        if access_token == TEST_ACCESS_TOKEN:
            session.update_tokens("rotated-access", "rotated-refresh")
        return []

    monkeypatch.setattr(api_client, "list_vault_entries", list_entries)
    _bootstrap(test_client)
    monkeypatch.setattr(dash_cache, "LIST_TTL_SECONDS", 0)
    _bootstrap(test_client)
    assert calls["tokens"] == [TEST_ACCESS_TOKEN, "rotated-access"]


def test_refresh_query_bypasses_a_cached_list_error(client, monkeypatch):
    test_client, calls, _gets, _stored = client
    state = {"fail": True}

    def list_entries(access_token, refresh_token):
        calls["list_entries"] += 1
        if state["fail"]:
            raise ConnectionError("backend down")
        return []

    monkeypatch.setattr(api_client, "list_vault_entries", list_entries)
    first = test_client.get("/api/bootstrap")
    assert first.get_json()["entries"] is None
    state["fail"] = False
    cached = test_client.get("/api/bootstrap")
    assert cached.get_json()["entries"] is None
    assert calls["list_entries"] == 1
    refreshed = test_client.get("/api/bootstrap?refresh=1")
    assert refreshed.get_json()["entries"] == []
    assert calls["list_entries"] == 2


def test_expired_session_tells_the_user_which_command_restores_it(client, monkeypatch):
    from errors import SessionExpiredError

    test_client, _calls, gets, _stored = client
    _bootstrap(test_client)
    reads_after_login = gets["n"]

    def expired(access_token, refresh_token):
        raise SessionExpiredError(
            "Your session has expired",
            hint="Run  psamvault login  to sign in again",
        )

    monkeypatch.setattr(api_client, "list_vault_entries", expired)
    failed = test_client.get("/api/bootstrap?refresh=1")
    body = failed.get_json()
    assert body["entries"] is None
    assert body["entries_recovery"] == "session"
    assert "pv list" in body["entries_error"]
    assert "pv login" in body["entries_error"]

    monkeypatch.setattr(api_client, "list_vault_entries", lambda access_token, refresh_token: [])
    restored = test_client.get("/api/bootstrap?refresh=1")
    restored_body = restored.get_json()
    assert restored_body["entries"] == []
    assert restored_body["entries_recovery"] is None
    # The failed call drops the cached tokens, so Retry reads the keychain again.
    assert gets["n"] >= reads_after_login + 6


def test_project_key_is_grouped_and_the_row_actions_use_the_stored_name(client, monkeypatch):
    """A project/.env/KEY row is labeled, and view/delete send that full name."""
    test_client, calls, _gets, stored = client
    scoped_blob, scoped_iv = encrypt_api_key(TEST_VEK, "scan", "sk-scoped", "scoped note")
    scoped = {
        "name": "atlas054probe/.env/my_custom_key",
        "service_hint": "scan",
        "updated_at": "2026-09-26T00:00:00Z",
        "encrypted_blob": scoped_blob,
        "iv": scoped_iv,
    }
    stale = {
        "name": "env/.env.bak-20260911t114609z/openrouter_api_key",
        "service_hint": "scan",
        "updated_at": "2026-09-11T00:00:00Z",
        "encrypted_blob": scoped_blob,
        "iv": scoped_iv,
    }

    def list_keys(access_token, refresh_token):
        calls["list_keys"] += 1
        return [dict(stored["key"]), scoped, stale]

    seen = {}

    def get_key(access_token, refresh_token, name):
        seen["get"] = name
        if name == scoped["name"]:
            return dict(scoped)
        raise NotFoundError(f"No API key entry found for '{name}'.")

    def delete_key(access_token, refresh_token, name):
        seen["delete"] = name
        return {"ok": True}

    monkeypatch.setattr(api_client, "list_api_key_entries", list_keys)
    monkeypatch.setattr(api_client, "get_api_key_entry", get_key)
    monkeypatch.setattr(api_client, "delete_api_key_entry", delete_key)
    monkeypatch.setattr(dash_cache, "LIST_TTL_SECONDS", 0)
    dash_cache.CACHE.api_keys_at = 0

    _response, body = _bootstrap(test_client, query_string={"refresh": "1"})
    rows = {row["name"]: row for row in body["api_keys"]}
    assert rows[scoped["name"]]["project"] == "atlas054probe"
    assert rows[scoped["name"]]["key_name"] == "my_custom_key"
    assert rows[scoped["name"]]["source"] == ".env"
    assert rows[scoped["name"]]["stale"] is False
    assert rows[stale["name"]]["project"] == "(unscoped)"
    assert rows[stale["name"]]["stale"] is True
    assert rows["OpenAI"]["project"] is None
    assert rows["OpenAI"]["key_name"] == "OpenAI"

    detail = test_client.get("/api/api-keys/atlas054probe/.env/my_custom_key")
    assert detail.status_code == 200, detail.data
    assert "notes" not in detail.get_json()
    assert detail.get_json()["has_notes"] is True
    assert "scoped note" not in detail.get_data(as_text=True)
    assert seen["get"] == scoped["name"]
    assert "sk-scoped" not in detail.get_data(as_text=True)

    deleted = test_client.delete(
        "/api/api-keys/atlas054probe/.env/my_custom_key",
        headers=_csrf(body),
    )
    assert deleted.status_code == 200, deleted.data
    assert seen["delete"] == scoped["name"]


def test_decrypt_failure_on_reveal_is_an_error(client, monkeypatch):
    test_client, _calls, _gets, _stored = client
    _response, body = _bootstrap(test_client)

    def bad_decrypt(*args, **kwargs):
        raise InvalidTag()

    monkeypatch.setattr("dashboard.api.decrypt_credentials", bad_decrypt)
    response = test_client.post(
        "/api/entries/GitHub/reveal",
        json={"fields": ["password"]},
        headers=_csrf(body),
    )
    assert response.status_code == 404


def test_dashboard_login_then_logout_revokes_the_server_session(client, monkeypatch):
    """Sign-in stores a keychain session. Sign-out revokes that refresh token."""
    from crypto import decrypt_vek, derive_key, derive_master_password, encrypt_vek

    import account_flows

    test_client, _calls, _gets, _stored = client
    password = "Password1"
    salt = "ab" * 32
    key = derive_key(derive_master_password(password), salt)
    encrypted, iv = encrypt_vek(bytes(key), TEST_VEK)
    revoked = {}

    def login(username, master):
        return {
            "access_token": "fresh-access",
            "refresh_token": "fresh-refresh",
            "kdf_salt": salt,
            "encrypted_vek": encrypted,
            "vek_iv": iv,
            "has_recovery_codes": False,
        }

    def revoke(access_token, refresh_token):
        revoked["pair"] = (access_token, refresh_token)

    monkeypatch.setattr(api_client, "login", login)
    monkeypatch.setattr(api_client, "logout", revoke)

    signed_in = test_client.post("/api/auth/login", json={"username": "psam", "password": password})
    assert signed_in.status_code == 200, signed_in.data
    body = signed_in.get_json()
    assert body == {"ok": True, "username": "psam", "has_recovery_codes": False}
    text = signed_in.get_data(as_text=True)
    assert password not in text
    assert TEST_VEK.hex() not in text
    assert "fresh-access" not in text

    dash_cache.CACHE.reset()
    loaded = session.load_session()
    assert bytes(decrypt_vek(key, loaded["encrypted_vek"], loaded["vek_iv"])) == TEST_VEK
    _response, bootstrap = _bootstrap(test_client)

    signed_out = test_client.post("/api/logout", json={}, headers=_csrf(bootstrap))
    assert signed_out.status_code == 200
    assert revoked["pair"] == ("fresh-access", "fresh-refresh")
    assert session.is_logged_in() is False
    again = test_client.get("/api/bootstrap")
    assert again.status_code == 401


def test_dashboard_auth_routes_reject_another_sites_origin(client):
    test_client, _calls, _gets, _stored = client
    response = test_client.post(
        "/api/auth/login",
        json={"username": "psam", "password": "Password1"},
        headers={"Origin": "https://evil.example"},
    )
    assert response.status_code == 403
    assert "Password1" not in response.get_data(as_text=True)


def test_dashboard_recover_rejects_a_mismatched_password_before_any_reset(client, monkeypatch):
    test_client, _calls, _gets, _stored = client

    def recover(*args, **kwargs):
        raise AssertionError("recovery must not call the server")

    monkeypatch.setattr(api_client, "recover_with_code", recover)
    response = test_client.post(
        "/api/auth/recover",
        json={
            "username": "psam",
            "recovery_code": "ABCD-EF01-2345",
            "new_password": "NewPassword1",
            "confirm": "NewPassword2",
        },
    )
    assert response.status_code == 400
    assert "match" in response.get_json()["error"]


def test_dashboard_issues_recovery_codes_only_with_the_csrf_token(client, monkeypatch):
    import account_flows

    test_client, _calls, _gets, _stored = client
    _response, body = _bootstrap(test_client)
    monkeypatch.setattr(api_client, "get_remaining_codes", lambda token: {"remaining_codes": 3})
    remaining = test_client.get("/api/auth/recovery-codes")
    assert remaining.status_code == 200
    assert remaining.get_json() == {"remaining": 3}

    blocked = test_client.post("/api/auth/recovery-codes", json={"password": "Password1"})
    assert blocked.status_code == 403

    monkeypatch.setattr(account_flows, "issue_recovery_codes", lambda password, session_data: ["AAAA-BBBB-CCCC"])
    issued = test_client.post(
        "/api/auth/recovery-codes",
        json={"password": "Password1"},
        headers=_csrf(body),
    )
    assert issued.status_code == 200
    assert issued.get_json() == {"codes": ["AAAA-BBBB-CCCC"]}
    assert "Password1" not in issued.get_data(as_text=True)


def test_bootstrap_returns_the_keychain_message_when_the_keyring_is_locked(client, monkeypatch):
    import keyring.errors

    test_client, _calls, _gets, _stored = client
    dash_cache.CACHE.reset()

    def boom(*_args, **_kwargs):
        raise keyring.errors.KeyringLocked("Failed to unlock the collection!")

    monkeypatch.setattr(session.keyring, "get_password", boom)
    response = test_client.get("/api/bootstrap")
    assert response.status_code == 503
    body = response.get_json()
    assert body is not None
    assert " — " in body["error"]
    assert "locked" in body["error"].lower()
    assert body["error"] != "not_logged_in"
    text = response.get_data(as_text=True)
    assert "Traceback" not in text
    assert "<html" not in text.lower()


def test_dashboard_login_returns_the_keychain_message_instead_of_a_500(client, monkeypatch):
    import keyring.errors

    from crypto import derive_key, derive_master_password, encrypt_vek

    test_client, _calls, _gets, _stored = client
    password = "Password1"
    salt = "ab" * 32
    key = derive_key(derive_master_password(password), salt)
    encrypted, iv = encrypt_vek(bytes(key), TEST_VEK)

    def login(username, master):
        return {
            "access_token": "fresh-access",
            "refresh_token": "fresh-refresh",
            "kdf_salt": salt,
            "encrypted_vek": encrypted,
            "vek_iv": iv,
            "has_recovery_codes": False,
        }

    def boom(*_args, **_kwargs):
        raise keyring.errors.NoKeyringError("No recommended backend was available")

    monkeypatch.setattr(api_client, "login", login)
    monkeypatch.setattr(session.keyring, "set_password", boom)
    response = test_client.post(
        "/api/auth/login",
        json={"username": "psam", "password": password},
    )
    assert response.status_code == 503
    body = response.get_json()
    assert body is not None
    assert " — " in body["error"]
    assert "No OS keychain" in body["error"]
    text = response.get_data(as_text=True)
    assert "Traceback" not in text
    assert "<html" not in text.lower()
    assert password not in text
    assert "fresh-access" not in text


_DASHBOARD_ORIGIN = "http://127.0.0.1:8500"


def _exchange(test_client, token: str, origin: str | None = _DASHBOARD_ORIGIN):
    headers = {}
    if origin is not None:
        headers["Origin"] = origin
    return test_client.post("/session", json={"token": token}, headers=headers)


def test_api_requires_a_browser_session_cookie(dashboard_app):
    """A local process that did not exchange the launch token gets no vault data."""
    app, _calls, _gets, _stored = dashboard_app
    raw = app.test_client()
    response = raw.get("/api/bootstrap", headers={"Origin": _DASHBOARD_ORIGIN})
    assert response.status_code == 401
    assert response.get_json()["error"] == "dashboard_session_required"
    assert "s3cr3t-Password1" not in response.get_data(as_text=True)
    assert "csrf_token" not in response.get_data(as_text=True)


def test_launch_token_is_single_use_and_sets_an_httponly_cookie(dashboard_app):
    app, _calls, _gets, _stored = dashboard_app
    token = dash_cache.CACHE.launch_token
    assert token
    raw = app.test_client()

    missing = _exchange(raw, token, origin=None)
    assert missing.status_code == 403
    assert dash_cache.CACHE.launch_spent is False

    first = _exchange(raw, token)
    assert first.status_code == 200
    set_cookie = first.headers["Set-Cookie"]
    assert "HttpOnly" in set_cookie
    assert "SameSite=Strict" in set_cookie
    assert token not in set_cookie
    assert TEST_VEK.hex() not in set_cookie
    assert first.get_json() == {"ok": True}

    again = _exchange(raw, token)
    assert again.status_code == 403
    assert "Set-Cookie" not in again.headers

    bootstrap = raw.get("/api/bootstrap", headers={"Origin": _DASHBOARD_ORIGIN})
    assert bootstrap.status_code == 200
    assert "s3cr3t-Password1" not in bootstrap.get_data(as_text=True)


def test_api_requires_the_dashboard_origin(dashboard_app):
    app, _calls, _gets, _stored = dashboard_app
    raw = app.test_client()
    token = dash_cache.CACHE.launch_token
    assert _exchange(raw, token).status_code == 200

    # Chrome omits Origin on a same-origin GET. The cookie is still required.
    missing = raw.get("/api/bootstrap")
    assert missing.status_code == 200, missing.data
    assert "s3cr3t-Password1" not in missing.get_data(as_text=True)

    post_without_origin = raw.post(
        "/api/entries/GitHub/reveal",
        json={"fields": ["password"]},
        headers={"X-CSRF-Token": "unused"},
    )
    assert post_without_origin.status_code == 403
    assert post_without_origin.get_json()["error"] == "Bad origin"
    assert "s3cr3t-Password1" not in post_without_origin.get_data(as_text=True)

    forged = raw.post(
        "/api/entries/GitHub/reveal",
        json={"fields": ["password"]},
        headers={"Origin": "http://evil.example", "X-CSRF-Token": "unused"},
    )
    assert forged.status_code == 403
    assert "s3cr3t-Password1" not in forged.get_data(as_text=True)


def test_dashboard_reveal_writes_an_allow_audit_row(dashboard_app):
    import audit

    app, _calls, _gets, _stored = dashboard_app
    raw = app.test_client()
    assert _exchange(raw, dash_cache.CACHE.launch_token).status_code == 200
    _response, body = _bootstrap(raw, headers={"Origin": _DASHBOARD_ORIGIN})
    reveal = raw.post(
        "/api/entries/GitHub/reveal",
        json={"fields": ["password"]},
        headers={"Origin": _DASHBOARD_ORIGIN, "X-CSRF-Token": body["csrf_token"]},
    )
    assert reveal.status_code == 200
    assert reveal.get_json() == {"password": "s3cr3t-Password1"}
    rows = audit.read()
    assert rows[-1]["command"] == "get"
    assert rows[-1]["entry"] == "GitHub"
    assert rows[-1]["decision"] == "allow"
    assert "s3cr3t-Password1" not in str(rows[-1])

    key = raw.post(
        "/api/api-keys/OpenAI/reveal",
        json={"fields": ["api_key"]},
        headers={"Origin": _DASHBOARD_ORIGIN, "X-CSRF-Token": body["csrf_token"]},
    )
    assert key.status_code == 200
    assert key.get_json() == {"api_key": "sk-test-secret"}
    assert audit.read()[-1]["command"] == "ak-get"
    assert audit.read()[-1]["decision"] == "allow"
    assert "sk-test-secret" not in str(audit.read()[-1])


def test_agent_started_dashboard_refuses_reveal_and_writes_a_deny_row(monkeypatch, tmp_path, fake_keychain):
    import audit

    monkeypatch.setenv("PSAMVAULT_AGENT", "1")
    app, _calls, _gets, _stored = _build_dashboard_app(monkeypatch, tmp_path, fake_keychain)
    raw = app.test_client()
    assert _exchange(raw, dash_cache.CACHE.launch_token).status_code == 200
    _response, body = _bootstrap(raw, headers={"Origin": _DASHBOARD_ORIGIN})
    reveal = raw.post(
        "/api/entries/GitHub/reveal",
        json={"fields": ["password", "notes"]},
        headers={"Origin": _DASHBOARD_ORIGIN, "X-CSRF-Token": body["csrf_token"]},
    )
    assert reveal.status_code == 403
    text = reveal.get_data(as_text=True)
    assert "s3cr3t-Password1" not in text
    assert "note text" not in text
    assert "blocked" in reveal.get_json()["error"]
    row = audit.read()[-1]
    assert row["command"] == "get"
    assert row["entry"] == "GitHub"
    assert row["decision"] == "deny"
    assert row["caller"] == "agent"
    assert "s3cr3t-Password1" not in str(row)

    key = raw.post(
        "/api/api-keys/OpenAI/reveal",
        json={"fields": ["api_key"]},
        headers={"Origin": _DASHBOARD_ORIGIN, "X-CSRF-Token": body["csrf_token"]},
    )
    assert key.status_code == 403
    assert "sk-test-secret" not in key.get_data(as_text=True)
    assert audit.read()[-1]["command"] == "ak-get"
    assert audit.read()[-1]["decision"] == "deny"


def test_dashboard_command_opens_the_token_in_the_fragment(monkeypatch):
    import webbrowser

    import waitress

    opened: dict = {}

    def _open(url):
        opened["url"] = url
        return True

    def _serve(*args, **kwargs):
        opened["serve"] = (args, kwargs)

    monkeypatch.setattr(webbrowser, "open", _open)
    monkeypatch.setattr(waitress, "serve", _serve)

    from typer.testing import CliRunner

    import main

    result = CliRunner().invoke(main.app, ["dashboard"])
    assert result.exit_code == 0, result.output
    url = opened["url"]
    assert url.startswith("http://localhost:8500/#")
    token = url.split("#", 1)[1]
    assert token
    assert token not in result.output
    assert "http://localhost:8500" in result.output
    _args, kwargs = opened["serve"]
    assert kwargs["host"] == "127.0.0.1"
    assert kwargs["port"] == 8500


def _listen(port: int):
    import socket

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", port))
    sock.listen(1)
    return sock


def _run_dashboard(monkeypatch, args: list[str]):
    """Invoke ``pv dashboard`` without opening a browser or binding Waitress."""
    import webbrowser

    import waitress
    from typer.testing import CliRunner

    import main

    opened: dict = {}

    def _open(url):
        opened["url"] = url
        return True

    def _serve(*args, **kwargs):
        opened["serve"] = (args, kwargs)

    monkeypatch.setattr(webbrowser, "open", _open)
    monkeypatch.setattr(waitress, "serve", _serve)
    result = CliRunner().invoke(main.app, ["dashboard", *args])
    return result, opened


def test_detail_and_list_gets_return_has_notes_and_not_the_text(client, monkeypatch):
    """List and detail GETs name whether notes exist. They do not return the text."""
    test_client, _calls, _gets, _stored = client
    response, body = _bootstrap(test_client)
    text = response.get_data(as_text=True)
    assert body["entries"][0]["has_notes"] is True
    assert body["api_keys"][0]["has_notes"] is True
    assert "note text" not in text
    assert "key note" not in text
    assert "notes" not in body["entries"][0]
    assert "notes" not in body["api_keys"][0]

    detail = test_client.get("/api/entries/GitHub")
    detail_body = detail.get_json()
    assert detail.status_code == 200
    assert detail_body["has_notes"] is True
    assert detail_body["username"] == "alice"
    assert "notes" not in detail_body
    assert "note text" not in detail.get_data(as_text=True)
    assert "password" not in detail_body

    key = test_client.get("/api/api-keys/OpenAI")
    assert key.status_code == 200
    assert key.get_json()["has_notes"] is True
    assert "notes" not in key.get_json()
    assert "key note" not in key.get_data(as_text=True)
    assert "api_key" not in key.get_json()

    import audit

    before = len(audit.read())
    assert test_client.get("/api/entries/GitHub").status_code == 200
    assert len(audit.read()) == before

    blank_blob, blank_iv = encrypt_credentials(TEST_VEK, "bob", "s3cr3t-Password1", "")
    blank = {
        "site_name": "GitLab",
        "username_hint": "bob",
        "updated_at": "2026-09-03T12:00:00Z",
        "login_url": "",
        "encrypted_blob": blank_blob,
        "iv": blank_iv,
    }
    monkeypatch.setattr(api_client, "list_vault_entries", lambda *_args, **_kwargs: [blank])
    monkeypatch.setattr(
        api_client,
        "get_vault_entry",
        lambda *_args, **_kwargs: dict(blank),
    )
    monkeypatch.setattr(dash_cache, "LIST_TTL_SECONDS", 0)
    dash_cache.CACHE.entries_at = 0
    _blank_response, blank_body = _bootstrap(test_client, query_string={"refresh": "1"})
    assert blank_body["entries"][0]["has_notes"] is False
    blank_detail = test_client.get("/api/entries/GitLab")
    assert blank_detail.get_json()["has_notes"] is False
    assert "notes" not in blank_detail.get_json()


def test_notes_reveal_is_a_gated_route_with_an_allow_audit_row(client):
    """Notes come from their own route, through the same gate as a password reveal."""
    import audit

    test_client, _calls, _gets, _stored = client
    _response, body = _bootstrap(test_client)

    # The password / API-key reveal must not smuggle notes out, even by default.
    password = test_client.post("/api/entries/GitHub/reveal", json={}, headers=_csrf(body))
    assert password.status_code == 200
    assert "note text" not in password.get_data(as_text=True)
    assert password.get_json().get("password") == "s3cr3t-Password1"
    asked = test_client.post(
        "/api/entries/GitHub/reveal",
        json={"fields": ["notes"]},
        headers=_csrf(body),
    )
    assert "note text" not in asked.get_data(as_text=True)

    before_csrf = len(audit.read())
    missing_csrf = test_client.post("/api/entries/GitHub/notes", json={})
    assert missing_csrf.status_code == 403
    assert len(audit.read()) == before_csrf

    before = len(audit.read())
    revealed = test_client.post("/api/entries/GitHub/notes", json={}, headers=_csrf(body))
    assert revealed.status_code == 200, revealed.data
    assert revealed.headers["Cache-Control"] == "no-store"
    assert revealed.get_json() == {"notes": "note text"}
    assert "s3cr3t-Password1" not in revealed.get_data(as_text=True)
    row = audit.read()[-1]
    assert row["command"] == "get"
    assert row["entry"] == "GitHub"
    assert row["decision"] == "allow"
    assert "note text" not in str(row)
    assert len(audit.read()) == before + 1

    key = test_client.post("/api/api-keys/OpenAI/notes", json={}, headers=_csrf(body))
    assert key.status_code == 200, key.data
    assert key.get_json() == {"notes": "key note"}
    assert "sk-test-secret" not in key.get_data(as_text=True)
    key_row = audit.read()[-1]
    assert key_row["command"] == "ak-get"
    assert key_row["entry"] == "OpenAI"
    assert key_row["decision"] == "allow"
    assert "key note" not in str(key_row)


def test_notes_reveal_denied_for_an_agent_writes_a_deny_row(monkeypatch, tmp_path, fake_keychain):
    import audit

    monkeypatch.setenv("PSAMVAULT_AGENT", "1")
    app, _calls, _gets, _stored = _build_dashboard_app(monkeypatch, tmp_path, fake_keychain)
    raw = app.test_client()
    assert _exchange(raw, dash_cache.CACHE.launch_token).status_code == 200
    _response, body = _bootstrap(raw, headers={"Origin": _DASHBOARD_ORIGIN})
    revealed = raw.post(
        "/api/entries/GitHub/notes",
        json={},
        headers={"Origin": _DASHBOARD_ORIGIN, "X-CSRF-Token": body["csrf_token"]},
    )
    assert revealed.status_code == 403
    text = revealed.get_data(as_text=True)
    assert "note text" not in text
    assert "s3cr3t-Password1" not in text
    assert "blocked" in revealed.get_json()["error"]
    row = audit.read()[-1]
    assert row["command"] == "get"
    assert row["entry"] == "GitHub"
    assert row["decision"] == "deny"
    assert row["caller"] == "agent"
    assert "note text" not in str(row)

    key = raw.post(
        "/api/api-keys/OpenAI/notes",
        json={},
        headers={"Origin": _DASHBOARD_ORIGIN, "X-CSRF-Token": body["csrf_token"]},
    )
    assert key.status_code == 403
    assert "key note" not in key.get_data(as_text=True)
    assert audit.read()[-1]["command"] == "ak-get"
    assert audit.read()[-1]["entry"] == "OpenAI"
    assert audit.read()[-1]["decision"] == "deny"


def test_save_does_not_wipe_notes_that_were_never_revealed(client, monkeypatch):
    """A save that sends notes, or omits them, keeps the stored text until a notes reveal."""
    test_client, _calls, _gets, _stored = client
    _response, body = _bootstrap(test_client)
    seen = {}

    def update_entry(access_token, refresh_token, site_name, blob, iv, username_hint=None, login_url=None):
        from crypto import decrypt_credentials

        seen["plain"] = decrypt_credentials(TEST_VEK, blob, iv)
        return {"ok": True}

    def update_key(access_token, refresh_token, name, service, blob, iv, notes=None):
        from crypto import decrypt_api_key

        seen["key"] = decrypt_api_key(TEST_VEK, blob, iv)
        return {"ok": True}

    monkeypatch.setattr(api_client, "update_vault_entry", update_entry)
    monkeypatch.setattr(api_client, "update_api_key_entry", update_key)

    omitted = test_client.patch(
        "/api/entries/GitHub",
        json={"username": "alice"},
        headers=_csrf(body),
    )
    assert omitted.status_code == 200, omitted.data
    assert seen["plain"]["notes"] == "note text"
    assert "note text" not in omitted.get_data(as_text=True)

    wiped = test_client.patch(
        "/api/entries/GitHub",
        json={"notes": ""},
        headers=_csrf(body),
    )
    assert wiped.status_code == 200, wiped.data
    assert seen["plain"]["notes"] == "note text"
    assert seen["plain"]["password"] == "s3cr3t-Password1"

    replaced = test_client.patch(
        "/api/entries/GitHub",
        json={"notes": "replaced without looking"},
        headers=_csrf(body),
    )
    assert replaced.status_code == 200, replaced.data
    assert seen["plain"]["notes"] == "note text"

    key = test_client.patch(
        "/api/api-keys/OpenAI",
        json={"notes": ""},
        headers=_csrf(body),
    )
    assert key.status_code == 200, key.data
    assert seen["key"]["notes"] == "key note"
    assert "key note" not in key.get_data(as_text=True)

    revealed = test_client.post("/api/entries/GitHub/notes", json={}, headers=_csrf(body))
    assert revealed.status_code == 200, revealed.data
    cleared = test_client.patch(
        "/api/entries/GitHub",
        json={"notes": ""},
        headers=_csrf(body),
    )
    assert cleared.status_code == 200, cleared.data
    assert seen["plain"]["notes"] == ""
    assert seen["plain"]["password"] == "s3cr3t-Password1"


def test_frontend_hides_notes_until_reveal_and_omits_them_on_save():
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    app = (root / "dashboard/frontend/src/App.tsx").read_text()
    api = (root / "dashboard/frontend/src/api.ts").read_text()
    assert "revealEntryNotes" in api
    assert "revealApiKeyNotes" in api
    assert "/notes" in api
    assert "has_notes" in api
    assert "if (!notesRevealed) delete payload.notes;" in app
    assert ">Reveal<" in app


def test_built_bundle_calls_the_notes_reveal_route(client):
    test_client, _calls, _gets, _stored = client
    page = test_client.get("/")
    html = page.get_data(as_text=True)
    src = html.split('src="', 1)[1].split('"', 1)[0]
    asset = test_client.get(src)
    assert asset.status_code == 200
    text = asset.get_data(as_text=True)
    assert "/notes" in text


def test_dashboard_falls_back_when_the_default_port_is_busy(monkeypatch):
    import dashboard as dashboard_pkg
    import dashboard.api as dashboard_api

    held = _listen(8500)
    try:
        result, opened = _run_dashboard(monkeypatch, [])
    finally:
        held.close()
    assert result.exit_code == 0, result.output
    _args, kwargs = opened["serve"]
    port = kwargs["port"]
    assert port != 8500
    assert kwargs["host"] == "127.0.0.1"
    url = opened["url"]
    assert url.startswith(f"http://localhost:{port}/#")
    token = url.split("#", 1)[1]
    assert token
    assert token not in result.output
    assert f"http://localhost:{port}" in result.output
    assert "8500" in result.output
    assert dashboard_api._ALLOWED_ORIGINS == {
        f"http://127.0.0.1:{port}",
        f"http://localhost:{port}",
        f"http://[::1]:{port}",
    }
    assert f"127.0.0.1:{port}" in dashboard_pkg._ALLOWED_HOSTS
    assert f"localhost:{port}" in dashboard_pkg._ALLOWED_HOSTS
    assert f"[::1]:{port}" in dashboard_pkg._ALLOWED_HOSTS


def test_explicit_port_is_bound_and_a_busy_one_fails(monkeypatch):
    import dashboard.api as dashboard_api

    free = 18766
    result, opened = _run_dashboard(monkeypatch, ["--port", str(free)])
    assert result.exit_code == 0, result.output
    _args, kwargs = opened["serve"]
    assert kwargs["port"] == free
    assert opened["url"].startswith(f"http://localhost:{free}/#")
    token = opened["url"].split("#", 1)[1]
    assert token not in result.output
    assert f"http://localhost:{free}" in result.output
    assert dashboard_api._ALLOWED_ORIGINS == {
        f"http://127.0.0.1:{free}",
        f"http://localhost:{free}",
        f"http://[::1]:{free}",
    }

    busy = 18767
    held = _listen(busy)
    try:
        failed, failed_opened = _run_dashboard(monkeypatch, ["--port", str(busy)])
    finally:
        held.close()
    assert failed.exit_code != 0
    assert "serve" not in failed_opened
    assert str(busy) in failed.output
    assert "in use" in failed.output.lower()


def test_origin_allow_list_uses_the_bound_port(monkeypatch, tmp_path, fake_keychain):
    _build_dashboard_app(monkeypatch, tmp_path, fake_keychain)
    dash_cache.CACHE.reset()
    app = create_app(port=8603)
    app.config["TESTING"] = True
    raw = app.test_client()
    token = dash_cache.CACHE.launch_token
    origin = "http://127.0.0.1:8603"
    opened = raw.post("/session", json={"token": token}, headers={"Origin": origin})
    assert opened.status_code == 200, opened.data
    # The test client keeps the cookie for the host that set it, and a
    # different Host header does not see that jar entry. Copy it onto the
    # names the allow-list covers so those requests are testing the host
    # check, not a missing cookie.
    session_value = opened.headers["Set-Cookie"].split(";", 1)[0].split("=", 1)[1]
    for domain in ("127.0.0.1", "localhost", "::1"):
        raw.set_cookie(dash_cache.BROWSER_COOKIE, session_value, domain=domain)

    for allowed in (
        "http://127.0.0.1:8603",
        "http://localhost:8603",
        "http://[::1]:8603",
    ):
        response = raw.get("/api/bootstrap", headers={"Origin": allowed})
        assert response.status_code == 200, allowed
        assert "note text" not in response.get_data(as_text=True)

    rejected = raw.get("/api/bootstrap", headers={"Origin": "http://127.0.0.1:8500"})
    assert rejected.status_code == 403

    host_ok = raw.get(
        "/api/bootstrap",
        headers={"Origin": origin, "Host": "127.0.0.1:8603"},
    )
    assert host_ok.status_code == 200, host_ok.data
    host_bad = raw.get(
        "/api/bootstrap",
        headers={"Origin": origin, "Host": "127.0.0.1:8500"},
    )
    assert host_bad.status_code == 403
    localhost_host = raw.get(
        "/api/bootstrap",
        headers={"Origin": "http://localhost:8603", "Host": "localhost:8603"},
    )
    assert localhost_host.status_code == 200, localhost_host.data
    v6_host = raw.get(
        "/api/bootstrap",
        headers={"Origin": "http://[::1]:8603", "Host": "[::1]:8603"},
    )
    assert v6_host.status_code == 200, v6_host.data
