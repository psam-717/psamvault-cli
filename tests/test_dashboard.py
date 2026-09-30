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


@pytest.fixture
def dashboard_app(monkeypatch, tmp_path, fake_keychain):
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
def client(dashboard_app):
    app, calls, gets, stored = dashboard_app
    with app.test_client() as test_client:
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
    response = test_client.patch(
        "/api/entries/GitHub",
        json={"password": "", "notes": ""},
        headers=_csrf(body),
    )
    assert response.status_code == 200, response.data
    assert seen["plain"]["password"] == "s3cr3t-Password1"
    assert seen["plain"]["notes"] == ""
    assert calls["get_entry"] == 1
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
    assert detail_body["notes"] == "note text"
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
    assert detail.get_json()["notes"] == "key note"
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
    assert detail.get_json()["notes"] == "scoped note"
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
