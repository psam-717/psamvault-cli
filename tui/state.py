"""
Session state for the psamvault TUI.

Loads the user's session from the OS keychain, provides the VEK for
decryption, and caches vault entries + API keys in memory so the TUI
can navigate between screens without re-fetching.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

# ── The project's own modules ──────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import typer  # noqa: TID251 — needed only to catch typer.Exit in Textual context

from api_client import (
    add_vault_entry,
    add_api_key_entry,
    delete_vault_entry,
    delete_api_key_entry,
    get_vault_entry,
    get_api_key_entry,
    list_vault_entries,
    list_api_key_entries,
    login as api_login,
    signup as api_signup,
    me as api_me,
)
from crypto import derive_master_password, derive_key, decrypt_vek
from crypto import decrypt_credentials, decrypt_api_key
from session import load_session, save_session, is_logged_in, clear_session, update_tokens
from config import load_config


class SessionExpired(Exception):
    """Raised when the API client's token refresh fails inside a Textual context."""


@dataclass
class DecryptedEntry:
    """A fully-decrypted vault entry ready for the UI."""
    site_name: str
    username: str
    password: str
    notes: str
    login_url: str
    encrypted_blob: str
    iv: str
    username_hint: str


@dataclass
class DecryptedApiKey:
    """A fully-decrypted API key ready for the UI."""
    name: str
    service: str
    api_key: str
    notes: str
    encrypted_blob: str
    iv: str
    service_hint: str


@dataclass
class UserProfile:
    """User profile info from GET /auth/me."""
    username: str
    email: str
    created_at: str


class AppState:
    """
    Holds the session, VEK, and cached decrypted entries.

    One instance lives in the app's ``app.state`` attribute and is shared
    across all screens via ``self.app.state``.
    """

    def __init__(self) -> None:
        load_config()
        self._vek: bytes | None = None
        self._access_token: str | None = None
        self._refresh_token: str | None = None
        self._profile: UserProfile | None = None

        # --- cached data ---
        self.vault_entries: list[DecryptedEntry] = []
        self.api_keys: list[DecryptedApiKey] = []

        # --- cache-freshness flags: skip network calls when already up-to-date ---
        self._vault_needs_refresh = True
        self._api_keys_needs_refresh = True
        self._profile_fetched = False

        # --- mutation callbacks called by screens to invalidate cache ---
        self._on_refresh: Callable[[], None] | None = None

    # ── login / logout ────────────────────────────────────────────────────

    def load_existing_session(self) -> bool:
        """Restore session from keychain. Returns True if logged in."""
        if not is_logged_in():
            return False
        try:
            sess = load_session()
            self._access_token = sess["access_token"]
            self._refresh_token = sess["refresh_token"]
            kdf_salt = sess["kdf_salt"]
            vek_hex = sess.get("vek")
            encrypted_vek = sess.get("encrypted_vek", "")
            vek_iv = sess.get("vek_iv", "")

            # Derive login password not available — so we need the pre-decrypted VEK
            # from the keychain.  If `vek` is *not* stored (pre-v0.3 session) we
            # cannot decrypt without asking for the password; the login screen
            # handles that case by doing a fresh login.
            if vek_hex:
                self._vek = bytes.fromhex(vek_hex)
            return True
        except Exception:
            return False

    def refresh_session(self) -> bool:
        """Refresh the access token using the stored refresh token.

        Returns True on success, or raises SessionExpired if the refresh
        token itself is expired/invalid (which will redirect to login).
        """
        if not self._refresh_token:
            raise SessionExpired("No refresh token available")
        try:
            from api_client import refresh_access_token
            new_access, new_refresh = refresh_access_token(self._refresh_token)
            self._access_token = new_access
            self._refresh_token = new_refresh
            update_tokens(new_access, new_refresh)
            return True
        except (SystemExit, typer.Exit):
            self.logout()
            raise SessionExpired("Refresh token expired — please log in again")

    def login(self, username: str, password: str) -> str | None:
        """
        Full login — hit the API, derive VEK, persist session.
        Returns None on success, or an error message string.
        """
        try:
            data = api_login(username, password)
            self._access_token = data["access_token"]
            self._refresh_token = data["refresh_token"]
            kdf_salt = data["kdf_salt"]

            master = derive_master_password(password)
            login_key = derive_key(master, kdf_salt)
            vek_bytes = decrypt_vek(
                bytes(login_key),
                data.get("encrypted_vek", ""),
                data.get("vek_iv", ""),
            )
            self._vek = bytes(vek_bytes)

            save_session(
                access_token=self._access_token,
                refresh_token=self._refresh_token,
                kdf_salt=kdf_salt,
                vek=self._vek.hex(),
                encrypted_vek=data.get("encrypted_vek", ""),
                vek_iv=data.get("vek_iv", ""),
            )
            return None
        except Exception as exc:
            return str(exc)

    def logout(self) -> None:
        """Clear local session."""
        clear_session()
        self._vek = None
        self._access_token = None
        self._refresh_token = None
        self.vault_entries.clear()
        self.api_keys.clear()
        self._profile = None
        self._vault_needs_refresh = True
        self._api_keys_needs_refresh = True
        self._profile_fetched = False

    @property
    def is_authenticated(self) -> bool:
        return self._access_token is not None and self._vek is not None

    @property
    def access_token(self) -> str:
        assert self._access_token is not None
        return self._access_token

    @property
    def refresh_token(self) -> str:
        assert self._refresh_token is not None
        return self._refresh_token

    @property
    def vek(self) -> bytes:
        assert self._vek is not None
        return self._vek

    # ── profile ───────────────────────────────────────────────────────────

    def load_profile(self) -> UserProfile | None:
        """Fetch /auth/me and cache the profile (only once per session)."""
        if self._profile_fetched and self._profile is not None:
            return self._profile
        try:
            data = api_me(self.access_token)
            self._profile = UserProfile(
                username=data.get("username", "?"),
                email=data.get("email", "?"),
                created_at=data.get("created_at", ""),
            )
            self._profile_fetched = True
            return self._profile
        except Exception:
            return self._profile

    @property
    def profile(self) -> UserProfile | None:
        return self._profile

    # ── fetch & decrypt ───────────────────────────────────────────────────

    def refresh_vault(self) -> list[DecryptedEntry]:
        """Fetch and decrypt all vault entries (cached — skips network if already fresh)."""
        if not self._vault_needs_refresh:
            return self.vault_entries
        try:
            token = self.access_token
            refresh = self.refresh_token
            data = list_vault_entries(token, refresh)
        except (SystemExit, typer.Exit):  # nosec — api_client typer.echo crashes under Textual
            # Session stale (refresh token expired). Clear and raise so TUI shows login.
            self.logout()
            raise SessionExpired("Vault data fetch failed — session expired")
        except Exception:
            raise SessionExpired("Vault data fetch failed — session expired")

        entries: list[dict] = data if isinstance(data, list) else data.get("entries", [])

        self.vault_entries = []
        for e in entries:
            try:
                decrypted = decrypt_credentials(
                    self.vek,
                    e["encrypted_blob"],
                    e["iv"],
                )
            except Exception:
                decrypted = {"username": "?", "password": "?", "notes": ""}

            self.vault_entries.append(DecryptedEntry(
                site_name=e.get("site_name", "?"),
                username=decrypted.get("username", ""),
                password=decrypted.get("password", ""),
                notes=decrypted.get("notes", ""),
                login_url=e.get("login_url", ""),
                encrypted_blob=e.get("encrypted_blob", ""),
                iv=e.get("iv", ""),
                username_hint=e.get("username_hint", ""),
            ))

        self._vault_needs_refresh = False

        if self._on_refresh:
            self._on_refresh()
        return self.vault_entries

    def refresh_api_keys(self) -> list[DecryptedApiKey]:
        """Fetch and decrypt all API key entries (cached — skips network if already fresh)."""
        if not self._api_keys_needs_refresh:
            return self.api_keys
        try:
            token = self.access_token
            refresh = self.refresh_token
            data = list_api_key_entries(token, refresh)
        except (SystemExit, typer.Exit):
            self.logout()
            raise SessionExpired("API key fetch failed — session expired")
        except Exception:
            raise SessionExpired("API key fetch failed — session expired")

        entries: list[dict] = data if isinstance(data, list) else data.get("entries", [])

        self.api_keys = []
        for e in entries:
            try:
                decrypted = decrypt_api_key(
                    self.vek,
                    e["encrypted_blob"],
                    e["iv"],
                )
            except Exception:
                decrypted = {"service": "", "api_key": "?", "notes": ""}

            self.api_keys.append(DecryptedApiKey(
                name=e.get("name", "?"),
                service=decrypted.get("service", ""),
                api_key=decrypted.get("api_key", ""),
                notes=decrypted.get("notes", ""),
                encrypted_blob=e.get("encrypted_blob", ""),
                iv=e.get("iv", ""),
                service_hint=e.get("service_hint", ""),
            ))

        self._api_keys_needs_refresh = False

        if self._on_refresh:
            self._on_refresh()
        return self.api_keys

    def add_entry(
        self,
        site_name: str,
        username: str,
        password: str,
        notes: str,
        login_url: str,
    ) -> str | None:
        """Add a vault entry. Returns None on success, or an error string."""
        from crypto import encrypt_credentials
        blob, iv = encrypt_credentials(self.vek, username, password, notes)
        try:
            add_vault_entry(
                self.access_token,
                self.refresh_token,
                site_name,
                blob,
                iv,
                username_hint=username,
                login_url=login_url or None,
            )
            self._vault_needs_refresh = True
            return None
        except Exception as exc:
            return str(exc)

    def delete_entry(self, site_name: str) -> str | None:
        """Delete a vault entry. Returns None on success, or an error string."""
        try:
            delete_vault_entry(self.access_token, self.refresh_token, site_name)
            self._vault_needs_refresh = True
            return None
        except Exception as exc:
            return str(exc)

    def add_api_key(
        self,
        name: str,
        service: str,
        api_key: str,
        notes: str,
    ) -> str | None:
        """Add an API key entry."""
        from crypto import encrypt_api_key
        blob, iv = encrypt_api_key(self.vek, service, api_key, notes)
        try:
            add_api_key_entry(
                self.access_token,
                self.refresh_token,
                name,
                service,
                blob,
                iv,
            )
            self._api_keys_needs_refresh = True
            return None
        except Exception as exc:
            return str(exc)

    def delete_api_key(self, name: str) -> str | None:
        try:
            delete_api_key_entry(self.access_token, self.refresh_token, name)
            self._api_keys_needs_refresh = True
            return None
        except Exception as exc:
            return str(exc)

    # ── stats ─────────────────────────────────────────────────────────────

    @property
    def entry_count(self) -> int:
        return len(self.vault_entries)

    @property
    def api_key_count(self) -> int:
        return len(self.api_keys)

    @property
    def total_count(self) -> int:
        return self.entry_count + self.api_key_count