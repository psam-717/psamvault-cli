"""Process-local dashboard session.

`pv dashboard` is one user on one machine. Reading the OS keychain and calling
GET /auth/me on every click is what made the page feel stuck. This cache does
that work once, then keeps the tokens, the username, and the ciphertext lists
in memory until the process exits or the short list TTL passes.

Plaintext passwords are never stored here.
"""

from __future__ import annotations

import secrets
import threading
import time

import api_client
import session as session_store

# Short enough that a change made from the CLI shows up on refresh, long
# enough that a tab click does not pay for another round trip.
LIST_TTL_SECONDS = 30

_lock = threading.Lock()


class ProcessCache:
    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self.auth: dict | None = None
        self.auth_loaded = False
        self.username = "User"
        self.csrf_token = secrets.token_urlsafe(32)
        self.entries: list | None = None
        self.entries_error: str | None = None
        self.entries_recovery: str | None = None
        self.entries_at = 0.0
        self.api_keys: list | None = None
        self.api_keys_error: str | None = None
        self.api_keys_recovery: str | None = None
        self.api_keys_at = 0.0

    def set_tokens(self, access_token: str, refresh_token: str) -> None:
        if self.auth is None:
            return
        self.auth["access_token"] = access_token
        self.auth["refresh_token"] = refresh_token


CACHE = ProcessCache()


def install_token_hook() -> None:
    """Keep the in-memory tokens in step with a refresh.

    api_client writes rotated tokens to the keychain and does not return them.
    Wrapping the writer is how this process hears about the new pair without
    reading the keychain again. The dashboard process does not serve CLI
    commands, so the wrap does not change the terminal.
    """
    current = session_store.update_tokens
    if getattr(current, "_dashboard_hook", False):
        return
    original = current

    def wrapped(access_token: str, refresh_token: str) -> None:
        original(access_token, refresh_token)
        with _lock:
            CACHE.set_tokens(access_token, refresh_token)

    wrapped._dashboard_hook = True  # type: ignore[attr-defined]
    session_store.update_tokens = wrapped


def ensure_auth() -> dict | None:
    """Return the cached CLI session, loading it on the first successful call."""
    with _lock:
        if CACHE.auth_loaded:
            return CACHE.auth
        if not session_store.is_logged_in():
            return None
        try:
            loaded = session_store.load_session()
        except (SystemExit, Exception):
            return None
        CACHE.auth = loaded
        CACHE.auth_loaded = True
        token = loaded["access_token"]

    try:
        profile = api_client.me(token)
        username = profile.get("username") or "User"
    except BaseException:
        username = "User"
    with _lock:
        CACHE.username = username
        return CACHE.auth


# Shown when the access token is dead but a CLI command can refresh the
# keychain copy. `pv list` runs that refresh. A missing login is a different
# screen: the dashboard tells the user to run `pv login`.
SESSION_RECOVERY = "session"
SESSION_GUIDE = (
    "Your session has expired. Run pv list in the terminal to restore it, then click Retry. "
    "If you are logged out, run pv login instead."
)


def drop_auth() -> None:
    """Forget the in-memory tokens so the next request reads the keychain again."""
    with _lock:
        CACHE.auth = None
        CACHE.auth_loaded = False


def _is_session_failure(exc: BaseException) -> bool:
    if isinstance(exc, SystemExit) or type(exc).__name__ == "SessionExpiredError":
        return True
    text = f"{getattr(exc, 'message', '')} {getattr(exc, 'hint', '')} {exc}".lower()
    return "session" in text and ("expir" in text or "invalid" in text)


def describe_failure(exc: BaseException) -> tuple[str, str | None]:
    """Return the message to show, and 'session' when the user must use the CLI."""
    if _is_session_failure(exc):
        drop_auth()
        return SESSION_GUIDE, SESSION_RECOVERY
    text = (getattr(exc, "message", None) or str(exc)).strip() or "Request failed"
    hint = getattr(exc, "hint", None)
    if hint and hint not in text:
        text = f"{text} {hint}"
    return text, None


def _fresh(stamp: float, refresh: bool) -> bool:
    if refresh or not stamp:
        return False
    return (time.monotonic() - stamp) < LIST_TTL_SECONDS


def _rows(data) -> list:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        rows = data.get("entries")
        if isinstance(rows, list):
            return rows
    return []


def load_entries(refresh: bool = False) -> tuple[list | None, str | None]:
    with _lock:
        if _fresh(CACHE.entries_at, refresh):
            return CACHE.entries, CACHE.entries_error
        auth = dict(CACHE.auth or {})
    try:
        data = api_client.list_vault_entries(auth["access_token"], auth["refresh_token"])
    except (Exception, SystemExit) as exc:
        message, recovery = describe_failure(exc)
        with _lock:
            CACHE.entries = None
            CACHE.entries_error = message
            CACHE.entries_recovery = recovery
            CACHE.entries_at = time.monotonic()
        return None, message
    # Caller stores the stripped rows. The raw payload can carry ciphertext.
    return _rows(data), None


def load_api_keys(refresh: bool = False) -> tuple[list | None, str | None]:
    with _lock:
        if _fresh(CACHE.api_keys_at, refresh):
            return CACHE.api_keys, CACHE.api_keys_error
        auth = dict(CACHE.auth or {})
    try:
        data = api_client.list_api_key_entries(auth["access_token"], auth["refresh_token"])
    except (Exception, SystemExit) as exc:
        message, recovery = describe_failure(exc)
        with _lock:
            CACHE.api_keys = None
            CACHE.api_keys_error = message
            CACHE.api_keys_recovery = recovery
            CACHE.api_keys_at = time.monotonic()
        return None, message
    return _rows(data), None


def remember_entries(rows: list) -> None:
    with _lock:
        CACHE.entries = rows
        CACHE.entries_error = None
        CACHE.entries_recovery = None
        CACHE.entries_at = time.monotonic()


def remember_api_keys(rows: list) -> None:
    with _lock:
        CACHE.api_keys = rows
        CACHE.api_keys_error = None
        CACHE.api_keys_recovery = None
        CACHE.api_keys_at = time.monotonic()
