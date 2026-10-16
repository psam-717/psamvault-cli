"""OS keychain access that fails closed.

The pepper and the session tokens live in the OS keychain. A missing or
locked keychain is an error: this module never writes those secrets to a
file, and it never swaps in a plaintext or null store.

``--version`` and ``--help`` must not call into here. Importing the CLI
loads the non-secret ``config.env`` only. The first command that actually
needs a secret is what reaches ``call``.

A locked Secret Service collection is reported immediately. keyring's
Secret Service backend calls ``collection.unlock()``, and that call blocks
on a GUI prompter for as long as ``DISPLAY`` is set — including an SSH
session that forwarded a display and will never answer the dialog. Reading
the ``Locked`` property does not prompt, so a locked collection becomes the
same one-line error as a keyring that raises ``KeyringLocked``.

A Secret Service with no default collection is the same kind of failure.
keyring's ``get_default_collection`` calls ``create_collection`` in that
case, and creating one blocks in ``exec_prompt`` (``gcr-prompter``) whether
or not ``DISPLAY`` is set. The probe only looks up the default alias. It
does not create a collection and it does not unlock one.
"""

from __future__ import annotations

import enum
import threading
from typing import Any, Callable, NoReturn

import keyring
import keyring.errors
import typer

_MISSING = (
    "No OS keychain is available — on Linux install gnome-keyring, dbus-user-session "
    "and libsecret-tools, start a D-Bus session and unlock the keyring; "
    "on macOS or Windows unlock the login keychain (see the installation guide)"
)
_LOCKED = (
    "The OS keychain is locked — unlock it and run this command again "
    "(on Linux: echo -n '<password>' | gnome-keyring-daemon --unlock --components=secrets; "
    "see the installation guide)"
)
_UNUSABLE = (
    "The OS keychain could not be opened — unlock it or start a Secret Service, then retry "
    "(see the installation guide)"
)
_NO_DEFAULT = (
    "The OS keychain has no default collection — create and unlock a login keyring, "
    "then run this command again "
    "(on Linux: echo -n '<password>' | gnome-keyring-daemon --unlock --components=secrets; "
    "see the installation guide)"
)
NOT_KEPT = (
    "The OS keychain did not keep the pepper — use the system keychain "
    "(Linux Secret Service, macOS Keychain, or Windows Credential Manager) "
    "and run the command again. The pepper is never written to config.env"
)


def message_for(exc: BaseException) -> str:
    """One line: what failed, then what to do. No traceback, no secret."""
    if isinstance(exc, keyring.errors.KeyringLocked):
        return _LOCKED
    if isinstance(exc, keyring.errors.NoKeyringError):
        return _MISSING
    return _UNUSABLE


def _verbose() -> bool:
    try:
        import error_ui
    except Exception:
        return False
    return bool(getattr(error_ui, "_verbose_enabled", False))


def abort(message: str, *, exc: BaseException | None = None) -> NoReturn:
    """Print ``✗ <what failed> — <what to do next>`` and exit 1."""
    typer.echo(f"\n✗ {message}", err=True)
    if exc is not None and _verbose():
        typer.echo(f"   [{type(exc).__name__}] {exc}", err=True)
    raise KeychainUnavailable(message)


class KeychainUnavailable(typer.Exit):
    """Keychain failure that exits the CLI and stays catchable in the dashboard.

    A bare ``typer.Exit`` from inside ``session`` or ``config`` is an
    ``Exception``. Flask turns an unhandled one into an HTML 500. This
    subclass still exits the CLI (it is a ``typer.Exit``) and carries the
    same sentence so a request handler can return it as JSON.
    """

    def __init__(self, message: str) -> None:
        super().__init__(code=1)
        self.message = message
        self.args = (message,)


# One Secret Service connection for the probe. ``load_session`` reads six
# secrets, and opening a D-Bus connection per read is the expensive part.
# The alias and the Locked property are still read on every call, so a
# collection that locks later is still noticed. The connection is only used
# while ``_probe_lock`` is held; jeepney's blocking connection is not safe
# to share across threads without that.
_probe_lock = threading.Lock()
_dbus_connection: Any | None = None


class _Probe(enum.Enum):
    """What the Secret Service probe found. ``READY`` means the real call may run."""

    READY = "ready"
    LOCKED = "locked"
    NO_DEFAULT = "no_default"


def _secret_service_selected() -> bool:
    try:
        backend = keyring.get_keyring()
    except Exception:
        return False
    qualname = f"{type(backend).__module__}.{type(backend).__name__}"
    return "SecretService" in qualname


def _close_connection(connection: Any) -> None:
    close = getattr(connection, "close", None)
    if close is None:
        return
    try:
        close()
    except Exception:
        pass


def reset_probe_cache() -> None:
    """Drop the cached Secret Service connection. Tests call this between cases."""
    global _dbus_connection
    with _probe_lock:
        connection = _dbus_connection
        _dbus_connection = None
    _close_connection(connection)


def _drop_dbus_connection() -> None:
    """Caller holds ``_probe_lock``."""
    global _dbus_connection
    connection = _dbus_connection
    _dbus_connection = None
    _close_connection(connection)


def _inspect_collection(connection: Any) -> _Probe:
    import secretstorage
    from secretstorage.exceptions import ItemNotFoundException, LockedException

    try:
        collection = secretstorage.Collection(connection)
    except ItemNotFoundException:
        # The default alias does not resolve. keyring's next step is
        # create_collection(), which blocks on a GUI prompt.
        return _Probe.NO_DEFAULT
    except LockedException:
        return _Probe.LOCKED
    try:
        if collection.is_locked():
            return _Probe.LOCKED
    except LockedException:
        return _Probe.LOCKED
    return _Probe.READY


def _probe_secret_service() -> _Probe:
    """Look at the Secret Service default alias without creating or unlocking it.

    ``READY`` for any other backend, or when Secret Service cannot be asked,
    so the real keyring call can raise its own error. ``NO_DEFAULT`` is not
    that case: the alias lookup succeeded and the alias is missing, and the
    real call would block inside ``create_collection``.

    The D-Bus connection is reused. A failed connection is dropped and opened
    once more; a second failure returns ``READY`` so the keyring call can
    raise its own error instead of this probe hiding it.
    """
    if not _secret_service_selected():
        return _Probe.READY
    try:
        import secretstorage
        from secretstorage.exceptions import SecretStorageException
    except ImportError:
        return _Probe.READY

    global _dbus_connection
    with _probe_lock:
        for _attempt in range(2):
            try:
                if _dbus_connection is None:
                    _dbus_connection = secretstorage.dbus_init()
                return _inspect_collection(_dbus_connection)
            except SecretStorageException:
                _drop_dbus_connection()
            except Exception:
                _drop_dbus_connection()
        return _Probe.READY


def _probe_secret_service_locked() -> bool:
    """True when the selected backend is Secret Service and its default collection is locked."""
    return _probe_secret_service() is _Probe.LOCKED


def call(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    """Run one keyring operation.

    ``PasswordDeleteError`` propagates so callers can ignore a missing row.
    Every other ``KeyringError`` becomes the one-line error and exits.
    A locked Secret Service collection, and a Secret Service with no default
    collection, exit the same way before ``fn`` runs, so ``unlock()`` and
    ``create_collection()`` never get a chance to wait on a prompter.
    """
    state = _probe_secret_service()
    if state is _Probe.LOCKED:
        abort(message_for(keyring.errors.KeyringLocked("Failed to unlock the collection!")))
    if state is _Probe.NO_DEFAULT:
        abort(_NO_DEFAULT)
    try:
        return fn(*args, **kwargs)
    except keyring.errors.PasswordDeleteError:
        raise
    except keyring.errors.KeyringError as exc:
        abort(message_for(exc), exc=exc)
