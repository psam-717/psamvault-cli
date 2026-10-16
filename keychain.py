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
"""

from __future__ import annotations

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
    raise typer.Exit(code=1)


def _probe_secret_service_locked() -> bool:
    """True when the selected backend is Secret Service and its default collection is locked.

    Does not create a collection and does not call ``unlock`` — both of those
    can block on a prompt. Any other backend, or a Secret Service we cannot
    ask, returns False so the real keyring call can raise its own error.
    """
    try:
        backend = keyring.get_keyring()
    except Exception:
        return False
    qualname = f"{type(backend).__module__}.{type(backend).__name__}"
    if "SecretService" not in qualname:
        return False
    try:
        import secretstorage
        from secretstorage.exceptions import (
            ItemNotFoundException,
            LockedException,
            SecretStorageException,
        )
    except ImportError:
        return False

    connection = None
    try:
        connection = secretstorage.dbus_init()
        try:
            collection = secretstorage.Collection(connection)
        except ItemNotFoundException:
            # No default collection yet. Creating one prompts, so leave that
            # to the keyring call. This probe must not create anything.
            return False
        except LockedException:
            return True
        try:
            return bool(collection.is_locked())
        except LockedException:
            return True
    except SecretStorageException:
        return False
    except Exception:
        return False
    finally:
        close = getattr(connection, "close", None)
        if close is not None:
            try:
                close()
            except Exception:
                pass


def call(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    """Run one keyring operation.

    ``PasswordDeleteError`` propagates so callers can ignore a missing row.
    Every other ``KeyringError`` becomes the one-line error and exits.
    A locked Secret Service collection exits the same way, before ``fn``
    runs, so ``unlock()`` never gets a chance to wait on a prompter.
    """
    if _probe_secret_service_locked():
        abort(message_for(keyring.errors.KeyringLocked("Failed to unlock the collection!")))
    try:
        return fn(*args, **kwargs)
    except keyring.errors.PasswordDeleteError:
        raise
    except keyring.errors.KeyringError as exc:
        abort(message_for(exc), exc=exc)
