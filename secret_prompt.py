"""Secret prompts: hidden by default, visible on request, never a silent block.

One place decides how a secret is read, so every prompt that hides its input
behaves the same way:

* hidden by default — ``hide_input=True``, exactly as before;
* visible when ``PSAMVAULT_SHOW_SECRETS`` is set to a truthy value, so a typo can
  be seen (a leading or trailing space is a *different* password, and it is never
  stripped or normalised);
* and when there is no console to read from, fail on the spot with a non-zero
  exit instead of blocking for ever printing nothing. A hidden prompt reads the
  controlling terminal, which a pipe, a redirect, a background job or a CI runner
  does not provide — those callers used to hang silently.

``export`` and ``import`` passphrases are already visible and stay that way: they
are chosen by the same person who types them, in front of the screen.
"""

import os
import sys

import typer

SHOW_SECRETS_ENV = "PSAMVAULT_SHOW_SECRETS"
_TRUTHY = {"1", "true", "yes", "on"}

NO_CONSOLE_MESSAGE = (
    "  ✗ This prompt has no terminal to read the answer from, so it cannot be answered.\n"
    "  → Run this command in a terminal, or set PSAMVAULT_SHOW_SECRETS=1 to type the\n"
    "     value in the open.\n"
)


def show_secrets() -> bool:
    """True when PSAMVAULT_SHOW_SECRETS asks for secret input to be visible."""
    return os.environ.get(SHOW_SECRETS_ENV, "").strip().lower() in _TRUTHY


def has_console() -> bool:
    """True when a hidden prompt can actually read an answer here.

    A terminal is the normal case. The other honest case is a caller that supplied
    its own stdin — ``typer.testing.CliRunner`` and the in-process harnesses do
    exactly that, and ``getpass`` reads that stream. What this reports as
    unavailable is the case that used to hang: the process's own stdin is a pipe,
    a redirect or an empty handle, so ``getpass`` goes looking for a console
    keystroke that is never coming (printing nothing while it waits).
    """
    stream = sys.stdin
    if stream is None:
        return False
    try:
        if stream.isatty():
            return True
    except (AttributeError, ValueError):
        return False
    return stream is not getattr(sys, "__stdin__", None)


def secret_prompt(text: str, *, default=None):
    """Read a secret, hidden unless PSAMVAULT_SHOW_SECRETS says otherwise."""
    if show_secrets():
        return typer.prompt(text, hide_input=False, default=default)
    if not has_console():
        typer.echo(NO_CONSOLE_MESSAGE, err=True)
        raise typer.Exit(code=1)
    return typer.prompt(text, hide_input=True, default=default)
