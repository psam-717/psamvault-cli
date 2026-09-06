"""
CLI rendering for typed psamvault errors.

Single print site for errors (the command layer). api_client raises typed
exceptions WITHOUT echoing; commands catch and call :func:`print_error` so the
user sees exactly one clean message:

    ✗ <message>
       • <detail>        (ValidationError only)
    → <hint>
"""
import typer

from errors import PsamVaultError


def print_error(exc: PsamVaultError, verbose: bool = False) -> None:
    """Render a PsamVaultError to stderr and exit non-zero."""
    message = getattr(exc, "message", None) or str(exc)
    typer.echo(f"\n ✗ {message}", err=True)

    details = getattr(exc, "details", None)
    if details:
        for d in details:
            typer.echo(f"   • {d}", err=True)

    hint = getattr(exc, "hint", None)
    if hint:
        typer.echo(f" → {hint}", err=True)

    if verbose:
        typer.echo(f"   [{type(exc).__name__}] {exc!r}", err=True)


def exit_error(exc: PsamVaultError, verbose: bool = False) -> None:
    """Render a typed error and raise typer.Exit(1)."""
    print_error(exc, verbose=verbose)
    raise typer.Exit(code=1)
