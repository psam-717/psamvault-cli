import subprocess
import sys
import typer

from session import set_last_seen_version
from spinner import Spinner
from update_check import get_installed_version, fetch_latest_version, version_tuple

app = typer.Typer(name="upgrade", help="Upgrade psamvault to the latest version")


@app.callback(invoke_without_command=True)
def upgrade(ctx: typer.Context):
    """
    Upgrade psamvault to the latest version available on PyPI.

    Uses pipx to perform the upgrade. If pipx is not available on your
    system, instructions will be shown.

    \b
    Example:
        psamvault upgrade
    """
    if ctx.invoked_subcommand is None:
        _run_update()


def _run_update() -> None:
    """Core update logic — check PyPI, then run pipx upgrade."""
    installed = get_installed_version()
    if not installed:
        typer.echo(
            "  Could not detect installed version. Are you running from a source checkout?\n"
            "  Try:  pipx install -e .  or  pip install -e .",
            err=True,
        )
        raise typer.Exit(code=1)

    # Step 1: check PyPI for latest version
    with Spinner("Checking for updates"):
        latest = fetch_latest_version()

    if not latest:
        typer.echo("  Could not reach PyPI to check for updates. Check your internet connection.\n", err=True)
        raise typer.Exit(code=1)

    if version_tuple(latest) <= version_tuple(installed):
        typer.echo(f"  psamvault is already up to date (v{installed}).\n")
        return

    typer.echo(f"  Update available: v{installed} → v{latest}\n")

    # Step 2: run pipx upgrade
    confirm = typer.confirm("  Proceed with upgrade?")
    if not confirm:
        typer.echo("  Cancelled.")
        raise typer.Exit()

    typer.echo("")

    try:
        result = subprocess.run(
            ["pipx", "upgrade", "psamvault"],
            capture_output=False,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        typer.echo(
            "  Error: pipx is not installed or not on your PATH.\n"
            "  To upgrade manually:\n"
            "    pip install --upgrade pipx\n"
            "    pipx upgrade psamvault\n",
            err=True,
        )
        raise typer.Exit(code=1)

    if result.returncode != 0:
        typer.echo(f"\n  Error: pipx upgrade failed (exit code {result.returncode}).\n", err=True)
        raise typer.Exit(code=1)

    # Upgrade succeeded — update last_seen_version so the startup notice
    # doesn't re-trigger until the NEXT upgrade.
    set_last_seen_version(latest)

    typer.echo(f"\n  psamvault upgraded to v{latest} successfully.\n")
    typer.echo("  Run  psamvault changelog  to see what's new.\n")