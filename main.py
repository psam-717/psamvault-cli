from config import load_config
load_config()
import importlib.metadata
from typing import Annotated, Optional
import typer

from command.auth_commands import app as auth_app
from command.vault_commands import app as vault_app
from command.recovery_commands import app as recovery_app
from command.api_key_commands import app as apikey_app
from command.browser_commands import app as browser_app
from command.changelog_command import app as changelog_app
from command.upgrade_command import app as update_app
from command.uninstall_command import app as uninstall_app
from command.import_command import app as import_app
from command.export_command import app as export_app

from update_check import start_update_check, print_update_notice
from changelog import check_and_show_upgrade_notice



app = typer.Typer(
    name="psamvault",
    help=(
        "psamvault — a secure password vault for the terminal.\n\n"
        "Your credentials are encrypted locally before being sent to the server.\n"
        "The server never sees your plaintext passwords.\n\n"
        "Grouped commands — run any of these to see what's inside:\n\n"
        "  psamvault auth       — account commands (signup, login, logout, whoami)\n"
        "  psamvault vault      — credential commands (add, get, update, delete, list)\n"
        "  psamvault ak         — API key commands (ak-add, ak-get, ak-list, ...)\n"
        "  psamvault recovery   — account recovery (generate-codes, recover)\n"
        "  psamvault browser    — browser autofill (open)\n"
        "  psamvault changelog  — view version history\n"
        "  psamvault upgrade    — upgrade psamvault in-place\n\n"
        "Or use the short forms directly — psamvault login, psamvault add, psamvault open, etc."
    ),
    no_args_is_help=True,
    result_callback= lambda result, **kwargs: print_update_notice() # runs after every command
)


def _version_callback(value: bool) -> None:
    if value:
        try:
            version = importlib.metadata.version("psamvault")
        except importlib.metadata.PackageNotFoundError:
            import tomllib
            from pathlib import Path
            pyproject = Path(__file__).parent / "pyproject.toml"
            if pyproject.exists():
                with open(pyproject, "rb") as f:
                    version = tomllib.load(f)["project"]["version"]
            else:
                version = "unknown"
        typer.echo(f"psamvault {version}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        Optional[bool],
        typer.Option("--version", "-V", help="Show version and exit", callback=_version_callback),
    ] = None,
) -> None:
    """psamvault — a secure password vault for the terminal."""
    pass


# ── Include sub-command groups ──────────────────────────────────────────
app.add_typer(auth_app, name="auth", help="Account commands (signup, login, logout, whoami)")
app.add_typer(vault_app, name="vault", help="Credential commands (add, get, update, delete, list)")
app.add_typer(recovery_app, name="recovery", help="Account recovery (generate-codes, recover)")
app.add_typer(apikey_app, name="ak", help="API key commands (ak-add, ak-get, ak-list, ak-update, ak-delete)")
app.add_typer(browser_app, name="browser", help="Browser autofill (open)")
app.add_typer(changelog_app, name="changelog", help="View version history")
app.add_typer(update_app, name="upgrade", help="Upgrade psamvault in-place")
app.add_typer(uninstall_app, name="uninstall", help="Uninstall psamvault")
app.add_typer(import_app, name="import", help="Import entries from other password managers")
app.add_typer(export_app, name="export", help="Export vault entries to a JSON file")

# ── TUI — source kept in repo, command hidden from --help ──────────────
# from tui.app import run_tui

# @app.command(hidden=True)
# def tui() -> None:
#     """Launch the terminal UI (experimental)."""
#     run_tui()


@app.command()
def dashboard() -> None:
    """Launch the web dashboard for psamvault (fresh — kills stale servers & clears cache)."""
    import subprocess
    import shutil
    from pathlib import Path

    # ── Kill any stale process on port 8500 ────────────────────────────
    typer.echo("  Cleaning up stale dashboard processes...")
    try:
        result = subprocess.run(
            ["netstat", "-ano"], capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.splitlines():
            if ":8500" in line and "LISTENING" in line:
                parts = line.strip().split()
                pid = parts[-1]
                subprocess.run(
                    ["taskkill", "/F", "/PID", pid],
                    capture_output=True, text=True, timeout=5,
                )
                typer.echo(f"  Killed stale process PID {pid}")
    except Exception:
        pass  # best-effort cleanup

    # ── Clear Python bytecode cache for dashboard ──────────────────────
    dashboard_dir = Path(__file__).parent / "dashboard"
    for pycache in dashboard_dir.rglob("__pycache__"):
        shutil.rmtree(pycache, ignore_errors=True)

    # ── Start fresh ────────────────────────────────────────────────────
    from dashboard import create_app
    import webbrowser

    app = create_app()
    port = 8500
    url = f"http://localhost:{port}"

    typer.echo(f" \n  psamvault dashboard starting...")
    typer.echo(f"  → {url}")
    typer.echo(f"  Press Ctrl+C to stop.\n")

    try:
        if not webbrowser.open(url):
            raise RuntimeError("webbrowser.open returned False")
    except Exception:
        typer.echo(f"  ⚠ Could not open browser automatically.")
        typer.echo(f"  → Open {url} manually in your browser.\n")

    from waitress import serve
    serve(app, host="127.0.0.1", port=port)

from command.auth_commands import login, logout, signup, whoami, config_show, configure, migrate
from command.vault_commands import add, delete, generate, get, list_entries, site_list, update
from command.recovery_commands import generate_codes, remaining_codes, recover
from command.api_key_commands import ak_add, ak_get, ak_delete, ak_list, ak_update
from command.browser_commands import open_site

app.command("migrate")(migrate)
app.command("configure")(configure)
app.command("config-show")(config_show)
app.command("signup")(signup)
app.command("login")(login)
app.command("logout")(logout)
app.command("whoami")(whoami)
app.command("add")(add)
app.command("delete")(delete)
app.command("generate")(generate)
app.command("get")(get)
app.command("list")(list_entries)
app.command("site-list")(site_list)
app.command("update")(update)
app.command("ak-list")(ak_list)
app.command("ak-add")(ak_add)
app.command("ak-get")(ak_get)
app.command("ak-delete")(ak_delete)
app.command("ak-update")(ak_update)
app.command("open")(open_site)
app.command("generate-codes")(generate_codes)
app.command("remaining-codes")(remaining_codes)
app.command("recover")(recover)

if __name__ == "__main__":
    start_update_check()
    check_and_show_upgrade_notice()
    app()