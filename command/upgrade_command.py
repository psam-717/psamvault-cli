import subprocess
import sys
import typer

from session import SESSION_DIR, set_last_seen_version
from spinner import Spinner
from update_check import (
    get_installed_version,
    fetch_latest_version,
    version_tuple,
    is_source_install,
    _get_git_root,
)
from upgrade_utils import git_repo_state, is_pipx_editable, snapshot_state, stash_and_pull

app = typer.Typer(name="upgrade", help="Upgrade psamvault to the latest version")


@app.callback(invoke_without_command=True)
def upgrade(ctx: typer.Context):
    """
    Upgrade psamvault to the latest version.

    - Source install (git clone): runs `git pull` in the repo directory.
    - PyPI install (pipx): runs `pipx upgrade psamvault`.

    Detects your install type automatically.

    \\b
    Example:
        psamvault upgrade
    """
    if ctx.invoked_subcommand is None:
        _run_update()


def _run_update() -> None:
    installed = get_installed_version()
    if not installed and not is_source_install():
        typer.echo(
            "  Could not detect installed version. Are you running from a source checkout?\n"
            "  Try:  pipx install -e .  or  pip install -e .",
            err=True,
        )
        raise typer.Exit(code=1)

    if is_source_install():
        _upgrade_source()
    else:
        _upgrade_pypi()


# ── Source track (git pull) ─────────────────────────────────────────────


def _upgrade_source() -> None:
    repo_root = _get_git_root()
    if not repo_root:
        typer.echo("  Error: could not locate git repository.\n", err=True)
        raise typer.Exit(code=1)

    with Spinner("Checking for updates"):
        try:
            # Fetch latest refs first
            subprocess.run(
                ["git", "fetch", "origin"],
                cwd=repo_root,
                capture_output=True,
                text=True,
                timeout=15,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            typer.echo(f"  Error: could not reach remote: {exc}\n", err=True)
            raise typer.Exit(code=1)

        state = git_repo_state(repo_root)

    if not state["ok"]:
        typer.echo("  Error: could not determine commit status (no origin/main?).\n", err=True)
        raise typer.Exit(code=1)

    if state["ahead"] > 0:
        typer.echo(
            f"  You have {state['ahead']} local commit(s) not on origin/main.\n"
            "  Upgrade keeps them but cannot fast-forward past them.\n"
            "  Resolve first, e.g.:  git pull --rebase origin main\n",
            err=True,
        )
        raise typer.Exit(code=1)

    if state["behind"] == 0:
        typer.echo(f"  psamvault is already up to date (v{get_installed_version() or '?'}).\n")
        return

    typer.echo(f"  You are {state['behind']} commit(s) behind main.\n")

    confirm = typer.confirm("  Proceed with upgrade?")
    if not confirm:
        typer.echo("  Cancelled.")
        raise typer.Exit()

    typer.echo("")
    typer.echo("  Saving a pre-update snapshot of your psamvault state...")
    backup = snapshot_state(source_dir=SESSION_DIR, backups_parent=SESSION_DIR / "backups")
    if backup:
        typer.echo(f"    → {backup.name}")

    result = stash_and_pull(repo_root)
    if not result["ok"]:
        typer.echo(f"\n  Error: upgrade failed — {result['message']}\n", err=True)
        raise typer.Exit(code=1)

    if result["stashed"] and result["conflict"]:
        typer.echo(f"\n  ⚠ {result['message']}\n")
    elif result["stashed"]:
        typer.echo("  Local changes stashed and restored.")

    typer.echo("\n  psamvault upgraded successfully.\n")

    # Re-install in case dependencies changed, then smoke-test the result.
    typer.echo("  Re-installing package...")
    inst = subprocess.run(
        [sys.executable, "-m", "pip", "install", "-e", "."],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )
    if inst.returncode != 0:
        typer.echo(
            "  Error: dependency install failed — the code was pulled but the\n"
            "  package may be inconsistent. Re-run  psamvault upgrade  to retry.",
            err=True,
        )
        raise typer.Exit(code=1)

    smoke = subprocess.run(
        [sys.executable, "-c", "import main"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    if smoke.returncode != 0:
        typer.echo(
            "  Error: the updated code failed to import.\n"
            "  Roll back with:  git reset --hard origin/main  &&  pip install -e .",
            err=True,
        )
        raise typer.Exit(code=1)

    typer.echo("  Done. Run  psamvault changelog  to see what's new.\n")


# ── PyPI track (pipx upgrade) ───────────────────────────────────────────


def _upgrade_pypi() -> None:
    installed = get_installed_version()
    if not installed:
        typer.echo(
            "  Could not detect installed version.\n",
            err=True,
        )
        raise typer.Exit(code=1)

    with Spinner("Checking for updates"):
        latest = fetch_latest_version()

    if not latest:
        typer.echo("  Could not reach PyPI to check for updates. Check your internet connection.\n", err=True)
        raise typer.Exit(code=1)

    if version_tuple(latest) <= version_tuple(installed):
        typer.echo(f"  psamvault is already up to date (v{installed}).\n")
        return

    typer.echo(f"  Update available: v{installed} → v{latest}\n")

    if is_pipx_editable("psamvault"):
        typer.echo(
            "  This psamvault install is editable/source-linked — pipx upgrade\n"
            "  would break that link or fail.\n"
            "  If you installed from a local checkout, run  psamvault upgrade  inside\n"
            "  that checkout (source track), or reinstall from PyPI first:\n"
            "    pipx reinstall psamvault\n",
            err=True,
        )
        raise typer.Exit(code=1)

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

    set_last_seen_version(latest)
    typer.echo(f"\n  psamvault upgraded to v{latest} successfully.\n")
    typer.echo("  Run  psamvault changelog  to see what's new.\n")
