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
from upgrade_utils import (
    InstallInfo,
    git_repo_state,
    in_place_upgrade_argv,
    install_info,
    manager_version,
    recreate_install_command,
    running_from_venv,
    snapshot_state,
    stash_and_pull,
)

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


# ── PyPI track (pipx / uv tool, in place) ───────────────────────────────────


def _run_tool(argv: list[str]):
    """Run an upgrade command, returning None when the tool is not installed."""
    try:
        return subprocess.run(list(argv), check=False)
    except FileNotFoundError:
        return None


def _recreate_or_explain(latest: str, info: InstallInfo, *, reason: str) -> None:
    """Rebuild the environment from the registry — or hand the command over.

    Rebuilding deletes and recreates the environment, so it can only run from
    OUTSIDE it: from inside, pipx cannot replace the running interpreter and uv
    removes the environment before failing, which leaves psamvault unimportable.
    """
    command = recreate_install_command(info.manager, latest)
    if info.venv_dir is None or running_from_venv(info.venv_dir):
        typer.echo(
            f"\n  Error: {reason},\n"
            "  and the reinstall that would fix it cannot run from here: it rebuilds\n"
            "  the environment psamvault is running from.\n"
            "  Run this once, after this command exits:\n"
            f"    {command}\n",
            err=True,
        )
        raise typer.Exit(code=1)

    typer.echo(f"\n  Retrying with a reinstall:  {command}")
    result = _run_tool(command.split())
    if result is None or result.returncode != 0:
        how = "the tool is not available" if result is None else f"exit code {result.returncode}"
        typer.echo(
            f"\n  Error: the reinstall failed ({how}).\n"
            f"  Retry manually:  {command}\n",
            err=True,
        )
        raise typer.Exit(code=1)


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

    # ONE probe of the owning tool: the same answer drives the editable refusal,
    # the upgrade command, the read-back and the environment guard.
    info = install_info("psamvault")

    if info.editable:
        typer.echo(
            "  This psamvault install is editable/source-linked — pipx upgrade\n"
            "  would break that link or fail.\n"
            "  If you installed from a local checkout, run  psamvault upgrade  inside\n"
            "  that checkout (source track), or reinstall from PyPI first:\n"
            "    pipx reinstall psamvault\n",
            err=True,
        )
        raise typer.Exit(code=1)

    if not info.known:
        typer.echo(
            "  Error: psamvault was not installed by pipx or by uv tool, so this\n"
            "  command cannot upgrade it. Upgrade it with the tool that did, e.g.:\n"
            "    pip install --upgrade psamvault\n",
            err=True,
        )
        raise typer.Exit(code=1)

    confirm = typer.confirm("  Proceed with upgrade?")
    if not confirm:
        typer.echo("  Cancelled.")
        raise typer.Exit()

    argv = in_place_upgrade_argv(info.manager)
    typer.echo("")
    # Upgrade IN PLACE, never by recreating the environment: this process runs
    # from it, and a rebuild would have to replace the interpreter it is using.
    typer.echo(f"  Upgrading in place ({' '.join(argv)})...")

    result = _run_tool(argv)

    if result is None:
        typer.echo(
            f"  Error: {info.manager} is not installed or not on your PATH.\n"
            "  To upgrade manually:\n"
            f"    {recreate_install_command(info.manager, latest)}\n",
            err=True,
        )
        raise typer.Exit(code=1)

    if result.returncode != 0:
        _recreate_or_explain(
            latest, info, reason=f"{info.manager} upgrade failed (exit code {result.returncode})"
        )

    landed = manager_version(info.manager)
    if not landed or version_tuple(landed) < version_tuple(latest):
        detail = (
            f" (recorded source: {info.source})" if info.source not in ("", "psamvault") else ""
        )
        _recreate_or_explain(
            latest,
            info,
            reason=(
                f"{info.manager} still reports v{landed or 'unknown'} after the in-place "
                f"upgrade{detail}"
            ),
        )

    set_last_seen_version(latest)
    typer.echo(f"\n  psamvault upgraded to v{latest} successfully.\n")
    typer.echo("  Run  psamvault changelog  to see what's new.\n")
