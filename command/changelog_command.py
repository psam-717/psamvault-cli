import typer

from changelog import CHANGELOG, format_changelog, format_version, get_latest_version, version_tuple

app = typer.Typer(name="changelog", help="View the psamvault changelog")


@app.callback(invoke_without_command=True)
def changelog(ctx: typer.Context):
    """
    Show the psamvault changelog for the latest version.

    Run  psamvault changelog all  to see the full history,
    or  psamvault changelog show <version>  for a specific version.

    \b
    Examples:
        psamvault changelog
        psamvault changelog latest
        psamvault changelog all
        psamvault changelog show 0.3.0
    """
    if ctx.invoked_subcommand is None:
        # Default: show latest version only
        latest = get_latest_version()
        if not latest:
            typer.echo("No changelog entries found.")
            return
        typer.echo("\n  psamvault — Changelog (latest)")
        typer.echo("  " + "=" * 62)
        typer.echo(format_version(latest))
        typer.echo()


@app.command(name="latest")
def changelog_latest():
    """
    Show only the latest version's changelog.

    \b
    Example:
        psamvault changelog latest
    """
    latest = get_latest_version()
    if not latest:
        typer.echo("No changelog entries found.")
        return
    typer.echo("\n  psamvault — Changelog (latest)")
    typer.echo("  " + "=" * 62)
    typer.echo(format_version(latest))
    typer.echo()


@app.command(name="all")
def changelog_all():
    """
    Show the full changelog for all versions.

    \b
    Example:
        psamvault changelog all
    """
    versions = sorted(CHANGELOG.keys(), key=version_tuple, reverse=True)
    if not versions:
        typer.echo("No changelog entries found.")
        return
    typer.echo("\n  psamvault — Changelog")
    typer.echo("  " + "=" * 62)
    typer.echo(format_changelog(versions))
    typer.echo()


@app.command(name="show")
def changelog_show(
    version: str = typer.Argument(..., help="Version to show, e.g. 0.3.0"),
):
    """
    Show the changelog for a specific version.

    \b
    Example:
        psamvault changelog show 0.3.0
    """
    entries = CHANGELOG.get(version)
    if not entries:
        typer.echo(f"  Version '{version}' not found in changelog.")
        raise typer.Exit(code=1)

    typer.echo(f"\n  psamvault — Changelog (v{version})")
    typer.echo("  " + "=" * 62)
    typer.echo(f"\n  ── v{version} {'─' * (60 - len(version))}")
    for entry in entries:
        typer.echo(f"  {entry}")
    typer.echo()