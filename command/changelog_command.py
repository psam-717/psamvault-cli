import typer

from changelog import CHANGELOG, format_changelog, _version_tuple

app = typer.Typer(name="changelog", help="Changelog commands")


def changelog():
    """
    Show the full psamvault changelog.

    Displays all versions from newest to oldest with their change notes.

    \b
    Example:
        psamvault changelog
    """
    versions = sorted(CHANGELOG.keys(), key=_version_tuple, reverse=True)

    if not versions:
        typer.echo("No changelog entries found.")
        return

    typer.echo("\n  psamvault — Changelog")
    typer.echo("  " + "═" * 62)
    typer.echo(format_changelog(versions))
    typer.echo()
