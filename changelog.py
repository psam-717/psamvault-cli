"""
Changelog for psamvault.

CHANGELOG maps version strings to a list of human-readable change entries.
Keep versions in descending order (newest first) so display loops are simple.
"""

import importlib.metadata
from typing import Optional

from session import get_last_seen_version, set_last_seen_version


CHANGELOG: dict[str, list[str]] = {
    "0.3.0": [
        "New:   psamvault changelog — view the full version history on demand",
        "New:   Auto-shows what changed on first run after pipx upgrade psamvault",
        "New:   scripts/release.py — one-command GitHub release from changelog.py",
    ],
    "0.2.3": [
        "Fixed: first-run 'Refresh token invalid' error in psamvault list, update, and ak-update",
        "       (caused by stale session tokens after token rotation mid-command)",
    ],
    "0.2.2": [
        "New:   psamvault site-list — list site credentials only",
        "New:   psamvault list now shows a combined view of sites + API keys",
    ],
    "0.2.1": [
        "New:   API key commands — ak-add, ak-get, ak-list, ak-update, ak-delete",
        "New:   psamvault migrate — upgrade account from legacy password format",
        "New:   Session and config secrets now stored in the OS keychain",
        "       (macOS Keychain, Windows Credential Manager, Linux Secret Service)",
        "New:   Background update checker — notifies you when a new version is available",
    ],
    "0.1.4": [
        "New:   psamvault --version / -V flag",
        "Fixed: Minor stability and packaging improvements",
    ],
}


def _version_tuple(v: str) -> tuple[int, ...]:
    try:
        return tuple(int(x) for x in v.strip().split("."))
    except ValueError:
        return (0,)


def _get_installed_version() -> Optional[str]:
    try:
        return importlib.metadata.version("psamvault")
    except importlib.metadata.PackageNotFoundError:
        return None


def format_changelog(versions: list[str]) -> str:
    """Return a formatted multi-line string for the given list of version keys."""
    lines = []
    for version in versions:
        entries = CHANGELOG.get(version, [])
        if not entries:
            continue
        lines.append(f"\n  ── v{version} {'─' * (60 - len(version))}")
        for entry in entries:
            lines.append(f"  {entry}")
    return "\n".join(lines)


def check_and_show_upgrade_notice() -> None:
    """
    Compare the installed version against the last-seen version stored in
    ~/.psamvault/last_seen_version. If the installed version is newer, print
    only the changelog entries for versions the user has not yet seen, then
    update the stored version. Silently does nothing on any error.
    """
    try:
        installed = _get_installed_version()
        if not installed:
            return

        last_seen = get_last_seen_version()

        # Always update the stored version so future runs stay in sync.
        set_last_seen_version(installed)

        if last_seen is None:
            # First ever run — don't flood with history, just record version.
            return

        if _version_tuple(installed) <= _version_tuple(last_seen):
            return

        # Collect versions newer than last_seen, sorted newest-first.
        new_versions = [
            v for v in CHANGELOG
            if _version_tuple(v) > _version_tuple(last_seen)
        ]
        new_versions.sort(key=_version_tuple, reverse=True)

        if not new_versions:
            return

        import typer
        typer.echo(
            f"\n  🎉 psamvault updated {last_seen} → {installed}  What's new:\n"
            + format_changelog(new_versions)
            + "\n\n  Run  psamvault changelog  to see the full history.\n",
            err=True,
        )
    except Exception:
        pass  # never let changelog logic break a command
