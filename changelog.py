"""
Changelog for psamvault.

CHANGELOG maps version strings to a list of human-readable change entries.
Keep versions in descending order (newest first) so display loops are simple.
"""

import importlib.metadata
from typing import Optional

from session import get_last_seen_version, set_last_seen_version


CHANGELOG: dict[str, list[str]] = {
    "0.5.0": [
        "New:   psamvault dashboard — web dashboard for managing vault entries and API keys",
        "       Flask + Waitress on localhost:8500, CLI-only authentication, auto-login from session",
        "New:   Server-side sessions — VEK and tokens stored on filesystem, not in browser cookie",
        "New:   On-demand password reveal — passwords fetched via fetch(), never in HTML source",
        "Fixed: Plaintext passwords no longer embedded in HTML/JS page source",
        "Fixed: VEK no longer exposed in signed (unencrypted) Flask session cookie",
        "Fixed: XSS vectors in confirm() dialogs and flash message rendering",
        "Fixed: Dashboard auto-cleanup kills stale server processes on startup",
        "Changed: pv tui command hidden from --help (WIP, source files retained in repo)",
        "Changed: pv dashboard server uses Waitress (production-grade, no dev warning)",
    ],
    "0.4.3": [
        "New:   psamvault export — export all credentials to an encrypted backup file on Desktop",
        "New:   psamvault export --plaintext — export as readable JSON (with security warning)",
        "New:   psamvault import — restore credentials from encrypted or plaintext backup",
        "New:   psamvault uninstall — cleanly remove psamvault with full data backup",
        "New:   Auto-detect backup after login — prompts to import if a backup is found on Desktop",
        "New:   Backend endpoints — GET /vault/export/all, GET /apikeys/export/all, DELETE /auth/account",
        "Changed: Passphrase prompts now show visible input with example hint",
    ],
    "0.4.2": [
        "New:   Complete test suite — 4-layer coverage (crypto, CLI, API client, browser)",
        "New:   CI pipeline — GitHub Actions with pytest on Python 3.11/3.12/3.13",
        "New:   pv alias — 'pv' works as shorthand for every psamvault command",
        "New:   Browser CAPTCHA detection, auto-login URL discovery, multi-step form support",
        "Fixed: Clear error message when PSAMVAULT_PEPPER is missing or empty",
        "Fixed: Graceful failure on persistent 401 after token refresh",
        "Changed: Development status from Alpha to Beta",
    ],
    "0.4.1": [
        "New:   psamvault browser — shows command table when run with no subcommand",
        "New:   psamvault --help now lists all command groups with descriptions",
    ],
    "0.4.0": [
        "New:   psamvault open — browser autofill for vault entries via Playwright",
        "New:   --login-url flag on add/update to associate a URL with an entry",
        "New:   psamvault upgrade — upgrade psamvault in-place via pipx",
        "New:   psamvault changelog latest/all/show — richer changelog subcommands",
    ],
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


def get_latest_version() -> str | None:
    """Return the newest version key from CHANGELOG, or None if empty."""
    if not CHANGELOG:
        return None
    return max(CHANGELOG.keys(), key=version_tuple)


def format_version(v: str) -> str:
    """Return formatted changelog entries for a single version, or an error string."""
    entries = CHANGELOG.get(v)
    if not entries:
        return f"  Version {v} not found in changelog."
    lines = [f"\n  ── v{v} {'─' * (60 - len(v))}"]
    for entry in entries:
        lines.append(f"  {entry}")
    return "\n".join(lines)


def version_tuple(v: str) -> tuple[int, ...]:
    """Convert a version string like '0.3.0' into a comparable tuple of ints."""
    try:
        return tuple(int(x) for x in v.strip().split("."))
    except ValueError:
        return (0,)


_version_tuple = version_tuple  # backward compat for internal callers


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
            + "\n\n  Run  psamvault changelog all  to see the full history.\n",
            err=True,
        )
    except Exception:
        pass  # never let changelog logic break a command
