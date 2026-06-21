"""
Background update checker for psamvault.

Detects install type (source vs PyPI) and creates an appropriate update
notice. Runs in a background thread so it never blocks command execution.
"""

import importlib.metadata
import os
import pathlib
import subprocess
import threading
from typing import Optional

import httpx


PYPI_URL = "https://pypi.org/pypi/psamvault/json"
GITHUB_REPO = "psam-717/psamvault-cli"
_UPDATE_NOTICE: Optional[str] = None


# ── Install type detection ──────────────────────────────────────────────


def _package_path() -> Optional[pathlib.Path]:
    """Return the filesystem path to the installed psamvault package."""
    try:
        dist = importlib.metadata.distribution("psamvault")
        # The distribution's `_path` points to the .dist-info directory;
        # the actual package lives alongside it.
        if dist._path:
            return dist._path.parent
    except importlib.metadata.PackageNotFoundError:
        pass
    return None


def _find_git_root(start: pathlib.Path) -> Optional[pathlib.Path]:
    """Walk up from `start` looking for a .git directory."""
    for parent in [start, *start.parents]:
        if (parent / ".git").is_dir():
            return parent
    return None


def is_source_install() -> bool:
    """Detect whether psamvault is installed from a git clone (source) or PyPI."""
    pkg_path = _package_path()
    if pkg_path is None:
        return False
    return _find_git_root(pkg_path) is not None


def _get_git_root() -> Optional[pathlib.Path]:
    """Return the git repo root if this is a source install."""
    pkg_path = _package_path()
    if pkg_path is None:
        return None
    return _find_git_root(pkg_path)


# ── Version helpers (PyPI track) ────────────────────────────────────────


def get_installed_version() -> Optional[str]:
    try:
        return importlib.metadata.version("psamvault")
    except importlib.metadata.PackageNotFoundError:
        return None


_get_installed_version = get_installed_version  # backward compat


def fetch_latest_version() -> Optional[str]:
    try:
        response = httpx.get(PYPI_URL, timeout=3)
        response.raise_for_status()
        return response.json()["info"]["version"]
    except Exception:
        return None


_fetch_latest_version = fetch_latest_version  # backward compat


def version_tuple(v: str) -> tuple[int, ...]:
    """Convert a version string like '1.2.3' into a comparable tuple"""
    try:
        return tuple(int(x) for x in v.strip().split("."))
    except ValueError:
        return (0,)


_version_tuple = version_tuple  # backward compat


# ── Commit counting (source track) ──────────────────────────────────────


def _count_commits_behind(repo_root: pathlib.Path) -> Optional[int]:
    """Count commits between HEAD and origin/main in the given repo."""
    try:
        result = subprocess.run(
            ["git", "rev-list", "--count", "HEAD..origin/main"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            count = result.stdout.strip()
            return int(count) if count else 0
    except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
        pass
    return None


def _commit_update_notice(commits_behind: int) -> str:
    """Build the update notice for source installs."""
    if commits_behind <= 0:
        return ""
    s = "s" if commits_behind != 1 else ""
    return (
        f"\n  💡 You are {commits_behind} commit{s} behind the main branch.\n"
        f"     Run  psamvault upgrade  to update.\n"
    )


def _version_update_notice(installed: str, latest: str) -> str:
    """Build the update notice for PyPI installs."""
    return (
        f"\n  💡 Update available: {installed} → {latest}\n"
        f"     Run  psamvault upgrade  to update.\n"
    )


# ── Background check ────────────────────────────────────────────────────


def _check(installed: str) -> None:
    """Run in a background thread - sets _UPDATE_NOTICE if an update exists."""
    global _UPDATE_NOTICE

    if is_source_install():
        repo_root = _get_git_root()
        if repo_root:
            behind = _count_commits_behind(repo_root)
            if behind is not None and behind > 0:
                _UPDATE_NOTICE = _commit_update_notice(behind)
        return

    # PyPI track: compare version
    latest = fetch_latest_version()
    if latest and version_tuple(latest) > version_tuple(installed):
        _UPDATE_NOTICE = _version_update_notice(installed, latest)


# The thread handle - kept so we can join() it before printing
_checker_thread: Optional[threading.Thread] = None


def start_update_check() -> None:
    """
    Spawn a background thread to check for updates.
    Call this early in the CLI lifecycle (e.g. in the main callback).
    """
    global _checker_thread

    installed = _get_installed_version()
    if not installed:
        return

    _checker_thread = threading.Thread(
        target=_check, args=(installed,), daemon=True
    )
    _checker_thread.start()


def print_update_notice() -> None:
    """
    Wait for the background check to finish, then print any update notice.
    Call this at the very end of the CLI lifecycle via a typer atexit hook.
    Blocks for at most ~5 s, but usually much less.
    """
    if _checker_thread is not None:
        _checker_thread.join(timeout=5)

    if _UPDATE_NOTICE:
        import typer
        typer.echo(_UPDATE_NOTICE, err=True)
