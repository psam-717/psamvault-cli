"""
Background update checker for psamvault.
 
Fetches the latest version from PyPI in a background thread so it never
blocks command execution. The result is printed as a notice after the
command completes.
"""

import importlib.metadata
import threading
from typing import Optional

import httpx


PYPI_URL = "https://pypi.org/pypi/psamvault/json"
_UPDATE_NOTICE: Optional[str] = None

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
        return None # silently ignore network error, timeouts, etc


_fetch_latest_version = fetch_latest_version  # backward compat


def version_tuple(v: str) -> tuple[int, ...]:
    """Convert a version string like '1.2.3' into a comparable tuple"""
    try:
        return tuple(int(x) for x in v.strip().split("."))
    except ValueError:
        return (0,)


_version_tuple = version_tuple  # backward compat
    

def _check(installed: str) -> None:
    """Run in a background thread - sets _UPDATE_NOTICE if an update exists"""
    global _UPDATE_NOTICE 
    latest = _fetch_latest_version()
    if latest and _version_tuple(latest) > _version_tuple(installed):
        _UPDATE_NOTICE = (
            f"\n  💡 Update available: {installed} → {latest}\n"
            f"     Run  pipx upgrade psamvault  to update.\n"
        )
        
        
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
        return # cannot compare without a known version
    
    _checker_thread = threading.Thread(
        target=_check, args=(installed,), daemon=True
    )
    _checker_thread.start()
    
    
    
def print_update_notice() -> None:
    """
    Wait for the background check to finish, then print any update notice.
    Call this at the very end of the CLI lifecycle via a typer atexit hook.
    Blocks for at most ~3 s (the httpx timeout), but usually much less.
    """
    if _checker_thread is not None:
        _checker_thread.join(timeout=4)
        
    if _UPDATE_NOTICE:
        import typer
        typer.echo(_UPDATE_NOTICE, err= True)
    