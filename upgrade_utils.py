"""
Upgrade safety helpers for psamvault.

Hermes-style upgrade behaviour for source installs:
1. Snapshot ~/.psamvault state before touching anything.
2. Detect dirty tree / ahead / behind.
3. Auto-stash local changes -> pull -> auto-restore. If the restore
   conflicts, the stash is left parked with instructions — user work is
   never clobbered. If the pull itself fails, local changes are restored
   before returning.
"""
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

BACKUP_DIR_NAME = "backups"
STASH_PREFIX = "psamvault-upgrade-autostash"

# Files in the psamvault state dir worth snapshotting (keyring holds secrets).
_STATE_FILES = ("session.json", "last_seen_version")

KEEP_SNAPSHOTS = 5


def _git(repo_root: Path, *args: str, timeout: int = 60) -> subprocess.CompletedProcess:
    """Run git in repo_root, capturing output."""
    return subprocess.run(
        ["git", *args],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _utc_stamp() -> str:
    # Microseconds so back-to-back snapshots get unique, sortable names.
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S-%f")


def _next_snapshot_dir(backups_parent: Path) -> Path:
    """A snapshot directory that cannot collide with an existing one.

    The stamp is microsecond-precise, but Windows' clock granularity is ~15 ms, so
    back-to-back snapshots (or a retried upgrade) can be handed the same value and
    would otherwise merge into one directory, silently losing a snapshot. A counter
    suffix keeps every snapshot separate; the stamp still sorts first, so pruning
    order is unchanged.
    """
    stamp = _utc_stamp()
    candidate = backups_parent / f"backup-{stamp}"
    suffix = 0
    while candidate.exists():
        suffix += 1
        candidate = backups_parent / f"backup-{stamp}-{suffix}"
    return candidate


# ── Pre-update snapshot ─────────────────────────────────────────────────────


def snapshot_state(source_dir: Path, backups_parent: Path, keep: int = KEEP_SNAPSHOTS) -> "Path | None":
    """Copy psamvault state files into a timestamped backup dir.

    Returns the backup path, or None when there is nothing to snapshot.
    Prunes old backups so at most ``keep`` remain.
    """
    existing = [f for f in _STATE_FILES if (source_dir / f).is_file()]
    if not existing:
        return None

    backups_parent.mkdir(parents=True, exist_ok=True)
    backup = _next_snapshot_dir(backups_parent)
    backup.mkdir(parents=True, exist_ok=True)
    for name in existing:
        shutil.copy2(source_dir / name, backup / name)

    # Prune oldest (timestamped names sort lexicographically).
    all_backups = sorted(backups_parent.glob("backup-*"))
    for old in all_backups[:-keep]:
        shutil.rmtree(old, ignore_errors=True)
    return backup


# ── Git state detection ─────────────────────────────────────────────────────


def git_repo_state(repo_root: Path) -> dict:
    """Return dirty/ahead/behind for a repo relative to origin/main.

    Returns dict keys: dirty (bool), ahead (int), behind (int),
    ok (bool — False when origin/main is unreachable/absent).
    """
    status = _git(repo_root, "status", "--porcelain")
    dirty = bool(status.stdout.strip())

    def _count(rev_range: str) -> int:
        r = _git(repo_root, "rev-list", "--count", rev_range)
        if r.returncode != 0:
            return None
        try:
            return int(r.stdout.strip() or "0")
        except ValueError:
            return None

    behind = _count("HEAD..origin/main")
    ahead = _count("origin/main..HEAD")
    return {
        "dirty": dirty,
        "ahead": ahead if ahead is not None else 0,
        "behind": behind if behind is not None else 0,
        "ok": behind is not None and ahead is not None,
    }


# ── Stash -> pull -> restore ────────────────────────────────────────────────


def stash_and_pull(repo_root: Path) -> dict:
    """Run the Hermes-style source upgrade core.

    - stashes local changes (including untracked) when the tree is dirty
    - pulls origin/main with --ff-only
    - restores the stash on success; on a pop conflict the stash is LEFT
      PARKED so nothing is lost
    - on a failed pull, restores the stash before returning

    Returns {"ok": bool, "stashed": bool, "conflict": bool, "message": str}.
    """
    state = git_repo_state(repo_root)
    label = f"{STASH_PREFIX}-{_utc_stamp()}"
    stashed = False

    if state["dirty"]:
        r = _git(repo_root, "stash", "push", "-u", "-m", label)
        if r.returncode != 0:
            return {
                "ok": False,
                "stashed": False,
                "conflict": False,
                "message": f"Could not stash local changes:\n{r.stderr.strip()}",
            }
        stashed = True

    pull = _git(repo_root, "pull", "--ff-only", "origin", "main", timeout=180)
    if pull.returncode != 0:
        if stashed:
            _git(repo_root, "stash", "pop")  # restore user's changes
        return {
            "ok": False,
            "stashed": stashed,
            "conflict": False,
            "message": (
                f"git pull failed (exit {pull.returncode}).\n{pull.stderr.strip()}"
                if stashed is False
                else (
                    "git pull failed — your local changes were restored.\n"
                    f"{pull.stderr.strip()}"
                )
            ),
        }

    if stashed:
        pop = _git(repo_root, "stash", "pop")
        if pop.returncode != 0:
            # Conflict: stash stays parked (git does not drop on conflict).
            return {
                "ok": True,
                "stashed": True,
                "conflict": True,
                "message": (
                    "Upgrade succeeded but restoring your local changes hit a conflict.\n"
                    f"Your changes are parked in the stash ('{label}').\n"
                    "Resolve it manually:\n"
                    "  git stash list\n"
                    "  git stash pop   # after resolving any conflicts"
                ),
            }

    return {"ok": True, "stashed": stashed, "conflict": False, "message": ""}


# ── install-manager introspection (PyPI track) ──────────────────────────────

MANAGER_PIPX = "pipx"
MANAGER_UV = "uv"

_UV_TOOL_LINE = re.compile(r"^(?P<name>\S+)\s+v(?P<version>\S+)(?:\s+\((?P<dir>.+)\))?$")


@dataclass(frozen=True)
class InstallInfo:
    """Which tool owns this psamvault install, and what that tool records.

    ``venv_dir`` is the environment the owning tool would rebuild, which is what
    decides whether a recreating reinstall may run at all (see
    :func:`running_from_venv`).
    """

    manager: str | None = None  # MANAGER_PIPX | MANAGER_UV | None
    version: str | None = None
    venv_dir: Path | None = None
    editable: bool = False
    source: str = ""  # the recorded requirement / package_or_url

    @property
    def known(self) -> bool:
        return self.manager is not None


def in_place_upgrade_argv(manager: str, package: str = "psamvault") -> list[str]:
    """The command that upgrades IN PLACE — installs into the existing environment."""
    if manager == MANAGER_PIPX:
        return ["pipx", "upgrade", package]
    if manager == MANAGER_UV:
        return ["uv", "tool", "upgrade", package]
    raise ValueError(f"unknown install manager: {manager!r}")


def recreate_install_command(manager: str, version: str, package: str = "psamvault") -> str:
    """The command that REBUILDS the environment from the registry.

    Never runnable from inside the environment it replaces: pipx cannot overwrite
    the running ``python.exe`` (os error 32), and uv removes the environment
    directory before reinstalling and gives up part-way (os error 5), leaving the
    tool broken. Print it, or run it from a process outside that environment.
    """
    if manager == MANAGER_PIPX:
        return f"pipx install --force {package}=={version}"
    if manager == MANAGER_UV:
        return f"uv tool install --force {package}=={version}"
    raise ValueError(f"unknown install manager: {manager!r}")


def _pipx_json() -> dict:
    """Parsed `pipx list --json`, or {} when pipx cannot answer."""
    try:
        r = subprocess.run(
            ["pipx", "list", "--json"], capture_output=True, text=True, timeout=30
        )
        if r.returncode != 0:
            return {}
        return json.loads(r.stdout or "{}")
    except Exception:
        return {}


def pipx_main_package(package: str = "psamvault") -> dict:
    """pipx's recorded main-package metadata for `package` ({} when unknown)."""
    try:
        meta = _pipx_json().get("venvs", {}).get(package, {}).get("metadata", {}) or {}
        return meta.get("main_package", {}) or {}
    except Exception:
        return {}


def _pipx_home_venv(package: str) -> Path | None:
    """`<PIPX_HOME>/venvs/<package>`, the fallback when no app path is recorded."""
    try:
        r = subprocess.run(
            ["pipx", "environment", "--value", "PIPX_HOME"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        home = (r.stdout or "").strip()
        if r.returncode == 0 and home:
            return Path(home) / "venvs" / package
    except Exception:
        pass
    return None


def _pipx_info(package: str = "psamvault") -> InstallInfo:
    main = pipx_main_package(package)
    if not main:
        return InstallInfo()
    source = str(main.get("package_or_url", ""))
    venv_dir = None
    for entry in main.get("app_paths") or []:
        raw = entry.get("__Path__") if isinstance(entry, dict) else entry
        if raw:
            venv_dir = Path(str(raw)).parent.parent
            break
    if venv_dir is None:
        venv_dir = _pipx_home_venv(package)
    return InstallInfo(
        manager=MANAGER_PIPX,
        version=str(main["package_version"]) if main.get("package_version") else None,
        venv_dir=venv_dir,
        editable=bool(main.get("editable")) or source.startswith(("file://", "git+file://")),
        source=source,
    )


def uv_tool_info(package: str = "psamvault") -> InstallInfo:
    """What `uv tool list --show-paths` records for `package` (empty when uv has no such tool)."""
    try:
        r = subprocess.run(
            ["uv", "tool", "list", "--show-paths"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if r.returncode != 0:
            return InstallInfo()
        for line in (r.stdout or "").splitlines():
            match = _UV_TOOL_LINE.match(line.strip())
            if match and match.group("name") == package:
                raw_dir = match.group("dir")
                return InstallInfo(
                    manager=MANAGER_UV,
                    version=match.group("version"),
                    venv_dir=Path(raw_dir) if raw_dir else None,
                )
    except Exception:
        return InstallInfo()
    return InstallInfo()


def install_info(package: str = "psamvault") -> InstallInfo:
    """Which manager owns this install — pipx first, then uv tool ({} when neither)."""
    info = _pipx_info(package)
    return info if info.known else uv_tool_info(package)


def manager_version(manager: str, package: str = "psamvault") -> str | None:
    """The version the owning manager records — a read-back after an upgrade.

    Read from the manager, never from this process's own metadata: the
    interpreter that ran an upgrade still has the pre-upgrade distribution on
    sys.path, so an in-process read reports the version that was there before.
    """
    if manager == MANAGER_PIPX:
        return _pipx_info(package).version
    if manager == MANAGER_UV:
        return uv_tool_info(package).version
    return None


def is_pipx_editable(package: str = "psamvault") -> bool:
    """Return True when pipx reports the package as an editable/source install.

    ``pipx upgrade`` cannot upgrade an editable install in place — it fails or
    silently drops the source link. Detect first so the CLI can explain.
    """
    return _pipx_info(package).editable


def running_from_venv(venv_dir: Path | None, *, executable: Path | None = None) -> bool:
    """True when this process's interpreter lives inside `venv_dir`.

    A recreating reinstall must not run then: Windows locks a running image, so
    the rebuild either cannot replace ``Scripts\\python.exe`` or — uv — removes
    the environment first and leaves the tool unimportable. False when the
    environment is unknown, so callers report instead of guessing.
    """
    if venv_dir is None:
        return False
    candidate = Path(executable) if executable is not None else Path(sys.executable)
    try:
        candidate = candidate.resolve()
        venv_dir = venv_dir.resolve()
    except OSError:
        pass
    inside = os.path.normcase(os.path.normpath(str(candidate)))
    root = os.path.normcase(os.path.normpath(str(venv_dir)))
    return inside == root or inside.startswith(root.rstrip("\\/") + os.sep)
