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
import shutil
import subprocess
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
    backup = backups_parent / f"backup-{_utc_stamp()}"
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


# ── pipx editable detection (PyPI track) ────────────────────────────────────


def is_pipx_editable(package: str = "psamvault") -> bool:
    """Return True when pipx reports the package as an editable/source install.

    ``pipx upgrade`` cannot upgrade an editable install in place — it fails or
    silently drops the source link. Detect first so the CLI can explain.
    """
    try:
        r = subprocess.run(
            ["pipx", "list", "--json"], capture_output=True, text=True, timeout=30
        )
        if r.returncode != 0:
            return False
        data = json.loads(r.stdout or "{}")
        meta = data.get("venvs", {}).get(package, {}).get("metadata", {})
        main_pkg = meta.get("main_package", {}) or {}
        if main_pkg.get("editable"):
            return True
        package_or_url = str(main_pkg.get("package_or_url", ""))
        return package_or_url.startswith(("file://", "git+file://"))
    except Exception:
        return False
