"""
Integration tests for upgrade_utils: snapshot, git-state detection, and the
Hermes-style stash -> pull -> restore flow, exercised against REAL temp git
repos (no mocking of git itself).
"""
import os
import shutil
import subprocess
from pathlib import Path

import pytest

import upgrade_utils


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def git_env():
    """Temporary git identity so commits work in CI sandboxes."""
    return {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}


def _git(cwd: Path, *args: str, env=None) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=str(cwd), capture_output=True, text=True, env=env, timeout=60)


@pytest.fixture
def repo_pair(tmp_path: Path, git_env):
    """(remote_bare, work) — work is behind-capable clone with a clean main."""
    remote = tmp_path / "remote.git"
    _git(tmp_path, "init", "--bare", "-b", "main", str(remote))
    work = tmp_path / "work"
    subprocess.run(["git", "clone", str(remote), str(work)], check=True, capture_output=True)
    (work / "file.txt").write_text("base\n")
    _git(work, "add", "-A")
    _git(work, "commit", "-m", "base", env=git_env)
    _git(work, "push", "origin", "main")
    return remote, work


def _advance_remote(remote: Path, work_other: Path, git_env) -> None:
    """Add one upstream commit to the bare remote via a scratch clone."""
    if work_other.exists():
        shutil.rmtree(work_other)
    subprocess.run(["git", "clone", str(remote), str(work_other)], check=True, capture_output=True)
    (work_other / "upstream.txt").write_text("upstream change\n")
    _git(work_other, "add", "-A")
    _git(work_other, "commit", "-m", "upstream", env=git_env)
    _git(work_other, "push", "origin", "main")


# ── snapshot_state ───────────────────────────────────────────────────────────

def test_snapshot_copies_state_files_and_prunes(tmp_path):
    src = tmp_path / "state"
    src.mkdir()
    (src / "session.json").write_text("{}")
    (src / "last_seen_version").write_text("0.5.5")

    p1 = upgrade_utils.snapshot_state(source_dir=src, backups_parent=tmp_path / "bk")
    assert p1 is not None and p1.exists()
    assert (p1 / "session.json").read_text() == "{}"
    assert (p1 / "last_seen_version").read_text() == "0.5.5"

    # Create 6 more snapshots -> only newest 5 remain after pruning
    for _ in range(6):
        upgrade_utils.snapshot_state(source_dir=src, backups_parent=tmp_path / "bk")
    backups = list((tmp_path / "bk").glob("backup-*"))
    assert len(backups) == 5


def test_snapshot_returns_none_when_nothing_to_copy(tmp_path):
    src = tmp_path / "empty"
    src.mkdir()
    assert upgrade_utils.snapshot_state(source_dir=src, backups_parent=tmp_path / "bk") is None


# ── git state detection ──────────────────────────────────────────────────────

def test_git_state_clean_and_behind_zero(repo_pair):
    _, work = repo_pair
    st = upgrade_utils.git_repo_state(work)
    assert st["dirty"] is False
    assert st["behind"] == 0
    assert st["ahead"] == 0


def test_git_state_dirty_when_local_edit(repo_pair):
    _, work = repo_pair
    (work / "file.txt").write_text("edited locally\n")
    st = upgrade_utils.git_repo_state(work)
    assert st["dirty"] is True


def test_git_state_behind_after_upstream_move(repo_pair, tmp_path, git_env):
    remote, work = repo_pair
    _advance_remote(remote, tmp_path / "other", git_env)
    _git(work, "fetch", "origin")
    st = upgrade_utils.git_repo_state(work)
    assert st["behind"] == 1
    assert st["ahead"] == 0


def test_git_state_ahead_with_local_commit(repo_pair, git_env):
    _, work = repo_pair
    (work / "local.txt").write_text("local\n")
    _git(work, "add", "-A")
    _git(work, "commit", "-m", "local commit", env=git_env)
    st = upgrade_utils.git_repo_state(work)
    assert st["ahead"] == 1


# ── stash_and_pull ───────────────────────────────────────────────────────────

def test_stash_and_pull_clean_tree_just_pulls(repo_pair, tmp_path, git_env):
    remote, work = repo_pair
    _advance_remote(remote, tmp_path / "other", git_env)
    out = upgrade_utils.stash_and_pull(work)
    assert out["ok"] is True
    assert out["stashed"] is False
    assert (work / "upstream.txt").exists()  # upstream change arrived


def test_stash_and_pull_disjoint_changes_restores(repo_pair, tmp_path, git_env):
    remote, work = repo_pair
    (work / "file.txt").write_text("local edit\n")  # dirty a file upstream does NOT touch
    _advance_remote(remote, tmp_path / "other", git_env)

    out = upgrade_utils.stash_and_pull(work)
    assert out["ok"] is True
    assert out["stashed"] is True
    assert out["conflict"] is False
    # both the local edit AND the upstream change survived
    assert (work / "file.txt").read_text() == "local edit\n"
    assert (work / "upstream.txt").exists()
    # stash fully restored -> empty
    assert _git(work, "stash", "list").stdout.strip() == ""


def test_stash_and_pull_conflict_parks_stash(repo_pair, tmp_path, git_env):
    remote, work = repo_pair
    (work / "file.txt").write_text("local line\n")  # same file upstream will change
    _advance_remote(remote, tmp_path / "other", git_env)
    # upstream edits the same file's same line -> guaranteed conflict
    other = tmp_path / "other"
    (other / "file.txt").write_text("upstream line\n")
    _git(other, "add", "-A")
    _git(other, "commit", "-m", "upstream same file", env=git_env)
    _git(other, "push", "origin", "main")

    out = upgrade_utils.stash_and_pull(work)
    assert out["ok"] is True            # the PULL succeeded
    assert out["stashed"] is True
    assert out["conflict"] is True      # pop conflicted
    # the stash is still parked so nothing is lost
    assert "psamvault-upgrade-autostash" in _git(work, "stash", "list").stdout


def test_stash_and_pull_restores_on_pull_failure(repo_pair, tmp_path, git_env):
    remote, work = repo_pair
    (work / "file.txt").write_text("keep me\n")
    # Break the remote so pull cannot succeed
    _git(work, "remote", "set-url", "origin", "https://127.0.0.1:1/nope.git")

    out = upgrade_utils.stash_and_pull(work)
    assert out["ok"] is False
    assert out["stashed"] is True
    # user's local edit was restored even though the upgrade failed
    assert (work / "file.txt").read_text() == "keep me\n"
    assert _git(work, "stash", "list").stdout.strip() == ""
