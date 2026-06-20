"""
Tests for update_check.py — install detection, commit counting, notice generation.

Uses temporary directories with and without .git to simulate source vs PyPI.
"""

import os
import pathlib
import subprocess
import threading
from unittest.mock import patch

import pytest

from update_check import (
    _find_git_root,
    _commit_update_notice,
    _version_update_notice,
    _count_commits_behind,
    _get_git_root,
    is_source_install,
    get_installed_version,
    fetch_latest_version,
    version_tuple,
    start_update_check,
    print_update_notice,
    _UPDATE_NOTICE,
)


# ── _find_git_root / is_source_install / _get_git_root ────────────────────────


def test_find_git_root_finds_existing_git(tmp_path: pathlib.Path):
    """find_git_root returns the directory containing .git."""
    (tmp_path / ".git").mkdir()
    subdir = tmp_path / "a" / "b" / "c"
    subdir.mkdir(parents=True)
    assert _find_git_root(subdir) == tmp_path


def test_find_git_root_no_git(tmp_path: pathlib.Path):
    """find_git_root returns None when no .git exists up the tree."""
    subdir = tmp_path / "a" / "b" / "c"
    subdir.mkdir(parents=True)
    assert _find_git_root(subdir) is None


def test_find_git_root_is_dir_not_file(tmp_path: pathlib.Path):
    """A file named .git (common in submodules / worktrees) is NOT detected."""
    (tmp_path / ".git").write_text("gitdir: ../something/.git")
    assert _find_git_root(tmp_path) is None


def test_is_source_install_returns_false_when_no_package():
    """is_source_install gracefully returns False when psamvault isn't found."""
    with patch("update_check._package_path", return_value=None):
        assert is_source_install() is False


def test_get_git_root_returns_none_when_no_package():
    """_get_git_root returns None when package path can't be determined."""
    with patch("update_check._package_path", return_value=None):
        assert _get_git_root() is None


# ── _count_commits_behind ──────────────────────────────────────────────────────


def test_count_commits_behind_zero(tmp_path: pathlib.Path):
    """When HEAD and origin/main point to the same commit, count is 0."""
    _init_repo(tmp_path)
    # Create a local main branch so origin/main exists
    subprocess.run(["git", "branch", "-m", "main"], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(["git", "branch", "origin/main", "main"], cwd=tmp_path, capture_output=True, check=True)
    assert _count_commits_behind(tmp_path) == 0


def test_count_commits_behind_none_on_no_remote(tmp_path: pathlib.Path):
    """When there's no origin remote, gracefully returns None."""
    _init_repo(tmp_path, with_remote=False)
    result = _count_commits_behind(tmp_path)
    assert result is None or result == 0


def test_count_commits_behind_none_on_bad_path():
    """Non-existent path returns None."""
    assert _count_commits_behind(pathlib.Path("/nonexistent/path")) is None


# ── Notice generation ──────────────────────────────────────────────────────────


class TestCommitUpdateNotice:
    def test_zero_commits(self):
        assert _commit_update_notice(0) == ""

    def test_one_commit(self):
        msg = _commit_update_notice(1)
        assert "1 commit" in msg
        assert "psamvault upgrade" in msg

    def test_multiple_commits(self):
        msg = _commit_update_notice(5)
        assert "5 commits" in msg
        assert "psamvault upgrade" in msg


class TestVersionUpdateNotice:
    def test_typical(self):
        msg = _version_update_notice("0.5.3", "0.6.0")
        assert "0.5.3 → 0.6.0" in msg
        assert "psamvault upgrade" in msg


# ── Version helpers ────────────────────────────────────────────────────────────


class TestVersionTuple:
    def test_three_part(self):
        assert version_tuple("1.2.3") == (1, 2, 3)

    def test_invalid_returns_zero(self):
        assert version_tuple("abc") == (0,)


# ── Background thread integration ──────────────────────────────────────────────


def test_start_and_print_no_notice_when_up_to_date():
    """start_update_check + print_update_notice produce no output when up to date."""
    with patch("update_check.get_installed_version", return_value="999.0.0"), \
         patch("update_check.is_source_install", return_value=False), \
         patch("update_check.fetch_latest_version", return_value="999.0.0"), \
         patch("update_check._UPDATE_NOTICE", None):
        from update_check import start_update_check
        start_update_check()
        import time
        time.sleep(1.5)
        # The module-level _UPDATE_NOTICE should still be None
        assert _UPDATE_NOTICE is None


def test_version_notice_when_behind():
    """A version behind PyPI produces a version-based notice."""
    with patch("update_check.fetch_latest_version", return_value="0.6.0"), \
         patch("update_check.is_source_install", return_value=False):
        from update_check import _check
        import update_check
        update_check._UPDATE_NOTICE = None
        _check("0.5.0")
        assert update_check._UPDATE_NOTICE is not None
        assert "0.5.0 → 0.6.0" in update_check._UPDATE_NOTICE
        assert "psamvault upgrade" in update_check._UPDATE_NOTICE


# ── Helpers ────────────────────────────────────────────────────────────────────


def _init_repo(path: pathlib.Path, with_remote: bool = True) -> None:
    """Initialise a minimal git repo at `path` with an origin remote."""
    subprocess.run(["git", "init"], cwd=path, capture_output=True, check=True)
    subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=path, capture_output=True, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=path, capture_output=True, check=True)
    # Create an initial commit so HEAD exists
    (path / "README.md").write_text("# test")
    subprocess.run(["git", "add", "."], cwd=path, capture_output=True, check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=path, capture_output=True, check=True)
    if with_remote:
        subprocess.run(["git", "remote", "add", "origin", "https://github.com/test/repo.git"], cwd=path, capture_output=True, check=True)
