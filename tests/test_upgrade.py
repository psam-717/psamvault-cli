"""
Integration tests for upgrade_utils: snapshot, git-state detection, and the
Hermes-style stash -> pull -> restore flow, exercised against REAL temp git
repos (no mocking of git itself).
"""
import json
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


def test_snapshots_never_share_a_directory_when_the_clock_does_not_advance(tmp_path, monkeypatch):
    """Windows' clock granularity is ~15 ms, so back-to-back snapshots can get one stamp.

    Freezing the stamp makes that deterministic: the second snapshot must still be a
    separate directory instead of silently merging into the first.
    """
    monkeypatch.setattr(upgrade_utils, "_utc_stamp", lambda: "20260921T010000-000000")
    src = tmp_path / "state"
    src.mkdir()
    (src / "session.json").write_text("{}")

    first = upgrade_utils.snapshot_state(source_dir=src, backups_parent=tmp_path / "bk")
    second = upgrade_utils.snapshot_state(source_dir=src, backups_parent=tmp_path / "bk")

    assert first != second
    assert first.is_dir() and second.is_dir()
    assert len(list((tmp_path / "bk").glob("backup-*"))) == 2


def test_snapshot_prune_keeps_five_when_the_clock_does_not_advance(tmp_path, monkeypatch):
    """Seven snapshots under one frozen stamp must still prune to five, not fewer."""
    monkeypatch.setattr(upgrade_utils, "_utc_stamp", lambda: "20260921T010000-000000")
    src = tmp_path / "state"
    src.mkdir()
    (src / "last_seen_version").write_text("0.5.5")

    for _ in range(7):
        upgrade_utils.snapshot_state(source_dir=src, backups_parent=tmp_path / "bk")

    assert len(list((tmp_path / "bk").glob("backup-*"))) == 5


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


# ── pipx editable detection ─────────────────────────────────────────────────

def _fake_pipx_run(payload: str, rc: int = 0):
    def _run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, rc, payload, "")
    return _run


def test_is_pipx_editable_true_when_editable(monkeypatch):
    payload = json.dumps({"venvs": {"psamvault": {"metadata": {"main_package": {
        "editable": True, "package_or_url": "file:///src/psamvault-cli"}}}}})
    monkeypatch.setattr("upgrade_utils.subprocess.run", _fake_pipx_run(payload))
    assert upgrade_utils.is_pipx_editable() is True


def test_is_pipx_editable_false_for_pypi_install(monkeypatch):
    payload = json.dumps({"venvs": {"psamvault": {"metadata": {"main_package": {
        "editable": False, "package_or_url": "psamvault"}}}}})
    monkeypatch.setattr("upgrade_utils.subprocess.run", _fake_pipx_run(payload))
    assert upgrade_utils.is_pipx_editable() is False


def test_is_pipx_editable_false_when_pipx_missing(monkeypatch):
    monkeypatch.setattr("upgrade_utils.subprocess.run", _fake_pipx_run("", rc=127))
    assert upgrade_utils.is_pipx_editable() is False




# ── install-manager introspection (PyPI track) ──────────────────────────────

def _fake_pipx_env(value: str, rc: int = 0):
    def _run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, rc, value, "")
    return _run


def test_running_from_venv_true_for_the_environments_own_interpreter(tmp_path):
    venv = tmp_path / "venvs" / "psamvault"
    assert upgrade_utils.running_from_venv(venv, executable=venv / "Scripts" / "python.exe") is True


def test_running_from_venv_false_for_an_interpreter_outside_it(tmp_path):
    venv = tmp_path / "venvs" / "psamvault"
    assert upgrade_utils.running_from_venv(venv, executable=tmp_path / "other" / "python.exe") is False


def test_running_from_venv_false_when_the_environment_is_unknown():
    assert upgrade_utils.running_from_venv(None) is False


def test_uv_tool_info_reads_the_version_and_the_environment(tmp_path, monkeypatch):
    tool_dir = tmp_path / "tools" / "psamvault"
    payload = (
        f"psamvault v0.5.6 ({tool_dir})\n"
        "- psamvault (/bin/psamvault)\n"
        "- pv (/bin/pv)\n"
        "twine v7.0.0 (/tools/twine)\n"
    )
    monkeypatch.setattr("upgrade_utils.subprocess.run", _fake_pipx_env(payload))

    info = upgrade_utils.uv_tool_info()

    assert info.manager == "uv"
    assert info.version == "0.5.6"
    assert info.venv_dir == tool_dir


def test_uv_tool_info_empty_when_uv_does_not_own_the_package(monkeypatch):
    monkeypatch.setattr("upgrade_utils.subprocess.run", _fake_pipx_env("twine v7.0.0 (C:\\tools\\twine)\n"))
    assert upgrade_utils.uv_tool_info().known is False


def test_uv_tool_info_empty_when_uv_is_missing(monkeypatch):
    monkeypatch.setattr("upgrade_utils.subprocess.run", _fake_pipx_env("", rc=127))
    assert upgrade_utils.uv_tool_info().known is False


def test_install_info_reads_pipx_environment_from_the_recorded_app_path(tmp_path, monkeypatch):
    venv_dir = tmp_path / "pipx" / "venvs" / "psamvault"
    payload = json.dumps({"venvs": {"psamvault": {"metadata": {"main_package": {
        "package_or_url": "psamvault", "package_version": "0.5.6",
        "app_paths": [{"__Path__": str(venv_dir / "Scripts" / "psamvault.exe")}]}}}}})
    monkeypatch.setattr("upgrade_utils.subprocess.run", _fake_pipx_run(payload))

    info = upgrade_utils.install_info()

    assert info.manager == "pipx"
    assert info.version == "0.5.6"
    assert info.venv_dir == venv_dir


def test_install_info_falls_back_to_uv_when_pipx_does_not_know_the_package(tmp_path, monkeypatch):
    tool_dir = tmp_path / "tools" / "psamvault"

    def _run(cmd, **kwargs):
        if list(cmd)[:2] == ["pipx", "list"]:
            return subprocess.CompletedProcess(cmd, 0, json.dumps({"venvs": {}}), "")
        return subprocess.CompletedProcess(cmd, 0, f"psamvault v0.5.6 ({tool_dir})\n", "")
    monkeypatch.setattr("upgrade_utils.subprocess.run", _run)

    info = upgrade_utils.install_info()

    assert info.manager == "uv"
    assert info.version == "0.5.6"
    assert info.venv_dir == tool_dir


def test_install_info_unknown_when_no_manager_owns_it(monkeypatch):
    monkeypatch.setattr("upgrade_utils.subprocess.run", _fake_pipx_env("", rc=127))
    assert upgrade_utils.install_info().known is False


def test_manager_version_is_none_for_an_unknown_manager():
    assert upgrade_utils.manager_version("pip") is None


def test_recreate_commands_are_named_per_manager():
    assert upgrade_utils.recreate_install_command("pipx", "1.2.3") == "pipx install --force psamvault==1.2.3"
    assert upgrade_utils.recreate_install_command("uv", "1.2.3") == "uv tool install --force psamvault==1.2.3"


def test_in_place_upgrade_argv_per_manager():
    assert upgrade_utils.in_place_upgrade_argv("pipx") == ["pipx", "upgrade", "psamvault"]
    assert upgrade_utils.in_place_upgrade_argv("uv") == ["uv", "tool", "upgrade", "psamvault"]
