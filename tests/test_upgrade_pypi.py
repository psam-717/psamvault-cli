"""
Command-level tests for the PyPI/pipx track of `psamvault upgrade`.

The pipx track must reinstall from the PyPI registry by pinned version
(`pipx install --force psamvault==<latest>`) instead of `pipx upgrade`, so
installs whose recorded source is a URL/TestPyPI/editable get healed on the
next version bump and future upgrades always track the registry.
"""
import subprocess

import pytest
import typer

import command.upgrade_command as uc


def test_upgrade_pypi_uses_force_install_pinned_latest(monkeypatch):
    calls = []
    monkeypatch.setattr(uc, "get_installed_version", lambda: "0.5.6")
    monkeypatch.setattr(uc, "fetch_latest_version", lambda: "0.5.7")
    monkeypatch.setattr(uc, "is_pipx_editable", lambda pkg: False)
    monkeypatch.setattr(uc, "set_last_seen_version", lambda v: None)
    monkeypatch.setattr("typer.confirm", lambda msg: True)

    def _fake_run(cmd, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(uc.subprocess, "run", _fake_run)

    uc._upgrade_pypi()

    install_calls = [c for c in calls if c[:2] == ["pipx", "install"]]
    assert install_calls, f"expected pipx install --force call, got {calls}"
    assert install_calls[0] == ["pipx", "install", "--force", "psamvault==0.5.7"]
    assert not any(c[:2] == ["pipx", "upgrade"] for c in calls)


def test_upgrade_pypi_reports_failure_and_manual_hint(monkeypatch, capsys):
    monkeypatch.setattr(uc, "get_installed_version", lambda: "0.5.6")
    monkeypatch.setattr(uc, "fetch_latest_version", lambda: "0.5.7")
    monkeypatch.setattr(uc, "is_pipx_editable", lambda pkg: False)
    monkeypatch.setattr(uc, "set_last_seen_version", lambda v: None)
    monkeypatch.setattr("typer.confirm", lambda msg: True)

    def _fail_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 1, "", "boom")

    monkeypatch.setattr(uc.subprocess, "run", _fail_run)

    with pytest.raises(typer.Exit) as ei:
        uc._upgrade_pypi()
    assert ei.value.exit_code == 1
    out = capsys.readouterr().err
    assert "pipx install --force psamvault==0.5.7" in out
