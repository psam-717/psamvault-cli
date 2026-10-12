"""
Command-level tests for the PyPI/pipx track of `psamvault upgrade`.

The track upgrades IN PLACE (`pipx upgrade psamvault`). It must never recreate
the venv from inside that venv: the process running the upgrade IS the venv's
interpreter, and Windows locks a running image, so pipx's pinned force install
(`pipx install --force psamvault==<latest>`, which rebuilds the venv and
rewrites Scripts\\python.exe) dies with "os error 32 - being used by another
process". Reproduced from a scratch pipx venv on 2026-10-12.

The pinned reinstall survives as a fallback for a caller OUTSIDE the venv, and
as the printed follow-up command everywhere else — including when the recorded
source is not the registry, so an in-place upgrade resolves to itself and the
version never moves.
"""
import subprocess

import pytest
import typer

import command.upgrade_command as uc


def _fake_run(calls, rc=0):
    def _run(cmd, **kwargs):
        calls.append(list(cmd))
        return subprocess.CompletedProcess(cmd, rc, "", "")
    return _run


def _scripted_run(calls, rcs):
    """Return one exit code per invocation, in order."""
    def _run(cmd, **kwargs):
        calls.append(list(cmd))
        rc = rcs.pop(0) if rcs else 0
        return subprocess.CompletedProcess(cmd, rc, "", "")
    return _run


def _missing_pipx(cmd, **kwargs):
    raise FileNotFoundError("pipx")


@pytest.fixture
def wired(monkeypatch):
    """One version behind PyPI, running from the pipx venv, every side effect captured."""
    monkeypatch.setattr(uc, "get_installed_version", lambda: "0.5.6")
    monkeypatch.setattr(uc, "fetch_latest_version", lambda: "0.5.7")
    monkeypatch.setattr(uc, "is_pipx_editable", lambda pkg: False)
    monkeypatch.setattr("typer.confirm", lambda msg: True)
    monkeypatch.setattr(uc, "running_from_pipx_venv", lambda pkg="psamvault": True)
    monkeypatch.setattr(uc, "pipx_installed_version", lambda pkg="psamvault": "0.5.7")
    monkeypatch.setattr(
        uc, "pipx_main_package", lambda pkg="psamvault": {"package_or_url": "psamvault"}
    )
    seen = []
    monkeypatch.setattr(uc, "set_last_seen_version", seen.append)
    return seen


def test_upgrade_pypi_upgrades_in_place_and_never_recreates_the_venv(wired, monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(uc.subprocess, "run", _fake_run(calls))

    uc._upgrade_pypi()

    assert calls == [["pipx", "upgrade", "psamvault"]]
    assert not any(c[:2] == ["pipx", "install"] for c in calls)
    assert wired == ["0.5.7"]
    assert "upgraded to v0.5.7" in capsys.readouterr().out


def test_upgrade_pypi_never_recreates_the_venv_it_runs_from(wired, monkeypatch, capsys):
    """The reported failure: the pinned force install cannot replace the running venv."""
    calls = []
    monkeypatch.setattr(uc.subprocess, "run", _fake_run(calls, rc=1))

    with pytest.raises(typer.Exit) as ei:
        uc._upgrade_pypi()

    assert ei.value.exit_code == 1
    # the venv-recreating route is never attempted from inside the venv
    assert calls == [["pipx", "upgrade", "psamvault"]]
    err = capsys.readouterr().err
    assert "pipx install --force psamvault==0.5.7" in err
    assert "after this command exits" in err
    assert wired == []


def test_upgrade_pypi_falls_back_to_the_pinned_install_from_outside_the_venv(wired, monkeypatch):
    monkeypatch.setattr(uc, "running_from_pipx_venv", lambda pkg="psamvault": False)
    calls = []
    monkeypatch.setattr(uc.subprocess, "run", _scripted_run(calls, [1, 0]))

    uc._upgrade_pypi()

    assert calls == [
        ["pipx", "upgrade", "psamvault"],
        ["pipx", "install", "--force", "psamvault==0.5.7"],
    ]
    assert wired == ["0.5.7"]


def test_upgrade_pypi_explains_a_version_that_did_not_move(wired, monkeypatch, capsys):
    """A URL/pinned/TestPyPI source resolves to itself: pipx succeeds, nothing moves."""
    monkeypatch.setattr(uc, "pipx_installed_version", lambda pkg="psamvault": "0.5.6")
    monkeypatch.setattr(
        uc,
        "pipx_main_package",
        lambda pkg="psamvault": {"package_or_url": "psamvault @ https://test.pypi.org/simple/"},
    )
    calls = []
    monkeypatch.setattr(uc.subprocess, "run", _fake_run(calls, rc=0))

    with pytest.raises(typer.Exit) as ei:
        uc._upgrade_pypi()

    assert ei.value.exit_code == 1
    err = capsys.readouterr().err
    assert "test.pypi.org" in err
    assert "pipx install --force psamvault==0.5.7" in err
    assert "after this command exits" in err
    assert wired == []


def test_upgrade_pypi_accepts_a_newer_than_advertised_result(wired, monkeypatch, capsys):
    """A release published mid-upgrade is a success, not a failure."""
    monkeypatch.setattr(uc, "pipx_installed_version", lambda pkg="psamvault": "0.5.8")
    calls = []
    monkeypatch.setattr(uc.subprocess, "run", _fake_run(calls))

    uc._upgrade_pypi()

    assert wired == ["0.5.7"]
    assert "upgraded to v0.5.7" in capsys.readouterr().out


def test_upgrade_pypi_missing_pipx_says_how_to_get_it(wired, monkeypatch, capsys):
    monkeypatch.setattr(uc.subprocess, "run", _missing_pipx)

    with pytest.raises(typer.Exit) as ei:
        uc._upgrade_pypi()

    assert ei.value.exit_code == 1
    err = capsys.readouterr().err
    assert "pipx is not installed" in err
    assert "pip install --upgrade pipx" in err


def test_upgrade_pypi_refuses_an_editable_install_before_running_anything(wired, monkeypatch, capsys):
    monkeypatch.setattr(uc, "is_pipx_editable", lambda pkg: True)
    calls = []
    monkeypatch.setattr(uc.subprocess, "run", _fake_run(calls))

    with pytest.raises(typer.Exit) as ei:
        uc._upgrade_pypi()

    assert ei.value.exit_code == 1
    assert calls == []
    assert "editable/source-linked" in capsys.readouterr().err


def test_upgrade_pypi_noops_when_already_current(wired, monkeypatch, capsys):
    monkeypatch.setattr(uc, "fetch_latest_version", lambda: "0.5.6")
    calls = []
    monkeypatch.setattr(uc.subprocess, "run", _fake_run(calls))

    uc._upgrade_pypi()

    assert calls == []
    assert "already up to date" in capsys.readouterr().out
