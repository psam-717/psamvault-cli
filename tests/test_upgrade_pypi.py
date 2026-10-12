"""
Command-level tests for the PyPI/tool track of `psamvault upgrade`.

The track upgrades IN PLACE through whichever tool owns the install — pipx or
`uv tool` — and must never run the environment-REBUILDING reinstall from inside
the environment it replaces. Measured in scratch environments on 2026-10-12:

* pipx: `pipx install --force` fails while rebuilding the venv ("the running
  Scripts\\python.exe is being used by another process", os error 32) and leaves
  the previous install in place.
* uv: `uv tool install --force` removes the environment directory first, fails
  (os error 5), and leaves psamvault UNIMPORTABLE ("No module named 'main'").
  That is the breakage the guard exists to prevent.

`pipx upgrade psamvault` and `uv tool upgrade psamvault` both install into the
existing environment and work from inside it — both verified moving 0.6.0 to
0.7.2 while the environment's own python.exe was running.
"""
import subprocess
from pathlib import Path

import pytest
import typer

import command.upgrade_command as uc
from upgrade_utils import InstallInfo


def _info(manager="pipx", version="0.5.7", venv="C:/venvs/psamvault", editable=False, source="psamvault"):
    return InstallInfo(
        manager=manager,
        version=version,
        venv_dir=Path(venv) if venv else None,
        editable=editable,
        source=source,
    )


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


def _missing_tool(cmd, **kwargs):
    raise FileNotFoundError("tool")


@pytest.fixture
def wired(monkeypatch):
    """One version behind PyPI, running from the pipx venv, every side effect captured."""
    monkeypatch.setattr(uc, "get_installed_version", lambda: "0.5.6")
    monkeypatch.setattr(uc, "fetch_latest_version", lambda: "0.5.7")
    monkeypatch.setattr(uc, "install_info", lambda pkg="psamvault": _info())
    monkeypatch.setattr(uc, "manager_version", lambda mgr, pkg="psamvault": "0.5.7")
    monkeypatch.setattr(uc, "running_from_venv", lambda venv, executable=None: True)
    monkeypatch.setattr("typer.confirm", lambda msg: True)
    seen = []
    monkeypatch.setattr(uc, "set_last_seen_version", seen.append)
    return seen


def test_upgrade_pypi_upgrades_in_place_with_pipx(wired, monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(uc.subprocess, "run", _fake_run(calls))

    uc._upgrade_pypi()

    assert calls == [["pipx", "upgrade", "psamvault"]]
    assert wired == ["0.5.7"]
    assert "upgraded to v0.5.7" in capsys.readouterr().out


def test_upgrade_pypi_upgrades_in_place_with_uv_tool(wired, monkeypatch, capsys):
    """A `uv tool install` gets uv's own in-place upgrade — never a pipx install."""
    monkeypatch.setattr(
        uc, "install_info", lambda pkg="psamvault": _info(manager="uv", venv="C:/tools/psamvault")
    )
    calls = []
    monkeypatch.setattr(uc.subprocess, "run", _fake_run(calls))

    uc._upgrade_pypi()

    assert calls == [["uv", "tool", "upgrade", "psamvault"]]
    assert wired == ["0.5.7"]
    assert "upgraded to v0.5.7" in capsys.readouterr().out


def test_upgrade_pypi_never_recreates_the_pipx_environment_it_runs_from(wired, monkeypatch, capsys):
    """The reported failure: the reinstall cannot replace the running venv."""
    calls = []
    monkeypatch.setattr(uc.subprocess, "run", _fake_run(calls, rc=1))

    with pytest.raises(typer.Exit) as ei:
        uc._upgrade_pypi()

    assert ei.value.exit_code == 1
    assert calls == [["pipx", "upgrade", "psamvault"]]
    err = capsys.readouterr().err
    assert "pipx install --force psamvault==0.5.7" in err
    assert "after this command exits" in err
    assert wired == []


def test_upgrade_pypi_never_recreates_the_uv_environment_it_runs_from(wired, monkeypatch, capsys):
    """uv's rebuild removes the environment first, so it must never run from inside it."""
    monkeypatch.setattr(
        uc, "install_info", lambda pkg="psamvault": _info(manager="uv", venv="C:/tools/psamvault")
    )
    calls = []
    monkeypatch.setattr(uc.subprocess, "run", _fake_run(calls, rc=1))

    with pytest.raises(typer.Exit) as ei:
        uc._upgrade_pypi()

    assert ei.value.exit_code == 1
    assert calls == [["uv", "tool", "upgrade", "psamvault"]]
    err = capsys.readouterr().err
    assert "uv tool install --force psamvault==0.5.7" in err
    assert "pipx install" not in err
    assert wired == []


def test_upgrade_pypi_runs_the_reinstall_only_from_outside_the_environment(wired, monkeypatch):
    monkeypatch.setattr(uc, "running_from_venv", lambda venv, executable=None: False)
    calls = []
    monkeypatch.setattr(uc.subprocess, "run", _scripted_run(calls, [1, 0]))

    uc._upgrade_pypi()

    assert calls == [
        ["pipx", "upgrade", "psamvault"],
        ["pipx", "install", "--force", "psamvault==0.5.7"],
    ]
    assert wired == ["0.5.7"]


def test_upgrade_pypi_will_not_rebuild_an_environment_it_cannot_identify(wired, monkeypatch, capsys):
    monkeypatch.setattr(uc, "install_info", lambda pkg="psamvault": _info(venv=None))
    calls = []
    monkeypatch.setattr(uc.subprocess, "run", _fake_run(calls, rc=1))

    with pytest.raises(typer.Exit):
        uc._upgrade_pypi()

    assert calls == [["pipx", "upgrade", "psamvault"]]
    assert "pipx install --force psamvault==0.5.7" in capsys.readouterr().err


def test_upgrade_pypi_explains_a_version_that_did_not_move(wired, monkeypatch, capsys):
    """A URL/TestPyPI source resolves to itself: the tool succeeds, nothing moves."""
    monkeypatch.setattr(
        uc,
        "install_info",
        lambda pkg="psamvault": _info(source="psamvault @ https://test.pypi.org/simple/"),
    )
    monkeypatch.setattr(uc, "manager_version", lambda mgr, pkg="psamvault": "0.5.6")
    calls = []
    monkeypatch.setattr(uc.subprocess, "run", _fake_run(calls, rc=0))

    with pytest.raises(typer.Exit) as ei:
        uc._upgrade_pypi()

    assert ei.value.exit_code == 1
    err = capsys.readouterr().err
    assert "test.pypi.org" in err
    assert "pipx install --force psamvault==0.5.7" in err
    assert wired == []


def test_upgrade_pypi_accepts_a_newer_than_advertised_result(wired, monkeypatch, capsys):
    """A release published mid-upgrade is a success, not a failure."""
    monkeypatch.setattr(uc, "manager_version", lambda mgr, pkg="psamvault": "0.5.8")
    calls = []
    monkeypatch.setattr(uc.subprocess, "run", _fake_run(calls))

    uc._upgrade_pypi()

    assert wired == ["0.5.7"]
    assert "upgraded to v0.5.7" in capsys.readouterr().out


def test_upgrade_pypi_missing_tool_says_how_to_get_it(wired, monkeypatch, capsys):
    monkeypatch.setattr(uc.subprocess, "run", _missing_tool)

    with pytest.raises(typer.Exit) as ei:
        uc._upgrade_pypi()

    assert ei.value.exit_code == 1
    err = capsys.readouterr().err
    assert "pipx is not installed" in err
    assert "pipx install --force psamvault==0.5.7" in err


def test_upgrade_pypi_refuses_an_editable_install_before_running_anything(wired, monkeypatch, capsys):
    monkeypatch.setattr(uc, "install_info", lambda pkg="psamvault": _info(editable=True))
    calls = []
    monkeypatch.setattr(uc.subprocess, "run", _fake_run(calls))

    with pytest.raises(typer.Exit) as ei:
        uc._upgrade_pypi()

    assert ei.value.exit_code == 1
    assert calls == []
    assert "editable/source-linked" in capsys.readouterr().err


def test_upgrade_pypi_refuses_an_install_no_manager_owns(wired, monkeypatch, capsys):
    """Never install a second copy with the wrong tool — that is how one breaks."""
    monkeypatch.setattr(uc, "install_info", lambda pkg="psamvault": InstallInfo())
    calls = []
    monkeypatch.setattr(uc.subprocess, "run", _fake_run(calls))

    with pytest.raises(typer.Exit) as ei:
        uc._upgrade_pypi()

    assert ei.value.exit_code == 1
    assert calls == []
    assert "not installed by pipx or by uv tool" in capsys.readouterr().err


def test_upgrade_pypi_noops_when_already_current(wired, monkeypatch, capsys):
    monkeypatch.setattr(uc, "fetch_latest_version", lambda: "0.5.6")
    calls = []
    monkeypatch.setattr(uc.subprocess, "run", _fake_run(calls))

    uc._upgrade_pypi()

    assert calls == []
    assert "already up to date" in capsys.readouterr().out
