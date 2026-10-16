"""Keychain startup and failure behaviour.

Rules under test:

- ``--version`` and ``--help`` (and commands that need no secret) never call
  the keyring, so a missing backend cannot crash them and a locked one cannot
  hang them. This is an import-time property, so the checks run in a fresh
  interpreter.
- A command that needs the keychain and finds it missing, locked, or unwilling
  to keep a secret stops with one line, ``✗ <what failed> — <what to do next>``,
  and no traceback.
- The pepper is stored only after the keychain read-back matches. A legacy
  pepper left in ``config.env`` is removed only after that read-back. It is
  never loaded into the environment from the file, and a failed store does
  not delete the only copy.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import keyring.errors
import pytest
import typer
from typer.testing import CliRunner

import config
import keychain
import session
from main import app

runner = CliRunner()

_HANG_SECONDS = 30


def _assert_actionable(text: str, what_failed: str) -> None:
    assert "Traceback" not in text
    line = next((item for item in text.splitlines() if "✗ " in item), "")
    assert " — " in line, text
    failed, _, nxt = line.partition(" — ")
    assert what_failed.lower() in failed.lower(), text
    assert nxt.strip(), text


def _isolated_env(home: Path, backend: str | None = None) -> dict[str, str]:
    env = os.environ.copy()
    env.pop("PSAMVAULT_PEPPER", None)
    env.pop("PSAMVAULT_API_URL", None)
    env["HOME"] = str(home)
    env["XDG_DATA_HOME"] = str(home / "xdg")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    if backend:
        env["PYTHON_KEYRING_BACKEND"] = backend
    else:
        env.pop("PYTHON_KEYRING_BACKEND", None)
    return env


def _write_backend(directory: Path, body: str) -> None:
    # One indent level for the whole module. Mixed indents survive dedent as a
    # syntax error, and a backend that does not import never exercises the keyring.
    directory.joinpath("keybackend.py").write_text(textwrap.dedent(body).lstrip("\n"))


_TOUCH_BACKEND = """
    from keyring.backend import KeyringBackend
    from keyring.compat import properties

    class Keyring(KeyringBackend):
        @properties.classproperty
        def priority(cls) -> float:
            return 1.0

        def get_password(self, service, username):
            raise SystemExit("KEYRING-TOUCHED")

        def set_password(self, service, username, password):
            raise SystemExit("KEYRING-TOUCHED")
"""

_HANG_BACKEND = f"""
    import time
    from keyring.backend import KeyringBackend
    from keyring.compat import properties

    class Keyring(KeyringBackend):
        @properties.classproperty
        def priority(cls) -> float:
            return 1.0

        def get_password(self, service, username):
            time.sleep({_HANG_SECONDS})
            return None

        def set_password(self, service, username, password):
            time.sleep({_HANG_SECONDS})
"""

_LOCKED_BACKEND = """
    from keyring.backend import KeyringBackend
    from keyring.compat import properties
    from keyring.errors import KeyringLocked

    class Keyring(KeyringBackend):
        @properties.classproperty
        def priority(cls) -> float:
            return 1.0

        def get_password(self, service, username):
            raise KeyringLocked("Failed to unlock the collection!")

        def set_password(self, service, username, password):
            raise KeyringLocked("Failed to unlock the collection!")
"""


def _run_fresh(
    home: Path,
    script: str,
    backend_body: str | None,
    timeout: float,
) -> subprocess.CompletedProcess[str]:
    """Run ``script`` in a new interpreter so import-time keychain access is visible."""
    home.mkdir(parents=True, exist_ok=True)
    work = home / "work"
    work.mkdir()
    backend = None
    if backend_body is not None:
        _write_backend(work, backend_body)
        backend = "keybackend.Keyring"
    script_path = work / "check.py"
    script_path.write_text(textwrap.dedent(script))
    env = _isolated_env(home / "user", backend)
    pythonpath = str(work)
    if env.get("PYTHONPATH"):
        pythonpath = pythonpath + os.pathsep + env["PYTHONPATH"]
    env["PYTHONPATH"] = pythonpath
    try:
        return subprocess.run(
            [sys.executable, str(script_path)],
            cwd=str(home),
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        pytest.fail(f"interpreter blocked on the keyring (timeout {timeout}s): {exc}")


def test_version_and_help_do_not_touch_a_failing_keyring(tmp_path: Path):
    """A backend that exits on every operation must not run for --version or --help."""
    completed = _run_fresh(
        tmp_path,
        """
        import json
        from typer.testing import CliRunner
        import main

        runner = CliRunner()
        results = {}
        for args in (["--version"], ["-V"], ["--help"], ["auth", "--help"], ["changelog"], ["generate"]):
            result = runner.invoke(main.app, args)
            results[" ".join(args)] = {
                "code": result.exit_code,
                "output": result.output,
            }
        print(json.dumps(results))
        """,
        _TOUCH_BACKEND,
        timeout=20,
    )
    assert completed.returncode == 0, completed.stderr + completed.stdout
    combined = completed.stdout + completed.stderr
    assert "KEYRING-TOUCHED" not in combined
    assert "Traceback" not in completed.stderr
    payload = json.loads(completed.stdout)
    for args, item in payload.items():
        assert item["code"] == 0, args + item["output"]
        assert "Traceback" not in item["output"]
        assert "NoKeyringError" not in item["output"]
    assert "psamvault" in payload["--version"]["output"]
    assert "psamvault" in payload["-V"]["output"]
    assert "auth" in payload["--help"]["output"]


def test_version_returns_while_the_keyring_would_block(tmp_path: Path):
    completed = _run_fresh(
        tmp_path,
        """
        from typer.testing import CliRunner
        import main
        result = CliRunner().invoke(main.app, ["--version"])
        print("EXIT", result.exit_code)
        print(result.output)
        """,
        _HANG_BACKEND,
        timeout=8,
    )
    assert completed.returncode == 0, completed.stderr + completed.stdout
    assert "EXIT 0" in completed.stdout
    assert "psamvault" in completed.stdout
    assert "Traceback" not in completed.stdout


def test_version_leaves_a_legacy_file_pepper_untouched(tmp_path: Path):
    legacy = "b" * 64
    home = tmp_path / "user"
    config_dir = home / ".psamvault"
    config_dir.mkdir(parents=True)
    (config_dir / "config.env").write_text(
        "PSAMVAULT_API_URL=https://test.example.com\n"
        f"PSAMVAULT_PEPPER={legacy}\n"
    )
    work = tmp_path / "work"
    work.mkdir()
    _write_backend(work, _TOUCH_BACKEND)
    script = work / "check.py"
    script.write_text(
        textwrap.dedent(
            f"""
            import os
            from pathlib import Path
            from typer.testing import CliRunner
            import main
            result = CliRunner().invoke(main.app, ["--version"])
            text = (Path.home() / ".psamvault" / "config.env").read_text()
            print("EXIT", result.exit_code)
            print("FILE_HAS_PEPPER", {legacy!r} in text)
            print("ENV_LOADED", os.environ.get("PSAMVAULT_PEPPER") == {legacy!r})
            print(result.output)
            """
        )
    )
    env = _isolated_env(home, "keybackend.Keyring")
    env["PYTHONPATH"] = str(work)
    completed = subprocess.run(
        [sys.executable, str(script)],
        cwd=str(tmp_path),
        env=env,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr + completed.stdout
    combined = completed.stdout + completed.stderr
    assert "KEYRING-TOUCHED" not in combined
    assert "EXIT 0" in completed.stdout
    assert "FILE_HAS_PEPPER True" in completed.stdout
    assert "ENV_LOADED False" in completed.stdout
    assert "psamvault" in completed.stdout


def test_configure_on_the_fail_backend_is_one_actionable_line(tmp_path: Path):
    home = tmp_path / "user"
    script = tmp_path / "check.py"
    script.write_text(
        textwrap.dedent(
            """
            from typer.testing import CliRunner
            import main
            result = CliRunner().invoke(main.app, ["configure"], input="\\n")
            print("EXIT", result.exit_code)
            print(result.output)
            """
        )
    )
    env = _isolated_env(home, "keyring.backends.fail.Keyring")
    completed = subprocess.run(
        [sys.executable, str(script)],
        cwd=str(tmp_path),
        env=env,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr + completed.stdout
    assert "EXIT 1" in completed.stdout
    output = completed.stdout.split("EXIT 1", 1)[1]
    _assert_actionable(output, "No OS keychain")
    assert "Configuration saved" not in output
    assert "You are ready" not in output
    assert not (home / ".psamvault" / "config.env").exists()


def test_configure_on_a_locked_backend_is_one_actionable_line(tmp_path: Path):
    home = tmp_path / "user"
    work = tmp_path / "work"
    work.mkdir()
    _write_backend(work, _LOCKED_BACKEND)
    script = work / "check.py"
    script.write_text(
        textwrap.dedent(
            """
            from typer.testing import CliRunner
            import main
            result = CliRunner().invoke(main.app, ["configure"], input="\\n")
            print("EXIT", result.exit_code)
            print(result.output)
            """
        )
    )
    env = _isolated_env(home, "keybackend.Keyring")
    env["PYTHONPATH"] = str(work)
    completed = subprocess.run(
        [sys.executable, str(script)],
        cwd=str(tmp_path),
        env=env,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr + completed.stdout
    assert "EXIT 1" in completed.stdout
    output = completed.stdout.split("EXIT 1", 1)[1]
    _assert_actionable(output, "locked")
    assert "Failed to unlock the collection" not in output
    assert not (home / ".psamvault" / "config.env").exists()


class _Memory:
    def __init__(self) -> None:
        self.data: dict[tuple[str, str], str] = {}

    def get_password(self, service, key):
        return self.data.get((service, key))

    def set_password(self, service, key, value):
        self.data[(service, key)] = value

    def delete_password(self, service, key):
        if (service, key) not in self.data:
            raise keyring.errors.PasswordDeleteError(key)
        del self.data[(service, key)]


class _Discard:
    """Accepts writes and returns nothing. Same contract as the null backend."""

    def get_password(self, service, key):
        return None

    def set_password(self, service, key, value):
        return None

    def delete_password(self, service, key):
        return None


@pytest.fixture
def isolated_config(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config, "CONFIG_FILE", tmp_path / "config.env")
    monkeypatch.delenv("PSAMVAULT_PEPPER", raising=False)
    return tmp_path


def test_public_config_never_calls_the_keyring(monkeypatch, isolated_config):
    legacy = "c" * 64
    isolated_config.joinpath("config.env").write_text(
        "PSAMVAULT_API_URL=https://example.test\n"
        f"PSAMVAULT_PEPPER={legacy}\n"
    )

    def boom(*_args, **_kwargs):
        raise AssertionError("keyring used while loading public config")

    monkeypatch.setattr(config.keyring, "get_password", boom)
    monkeypatch.setattr(config.keyring, "set_password", boom)
    monkeypatch.delenv("PSAMVAULT_API_URL", raising=False)
    config.load_public_config()
    text = isolated_config.joinpath("config.env").read_text()
    assert legacy in text
    assert os.environ.get("PSAMVAULT_PEPPER") != legacy
    assert os.environ["PSAMVAULT_API_URL"] == "https://example.test"


def test_legacy_pepper_moves_to_the_keyring_and_leaves_the_file(monkeypatch, isolated_config):
    legacy = "d" * 64
    isolated_config.joinpath("config.env").write_text(
        "# psamvault configuration\n"
        "PSAMVAULT_API_URL=https://example.test\n"
        f"PSAMVAULT_PEPPER={legacy}\n"
    )
    memory = _Memory()
    monkeypatch.setattr(config.keyring, "get_password", memory.get_password)
    monkeypatch.setattr(config.keyring, "set_password", memory.set_password)
    config.load_pepper()
    text = isolated_config.joinpath("config.env").read_text()
    assert "PSAMVAULT_PEPPER" not in text
    assert "PSAMVAULT_API_URL=https://example.test" in text
    assert memory.data[("psamvault", "config.pepper")] == legacy
    assert os.environ["PSAMVAULT_PEPPER"] == legacy


def test_legacy_pepper_stays_in_the_file_when_the_keyring_discards_it(monkeypatch, isolated_config):
    legacy = "e" * 64
    path = isolated_config.joinpath("config.env")
    path.write_text(f"PSAMVAULT_PEPPER={legacy}\n")
    discard = _Discard()
    monkeypatch.setattr(config.keyring, "get_password", discard.get_password)
    monkeypatch.setattr(config.keyring, "set_password", discard.set_password)
    with pytest.raises(typer.Exit) as exc:
        config.load_pepper()
    assert exc.value.exit_code == 1
    assert legacy in path.read_text()
    assert os.environ.get("PSAMVAULT_PEPPER") != legacy


def test_save_config_does_not_write_a_file_when_the_keyring_discards_the_pepper(
    monkeypatch, isolated_config
):
    discard = _Discard()
    monkeypatch.setattr(config.keyring, "get_password", discard.get_password)
    monkeypatch.setattr(config.keyring, "set_password", discard.set_password)
    pepper = "f" * 64
    with pytest.raises(typer.Exit):
        config.save_config("https://example.test", pepper)
    assert not (isolated_config / "config.env").exists()
    dumped = " ".join(
        path.read_text() for path in isolated_config.rglob("*") if path.is_file()
    )
    assert pepper not in dumped


def test_locked_collection_does_not_call_the_keyring_operation(monkeypatch):
    monkeypatch.setattr(keychain, "_probe_secret_service", lambda: keychain._Probe.LOCKED)
    called = {"n": 0}

    def operation(*_args, **_kwargs):
        called["n"] += 1
        raise AssertionError("keyring operation ran while the collection was locked")

    with pytest.raises(typer.Exit) as exc:
        keychain.call(operation)
    assert exc.value.exit_code == 1
    assert called["n"] == 0


def test_probe_sees_a_locked_collection_without_unlocking(monkeypatch):
    secretstorage = pytest.importorskip("secretstorage")

    class _Backend:
        pass

    _Backend.__module__ = "keyring.backends.SecretService"
    monkeypatch.setattr(keychain.keyring, "get_keyring", lambda: _Backend())

    unlocked = {"n": 0}

    class _Collection:
        def __init__(self, connection):
            self.connection = connection

        def is_locked(self):
            return True

        def unlock(self):
            unlocked["n"] += 1

    class _Connection:
        def close(self):
            return None

    created = {"n": 0}

    def _create(*_args, **_kwargs):
        created["n"] += 1
        raise AssertionError("probe created a collection")

    monkeypatch.setattr(secretstorage, "dbus_init", lambda: _Connection())
    monkeypatch.setattr(secretstorage, "Collection", _Collection)
    monkeypatch.setattr(secretstorage, "get_default_collection", _create)
    assert keychain._probe_secret_service_locked() is True
    assert unlocked["n"] == 0
    assert created["n"] == 0


def test_probe_does_not_create_a_missing_collection(monkeypatch):
    secretstorage = pytest.importorskip("secretstorage")
    from secretstorage.exceptions import ItemNotFoundException

    class _Backend:
        pass

    _Backend.__module__ = "keyring.backends.SecretService"
    monkeypatch.setattr(keychain.keyring, "get_keyring", lambda: _Backend())

    class _Connection:
        def close(self):
            return None

    def _collection(_connection):
        raise ItemNotFoundException("no default collection")

    created = {"n": 0}

    def _create(*_args, **_kwargs):
        created["n"] += 1
        raise AssertionError("created")

    monkeypatch.setattr(secretstorage, "dbus_init", lambda: _Connection())
    monkeypatch.setattr(secretstorage, "Collection", _collection)
    monkeypatch.setattr(secretstorage, "get_default_collection", _create)
    monkeypatch.setattr(secretstorage, "create_collection", _create)
    assert keychain._probe_secret_service() is keychain._Probe.NO_DEFAULT
    assert created["n"] == 0


def _install_secret_service(monkeypatch, collection):
    """Point the probe at a stand-in Secret Service. Returns the create counter."""
    secretstorage = pytest.importorskip("secretstorage")

    class _Backend:
        pass

    _Backend.__module__ = "keyring.backends.SecretService"
    monkeypatch.setattr(keychain.keyring, "get_keyring", lambda: _Backend())

    class _Connection:
        def close(self):
            return None

    created = {"n": 0}

    def _create(*_args, **_kwargs):
        created["n"] += 1
        raise AssertionError("created")

    monkeypatch.setattr(secretstorage, "dbus_init", lambda: _Connection())
    monkeypatch.setattr(secretstorage, "Collection", collection)
    monkeypatch.setattr(secretstorage, "get_default_collection", _create)
    monkeypatch.setattr(secretstorage, "create_collection", _create)
    return created


@pytest.mark.timeout(5)
def test_missing_default_collection_does_not_run_the_keyring_call(monkeypatch, capsys):
    """A fresh daemon with no login keyring must not reach create_collection."""
    from secretstorage.exceptions import ItemNotFoundException

    def _collection(_connection):
        raise ItemNotFoundException("no default collection")

    created = _install_secret_service(monkeypatch, _collection)
    called = {"n": 0}

    def _hang(*_args, **_kwargs):
        called["n"] += 1
        import time

        time.sleep(_HANG_SECONDS)

    with pytest.raises(typer.Exit) as exc:
        keychain.call(_hang)
    assert exc.value.exit_code == 1
    assert called["n"] == 0
    assert created["n"] == 0
    _assert_actionable(capsys.readouterr().err, "no default collection")


@pytest.mark.timeout(5)
def test_configure_exits_when_the_default_collection_is_missing(monkeypatch, tmp_path):
    from secretstorage.exceptions import ItemNotFoundException

    def _collection(_connection):
        raise ItemNotFoundException("no default collection")

    created = _install_secret_service(monkeypatch, _collection)
    monkeypatch.delenv("PSAMVAULT_PEPPER", raising=False)
    monkeypatch.delenv("PSAMVAULT_API_URL", raising=False)
    monkeypatch.setattr(config, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config, "CONFIG_FILE", tmp_path / "config.env")

    def _hang(*_args, **_kwargs):
        import time

        time.sleep(_HANG_SECONDS)

    monkeypatch.setattr(config.keyring, "get_password", _hang)
    monkeypatch.setattr(config.keyring, "set_password", _hang)
    result = runner.invoke(app, ["configure"], input="\n")
    assert result.exit_code == 1
    _assert_actionable(result.output, "no default collection")
    assert "Traceback" not in result.output
    assert "Configuration saved" not in result.output
    assert created["n"] == 0
    assert not (tmp_path / "config.env").exists()


def test_unlocked_default_collection_still_runs_the_operation(monkeypatch):
    class _Collection:
        def __init__(self, _connection):
            return None

        def is_locked(self):
            return False

        def unlock(self):
            raise AssertionError("unlock")

    created = _install_secret_service(monkeypatch, _Collection)
    assert keychain.call(lambda: "stored") == "stored"
    assert created["n"] == 0
    assert keychain._probe_secret_service() is keychain._Probe.READY


def test_probe_reuses_one_dbus_connection_across_session_reads(monkeypatch):
    """load_session reads six secrets. The probe should not open six buses."""
    secretstorage = pytest.importorskip("secretstorage")
    opened = {"n": 0}

    class _Backend:
        pass

    _Backend.__module__ = "keyring.backends.SecretService"
    monkeypatch.setattr(keychain.keyring, "get_keyring", lambda: _Backend())

    class _Connection:
        def close(self):
            return None

    class _Collection:
        def __init__(self, _connection):
            return None

        def is_locked(self):
            return False

    def dbus_init():
        opened["n"] += 1
        return _Connection()

    monkeypatch.setattr(secretstorage, "dbus_init", dbus_init)
    monkeypatch.setattr(secretstorage, "Collection", _Collection)
    keychain.reset_probe_cache()
    for _ in range(7):
        assert keychain.call(lambda: "ok") == "ok"
    assert opened["n"] == 1


def test_probe_reconnects_once_when_the_cached_connection_fails(monkeypatch):
    secretstorage = pytest.importorskip("secretstorage")
    from secretstorage.exceptions import SecretStorageException

    opened = {"n": 0}

    class _Backend:
        pass

    _Backend.__module__ = "keyring.backends.SecretService"
    monkeypatch.setattr(keychain.keyring, "get_keyring", lambda: _Backend())

    class _Connection:
        def __init__(self, good: bool):
            self.good = good

        def close(self):
            return None

    class _Collection:
        def __init__(self, connection):
            if not connection.good:
                raise SecretStorageException("stale")

        def is_locked(self):
            return False

    def dbus_init():
        opened["n"] += 1
        return _Connection(opened["n"] > 1)

    monkeypatch.setattr(secretstorage, "dbus_init", dbus_init)
    monkeypatch.setattr(secretstorage, "Collection", _Collection)
    keychain.reset_probe_cache()
    assert keychain._probe_secret_service() is keychain._Probe.READY
    assert opened["n"] == 2


def test_whoami_reports_a_missing_keyring(monkeypatch, tmp_path):
    session_file = tmp_path / "session.json"
    session_file.write_text("{}")
    monkeypatch.setattr(session, "SESSION_FILE", session_file)

    def boom(*_args, **_kwargs):
        raise keyring.errors.NoKeyringError("No recommended backend was available")

    monkeypatch.setattr(session.keyring, "get_password", boom)
    result = runner.invoke(app, ["whoami"])
    assert result.exit_code == 1
    _assert_actionable(result.output, "No OS keychain")
    assert "NoKeyringError" not in result.output


def test_whoami_reports_a_locked_keyring_without_calling_it_when_the_probe_says_locked(
    monkeypatch, tmp_path
):
    session_file = tmp_path / "session.json"
    session_file.write_text("{}")
    monkeypatch.setattr(session, "SESSION_FILE", session_file)
    monkeypatch.setattr(keychain, "_probe_secret_service", lambda: keychain._Probe.LOCKED)
    called = {"n": 0}

    def boom(*_args, **_kwargs):
        called["n"] += 1
        raise AssertionError("get_password ran")

    monkeypatch.setattr(session.keyring, "get_password", boom)
    result = runner.invoke(app, ["whoami"])
    assert result.exit_code == 1
    assert called["n"] == 0
    _assert_actionable(result.output, "locked")


def test_whoami_reports_keyring_locked_raised_by_the_backend(monkeypatch, tmp_path):
    session_file = tmp_path / "session.json"
    session_file.write_text("{}")
    monkeypatch.setattr(session, "SESSION_FILE", session_file)

    def boom(*_args, **_kwargs):
        raise keyring.errors.KeyringLocked("Failed to unlock the collection!")

    monkeypatch.setattr(session.keyring, "get_password", boom)
    result = runner.invoke(app, ["whoami"])
    assert result.exit_code == 1
    _assert_actionable(result.output, "locked")
    assert "Failed to unlock the collection" not in result.output


def test_verbose_names_the_keyring_exception(monkeypatch, tmp_path):
    session_file = tmp_path / "session.json"
    session_file.write_text("{}")
    monkeypatch.setattr(session, "SESSION_FILE", session_file)

    def boom(*_args, **_kwargs):
        raise keyring.errors.NoKeyringError("No recommended backend was available")

    monkeypatch.setattr(session.keyring, "get_password", boom)
    import error_ui

    error_ui._verbose_enabled = False
    quiet = runner.invoke(app, ["whoami"])
    assert "NoKeyringError" not in quiet.output
    result = runner.invoke(app, ["--verbose", "whoami"])
    assert result.exit_code == 1
    _assert_actionable(result.output, "No OS keychain")
    assert "NoKeyringError" in result.output
    error_ui._verbose_enabled = False
