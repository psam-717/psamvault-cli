"""``configure`` and ``config-show`` describe where the pepper actually lives.

The pepper is written to the OS keychain. ``config.env`` holds the API URL
only. The command must not print pepper characters, and it must not tell
the user to back up ``config.env`` as if that file held the pepper.
"""

from __future__ import annotations

import os

import keyring.errors
from typer.testing import CliRunner

import config
import httpx
from main import app

runner = CliRunner()


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


class _Resp:
    def raise_for_status(self) -> None:
        return None


def test_configure_stores_the_pepper_in_the_keyring_and_says_so(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config, "CONFIG_FILE", tmp_path / "config.env")
    monkeypatch.delenv("PSAMVAULT_PEPPER", raising=False)
    monkeypatch.setattr(httpx, "get", lambda *_args, **_kwargs: _Resp())
    memory = _Memory()
    monkeypatch.setattr(config.keyring, "get_password", memory.get_password)
    monkeypatch.setattr(config.keyring, "set_password", memory.set_password)

    result = runner.invoke(app, ["configure"], input="\n")
    assert result.exit_code == 0, result.output
    text = (tmp_path / "config.env").read_text()
    assert "PSAMVAULT_API_URL=" in text
    assert "PSAMVAULT_PEPPER" not in text
    pepper = memory.data[("psamvault", "config.pepper")]
    assert len(pepper) == 64
    assert pepper not in text
    assert pepper not in result.output
    assert pepper[:8] not in result.output
    assert "OS keychain" in result.output
    assert "API URL only" in result.output
    assert "psamvault backup create" in result.output
    assert "Back up this file" not in result.output
    assert "stored in ~/.psamvault/config.env" not in result.output
    assert "losing it means losing access" not in result.output


def test_config_show_does_not_print_pepper_characters(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config, "CONFIG_FILE", tmp_path / "config.env")
    monkeypatch.delenv("PSAMVAULT_PEPPER", raising=False)
    monkeypatch.setattr(httpx, "get", lambda *_args, **_kwargs: _Resp())
    memory = _Memory()
    monkeypatch.setattr(config.keyring, "get_password", memory.get_password)
    monkeypatch.setattr(config.keyring, "set_password", memory.set_password)

    saved = runner.invoke(app, ["configure"], input="\n")
    assert saved.exit_code == 0, saved.output
    # configure does not put the pepper in the environment. config-show has to
    # read it back from the keychain, and still must not print it.
    os.environ.pop("PSAMVAULT_PEPPER", None)
    result = runner.invoke(app, ["config-show"])
    assert result.exit_code == 0, result.output
    pepper = memory.data[("psamvault", "config.pepper")]
    assert pepper not in result.output
    assert pepper[:8] not in result.output
    assert "OS keychain" in result.output
    assert "API URL only" in result.output
    assert "PSAMVAULT_PEPPER" not in (tmp_path / "config.env").read_text()


def test_existing_configuration_preview_does_not_print_the_pepper(monkeypatch, tmp_path):
    """The conftest pepper is already in the environment. Preview it, then cancel."""
    monkeypatch.setattr(config, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config, "CONFIG_FILE", tmp_path / "config.env")
    result = runner.invoke(app, ["configure"], input="n\n")
    assert result.exit_code == 0, result.output
    assert "Cancelled" in result.output
    assert "a" * 8 not in result.output
    assert "OS keychain" in result.output
    assert "Back up this file" not in result.output
    assert "stored in ~/.psamvault/config.env" not in result.output
