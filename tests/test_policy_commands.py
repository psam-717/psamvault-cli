"""psamvault policy — human grants of destination hosts.

allow_entries is the reveal list. These commands edit entries.*.allow_hosts,
which is the destination list the MCP reads. An agent can list it and cannot
change it.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

import audit
import caller
import policy
import session
from main import app

runner = CliRunner()

SECRET = "SUPERSECRET-VALUE-should-never-print"


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    """A developer session must not turn a policy edit into an API call."""
    monkeypatch.setattr(session, "is_logged_in", lambda: False)


def as_human_terminal(monkeypatch):
    monkeypatch.setattr(caller, "tty_present", lambda: True)


def confirm_yes(monkeypatch):
    monkeypatch.setattr("typer.confirm", lambda *args, **kwargs: True)


def confirm_no(monkeypatch):
    monkeypatch.setattr("typer.confirm", lambda *args, **kwargs: False)


def write_policy(path: Path, body: dict) -> None:
    path.write_text(json.dumps(body), encoding="utf-8")


def test_policy_group_lists_the_three_commands():
    result = runner.invoke(app, ["policy"])
    assert result.exit_code == 0, result.output
    for name in ("allow-host", "remove-host", "hosts"):
        assert name in result.output


def test_root_help_mentions_the_policy_group():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "policy" in result.output


def test_a_human_grants_a_host_and_the_trail_records_it(monkeypatch):
    as_human_terminal(monkeypatch)
    confirm_yes(monkeypatch)
    result = runner.invoke(app, ["policy", "allow-host", "ledger-key", "API.Ledger.Example."])
    assert result.exit_code == 0, result.output
    assert "api.ledger.example" in result.output
    assert "ledger-key" in result.output
    assert SECRET not in result.output
    saved = json.loads(policy.POLICY_FILE.read_text(encoding="utf-8"))
    assert saved["entries"]["ledger-key"]["allow_hosts"] == ["api.ledger.example"]
    row = audit.read(audit.AUDIT_FILE)[-1]
    assert row["command"] == "policy allow-host"
    assert row["decision"] == "granted"
    assert row["entry"] == "ledger-key"
    assert row["host"] == "api.ledger.example"
    assert row["caller"] == "human"
    assert SECRET not in json.dumps(row)


def test_a_pipe_cannot_answer_the_confirmation(monkeypatch):
    monkeypatch.setattr(caller, "tty_present", lambda: False)
    called = {"confirm": False}

    def explode(*args, **kwargs):
        called["confirm"] = True
        return True

    monkeypatch.setattr("typer.confirm", explode)
    result = runner.invoke(app, ["policy", "allow-host", "ledger-key", "api.ledger.example"])
    assert result.exit_code == 1
    assert "real terminal" in result.output
    assert called["confirm"] is False
    assert not policy.POLICY_FILE.exists()
    assert audit.read(audit.AUDIT_FILE) == []


def test_cancelling_writes_nothing(monkeypatch):
    as_human_terminal(monkeypatch)
    confirm_no(monkeypatch)
    result = runner.invoke(app, ["policy", "allow-host", "ledger-key", "api.ledger.example"])
    assert result.exit_code == 1
    assert "Cancelled" in result.output
    assert not policy.POLICY_FILE.exists()
    assert audit.read(audit.AUDIT_FILE) == []


@pytest.mark.parametrize(
    "env",
    [
        {"PSAMVAULT_AGENT": "1"},
        {"AI_AGENT": "hermes-agent"},
        {"HERMES_AGENT": "true"},
        {"CLAUDECODE": "1"},
        {"TERMINAL_CWD": "/tmp/agent"},
    ],
)
def test_an_agent_marker_cannot_grant_or_remove(monkeypatch, env):
    as_human_terminal(monkeypatch)
    confirm_yes(monkeypatch)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    write_policy(policy.POLICY_FILE, {"entries": {"ledger-key": {"allow_hosts": ["api.ledger.example"]}}})
    before = policy.POLICY_FILE.read_bytes()

    granted = runner.invoke(app, ["policy", "allow-host", "ledger-key", "files.ledger.example"])
    assert granted.exit_code == 1, granted.output
    assert "blocked" in granted.output
    assert "agent" in granted.output.lower()
    assert policy.POLICY_FILE.read_bytes() == before

    removed = runner.invoke(app, ["policy", "remove-host", "ledger-key", "api.ledger.example"])
    assert removed.exit_code == 1, removed.output
    assert "blocked" in removed.output
    assert policy.POLICY_FILE.read_bytes() == before

    rows = audit.read(audit.AUDIT_FILE)
    assert len(rows) == 2
    assert {row["command"] for row in rows} == {"policy allow-host", "policy remove-host"}
    assert {row["decision"] for row in rows} == {"deny"}
    assert {row["caller"] for row in rows} == {"agent"}


def test_the_agent_flag_is_the_same_refusal(monkeypatch):
    as_human_terminal(monkeypatch)
    confirm_yes(monkeypatch)
    result = runner.invoke(app, ["--agent", "policy", "allow-host", "ledger-key", "api.ledger.example"])
    assert result.exit_code == 1, result.output
    assert "blocked" in result.output
    assert not policy.POLICY_FILE.exists()
    row = audit.read(audit.AUDIT_FILE)[-1]
    assert row["decision"] == "deny"
    assert any(signal.startswith("explicit:PSAMVAULT_AGENT") for signal in row["signals"])


def test_ancestry_classifies_the_caller_as_an_agent(monkeypatch):
    import ancestry

    as_human_terminal(monkeypatch)
    confirm_yes(monkeypatch)
    monkeypatch.setattr(
        caller,
        "_probe_ancestry",
        lambda: ancestry.AncestryResult(is_agent=True, matched_hint="hermes-agent/venv", depth=2),
    )
    result = runner.invoke(app, ["policy", "allow-host", "ledger-key", "api.ledger.example"])
    assert result.exit_code == 1, result.output
    assert "blocked" in result.output
    assert not policy.POLICY_FILE.exists()
    row = audit.read(audit.AUDIT_FILE)[-1]
    assert row["caller"] == "agent"
    assert any("ancestry:" in signal for signal in row["signals"])


@pytest.mark.parametrize("host", ["127.0.0.1", "com", "co.uk"])
def test_validation_refusals_do_not_write_or_ask(monkeypatch, host):
    as_human_terminal(monkeypatch)
    called = {"confirm": False}
    monkeypatch.setattr("typer.confirm", lambda *args, **kwargs: called.__setitem__("confirm", True) or True)
    result = runner.invoke(app, ["policy", "allow-host", "ledger-key", host])
    assert result.exit_code == 1, result.output
    assert host in result.output
    assert called["confirm"] is False
    assert not policy.POLICY_FILE.exists()
    assert audit.read(audit.AUDIT_FILE) == []


def test_a_missing_entry_is_a_warning_and_the_grant_still_proceeds(monkeypatch):
    from errors import NotFoundError

    as_human_terminal(monkeypatch)
    confirm_yes(monkeypatch)
    monkeypatch.setattr(session, "is_logged_in", lambda: True)
    monkeypatch.setattr("api_client.ensure_session", lambda: {"access_token": "t", "refresh_token": "r"})

    def missing(**kwargs):
        assert SECRET not in json.dumps(kwargs)
        raise NotFoundError("no")

    for reader in ("get_vault_entry", "get_api_key_entry", "get_note_entry"):
        monkeypatch.setattr(f"api_client.{reader}", missing)

    result = runner.invoke(app, ["policy", "allow-host", "ledger-key", "api.ledger.example"])
    assert result.exit_code == 0, result.output
    assert "No vault entry named 'ledger-key'" in result.output
    assert SECRET not in result.output
    saved = json.loads(policy.POLICY_FILE.read_text(encoding="utf-8"))
    assert saved["entries"]["ledger-key"]["allow_hosts"] == ["api.ledger.example"]


def test_a_lookup_that_returns_a_secret_never_prints_it(monkeypatch):
    as_human_terminal(monkeypatch)
    confirm_yes(monkeypatch)
    monkeypatch.setattr(session, "is_logged_in", lambda: True)
    monkeypatch.setattr("api_client.ensure_session", lambda: {"access_token": "t", "refresh_token": "r"})
    monkeypatch.setattr(
        "api_client.get_vault_entry",
        lambda **kwargs: {"site_name": "ledger.example", "password": SECRET, "notes": SECRET},
    )
    result = runner.invoke(app, ["policy", "allow-host", "ledger.example", "api.ledger.example"])
    assert result.exit_code == 0, result.output
    assert SECRET not in result.output
    assert "No vault entry" not in result.output
    blob = policy.POLICY_FILE.read_text(encoding="utf-8") + json.dumps(audit.read(audit.AUDIT_FILE))
    assert SECRET not in blob


def test_remove_and_list_per_entry_and_overall(monkeypatch):
    as_human_terminal(monkeypatch)
    confirm_yes(monkeypatch)
    write_policy(
        policy.POLICY_FILE,
        {
            "reveal": "strict",
            "allow_entries": ["github.com"],
            "entries": {
                "ledger-key": {"allow_hosts": ["api.ledger.example", "files.ledger.example"]},
                "github.com": {"allow_hosts": ["*.ghcr.io"]},
            },
        },
    )
    listed = runner.invoke(app, ["policy", "hosts"])
    assert listed.exit_code == 0, listed.output
    assert "api.ledger.example" in listed.output
    assert "files.ledger.example" in listed.output
    assert "*.ghcr.io" in listed.output

    one = runner.invoke(app, ["policy", "hosts", "github.com"])
    assert one.exit_code == 0, one.output
    assert "*.ghcr.io" in one.output
    assert "api.ledger.example" not in one.output

    removed = runner.invoke(app, ["policy", "remove-host", "ledger-key", "files.ledger.example"])
    assert removed.exit_code == 0, removed.output
    saved = json.loads(policy.POLICY_FILE.read_text(encoding="utf-8"))
    assert saved["reveal"] == "strict"
    assert saved["allow_entries"] == ["github.com"]
    assert saved["entries"]["ledger-key"]["allow_hosts"] == ["api.ledger.example"]
    assert saved["entries"]["github.com"]["allow_hosts"] == ["*.ghcr.io"]
    row = audit.read(audit.AUDIT_FILE)[-1]
    assert row["command"] == "policy remove-host"
    assert row["decision"] == "revoked"
    assert row["host"] == "files.ledger.example"
    assert row["entry"] == "ledger-key"

    again = runner.invoke(app, ["policy", "hosts", "LEDGER-KEY"])
    assert again.exit_code == 0, again.output
    assert "api.ledger.example" in again.output
    assert "files.ledger.example" not in again.output


def test_an_agent_may_list(monkeypatch):
    monkeypatch.setenv("PSAMVAULT_AGENT", "1")
    write_policy(policy.POLICY_FILE, {"entries": {"ledger-key": {"allow_hosts": ["api.ledger.example"]}}})
    result = runner.invoke(app, ["policy", "hosts"])
    assert result.exit_code == 0, result.output
    assert "api.ledger.example" in result.output
    assert audit.read(audit.AUDIT_FILE) == []


def test_list_reports_a_bad_stored_host(monkeypatch):
    monkeypatch.setenv("PSAMVAULT_AGENT", "1")
    write_policy(
        policy.POLICY_FILE,
        {"entries": {"ledger-key": {"allow_hosts": ["api.ledger.example", "127.0.0.1", "com"]}}},
    )
    result = runner.invoke(app, ["policy", "hosts", "ledger-key"])
    assert result.exit_code == 0, result.output
    assert "api.ledger.example" in result.output
    assert "127.0.0.1" in result.output
    assert "com" in result.output
    assert "public suffix" in result.output


def test_pv_lists_hosts_like_psamvault(tmp_path, monkeypatch):
    """`pv` is the same entry point. A real subprocess is the check that it is installed as one."""
    pv = Path(sys.executable).parent / "pv"
    if not pv.exists():
        pytest.skip("pv is not installed next to this interpreter")
    home = tmp_path / "home"
    home.mkdir()
    config = home / ".psamvault"
    config.mkdir()
    (config / "policy.json").write_text(
        json.dumps({"entries": {"ledger-key": {"allow_hosts": ["api.ledger.example"]}}}),
        encoding="utf-8",
    )
    env = os.environ.copy()
    env["HOME"] = str(home)
    for name in (
        "PSAMVAULT_AGENT",
        "AI_AGENT",
        "HERMES_AGENT",
        "CLAUDECODE",
        "CLAUDE_CODE_ENTRYPOINT",
        "TERMINAL_CWD",
        "TERMINAL_ENV",
    ):
        env.pop(name, None)
    completed = subprocess.run(
        [str(pv), "policy", "hosts", "ledger-key"],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "api.ledger.example" in completed.stdout
