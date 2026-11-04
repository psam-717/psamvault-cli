"""psamvault policy — which MCP tools may use a stored secret.

allow_hosts is where a secret may be sent. allow_tools is which MCP tool may
use it. Granting, revoking, the ask-each-time flag and the enforcement switch
are a human at a terminal. Listing is not a grant.
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
    monkeypatch.setattr(session, "is_logged_in", lambda: False)


def as_human_terminal(monkeypatch):
    monkeypatch.setattr(caller, "tty_present", lambda: True)


def confirm_yes(monkeypatch):
    monkeypatch.setattr("typer.confirm", lambda *args, **kwargs: True)


def confirm_no(monkeypatch):
    monkeypatch.setattr("typer.confirm", lambda *args, **kwargs: False)


def write_policy(path: Path, body: dict) -> None:
    path.write_text(json.dumps(body), encoding="utf-8")


def test_policy_group_lists_the_mcp_commands():
    result = runner.invoke(app, ["policy"])
    assert result.exit_code == 0, result.output
    for name in ("allow-tool", "remove-tool", "tools", "ask-each-time", "mcp-use"):
        assert name in result.output


def test_a_human_grants_a_tool_and_the_trail_records_it(monkeypatch):
    as_human_terminal(monkeypatch)
    confirm_yes(monkeypatch)
    result = runner.invoke(app, ["policy", "allow-tool", "ledger-key", "Use_Credential"])
    assert result.exit_code == 0, result.output
    assert "use_credential" in result.output
    assert "audit" in result.output
    assert SECRET not in result.output
    saved = json.loads(policy.POLICY_FILE.read_text(encoding="utf-8"))
    assert saved["entries"]["ledger-key"]["allow_tools"] == ["use_credential"]
    assert "mcp_use" not in saved
    row = audit.read(audit.AUDIT_FILE)[-1]
    assert row["command"] == "policy allow-tool"
    assert row["decision"] == "granted"
    assert row["entry"] == "ledger-key"
    assert row["tool"] == "use_credential"
    assert row["caller"] == "human"
    assert "host" not in row
    assert SECRET not in json.dumps(row)


def test_a_pipe_cannot_answer_the_tool_confirmation(monkeypatch):
    monkeypatch.setattr(caller, "tty_present", lambda: False)
    called = {"confirm": False}

    def explode(*args, **kwargs):
        called["confirm"] = True
        return True

    monkeypatch.setattr("typer.confirm", explode)
    for argv in (
        ["policy", "allow-tool", "ledger-key", "use_credential"],
        ["policy", "ask-each-time", "ledger-key", "on"],
        ["policy", "mcp-use", "enforce"],
    ):
        called["confirm"] = False
        result = runner.invoke(app, argv)
        assert result.exit_code == 1, result.output
        assert "real terminal" in result.output
        assert called["confirm"] is False
    assert not policy.POLICY_FILE.exists()
    assert audit.read(audit.AUDIT_FILE) == []


def test_cancelling_writes_nothing(monkeypatch):
    as_human_terminal(monkeypatch)
    confirm_no(monkeypatch)
    result = runner.invoke(app, ["policy", "allow-tool", "ledger-key", "browser_login"])
    assert result.exit_code == 1
    assert "Cancelled" in result.output
    assert not policy.POLICY_FILE.exists()
    assert audit.read(audit.AUDIT_FILE) == []


@pytest.mark.parametrize(
    "argv",
    [
        ["policy", "allow-tool", "ledger-key", "run_with_credential"],
        ["policy", "remove-tool", "ledger-key", "use_credential"],
        ["policy", "ask-each-time", "ledger-key", "on"],
        ["policy", "mcp-use", "enforce"],
    ],
)
def test_an_agent_cannot_change_the_mcp_policy(monkeypatch, argv):
    as_human_terminal(monkeypatch)
    confirm_yes(monkeypatch)
    monkeypatch.setenv("PSAMVAULT_AGENT", "1")
    write_policy(
        policy.POLICY_FILE,
        {"entries": {"ledger-key": {"allow_tools": ["use_credential"], "allow_hosts": ["api.ledger.example"]}}},
    )
    before = policy.POLICY_FILE.read_bytes()
    result = runner.invoke(app, argv)
    assert result.exit_code == 1, result.output
    assert "blocked" in result.output
    assert "agent" in result.output.lower()
    assert policy.POLICY_FILE.read_bytes() == before
    row = audit.read(audit.AUDIT_FILE)[-1]
    assert row["decision"] == "deny"
    assert row["caller"] == "agent"
    assert SECRET not in json.dumps(row)


def test_the_agent_flag_is_the_same_refusal(monkeypatch):
    as_human_terminal(monkeypatch)
    confirm_yes(monkeypatch)
    result = runner.invoke(app, ["--agent", "policy", "allow-tool", "ledger-key", "use_credential"])
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
    result = runner.invoke(app, ["policy", "mcp-use", "enforce"])
    assert result.exit_code == 1, result.output
    assert "blocked" in result.output
    assert not policy.POLICY_FILE.exists()
    row = audit.read(audit.AUDIT_FILE)[-1]
    assert row["caller"] == "agent"
    assert any("ancestry:" in signal for signal in row["signals"])


@pytest.mark.parametrize("tool", ["list_api_keys", "use_credental", "get_version"])
def test_a_tool_that_does_not_use_a_secret_is_refused_before_confirm(monkeypatch, tool):
    as_human_terminal(monkeypatch)
    called = {"confirm": False}
    monkeypatch.setattr("typer.confirm", lambda *args, **kwargs: called.__setitem__("confirm", True) or True)
    result = runner.invoke(app, ["policy", "allow-tool", "ledger-key", tool])
    assert result.exit_code == 1, result.output
    assert tool in result.output
    assert "stored secret" in result.output
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

    result = runner.invoke(app, ["policy", "allow-tool", "ledger-key", "export_key_to_env_file"])
    assert result.exit_code == 0, result.output
    assert "No vault entry named 'ledger-key'" in result.output
    assert SECRET not in result.output
    saved = json.loads(policy.POLICY_FILE.read_text(encoding="utf-8"))
    assert saved["entries"]["ledger-key"]["allow_tools"] == ["export_key_to_env_file"]


def test_a_lookup_that_returns_a_secret_never_prints_it(monkeypatch):
    as_human_terminal(monkeypatch)
    confirm_yes(monkeypatch)
    monkeypatch.setattr(session, "is_logged_in", lambda: True)
    monkeypatch.setattr("api_client.ensure_session", lambda: {"access_token": "t", "refresh_token": "r"})
    monkeypatch.setattr(
        "api_client.get_vault_entry",
        lambda **kwargs: {"site_name": "ledger.example", "password": SECRET, "notes": SECRET},
    )
    result = runner.invoke(app, ["policy", "allow-tool", "ledger.example", "verify_api_key"])
    assert result.exit_code == 0, result.output
    assert SECRET not in result.output
    blob = policy.POLICY_FILE.read_text(encoding="utf-8") + json.dumps(audit.read(audit.AUDIT_FILE))
    assert SECRET not in blob


def test_remove_ask_and_list(monkeypatch):
    as_human_terminal(monkeypatch)
    confirm_yes(monkeypatch)
    write_policy(
        policy.POLICY_FILE,
        {
            "reveal": "strict",
            "mcp_use": "enforce",
            "entries": {
                "ledger-key": {
                    "allow_hosts": ["api.ledger.example"],
                    "allow_tools": ["use_credential", "browser_login"],
                    "ask_each_time": True,
                },
                "github.com": {"allow_tools": ["run_with_credential"]},
            },
        },
    )
    listed = runner.invoke(app, ["policy", "tools"])
    assert listed.exit_code == 0, listed.output
    assert "mcp_use: enforce" in listed.output
    assert "use_credential" in listed.output
    assert "browser_login" in listed.output
    assert "run_with_credential" in listed.output
    assert "ask_each_time: yes" in listed.output
    assert "api.ledger.example" not in listed.output

    one = runner.invoke(app, ["policy", "tools", "github.com"])
    assert one.exit_code == 0, one.output
    assert "run_with_credential" in one.output
    assert "use_credential" not in one.output

    removed = runner.invoke(app, ["policy", "remove-tool", "ledger-key", "browser_login"])
    assert removed.exit_code == 0, removed.output
    saved = json.loads(policy.POLICY_FILE.read_text(encoding="utf-8"))
    assert saved["reveal"] == "strict"
    assert saved["mcp_use"] == "enforce"
    assert saved["entries"]["ledger-key"]["allow_hosts"] == ["api.ledger.example"]
    assert saved["entries"]["ledger-key"]["allow_tools"] == ["use_credential"]
    assert saved["entries"]["ledger-key"]["ask_each_time"] is True
    row = audit.read(audit.AUDIT_FILE)[-1]
    assert row["command"] == "policy remove-tool"
    assert row["decision"] == "revoked"
    assert row["tool"] == "browser_login"

    asked = runner.invoke(app, ["policy", "ask-each-time", "github.com", "off"])
    assert asked.exit_code == 0, asked.output
    saved = json.loads(policy.POLICY_FILE.read_text(encoding="utf-8"))
    assert saved["entries"]["github.com"]["ask_each_time"] is False
    assert saved["entries"]["github.com"]["allow_tools"] == ["run_with_credential"]
    ask_row = audit.read(audit.AUDIT_FILE)[-1]
    assert ask_row["command"] == "policy ask-each-time"
    assert ask_row["decision"] == "set"
    assert ask_row["ask"] is False
    assert ask_row["entry"] == "github.com"


def test_an_agent_may_list_tools_and_the_mode(monkeypatch):
    monkeypatch.setenv("PSAMVAULT_AGENT", "1")
    write_policy(
        policy.POLICY_FILE,
        {"entries": {"ledger-key": {"allow_tools": ["use_credential"], "ask_each_time": True}}},
    )
    listed = runner.invoke(app, ["policy", "tools"])
    assert listed.exit_code == 0, listed.output
    assert "use_credential" in listed.output
    assert "mcp_use: audit" in listed.output
    shown = runner.invoke(app, ["policy", "mcp-use"])
    assert shown.exit_code == 0, shown.output
    assert "audit" in shown.output
    assert "not refused" in shown.output
    assert audit.read(audit.AUDIT_FILE) == []


def test_enforce_names_the_lockout_before_it_writes(monkeypatch):
    as_human_terminal(monkeypatch)
    confirm_yes(monkeypatch)
    write_policy(policy.POLICY_FILE, {"reveal": "human-only", "entries": {"ledger-key": {"allow_hosts": ["api.ledger.example"]}}})
    result = runner.invoke(app, ["policy", "mcp-use", "enforce"])
    assert result.exit_code == 0, result.output
    assert "No entry lists a tool" in result.output
    assert "refused" in result.output
    saved = json.loads(policy.POLICY_FILE.read_text(encoding="utf-8"))
    assert saved["mcp_use"] == "enforce"
    assert saved["reveal"] == "human-only"
    assert saved["entries"]["ledger-key"]["allow_hosts"] == ["api.ledger.example"]
    row = audit.read(audit.AUDIT_FILE)[-1]
    assert row["command"] == "policy mcp-use"
    assert row["decision"] == "set"
    assert row["mcp_use"] == "enforce"
    assert row["entry"] is None


def test_a_bad_mode_does_not_ask_or_write(monkeypatch):
    as_human_terminal(monkeypatch)
    called = {"confirm": False}
    monkeypatch.setattr("typer.confirm", lambda *args, **kwargs: called.__setitem__("confirm", True) or True)
    write_policy(policy.POLICY_FILE, {"mcp_use": "audit"})
    before = policy.POLICY_FILE.read_bytes()
    result = runner.invoke(app, ["policy", "mcp-use", "sometimes"])
    assert result.exit_code == 1, result.output
    assert "audit" in result.output and "enforce" in result.output
    assert called["confirm"] is False
    assert policy.POLICY_FILE.read_bytes() == before


def test_pv_lists_tools_like_psamvault(tmp_path, monkeypatch):
    pv = Path(sys.executable).parent / "pv"
    if not pv.exists():
        pytest.skip("pv is not installed next to this interpreter")
    home = tmp_path / "home"
    config = home / ".psamvault"
    config.mkdir(parents=True)
    (config / "policy.json").write_text(
        json.dumps({"mcp_use": "audit", "entries": {"ledger-key": {"allow_tools": ["use_credential"]}}}),
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
        [str(pv), "policy", "tools", "ledger-key"],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "use_credential" in completed.stdout
    assert "mcp_use: audit" in completed.stdout
