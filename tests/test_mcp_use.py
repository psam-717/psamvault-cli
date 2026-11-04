"""Per-entry MCP tool policy: schema, rollout mode, and the decision the MCP copies.

``mcp_use`` absent means ``audit``. An unlisted tool is recorded and not refused
until a human sets ``enforce``. Loading an older file does not warn and does
not rewrite it.
"""
import json
import os

import pytest

import audit
import mcp_use
import policy


def write_policy(tmp_path, body, name="policy.json"):
    target = tmp_path / name
    target.write_text(json.dumps(body) if not isinstance(body, str) else body, encoding="utf-8")
    return target


def test_the_consuming_tools_are_the_contract():
    """Discovery tools are not in this list. They do not decrypt a secret."""
    assert mcp_use.TOOLS == (
        "use_credential",
        "run_with_credential",
        "browser_login",
        "export_key_to_mcp_config",
        "export_key_to_env_file",
        "verify_api_key",
    )
    assert "list_api_keys" not in mcp_use.TOOLS
    assert "get_username_for_site" not in mcp_use.TOOLS
    assert "scan_and_protect" not in mcp_use.TOOLS


def test_absent_file_is_audit_and_does_not_refuse(tmp_path):
    loaded = policy.load(tmp_path / "nope.json")
    assert loaded.mcp_use == mcp_use.MODE_AUDIT
    assert loaded.entry_tools == {}
    assert loaded.entry_ask == {}
    plan = policy.mcp_plan(loaded, "ledger-key", "use_credential")
    assert plan.decision == policy.ALLOW
    assert plan.reason == mcp_use.REASON_NOT_LISTED
    assert plan.ask is False
    assert plan.mcp_use == "audit"


def test_older_file_without_mcp_keys_still_loads_and_is_not_rewritten(tmp_path):
    target = write_policy(
        tmp_path,
        {
            "reveal": "strict",
            "allow_entries": ["github.com"],
            "entries": {"ledger-key": {"allow_hosts": ["api.ledger.example"], "allow_commands": ["curl"]}},
        },
    )
    if os.name == "posix":
        os.chmod(target, 0o600)
    before = target.read_bytes()
    loaded = policy.load(target)
    assert loaded.reveal == policy.MODE_STRICT
    assert loaded.entry_hosts["ledger-key"] == ["api.ledger.example"]
    assert loaded.mcp_use == "audit"
    assert loaded.entry_tools == {}
    assert loaded.entry_ask == {}
    assert loaded.warnings == []
    assert target.read_bytes() == before
    plan = policy.mcp_plan(loaded, "LEDGER-KEY", "browser_login")
    assert plan.decision == policy.ALLOW
    assert plan.reason == "not-listed"
    assert "curl" not in plan.reason


def test_unknown_mcp_use_falls_back_to_audit_with_a_warning(tmp_path):
    loaded = policy.load(write_policy(tmp_path, {"mcp_use": "enforced"}))
    assert loaded.mcp_use == "audit"
    assert any("mcp_use" in warning for warning in loaded.warnings)


def test_allow_tools_are_normalised_and_bad_tokens_are_reported(tmp_path):
    body = {
        "mcp_use": "enforce",
        "entries": {
            "ledger-key": {
                "allow_hosts": ["api.ledger.example"],
                "allow_commands": ["curl"],
                "allow_tools": ["Use_Credential", "use_credential", "list_api_keys", "not a tool", ""],
                "ask_each_time": "yes",
            }
        },
    }
    target = write_policy(tmp_path, body)
    before = target.read_bytes()
    loaded = policy.load(target)
    assert loaded.mcp_use == "enforce"
    assert loaded.entry_tools["ledger-key"] == ["use_credential", "list_api_keys"]
    assert loaded.entry_ask["ledger-key"] is False
    assert loaded.entry_hosts["ledger-key"] == ["api.ledger.example"]
    text = "\n".join(loaded.warnings)
    assert "list_api_keys" in text
    assert "not a tool" in text
    assert "ask_each_time" in text
    assert target.read_bytes() == before


def test_allow_tools_of_the_wrong_shape_warns_and_keeps_reveal_policy(tmp_path):
    loaded = policy.load(
        write_policy(tmp_path, {"reveal": "strict", "entries": {"ledger-key": {"allow_tools": "use_credential"}}})
    )
    assert loaded.reveal == policy.MODE_STRICT
    assert loaded.entry_tools.get("ledger-key", []) == []
    assert any("allow_tools must be a list" in warning for warning in loaded.warnings)


@pytest.mark.parametrize(
    ("mode", "tools", "tool", "decision", "reason"),
    [
        ("enforce", ["use_credential"], "use_credential", "allow", "listed"),
        ("enforce", ["use_credential"], "browser_login", "deny", "not-listed"),
        ("enforce", [], "use_credential", "deny", "not-listed"),
        ("audit", [], "export_key_to_env_file", "allow", "not-listed"),
        ("audit", ["verify_api_key"], "verify_api_key", "allow", "listed"),
        ("off", [], "run_with_credential", "allow", "mcp-use-off"),
        ("off", ["use_credential"], "browser_login", "allow", "mcp-use-off"),
    ],
)
def test_decide_matches_the_rollout_matrix(mode, tools, tool, decision, reason):
    assert mcp_use.decide(mode, tools, tool) == (decision, reason)


def test_a_leaf_name_matches_the_way_allow_hosts_already_does(tmp_path):
    """project/.env/KEY is the same policy entry as KEY. Several matches union."""
    loaded = policy.load(
        write_policy(
            tmp_path,
            {
                "mcp_use": "enforce",
                "entries": {
                    "KEY": {"allow_tools": ["use_credential"], "ask_each_time": True},
                    "project/.env/KEY": {"allow_tools": ["browser_login"]},
                },
            },
        )
    )
    listed = policy.mcp_plan(loaded, "project/.env/KEY", "use_credential")
    assert (listed.decision, listed.reason, listed.ask) == ("allow", "listed", True)
    also = policy.mcp_plan(loaded, "project/.env/KEY", "browser_login")
    assert (also.decision, also.reason) == ("allow", "listed")
    refused = policy.mcp_plan(loaded, "project/.env/KEY", "run_with_credential")
    assert (refused.decision, refused.reason, refused.ask) == ("deny", "not-listed", False)


def test_ask_each_time_does_not_turn_a_refusal_into_an_allow(tmp_path):
    loaded = policy.load(
        write_policy(
            tmp_path,
            {
                "mcp_use": "enforce",
                "entries": {"ledger-key": {"allow_tools": ["use_credential"], "ask_each_time": True}},
            },
        )
    )
    listed = policy.mcp_plan(loaded, "ledger-key", "use_credential")
    assert (listed.decision, listed.reason, listed.ask) == ("allow", "listed", True)
    refused = policy.mcp_plan(loaded, "ledger-key", "browser_login")
    assert (refused.decision, refused.reason, refused.ask) == ("deny", "not-listed", False)

    off = policy.load(
        write_policy(
            tmp_path,
            {"mcp_use": "off", "entries": {"ledger-key": {"ask_each_time": True}}},
            name="off.json",
        )
    )
    plan = policy.mcp_plan(off, "ledger-key", "use_credential")
    assert (plan.decision, plan.reason, plan.ask) == ("allow", "mcp-use-off", False)


def test_finalize_applies_the_in_chat_answer_without_hiding_a_denial():
    assert mcp_use.finalize("allow", "listed", ask=True, accepted=True) == ("allow", "listed")
    assert mcp_use.finalize("allow", "listed", ask=True, accepted=False) == ("deny", "ask-declined")
    assert mcp_use.finalize("allow", "not-listed", ask=True, accepted=None) == ("deny", "ask-unanswered")
    assert mcp_use.finalize("deny", "not-listed", ask=True, accepted=True) == ("deny", "not-listed")
    assert mcp_use.finalize("allow", "mcp-use-off", ask=False, accepted=False) == ("allow", "mcp-use-off")


def test_add_allow_tool_preserves_other_keys_and_does_not_turn_enforcement_on(tmp_path):
    target = write_policy(
        tmp_path,
        {
            "reveal": "strict",
            "allow_entries": ["github.com"],
            "future_key": {"keep": True},
            "entries": {
                "GitHub.com": {
                    "allow_commands": ["git"],
                    "allow_hosts": ["api.github.com"],
                }
            },
        },
    )
    key, tool, changed = policy.add_allow_tool("github.com", "Use_Credential", path=target)
    assert changed is True
    assert key == "GitHub.com"
    assert tool == "use_credential"
    saved = json.loads(target.read_text(encoding="utf-8"))
    assert "mcp_use" not in saved
    assert saved["reveal"] == "strict"
    assert saved["future_key"] == {"keep": True}
    spec = saved["entries"]["GitHub.com"]
    assert spec["allow_hosts"] == ["api.github.com"]
    assert spec["allow_commands"] == ["git"]
    assert spec["allow_tools"] == ["use_credential"]
    if os.name == "posix":
        assert target.stat().st_mode & 0o077 == 0

    again = policy.add_allow_tool("github.com", "use_credential", path=target)
    assert again[2] is False


def test_add_allow_tool_refuses_a_tool_that_does_not_use_a_secret(tmp_path):
    target = write_policy(tmp_path, {"reveal": "open"})
    before = target.read_bytes()
    for tool in ("list_api_keys", "use_credental", "get_version", ""):
        with pytest.raises(policy.ToolRejected):
            policy.add_allow_tool("ledger-key", tool, path=target)
        assert target.read_bytes() == before


def test_remove_allow_tool_and_ask_flag_keep_hosts(tmp_path):
    target = write_policy(
        tmp_path,
        {
            "entries": {
                "ledger-key": {
                    "allow_hosts": ["api.ledger.example"],
                    "allow_tools": ["use_credential", "browser_login"],
                    "ask_each_time": False,
                }
            }
        },
    )
    key, removed = policy.remove_allow_tool("LEDGER-KEY", "Browser_Login", path=target)
    assert key == "ledger-key"
    assert removed == ["browser_login"]
    saved = json.loads(target.read_text(encoding="utf-8"))
    assert saved["entries"]["ledger-key"]["allow_hosts"] == ["api.ledger.example"]
    assert saved["entries"]["ledger-key"]["allow_tools"] == ["use_credential"]

    stored, enabled, changed = policy.set_ask_each_time("ledger-key", True, path=target)
    assert (stored, enabled, changed) == ("ledger-key", True, True)
    saved = json.loads(target.read_text(encoding="utf-8"))
    assert saved["entries"]["ledger-key"]["ask_each_time"] is True
    assert saved["entries"]["ledger-key"]["allow_hosts"] == ["api.ledger.example"]


def test_set_mcp_use_preserves_entries_and_refuses_a_bad_mode(tmp_path):
    target = write_policy(
        tmp_path,
        {"reveal": "human-only", "entries": {"ledger-key": {"allow_tools": ["use_credential"]}}},
    )
    mode, changed = policy.set_mcp_use("enforce", path=target)
    assert (mode, changed) == ("enforce", True)
    saved = json.loads(target.read_text(encoding="utf-8"))
    assert saved["mcp_use"] == "enforce"
    assert saved["reveal"] == "human-only"
    assert saved["entries"]["ledger-key"]["allow_tools"] == ["use_credential"]
    with pytest.raises(policy.McpUseRejected):
        policy.set_mcp_use("sometimes", path=target)
    assert json.loads(target.read_text(encoding="utf-8"))["mcp_use"] == "enforce"


def test_mcp_audit_row_names_entry_tool_decision_and_reason(tmp_path):
    target = tmp_path / "audit.jsonl"
    audit.record_mcp_use(
        tool="use_credential",
        entry="ledger-key",
        decision="deny",
        reason="not-listed",
        mcp_use="enforce",
        ask=True,
        path=target,
    )
    raw = target.read_text(encoding="utf-8")
    assert raw.endswith("\n")
    assert raw.count("\n") == 1
    # Compact JSON: separators are comma and colon, with no space after them.
    # The command value itself contains one space, the same way "policy allow-host" does.
    assert '", "' not in raw
    assert '": "' not in raw
    row = audit.read(target)[0]
    assert row["command"] == "mcp use_credential"
    assert row["entry"] == "ledger-key"
    assert row["tool"] == "use_credential"
    assert row["decision"] == "deny"
    assert row["reason"] == "not-listed"
    assert row["mcp_use"] == "enforce"
    assert row["ask"] is True
    assert row["caller"] == "mcp"
    assert row["signals"] == []
    assert row["tty"] is False
    assert row["policy"] is None
    assert row["token_id"] is None
    assert "host" not in row
    assert row["ts"].endswith("Z")
    if os.name == "posix":
        assert target.stat().st_mode & 0o077 == 0


def test_an_mcp_row_has_nowhere_to_put_a_secret(tmp_path):
    """reason and tool are closed fields. A free-text value is not written."""
    target = tmp_path / "audit.jsonl"
    secret = "SUPERSECRET-VALUE-should-never-print"
    audit.record_mcp_use(
        tool=secret,
        entry="ledger-key",
        decision="allow",
        reason=secret,
        mcp_use="audit",
        ask=False,
        path=target,
    )
    blob = target.read_text(encoding="utf-8") if target.exists() else ""
    assert secret not in blob
    for row in audit.read(target):
        assert row.get("reason") in mcp_use.REASONS


def test_a_reveal_row_omits_mcp_fields(tmp_path):
    target = tmp_path / "audit.jsonl"
    audit.record(command="get", decision="deny", entry="github.com", caller="agent", path=target)
    row = audit.read(target)[0]
    assert "tool" not in row
    assert "reason" not in row
    assert "mcp_use" not in row
    assert "ask" not in row
    assert "host" not in row
