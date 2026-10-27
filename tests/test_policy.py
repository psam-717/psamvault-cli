"""Policy loading and the allow/deny matrix.

The matrix is the whole point of the module, so it is tested exhaustively: three
modes × three caller verdicts, plus the entry allowlist that overrides both.
"""
import json
import os

import pytest

import policy


def write_policy(tmp_path, body, name="policy.json"):
    target = tmp_path / name
    if isinstance(body, str):
        target.write_text(body, encoding="utf-8")
    else:
        target.write_text(json.dumps(body), encoding="utf-8")
    return target


# ── Loading ───────────────────────────────────────────────────────────────


def test_absent_file_means_safe_defaults(tmp_path):
    loaded = policy.load(tmp_path / "nope.json")
    assert loaded.reveal == policy.MODE_HUMAN_ONLY
    assert loaded.allow_entries == []
    assert loaded.approval_ttl_seconds == 120
    assert loaded.audit is True
    assert loaded.source == "default"
    assert loaded.warnings == []


def test_valid_file_is_applied(tmp_path):
    target = write_policy(
        tmp_path,
        {"reveal": "strict", "allow_entries": ["github.com"], "approval_ttl_seconds": 300, "audit": False},
    )
    loaded = policy.load(target)
    assert loaded.reveal == policy.MODE_STRICT
    assert loaded.allow_entries == ["github.com"]
    assert loaded.approval_ttl_seconds == 300
    assert loaded.audit is False
    assert loaded.source == "file"


def test_malformed_json_falls_back_to_defaults_with_a_warning(tmp_path):
    loaded = policy.load(write_policy(tmp_path, "{not json"))
    assert loaded.reveal == policy.MODE_HUMAN_ONLY
    assert loaded.source == "default"
    assert loaded.warnings and "not valid JSON" in loaded.warnings[0]


def test_non_object_json_falls_back(tmp_path):
    loaded = policy.load(write_policy(tmp_path, "[1, 2, 3]"))
    assert loaded.reveal == policy.MODE_HUMAN_ONLY
    assert "JSON object" in loaded.warnings[0]


def test_unknown_mode_is_ignored_with_a_warning(tmp_path):
    loaded = policy.load(write_policy(tmp_path, {"reveal": "paranoid"}))
    assert loaded.reveal == policy.MODE_HUMAN_ONLY
    assert any("unknown reveal mode" in w for w in loaded.warnings)


def test_ttl_is_clamped_into_a_sane_window(tmp_path):
    assert policy.load(write_policy(tmp_path, {"approval_ttl_seconds": 1})).approval_ttl_seconds == 15
    assert policy.load(write_policy(tmp_path, {"approval_ttl_seconds": 99999})).approval_ttl_seconds == 3600
    assert policy.load(write_policy(tmp_path, {"approval_ttl_seconds": "junk"})).approval_ttl_seconds == 120


def test_allow_entries_must_be_a_list(tmp_path):
    loaded = policy.load(write_policy(tmp_path, {"allow_entries": "github.com"}))
    assert loaded.allow_entries == []
    assert any("allow_entries" in w for w in loaded.warnings)


def test_unreadable_file_never_raises(tmp_path):
    """A directory where the file should be: unreadable, so defaults + warning."""
    target = tmp_path / "policy.json"
    target.mkdir()
    loaded = policy.load(target)
    assert loaded.reveal == policy.MODE_HUMAN_ONLY
    assert loaded.warnings


def test_older_file_without_entries_still_loads(tmp_path):
    """A pre-allow_hosts file has no entries key. Loading it must not warn or rewrite it."""
    target = write_policy(
        tmp_path,
        {"reveal": "strict", "allow_entries": ["github.com"], "audit": False},
    )
    if os.name == "posix":
        os.chmod(target, 0o600)
    before = target.read_bytes()
    loaded = policy.load(target)
    assert loaded.reveal == policy.MODE_STRICT
    assert loaded.allow_entries == ["github.com"]
    assert loaded.entry_hosts == {}
    assert loaded.warnings == []
    assert target.read_bytes() == before


def test_allow_hosts_are_validated_and_bad_values_are_reported(tmp_path):
    """entries.*.allow_hosts is read. A bad host is named. The file is not rewritten."""
    body = {
        "reveal": "human-only",
        "allow_entries": ["github.com"],
        "entries": {
            "ledger-key": {
                "allow_commands": ["curl"],
                "allow_hosts": [
                    "API.Ledger.Example.",
                    "https://files.ledger.example/v1",
                    "127.0.0.1",
                    "com",
                    "co.uk",
                    "*.co.uk",
                ],
            }
        },
    }
    target = write_policy(tmp_path, body)
    before = target.read_bytes()
    loaded = policy.load(target)
    assert loaded.reveal == policy.MODE_HUMAN_ONLY
    assert loaded.allow_entries == ["github.com"]
    assert loaded.entry_hosts["ledger-key"] == [
        "api.ledger.example",
        "files.ledger.example",
    ]
    text = "\n".join(loaded.warnings)
    assert "127.0.0.1" in text
    assert "loopback" in text
    assert "com" in text and "public suffix" in text
    assert "co.uk" in text
    assert target.read_bytes() == before


def test_entries_of_the_wrong_shape_warn_and_keep_reveal_policy(tmp_path):
    loaded = policy.load(write_policy(tmp_path, {"reveal": "strict", "entries": ["nope"]}))
    assert loaded.reveal == policy.MODE_STRICT
    assert loaded.entry_hosts == {}
    assert any("entries must be an object" in warning for warning in loaded.warnings)

    loaded = policy.load(
        write_policy(tmp_path, {"entries": {"ledger-key": {"allow_hosts": "api.ledger.example"}}})
    )
    assert loaded.entry_hosts.get("ledger-key", []) == []
    assert any("allow_hosts must be a list" in warning for warning in loaded.warnings)


def test_add_allow_host_preserves_other_keys_and_is_owner_only(tmp_path):
    target = write_policy(
        tmp_path,
        {
            "reveal": "strict",
            "allow_entries": ["github.com"],
            "approval_ttl_seconds": 90,
            "audit": False,
            "future_key": {"keep": True},
            "entries": {
                "GitHub.com": {
                    "allow_commands": ["git"],
                    "allow_inject": ["bearer_token"],
                    "allow_hosts": ["api.github.com"],
                }
            },
        },
    )
    key, host, changed = policy.add_allow_host("github.com", "Uploads.GitHub.com.", path=target)
    assert changed is True
    assert key == "GitHub.com"
    assert host == "uploads.github.com"
    saved = json.loads(target.read_text(encoding="utf-8"))
    assert saved["reveal"] == "strict"
    assert saved["allow_entries"] == ["github.com"]
    assert saved["approval_ttl_seconds"] == 90
    assert saved["audit"] is False
    assert saved["future_key"] == {"keep": True}
    spec = saved["entries"]["GitHub.com"]
    assert spec["allow_commands"] == ["git"]
    assert spec["allow_inject"] == ["bearer_token"]
    assert spec["allow_hosts"] == ["api.github.com", "uploads.github.com"]
    assert "github.com" not in saved["entries"]
    if os.name == "posix":
        assert target.stat().st_mode & 0o077 == 0


def test_add_allow_host_refuses_a_bad_host_without_writing(tmp_path):
    target = write_policy(tmp_path, {"reveal": "open", "entries": {}})
    before = target.read_bytes()
    for host in ("127.0.0.1", "com", "co.uk", "*.co.uk", "https://api.example.com/v1"):
        with pytest.raises(policy.HostRejected):
            policy.add_allow_host("ledger-key", host, path=target)
        assert target.read_bytes() == before


def test_remove_allow_host_can_delete_a_value_the_grant_command_would_refuse(tmp_path):
    target = write_policy(
        tmp_path,
        {"entries": {"ledger-key": {"allow_hosts": ["127.0.0.1", "api.ledger.example"], "allow_commands": ["curl"]}}},
    )
    key, removed = policy.remove_allow_host("LEDGER-KEY", "127.0.0.1", path=target)
    assert key == "ledger-key"
    assert removed == ["127.0.0.1"]
    saved = json.loads(target.read_text(encoding="utf-8"))
    assert saved["entries"]["ledger-key"]["allow_hosts"] == ["api.ledger.example"]
    assert saved["entries"]["ledger-key"]["allow_commands"] == ["curl"]


# ── The decision matrix ───────────────────────────────────────────────────


def make(mode, **kwargs):
    return policy.Policy(reveal=mode, **kwargs)


def test_human_is_allowed_in_every_mode():
    for mode in policy.MODES:
        assert policy.decide(make(mode), "human") == policy.ALLOW


def test_agent_is_refused_by_default_and_allowed_only_when_open():
    assert policy.decide(make(policy.MODE_HUMAN_ONLY), "agent") == policy.DENY
    assert policy.decide(make(policy.MODE_STRICT), "agent") == policy.DENY
    assert policy.decide(make(policy.MODE_OPEN), "agent") == policy.ALLOW


def test_uncertain_is_allowed_by_default_and_refused_when_strict():
    """The rule that keeps every existing pipe and CliRunner test working."""
    assert policy.decide(make(policy.MODE_HUMAN_ONLY), "uncertain") == policy.ALLOW
    assert policy.decide(make(policy.MODE_STRICT), "uncertain") == policy.DENY
    assert policy.decide(make(policy.MODE_OPEN), "uncertain") == policy.ALLOW


def test_allowlisted_entry_overrides_a_refusal():
    strict = make(policy.MODE_STRICT, allow_entries=["github.com"])
    assert policy.decide(strict, "agent", "github.com") == policy.ALLOW
    assert policy.decide(strict, "agent", "gitlab.com") == policy.DENY


def test_allowlist_matching_is_case_insensitive_and_trimmed():
    loaded = make(policy.MODE_STRICT, allow_entries=[" github.com "])
    assert policy.decide(loaded, "agent", "GitHub.com") == policy.ALLOW


def test_allowlist_does_not_cover_a_whole_vault_dump():
    """An entry allowlist must never become a master key."""
    loaded = make(policy.MODE_STRICT, allow_entries=["github.com"])
    assert policy.decide(loaded, "agent", None) == policy.DENY
