"""Policy loading and the allow/deny matrix.

The matrix is the whole point of the module, so it is tested exhaustively: three
modes × three caller verdicts, plus the entry allowlist that overrides both.
"""
import json

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
