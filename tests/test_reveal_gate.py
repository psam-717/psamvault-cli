"""The reveal gate: the allow/deny decisions, the token handover, and the trail.

Verdicts are injected, so these tests describe the gate's behaviour exactly
rather than depending on the machine the suite runs on. The classifier itself is
covered by ``test_caller.py`` and the live probe in the plan's step 1.
"""
import pytest

import audit
import caller
import policy
import reveal_gate
import session
from errors import RevealBlockedError


def verdict(kind, signals=None, tty=False):
    return caller.CallerVerdict(kind, list(signals or []), tty)


def agent():
    return verdict("agent", ["marker:AI_AGENT=hermes-agent"], tty=False)


def human():
    return verdict("human", [], tty=True)


def uncertain():
    return verdict("uncertain", [], tty=False)


def decisions(path):
    return [row["decision"] for row in audit.read(path)]


# ── Allowed paths ─────────────────────────────────────────────────────────


def test_a_human_reveal_is_allowed_and_audited(tmp_path):
    decision = reveal_gate.require_reveal("get", "github.com", verdict=human())
    assert decision.allowed is True
    assert decision.reason == "policy"
    assert decisions(audit.AUDIT_FILE) == ["allow"]


def test_an_uncertain_caller_is_allowed_by_default_and_marked_in_the_trail():
    decision = reveal_gate.require_reveal("get", "github.com", verdict=uncertain())
    assert decision.allowed is True
    row = audit.read(audit.AUDIT_FILE)[-1]
    assert row["caller"] == "uncertain"
    assert row["tty"] is False


def test_a_failed_fetch_before_the_gate_never_burns_a_token():
    """The gate is called at the emit point, not on entry — this is that rule."""
    import inspect

    source = inspect.getsource(reveal_gate.require_reveal)
    assert "consume_approval" in source  # the mechanism exists
    # and the commands call the gate only where they emit:
    import command.vault_commands as vault_commands

    body = inspect.getsource(vault_commands.get)
    assert body.index("require_reveal") > body.index("get_vault_entry")


# ── Refusals ──────────────────────────────────────────────────────────────


def test_an_agent_is_refused_by_default():
    with pytest.raises(RevealBlockedError) as excinfo:
        reveal_gate.require_reveal("get", "github.com", verdict=agent())
    assert "psamvault get is blocked" in excinfo.value.message
    assert "agent terminal detected" in excinfo.value.message
    assert decisions(audit.AUDIT_FILE) == ["deny"]


def test_the_refusal_names_the_entry_approval_and_the_capabilities():
    with pytest.raises(RevealBlockedError) as excinfo:
        reveal_gate.require_reveal("get", "github.com", verdict=agent())
    details = "\n".join(excinfo.value.details)
    assert "psamvault approve github.com --for-agent" in details
    assert "use_credential" in details
    assert "run_with_credential" in details
    assert "browser_login" in details


def test_the_refusal_does_not_teach_the_bypass():
    """The `--agent` escape hatch belongs in docs, not in the block message."""
    with pytest.raises(RevealBlockedError) as excinfo:
        reveal_gate.require_reveal("get", "github.com", verdict=agent())
    assert "--agent" not in "\n".join(excinfo.value.details)


def test_the_denied_row_names_the_matched_signal():
    with pytest.raises(RevealBlockedError):
        reveal_gate.require_reveal("ak-get", "openai-prod", verdict=agent())
    row = audit.read(audit.AUDIT_FILE)[-1]
    assert row["decision"] == "deny"
    assert row["entry"] == "openai-prod"
    assert row["signals"] == ["marker:AI_AGENT=hermes-agent"]
    assert row["caller"] == "agent"
    assert row["policy"] == "human-only"


def test_strict_mode_refuses_a_bare_pipe(tmp_path, monkeypatch):
    monkeypatch.setattr(policy, "POLICY_FILE", tmp_path / "policy.json")
    (tmp_path / "policy.json").write_text('{"reveal": "strict"}', encoding="utf-8")
    with pytest.raises(RevealBlockedError) as excinfo:
        reveal_gate.require_reveal("get", "github.com", verdict=uncertain())
    assert "policy mode is strict" in excinfo.value.message


def test_open_mode_allows_an_agent_but_still_audits(tmp_path, monkeypatch):
    monkeypatch.setattr(policy, "POLICY_FILE", tmp_path / "policy.json")
    (tmp_path / "policy.json").write_text('{"reveal": "open"}', encoding="utf-8")
    assert reveal_gate.require_reveal("get", "github.com", verdict=agent()).allowed is True
    assert decisions(audit.AUDIT_FILE) == ["allow"]


def test_an_allowlisted_entry_is_revealed_without_an_approval(tmp_path, monkeypatch):
    monkeypatch.setattr(policy, "POLICY_FILE", tmp_path / "policy.json")
    (tmp_path / "policy.json").write_text('{"allow_entries": ["github.com"]}', encoding="utf-8")
    assert reveal_gate.require_reveal("get", "github.com", verdict=agent()).allowed is True


# ── The approval handover ─────────────────────────────────────────────────


def test_a_live_approval_is_consumed_once(fake_keychain):
    session.mint_approval("github.com", ttl_seconds=120)
    first = reveal_gate.require_reveal("get", "github.com", verdict=agent())
    assert first.allowed is True
    assert first.reason == "approved"
    assert first.token_id

    with pytest.raises(RevealBlockedError):
        reveal_gate.require_reveal("get", "github.com", verdict=agent())

    assert [row["decision"] for row in audit.read(audit.AUDIT_FILE)] == ["approved", "deny"]
    assert audit.read(audit.AUDIT_FILE)[0]["token_id"] == first.token_id


def test_an_approval_only_covers_its_own_entry(fake_keychain):
    session.mint_approval("github.com", ttl_seconds=120)
    with pytest.raises(RevealBlockedError):
        reveal_gate.require_reveal("get", "gitlab.com", verdict=agent())


def test_an_expired_approval_is_refused_and_pruned(fake_keychain):
    session.mint_approval("github.com", ttl_seconds=15, now=1000.0)
    with pytest.raises(RevealBlockedError):
        reveal_gate.require_reveal("get", "github.com", verdict=agent())
    assert session.list_approvals() == []


def test_an_approval_covers_the_note_and_api_key_paths_too(fake_keychain):
    session.mint_approval("openai-prod", ttl_seconds=120)
    assert reveal_gate.require_reveal("ak-get", "openai-prod", verdict=agent()).allowed is True

    session.mint_approval("ssh-key", ttl_seconds=120)
    assert reveal_gate.require_reveal("note-get", "ssh-key", verdict=agent()).allowed is True


def test_a_whole_vault_dump_can_never_be_approved(fake_keychain):
    """Export mints no master key: an entry token that unlocked everything would
    make the guardrail decorative."""
    session.mint_approval("github.com", ttl_seconds=120)
    with pytest.raises(RevealBlockedError) as excinfo:
        reveal_gate.require_reveal(
            "export --plaintext", "github.com", whole_vault=True, verdict=agent()
        )
    assert "whole-vault dump cannot be approved" in "\n".join(excinfo.value.details)


def test_the_gate_does_not_touch_the_keychain_when_the_policy_allows():
    """A human's reveal must not pay for a token lookup."""
    calls = []

    def spy(entry, **kwargs):
        calls.append(entry)
        return None

    import session as session_module

    original = session_module.live_approval_for
    session_module.live_approval_for = spy
    try:
        reveal_gate.require_reveal("get", "github.com", verdict=human())
    finally:
        session_module.live_approval_for = original
    assert calls == []
