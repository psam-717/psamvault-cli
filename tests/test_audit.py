"""The audit trail: shape, rotation, and the two invariants that matter."""
import json
import os

import audit


def test_a_row_records_who_asked_and_what_was_decided(tmp_path):
    target = tmp_path / "audit.jsonl"
    audit.record(
        command="get",
        decision=audit.DECISION_DENY,
        caller="agent",
        entry="github.com",
        signals=["marker:AI_AGENT=hermes-agent"],
        tty=False,
        policy_mode="human-only",
        path=target,
    )
    rows = audit.read(target)
    assert len(rows) == 1
    row = rows[0]
    assert row["command"] == "get"
    assert row["decision"] == "deny"
    assert row["caller"] == "agent"
    assert row["entry"] == "github.com"
    assert row["signals"] == ["marker:AI_AGENT=hermes-agent"]
    assert row["tty"] is False
    assert row["policy"] == "human-only"
    assert row["token_id"] is None
    assert isinstance(row["pid"], int) and isinstance(row["ppid"], int)
    assert row["ts"].endswith("Z")


def test_rows_append_and_stay_jsonl(tmp_path):
    target = tmp_path / "audit.jsonl"
    for index in range(3):
        audit.record(command="get", decision="allow", entry=f"site-{index}", path=target)
    raw = target.read_text(encoding="utf-8")
    assert raw.count("\n") == 3
    assert [r["entry"] for r in audit.read(target)] == ["site-0", "site-1", "site-2"]


def test_a_row_carries_no_free_text_field_that_could_hold_a_secret():
    """The row schema is the guarantee: there is nowhere for a value to go."""
    import inspect

    params = set(inspect.signature(audit.record).parameters)
    assert params == {
        "command",
        "decision",
        "caller",
        "entry",
        "signals",
        "tty",
        "token_id",
        "policy_mode",
        "path",
    }
    for banned in ("value", "secret", "password", "plaintext", "key", "blob"):
        assert not any(banned in name for name in params), banned


def test_the_file_is_owner_only(tmp_path):
    target = tmp_path / "audit.jsonl"
    audit.record(command="get", decision="allow", path=target)
    if os.name == "posix":
        assert (target.stat().st_mode & 0o077) == 0


def test_rotation_keeps_one_generation(tmp_path, monkeypatch):
    target = tmp_path / "audit.jsonl"
    monkeypatch.setattr(audit, "MAX_AUDIT_BYTES", 120)
    for index in range(5):
        audit.record(command="get", decision="allow", entry=f"site-{index}", path=target)
    rotated = tmp_path / "audit.jsonl.1"
    assert rotated.exists(), "the trail should rotate rather than grow forever"
    first = json.loads(rotated.read_text(encoding="utf-8").splitlines()[0])
    assert first["ts"] is not None


def test_an_unwritable_trail_never_breaks_a_command(tmp_path):
    """A file where the directory should be: mkdir fails, the record is dropped."""
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory", encoding="utf-8")
    audit.record(command="get", decision="allow", path=blocker / "audit.jsonl")  # must not raise


def test_reading_a_missing_or_damaged_trail_is_empty(tmp_path):
    assert audit.read(tmp_path / "missing.jsonl") == []
    damaged = tmp_path / "audit.jsonl"
    damaged.write_text("not json\n{}\n", encoding="utf-8")
    assert audit.read(damaged) == [{}]


def test_default_path_lives_under_the_psamvault_dir():
    """The real location, checked by constants (the path itself is overridden for tests)."""
    assert audit.AUDIT_FILENAME == "audit.jsonl"
    assert audit.CONFIG_DIR.name == ".psamvault"
