"""Caller classification — the ladder, the truthiness rules, and the cost rule.

The environment is passed in explicitly (``classify(env={...})``) so each signal
is tested in isolation; the ancestry probe is injected, never the real process
tree, so the tests do not depend on what is running on the machine.
"""
import ancestry
import caller


def agent_result():
    return ancestry.AncestryResult(is_agent=True, matched_hint="hermes-agent\\venv")


def no_agent_result():
    return ancestry.AncestryResult(is_agent=False)


# ── Signal 1: explicit ────────────────────────────────────────────────────


def test_explicit_env_is_an_agent(monkeypatch):
    monkeypatch.setattr(caller, "tty_present", lambda: True)
    verdict = caller.classify({"PSAMVAULT_AGENT": "1"})
    assert verdict.verdict == "agent"
    assert verdict.signals == ["explicit:PSAMVAULT_AGENT"]


def test_explicit_env_beats_everything_else(monkeypatch):
    monkeypatch.setattr(caller, "tty_present", lambda: True)
    verdict = caller.classify({"PSAMVAULT_AGENT": "true", "AI_AGENT": "hermes-agent"})
    assert verdict.signals == ["explicit:PSAMVAULT_AGENT"]


def test_explicit_env_false_is_not_an_agent(monkeypatch):
    monkeypatch.setattr(caller, "tty_present", lambda: True)
    assert caller.classify({"PSAMVAULT_AGENT": "0"}).verdict == "human"


# ── Signal 2: host markers (each one measured on a real host) ─────────────


def test_ai_agent_marker_any_value_is_an_agent(monkeypatch):
    """Hermes exports AI_AGENT=hermes-agent; Claude Code exports its own value.

    Both were measured (2026-09-23): the shared variable name is what makes this
    signal reliable, so the value is not matched.
    """
    monkeypatch.setattr(caller, "tty_present", lambda: True)
    for value in ("hermes-agent", "claude-code_2-1-278_agent"):
        verdict = caller.classify({"AI_AGENT": value})
        assert verdict.verdict == "agent"
        assert verdict.signals == [f"marker:AI_AGENT={value}"]


def test_hermes_agent_marker(monkeypatch):
    monkeypatch.setattr(caller, "tty_present", lambda: True)
    assert caller.classify({"HERMES_AGENT": "true"}).signals == ["marker:HERMES_AGENT"]
    assert caller.classify({"HERMES_AGENT": "1"}).verdict == "agent"


def test_hermes_agent_marker_must_be_truthy(monkeypatch):
    monkeypatch.setattr(caller, "tty_present", lambda: True)
    assert caller.classify({"HERMES_AGENT": "false"}).verdict == "human"
    assert caller.classify({"HERMES_AGENT": ""}).verdict == "human"


def test_claude_code_markers(monkeypatch):
    monkeypatch.setattr(caller, "tty_present", lambda: True)
    assert caller.classify({"CLAUDECODE": "1"}).verdict == "agent"
    assert caller.classify({"CLAUDE_CODE_ENTRYPOINT": "sdk-cli"}).verdict == "agent"


def test_unknown_markers_do_not_block(monkeypatch):
    """Hermes internals that were never checked in the human's pane stay out."""
    monkeypatch.setattr(caller, "tty_present", lambda: True)
    verdict = caller.classify(
        {"_HERMES_GATEWAY": "1", "HERMES_DESKTOP": "1", "HERDR": "1", "TERM": "xterm-256color"}
    )
    assert verdict.verdict == "human"


def test_the_agent_terminal_environment_is_an_agent(monkeypatch):
    """Closes the measured MSYS `env.exe` gap: that hop breaks the parent chain,
    so a scrub that crosses it must still be caught here."""
    monkeypatch.setattr(caller, "tty_present", lambda: True)
    assert caller.classify({"TERMINAL_CWD": "/d/Projects/x"}).verdict == "agent"
    verdict = caller.classify({"TERMINAL_ENV": "local"})
    assert verdict.verdict == "agent"
    assert verdict.signals == ["marker:TERMINAL_ENV=local"]


# ── Signal 3: CI — recorded, not an agent ─────────────────────────────────


def test_ci_alone_is_unattended_not_an_agent(monkeypatch):
    """CI=true says no human is watching — not that a program is driving.

    Grading it as an agent would refuse secrets in every CI pipeline (GitHub
    Actions sets CI=true unconditionally) while catching no agent that its own
    markers or its ancestry would not already catch.
    """
    monkeypatch.setattr(caller, "tty_present", lambda: False)
    verdict = caller.classify({"CI": "true"})
    assert verdict.verdict == "uncertain"
    assert verdict.signals == ["env:CI"]


def test_ci_with_a_terminal_is_human_but_still_recorded(monkeypatch):
    monkeypatch.setattr(caller, "tty_present", lambda: True)
    verdict = caller.classify({"CI": "true"})
    assert verdict.verdict == "human"
    assert verdict.signals == ["env:CI"]


def test_ci_does_not_mask_an_agent_marker(monkeypatch):
    """An agent running inside CI is still caught — the markers win."""
    monkeypatch.setattr(caller, "tty_present", lambda: False)
    verdict = caller.classify({"CI": "true", "AI_AGENT": "hermes-agent"})
    assert verdict.verdict == "agent"
    assert "marker:AI_AGENT=hermes-agent" in verdict.signals
    assert "env:CI" in verdict.signals


def test_ci_false_is_not_an_agent(monkeypatch):
    monkeypatch.setattr(caller, "tty_present", lambda: True)
    verdict = caller.classify({"CI": "false"})
    assert verdict.verdict == "human"
    assert verdict.signals == []


# ── TTY: never a blocking signal ──────────────────────────────────────────


def test_clean_terminal_is_human(monkeypatch):
    monkeypatch.setattr(caller, "tty_present", lambda: True)
    verdict = caller.classify({})
    assert verdict.verdict == "human"
    assert verdict.signals == []
    assert verdict.tty is True


def test_bare_non_tty_is_uncertain_not_denied(monkeypatch):
    """CliRunner has no TTY — a "no TTY ⇒ agent" rule would break the suite."""
    monkeypatch.setattr(caller, "tty_present", lambda: False)
    verdict = caller.classify({})
    assert verdict.verdict == "uncertain"


# ── Signal 4: ancestry, and its cost rule ─────────────────────────────────


def test_ancestry_is_consulted_only_when_asked(monkeypatch):
    """Ordinary commands must not pay for the walk."""
    calls = {"n": 0}

    def probe():
        calls["n"] += 1
        return agent_result()

    verdict = caller.classify({}, with_ancestry=False, ancestry_probe=probe)
    assert calls["n"] == 0
    assert verdict.verdict == "uncertain"


def test_ancestry_detects_a_marker_scrubbed_agent(monkeypatch):
    monkeypatch.setattr(caller, "tty_present", lambda: True)
    verdict = caller.classify({}, with_ancestry=True, ancestry_probe=agent_result)
    assert verdict.verdict == "agent"
    assert verdict.signals == ["ancestry:hermes-agent\\venv"]


def test_markers_are_checked_before_ancestry(monkeypatch):
    def probe():  # pragma: no cover - must not run
        raise AssertionError("ancestry should not be consulted when a marker matched")

    monkeypatch.setattr(caller, "tty_present", lambda: True)
    verdict = caller.classify({"AI_AGENT": "hermes-agent"}, with_ancestry=True, ancestry_probe=probe)
    assert verdict.verdict == "agent"
    assert verdict.signals == ["marker:AI_AGENT=hermes-agent"]


def test_a_failing_ancestry_probe_never_blocks(monkeypatch):
    monkeypatch.setattr(caller, "tty_present", lambda: True)

    def boom():
        raise OSError("no process table")

    assert caller.classify({}, with_ancestry=True, ancestry_probe=boom).verdict == "human"


def test_clean_chain_in_a_terminal_is_human(monkeypatch):
    monkeypatch.setattr(caller, "tty_present", lambda: True)
    verdict = caller.classify({}, with_ancestry=True, ancestry_probe=no_agent_result)
    assert verdict.verdict == "human"


# ── Behaviour of the real tty probe ───────────────────────────────────────


def test_tty_requires_both_ends(monkeypatch):
    """Measured: the agent shell has stdin on a TTY but stdout piped."""

    class Fake:
        def __init__(self, tty):
            self._tty = tty

        def isatty(self):
            return self._tty

    monkeypatch.setattr(caller.sys, "stdin", Fake(True))
    monkeypatch.setattr(caller.sys, "stdout", Fake(False))
    assert caller.tty_present() is False

    monkeypatch.setattr(caller.sys, "stdout", Fake(True))
    assert caller.tty_present() is True


def test_tty_probe_survives_a_stream_without_isatty(monkeypatch):
    class Broken:
        def isatty(self):
            raise ValueError("no fileno")

    monkeypatch.setattr(caller.sys, "stdin", Broken())
    assert caller.tty_present() is False


def test_describe_names_the_evidence():
    verdict = caller.CallerVerdict("agent", ["marker:AI_AGENT=hermes-agent"], True)
    assert "AI_AGENT" in verdict.describe()
    assert caller.CallerVerdict("uncertain", [], False).describe().startswith("no signals")
