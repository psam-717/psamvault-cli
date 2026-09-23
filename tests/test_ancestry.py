"""Ancestry (caller ladder signal 4) — fake chains, plus a real walk smoke test.

The classifier is driven with fake chains on purpose: the point is the matching
RULE, and the rule must hold against a marker-scrubbed invocation without
depending on whatever happens to be running during the test. Real-chain
behaviour is proved once, separately, by the live probe in the plan's step 1.
"""
import os

import pytest

import ancestry


def chain(*paths, start_pid=100):
    """Build a fake chain: pid 100, 101, ... with the given paths."""
    entries = []
    for index, path in enumerate(paths):
        entries.append(
            ancestry.ProcessInfo(
                pid=start_pid + index,
                ppid=start_pid + index + 1,
                path=path,
            )
        )
    return entries


# ── The rule ──────────────────────────────────────────────────────────────


def test_hermes_agent_runtime_ancestor_is_detected():
    result = ancestry.agent_in_chain(
        chain(
            r"C:\Program Files\Git\usr\bin\bash.exe",
            r"C:\Users\psam\AppData\Local\hermes-agent\venv\Scripts\python.exe",
            r"C:\Windows\explorer.exe",
        )
    )
    assert result.is_agent is True
    assert result.matched_hint == "hermes-agent\\venv"
    assert "python.exe" in result.matched_path


def test_clean_human_chain_is_not_an_agent():
    result = ancestry.agent_in_chain(
        chain(
            r"C:\Users\psam\AppData\Local\pipx\venvs\psamvault\Scripts\python.exe",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            r"C:\Windows\explorer.exe",
        )
    )
    assert result.is_agent is False
    assert result.matched_hint is None
    assert result.depth == 3


def test_desktop_app_terminal_pane_is_not_an_agent():
    """The human's in-app terminal descends from the same install — never block it.

    This is the false-positive the hint list is shaped to avoid: matching a bare
    ``hermes-agent`` prefix would refuse the user's own pane.
    """
    result = ancestry.agent_in_chain(
        chain(
            r"C:\Users\psam\AppData\Local\hermes-agent\apps\desktop\Hermes.exe",
            r"C:\Windows\explorer.exe",
        )
    )
    assert result.is_agent is False


def test_hermes_cli_module_path_is_detected():
    result = ancestry.agent_in_chain(
        chain(r"C:\Users\psam\AppData\Roaming\uv\python\cpython-3.11\python.exe")
    )
    assert result.is_agent is False

    result = ancestry.agent_in_chain(
        [
            ancestry.ProcessInfo(
                pid=1,
                ppid=2,
                path=r"C:\Users\psam\AppData\Roaming\uv\python\cpython-3.11\python.exe",
                cmdline="python.exe -m hermes_cli.main gateway run",
            )
        ]
    )
    assert result.is_agent is True
    assert result.matched_hint == "hermes_cli"


def test_posix_cmdline_reveals_a_node_hosted_agent():
    """node.exe alone says nothing; its argv does."""
    result = ancestry.agent_in_chain(
        [
            ancestry.ProcessInfo(
                pid=1,
                ppid=2,
                path="/usr/local/bin/node",
                cmdline="node /home/u/.npm/global/node_modules/@anthropic-ai/claude-code/cli.js",
            )
        ]
    )
    assert result.is_agent is True


def test_matching_ignores_case_and_separator_style():
    result = ancestry.agent_in_chain(
        chain("/home/u/Hermes-Agent/VENV/bin/python3")
    )
    assert result.is_agent is True


def test_distinctly_named_agent_binary_is_detected():
    """The measured Claude Code CLI: a bare path with nothing distinctive in it.

    Its PATH (``~/.local/bin/claude.exe``) carries no hint fragment, so the
    basename is the only thing left to match — and it is safe to match because
    nothing a human runs is called ``claude``.
    """
    result = ancestry.agent_in_chain(chain(r"C:\Users\psam\.local\bin\claude.exe"))
    assert result.is_agent is True
    assert result.matched_hint == "exe:claude.exe"


def test_common_runtimes_are_never_matched_by_name():
    """The rule that matters: python/node/bash say nothing on their own."""
    result = ancestry.agent_in_chain(
        chain(r"C:\Python311\python.exe", "/usr/bin/node", "/usr/bin/bash", "/bin/sh")
    )
    assert result.is_agent is False


def test_the_measured_claude_code_chain_is_matched():
    """Replays the real chain captured by the step-1 probe (2026-09-23)."""
    entries = [
        ancestry.ProcessInfo(pid=4812, ppid=18896,
                             path=r"C:\Users\psam\AppData\Roaming\uv\python\cpython-3.11.16-windows-x86_64-none\python.exe"),
        ancestry.ProcessInfo(pid=18896, ppid=12748,
                             path=r"C:\Users\psam\AppData\Local\hermes\hermes-agent\venv\Scripts\python.exe"),
        ancestry.ProcessInfo(pid=12748, ppid=8180, path=r"C:\Program Files\Git\usr\bin\bash.exe"),
        ancestry.ProcessInfo(pid=25792, ppid=6652, path=r"C:\Users\psam\.local\bin\claude.exe"),
    ]
    result = ancestry.agent_in_chain(entries)
    assert result.is_agent is True
    # the nearest matching ancestor wins the audit row
    assert result.matched_hint == "hermes-agent\\venv"


def test_empty_and_missing_paths_are_safe():
    assert ancestry.agent_in_chain([]).is_agent is False
    result = ancestry.agent_in_chain(
        [ancestry.ProcessInfo(pid=1, ppid=2, path=""), ancestry.ProcessInfo(pid=2, ppid=0)]
    )
    assert result.is_agent is False


def test_summary_names_the_signal_for_the_audit_row():
    result = ancestry.agent_in_chain(
        chain(r"C:\x\hermes-agent\venv\Scripts\python.exe")
    )
    assert result.summary() == "ancestry:hermes-agent\\venv"
    assert ancestry.agent_in_chain([]).summary().startswith("ancestry:none")


# ── The walker ────────────────────────────────────────────────────────────


def test_walk_starts_at_this_process_and_terminates():
    entries = ancestry.walk(max_depth=4)
    assert entries, "walk returned nothing — the platform walker is broken"
    assert entries[0].pid == os.getpid()


def test_inspect_never_raises_when_the_walker_fails(monkeypatch):
    def boom(*_args, **_kwargs):
        raise OSError("no process table for you")

    monkeypatch.setattr(ancestry, "walk", boom)
    result = ancestry.inspect()
    assert result.is_agent is False


def test_inspect_does_not_hang_on_a_cyclic_chain(monkeypatch):
    """A re-parented process can hand us a loop; the seen-set must close it."""
    fake_table = {1: 2, 2: 1}
    monkeypatch.setattr(ancestry, "_posix_ppid", lambda pid: fake_table.get(pid, 0))
    monkeypatch.setattr(ancestry, "_posix_path", lambda pid: "")
    monkeypatch.setattr(ancestry, "_posix_cmdline", lambda pid: "")
    entries = ancestry._walk_posix(1, ancestry.MAX_DEPTH)
    assert len(entries) == 2, "a 1<->2 cycle should stop after both pids are seen"
