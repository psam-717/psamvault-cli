"""Audit trail — one JSONL row per reveal decision.

``~/.psamvault/audit.jsonl`` (mode ``0600``), size-rotated to ``audit.jsonl.1``.
Every row answers "who asked, what did the guardrail decide, and on what
evidence":

    {"ts": "...Z", "command": "get", "entry": "github.com", "caller": "agent",
     "signals": ["marker:AI_AGENT=hermes-agent"], "tty": false, "pid": 1234,
     "ppid": 1200, "decision": "deny", "token_id": null, "policy": "human-only"}

A destination grant adds ``"host"``: the hostname that was allowed or removed.
That field is a name, never a secret, and it is omitted on reveal rows.

An MCP use adds ``tool``, ``reason``, ``mcp_use`` and ``ask``. ``reason`` is one
of a closed set (``listed``, ``not-listed``, ``mcp-use-off``, ``ask-declined``,
``ask-unanswered``), never a sentence, so the field cannot carry a secret.
Those four keys are omitted on reveal rows. psamvault-mcp appends the same
shape itself; it does not import this module. See :func:`record_mcp_use`.

Two invariants, both pinned by tests:

* **A row never contains a secret.** Only names, ids, verdicts and signal
  names are written — never a value read out of the vault. The audit file is
  meant to be greppable and shareable, so it cannot carry key material.
* **Auditing never breaks a command.** Any I/O failure is swallowed: a
  read-only home directory must not stop a user from reading their password.
  This is documented in ``SECURITY.md`` as a deliberate limit — a full disk or
  a hostile ``~/.psamvault`` can silence the trail, which is why the trail is
  evidence of *well-behaved* callers, not a boundary.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

import mcp_use as mcp_policy
from config import CONFIG_DIR

AUDIT_FILENAME = "audit.jsonl"
AUDIT_FILE = CONFIG_DIR / AUDIT_FILENAME
MAX_AUDIT_BYTES = 1_000_000  # ~1 MB, then rotate one generation

# Decisions recorded in the trail. "minted" is the human's approval mint, so the
# trail shows BOTH sides of a handover and not just the agent's half.
DECISION_ALLOW = "allow"
DECISION_DENY = "deny"
DECISION_APPROVED = "approved"
DECISION_MINTED = "minted"
# A discovery command ran and revealed nothing; the row records who asked.
DECISION_DISCOVERY = "discovery"
# A human added or removed a destination host. The row's ``host`` is that name.
DECISION_GRANTED = "granted"
DECISION_REVOKED = "revoked"
# A human changed ask_each_time or the mcp_use mode. The row names which.
DECISION_SET = "set"


def _rotate(path: Path) -> None:
    try:
        if path.exists() and path.stat().st_size >= MAX_AUDIT_BYTES:
            rotated = path.parent / (path.name + ".1")
            if rotated.exists():
                rotated.unlink()
            path.rename(rotated)
    except OSError:
        pass


def record(
    *,
    command: str,
    decision: str,
    caller: str | None = None,
    entry: str | None = None,
    signals: list[str] | None = None,
    tty: bool | None = None,
    token_id: str | None = None,
    policy_mode: str | None = None,
    path: Path | None = None,
    host: str | None = None,
    tool: str | None = None,
    reason: str | None = None,
    mcp_use: str | None = None,
    ask: bool | None = None,
) -> None:
    """Append one audit row. Never raises.

    ``host`` is a destination hostname for a policy grant or removal. It is
    omitted when the decision is not about a host, so reveal rows stay as
    they were. It is never a secret value.

    ``tool``, ``reason``, ``mcp_use`` and ``ask`` are the MCP-use fields.
    They are omitted when this row is not about an MCP tool or a change to
    that policy. ``reason`` must already be one of :data:`mcp_policy.REASONS`;
    this function does not accept a free-text explanation.
    """
    target = Path(path) if path is not None else AUDIT_FILE
    row = {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "command": command,
        "entry": entry,
        "caller": caller,
        "signals": list(signals or []),
        "tty": tty,
        "pid": os.getpid(),
        "ppid": os.getppid(),
        "decision": decision,
        "token_id": token_id,
        "policy": policy_mode,
    }
    if host is not None:
        row["host"] = host
    # The new fields are closed. A value that is not a tool name, a known
    # reason, a known mode, or a boolean is omitted rather than written.
    if isinstance(tool, str):
        normalized_tool = mcp_policy.normalize_tool(tool)
        if normalized_tool:
            row["tool"] = normalized_tool
    if reason in mcp_policy.REASONS:
        row["reason"] = reason
    if mcp_use in mcp_policy.MODES:
        row["mcp_use"] = mcp_use
    if isinstance(ask, bool):
        row["ask"] = ask
    try:
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        _rotate(target)
        with open(target, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, separators=(",", ":")) + "\n")
        os.chmod(target, 0o600)
    except OSError:
        pass


def record_mcp_use(
    *,
    tool: str,
    entry: str | None,
    decision: str,
    reason: str,
    mcp_use: str,
    ask: bool = False,
    path: Path | None = None,
) -> None:
    """Append one MCP-use row. Never raises.

    The row is dropped, not rewritten with the caller's text, when ``tool``
    is not a tool name, ``reason`` is not in :data:`mcp_policy.REASONS`,
    ``decision`` is not ``allow`` or ``deny``, or ``mcp_use`` is not a known
    mode. That is what keeps a secret out of the trail.

    On-disk shape, one compact JSON object per line, UTF-8, mode ``0600``,
    in ``~/.psamvault/audit.jsonl`` (rotated to ``audit.jsonl.1`` at 1_000_000
    bytes, same as every other row)::

        {"ts":"2026-11-04T00:00:00Z","command":"mcp use_credential",
         "entry":"ledger-key","caller":"mcp","signals":[],"tty":false,
         "pid":1,"ppid":1,"decision":"deny","token_id":null,"policy":null,
         "tool":"use_credential","reason":"not-listed","mcp_use":"enforce",
         "ask":true}

    ``command`` is ``mcp <tool>``. ``caller`` is ``mcp``. ``policy`` (the
    reveal mode) is null. ``host`` is omitted. ``ts`` is UTC ``YYYY-MM-DDTHH:MM:SSZ``.
    A failure to write must not fail the tool call.
    """
    normalized = mcp_policy.normalize_tool(tool) if isinstance(tool, str) else None
    if (
        not normalized
        or decision not in (mcp_policy.ALLOW, mcp_policy.DENY)
        or reason not in mcp_policy.REASONS
        or mcp_use not in mcp_policy.MODES
    ):
        return
    record(
        command=f"mcp {normalized}",
        decision=decision,
        caller="mcp",
        entry=entry,
        signals=[],
        tty=False,
        token_id=None,
        policy_mode=None,
        path=path,
        tool=normalized,
        reason=reason,
        mcp_use=mcp_use,
        ask=bool(ask),
    )


def read(path: Path | None = None) -> list[dict]:
    """Read the trail back (used by tests; a reader command is not in this wave)."""
    target = Path(path) if path is not None else AUDIT_FILE
    rows: list[dict] = []
    try:
        with open(target, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError:
        return []
    return rows
