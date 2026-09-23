"""Audit trail — one JSONL row per reveal decision.

``~/.psamvault/audit.jsonl`` (mode ``0600``), size-rotated to ``audit.jsonl.1``.
Every row answers "who asked, what did the guardrail decide, and on what
evidence":

    {"ts": "...Z", "command": "get", "entry": "github.com", "caller": "agent",
     "signals": ["marker:AI_AGENT=hermes-agent"], "tty": false, "pid": 1234,
     "ppid": 1200, "decision": "deny", "token_id": null, "policy": "human-only"}

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
) -> None:
    """Append one audit row. Never raises."""
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
    try:
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        _rotate(target)
        with open(target, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, separators=(",", ":")) + "\n")
        os.chmod(target, 0o600)
    except OSError:
        pass


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
