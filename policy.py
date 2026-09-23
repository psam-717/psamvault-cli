"""Reveal policy — who may print a secret, and how long an approval lives.

``~/.psamvault/policy.json`` (mode ``0600``), absent means safe defaults, so a
fresh machine is protected with no setup and nothing to configure:

    {
      "reveal": "human-only",          // "human-only" | "strict" | "open"
      "allow_entries": [],             // per-entry allowlist, e.g. ["github.com"]
      "approval_ttl_seconds": 120,     // `approve` token lifetime
      "audit": true
    }

The three modes, and what each does to a caller:

* ``human-only`` (default) — an ``agent`` caller is refused; an ``uncertain``
  caller (a bare pipe, a script, a CI job, any CI-less non-TTY) is allowed and
  audited. This stops the real case (an agent's shell) without breaking existing
  pipes, CI pipelines or every ``CliRunner`` test in the suite.
* ``strict`` — ``agent`` *and* ``uncertain`` are refused. Opt-in, for anyone
  who wants "no TTY, no secret".
* ``open`` — everything is allowed, still audited. The escape hatch for a
  machine where the guardrail is in the way.

A malformed or unreadable policy file never crashes a command: it falls back to
the defaults and reports a warning, because failing closed on a typo would make
the vault unusable, and failing open silently would hide a misconfiguration.
"""
from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

from config import CONFIG_DIR

POLICY_FILE = CONFIG_DIR / "policy.json"

MODE_HUMAN_ONLY = "human-only"
MODE_STRICT = "strict"
MODE_OPEN = "open"
MODES = (MODE_HUMAN_ONLY, MODE_STRICT, MODE_OPEN)

DEFAULT_REVEAL_MODE = MODE_HUMAN_ONLY
DEFAULT_APPROVAL_TTL_SECONDS = 120
MIN_APPROVAL_TTL_SECONDS = 15
MAX_APPROVAL_TTL_SECONDS = 3600

ALLOW = "allow"
DENY = "deny"

# Any group/other permission bit on the policy file is a warning: the file says
# who is allowed to print secrets, so it is not secret — but it is ours to write.
_GROUP_OR_WORLD_BITS = stat.S_IRWXG | stat.S_IRWXO


@dataclass
class Policy:
    """A loaded policy: effective values plus where they came from."""

    reveal: str = DEFAULT_REVEAL_MODE
    allow_entries: list[str] = field(default_factory=list)
    approval_ttl_seconds: int = DEFAULT_APPROVAL_TTL_SECONDS
    audit: bool = True
    source: str = "default"
    warnings: list[str] = field(default_factory=list)


def clamp_ttl(value) -> int:
    """Coerce a requested TTL into the supported window (15s - 1h)."""
    try:
        ttl = int(value)
    except (TypeError, ValueError):
        return DEFAULT_APPROVAL_TTL_SECONDS
    return max(MIN_APPROVAL_TTL_SECONDS, min(MAX_APPROVAL_TTL_SECONDS, ttl))


def load(path: Path | None = None) -> Policy:
    """Load the policy file. Never raises; a bad file means defaults + warning."""
    target = Path(path) if path is not None else POLICY_FILE
    policy = Policy()

    try:
        if not target.exists():
            return policy
        raw = target.read_text(encoding="utf-8")
    except Exception as exc:  # unreadable file — defaults, and say so
        policy.warnings.append(f"could not read {target}: {exc}")
        return policy

    try:
        data = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError as exc:
        policy.warnings.append(
            f"{target} is not valid JSON ({exc.msg}) — using safe defaults"
        )
        return policy

    if not isinstance(data, dict):
        policy.warnings.append(f"{target} must contain a JSON object — using safe defaults")
        return policy

    policy.source = "file"

    mode = data.get("reveal", DEFAULT_REVEAL_MODE)
    if isinstance(mode, str) and mode in MODES:
        policy.reveal = mode
    else:
        policy.warnings.append(
            f"unknown reveal mode {mode!r} — using {DEFAULT_REVEAL_MODE}"
        )

    entries = data.get("allow_entries", [])
    if isinstance(entries, list):
        policy.allow_entries = [str(e) for e in entries if str(e).strip()]
    else:
        policy.warnings.append("allow_entries must be a list — ignored")

    if "approval_ttl_seconds" in data:
        policy.approval_ttl_seconds = clamp_ttl(data.get("approval_ttl_seconds"))
    if isinstance(data.get("audit"), bool):
        policy.audit = data["audit"]

    # POSIX only: Windows reports 0o666 for every file regardless of its ACLs,
    # so the check would warn on every load there and be worse than useless.
    if os.name == "posix":
        try:
            mode_bits = target.stat().st_mode
            if mode_bits & _GROUP_OR_WORLD_BITS:
                policy.warnings.append(
                    f"{target} is readable by other users — run: chmod 600 {target}"
                )
        except OSError:
            pass

    return policy


def entry_allowed(policy: Policy, entry: str | None) -> bool:
    """Is this entry explicitly allowlisted (case-insensitive exact match)?"""
    if not entry:
        return False
    wanted = entry.strip().casefold()
    return any(wanted == allowed.strip().casefold() for allowed in policy.allow_entries)


def decide(policy: Policy, verdict: str, entry: str | None = None) -> str:
    """Return :data:`ALLOW` or :data:`DENY` for a caller verdict."""
    if verdict == "human":
        return ALLOW
    if entry_allowed(policy, entry):
        return ALLOW
    if policy.reveal == MODE_OPEN:
        return ALLOW
    if verdict == "agent":
        return DENY
    # verdict == "uncertain": a plain pipe or a script, no positive agent signal
    return ALLOW if policy.reveal == MODE_HUMAN_ONLY else DENY
