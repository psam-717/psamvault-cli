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

``entries`` is a different list from ``allow_entries``. ``allow_entries`` names
secrets an agent may *reveal*. ``entries.<name>.allow_hosts`` names hosts a
stored secret may be *sent* to. The MCP reads ``allow_hosts`` and does not
write it. Loading validates each host and records a warning for a bad one.
It does not rewrite the file, so a hand-edited list and every other key survive.
"""
from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

import allow_hosts
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
    # Effective destination hosts, keyed by the name stored in the file.
    # A value the MCP would ignore, or that cannot take effect, is absent
    # here and named in ``warnings``. The file itself is not rewritten.
    entry_hosts: dict[str, list[str]] = field(default_factory=dict)


class HostRejected(Exception):
    """The host must not be written to allow_hosts."""

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


class PolicyDocumentError(Exception):
    """policy.json cannot be edited without losing or guessing at data."""

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


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

    _load_entry_hosts(policy, data)

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


def _load_entry_hosts(policy: Policy, data: dict) -> None:
    """Fill ``entry_hosts`` and warn about values that must not be treated as allowed.

    Older files have no ``entries`` key. That is the safe default: nothing
    extra is allowed, and nothing is warned about. A bad value is reported
    and left in the file for the human to remove.
    """
    if "entries" not in data or data.get("entries") is None:
        return
    entries = data.get("entries")
    if not isinstance(entries, dict):
        policy.warnings.append("entries must be an object — ignored")
        return

    for name, spec in entries.items():
        if not isinstance(name, str) or not name.strip():
            continue
        if not isinstance(spec, dict):
            policy.warnings.append(f"entries[{name!r}] must be an object — ignored")
            continue
        hosts = spec.get("allow_hosts", [])
        if hosts is None:
            policy.entry_hosts[name] = []
            continue
        if not isinstance(hosts, list):
            policy.warnings.append(
                f"entries[{name!r}].allow_hosts must be a list — ignored"
            )
            policy.entry_hosts[name] = []
            continue
        accepted: list[str] = []
        for item in hosts:
            verdict = allow_hosts.judge(str(item), strict=False)
            if verdict.problem or not verdict.normalized:
                detail = verdict.problem or f"{item!r} is not a hostname"
                policy.warnings.append(f"entries[{name!r}].allow_hosts: {detail}")
                continue
            if verdict.normalized not in accepted:
                accepted.append(verdict.normalized)
        policy.entry_hosts[name] = accepted


def matching_entry_key(entries: dict, name: str) -> str | None:
    """The stored key for ``name``. An exact match wins over a case-insensitive one."""
    wanted = name.strip()
    folded = wanted.casefold()
    fallback = None
    for key in entries:
        if not isinstance(key, str):
            continue
        if key == wanted:
            return key
        if key.strip().casefold() == folded and fallback is None:
            fallback = key
    return fallback


def read_document(path: Path | None = None) -> dict:
    """The raw policy object. Missing file is ``{}``.

    Raises :class:`PolicyDocumentError` when the file is unreadable or is not
    a JSON object — the editor must not replace it with a guess.
    """
    target = Path(path) if path is not None else POLICY_FILE
    if not target.exists():
        return {}
    try:
        raw = target.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyDocumentError(f"could not read {target}: {exc}") from exc
    try:
        data = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError as exc:
        raise PolicyDocumentError(
            f"{target} is not valid JSON ({exc.msg}) — not rewritten"
        ) from exc
    if not isinstance(data, dict):
        raise PolicyDocumentError(f"{target} must contain a JSON object — not rewritten")
    return data


def write_document(data: dict, path: Path | None = None) -> None:
    """Atomically replace the policy file. Owner-only, other keys preserved by the caller."""
    target = Path(path) if path is not None else POLICY_FILE
    payload = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = target.with_name(target.name + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, target)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    try:
        os.chmod(target, 0o600)
    except OSError:
        pass


def entry_spec(data: dict, name: str, *, create: bool) -> tuple[str | None, dict | None, list | None]:
    """Return ``(key, spec, allow_hosts)`` or raise when the shape cannot be edited."""
    entries = data.get("entries", {})
    if entries is None:
        entries = {}
        if create:
            data["entries"] = entries
    if not isinstance(entries, dict):
        raise PolicyDocumentError("entries must be an object — not rewritten")
    key = matching_entry_key(entries, name)
    if key is None:
        if not create:
            return None, None, None
        key = name.strip()
        if not key:
            raise HostRejected("An entry name is required.")
        entries[key] = {}
        data["entries"] = entries
    spec = entries[key]
    if not isinstance(spec, dict):
        raise PolicyDocumentError(f"entries[{key!r}] must be an object — not rewritten")
    hosts = spec.get("allow_hosts", [])
    if hosts is None:
        hosts = []
    if not isinstance(hosts, list):
        raise PolicyDocumentError(
            f"entries[{key!r}].allow_hosts must be a list — not rewritten"
        )
    return key, spec, hosts


def add_allow_host(entry: str, host: str, path: Path | None = None) -> tuple[str, str, bool]:
    """Append one normalised host. Returns ``(entry_key, host, changed)``.

    ``changed`` is false when that host is already listed. A refused host
    raises :class:`HostRejected` and the file is not opened for writing.
    """
    verdict = allow_hosts.judge(host, strict=True)
    if verdict.problem or not verdict.normalized:
        raise HostRejected(verdict.problem or f"{host!r} is not a hostname.")
    target = Path(path) if path is not None else POLICY_FILE
    data = read_document(target)
    key, spec, hosts = entry_spec(data, entry, create=True)
    assert key is not None and spec is not None and hosts is not None
    if any(allow_hosts.same_host(str(item), verdict.normalized) for item in hosts):
        return key, verdict.normalized, False
    hosts.append(verdict.normalized)
    spec["allow_hosts"] = hosts
    write_document(data, target)
    return key, verdict.normalized, True


def remove_allow_host(entry: str, host: str, path: Path | None = None) -> tuple[str, list[str]]:
    """Remove every listed value that is this host. Returns ``(entry_key, removed)``.

    A value the grant command would refuse can still be removed: that is how
    a loopback address or a bare suffix leaves the file. ``removed`` is empty
    when nothing matched. The file is not written in that case.
    """
    target = Path(path) if path is not None else POLICY_FILE
    data = read_document(target)
    key, spec, hosts = entry_spec(data, entry, create=False)
    if key is None or spec is None or hosts is None:
        return entry.strip(), []
    kept: list = []
    removed: list[str] = []
    for item in hosts:
        if allow_hosts.same_host(str(item), host):
            removed.append(str(item))
        else:
            kept.append(item)
    if not removed:
        return key, []
    spec["allow_hosts"] = kept
    write_document(data, target)
    return key, removed


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
