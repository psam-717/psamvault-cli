"""Pending claims — the human's half of a credential-blind handoff.

An agent that must never see a secret can still ask for the entry to exist: it
creates a *pending claim*, hands the human a code, and the human supplies the
value in their own terminal. The plaintext then goes straight into the vault and
never passes through the agent, its argv, its shell history or its transcript.

    ~/.psamvault/pending/<code>.json      (file 0600, directory 0700)

A record holds metadata only — the family the entry belongs to, its name, and
the non-secret fields the agent already knew (``service``, ``notes``,
``login_url``, ``category``, ``username``), plus the timestamps and a status.

Three invariants, all pinned by ``tests/test_pending_store.py``:

* **No secret is ever stored here.** Anything running as the user — the agent
  included — can read this directory, so the record must never carry more than
  *which* entries are being created. The exact field set is asserted by a test.
* **A code is single-use and short-lived.** 15 minutes by default; filling flips
  the status so a second fill cannot replay the code, and a code is never reused
  or overwritten — a collision re-rolls.
* **Expiry is enforced on access, not by a timer.** ``load`` and ``list_records``
  prune as they read, so a laptop that was asleep for a week does not wake up
  holding live claims. A filled claim is kept for an hour as evidence, then
  pruned.

The claim code is not a capability: it authorises *writing one named entry*, and
holding it lets an attacker fill in their own secret under a name the user is
about to be told. That is stated in ``SECURITY.md`` rather than papered over.
"""
from __future__ import annotations

import json
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

from config import CONFIG_DIR

PENDING_DIR = CONFIG_DIR / "pending"

DEFAULT_TTL_SECONDS = 900  # 15 minutes: the plan's decided window
MIN_TTL_SECONDS = 60
MAX_TTL_SECONDS = 3600
FILLED_RETENTION_SECONDS = 3600  # keep a filled claim as evidence for an hour

STATUS_PENDING = "pending"
STATUS_FILLED = "filled"

FAMILY_API_KEY = "api_key"
FAMILY_CREDENTIAL = "credential"
FAMILY_NOTE = "note"
FAMILIES = (FAMILY_API_KEY, FAMILY_CREDENTIAL, FAMILY_NOTE)

# Crockford base32: digits and letters without I, L, O and U, so a code read
# aloud or over a phone call cannot be transcribed into a different one.
CODE_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
CODE_CHARS = 8
CODE_PREFIX = "PV"

_TS_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
_MAX_COLLISION_ATTEMPTS = 20


# ── codes ─────────────────────────────────────────────────────────────────────


def generate_code() -> str:
    """A fresh claim code, ``PV-XXXX-XXXX``.

    Random, never clock-derived: this repository has already been bitten by
    ~15 ms clock granularity handing two snapshots the same name
    (``upgrade_utils``), and a code that repeats would let a fill land on
    somebody else's claim.
    """
    body = "".join(secrets.choice(CODE_ALPHABET) for _ in range(CODE_CHARS))
    return f"{CODE_PREFIX}-{body[:4]}-{body[4:]}"


def normalize_code(code: str | None) -> str:
    """Accept any reasonable typing of a code; raise ``ValueError`` otherwise.

    ``PV-4F2K-91QX``, ``pv4f2k91qx``, ``4F2K-91QX`` and ``pv 4f2k 91qx`` all
    normalise to the canonical form, because the human is usually retyping this
    from a chat message.
    """
    raw = "".join(ch for ch in (code or "").upper() if ch.isalnum())
    if raw.startswith(CODE_PREFIX):
        raw = raw[len(CODE_PREFIX) :]
    if len(raw) != CODE_CHARS or any(ch not in CODE_ALPHABET for ch in raw):
        raise ValueError(f"not a claim code: {code!r}")
    return f"{CODE_PREFIX}-{raw[:4]}-{raw[4:]}"


# ── storage ───────────────────────────────────────────────────────────────────


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _stamp(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime(_TS_FORMAT)


def _parse(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, _TS_FORMAT).replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def clamp_ttl(seconds) -> int:
    """Coerce a requested lifetime into the supported window."""
    try:
        ttl = int(seconds)
    except (TypeError, ValueError):
        return DEFAULT_TTL_SECONDS
    return max(MIN_TTL_SECONDS, min(MAX_TTL_SECONDS, ttl))


def _directory() -> Path:
    # Read the module attribute every time: tests (and the conftest safety
    # fixture) redirect PENDING_DIR, and the real vault must never be written to
    # from a test run.
    return Path(PENDING_DIR)


def _path(code: str) -> Path:
    return _directory() / f"{normalize_code(code)}.json"


def _write(path: Path, record: dict) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(record, handle, indent=2)
    try:
        os.chmod(path, 0o600)
    except OSError:  # pragma: no cover - a filesystem that cannot chmod
        pass


def _read(path: Path) -> dict | None:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _remove(path: Path) -> None:
    try:
        path.unlink()
    except OSError:
        pass


def is_expired(record: dict, *, now: datetime | None = None) -> bool:
    """A *pending* claim past its ``expires_at``. Filled claims never expire."""
    if record.get("status") != STATUS_PENDING:
        return False
    expires = _parse(record.get("expires_at"))
    if expires is None:
        return True  # unreadable timestamp: treat as dead rather than live
    return expires <= (now or _now())


def _is_stale(record: dict, *, now: datetime | None = None) -> bool:
    """True when the record should be pruned on sight (either kind)."""
    moment = now or _now()
    if is_expired(record, now=moment):
        return True
    if record.get("status") == STATUS_FILLED:
        filled = _parse(record.get("filled_at")) or _parse(record.get("created_at"))
        if filled is None:
            return False
        return filled + timedelta(seconds=FILLED_RETENTION_SECONDS) <= moment
    return False


# ── the public surface ────────────────────────────────────────────────────────


def create(
    family: str,
    name: str,
    *,
    service: str | None = None,
    notes: str | None = None,
    login_url: str | None = None,
    category: str | None = None,
    username: str | None = None,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    now: datetime | None = None,
) -> dict:
    """Write a new pending claim and return its record.

    ``name`` and ``family`` are the only required fields; everything else is
    whatever non-secret metadata the caller already had. Never overwrites an
    existing claim: a code collision re-rolls.
    """
    if family not in FAMILIES:
        raise ValueError(f"unknown family: {family!r}")

    moment = now or _now()
    ttl = clamp_ttl(ttl_seconds)
    _directory().mkdir(mode=0o700, parents=True, exist_ok=True)

    for _ in range(_MAX_COLLISION_ATTEMPTS):
        code = generate_code()
        path = _directory() / f"{code}.json"
        if path.exists():
            continue
        record = {
            "code": code,
            "family": family,
            "name": name,
            "service": service,
            "notes": notes,
            "login_url": login_url,
            "category": category,
            "username": username,
            "created_at": _stamp(moment),
            "expires_at": _stamp(moment + timedelta(seconds=ttl)),
            "ttl_seconds": ttl,
            "status": STATUS_PENDING,
            "filled_at": None,
        }
        _write(path, record)
        return record

    raise RuntimeError(
        "could not allocate a free claim code — the pending directory is full or unwritable"
    )


def peek(code: str, *, now: datetime | None = None) -> dict | None:
    """Read a claim and report it *even when it is expired or filled*.

    ``load`` answers "can this be used"; ``peek`` answers "what is this", which
    is what an expired-or-already-filled message needs. Only a missing or
    unreadable file comes back as ``None``.
    """
    try:
        path = _path(code)
    except ValueError:
        return None
    record = _read(path)
    if record is None:
        _remove(path)  # unreadable: drop it rather than leave a trap behind
        return None
    return record


def load(code: str, *, now: datetime | None = None) -> dict | None:
    """A claim that may still be used, or ``None`` (missing, expired, pruned)."""
    try:
        path = _path(code)
    except ValueError:
        return None
    record = _read(path)
    if record is None:
        _remove(path)
        return None
    if _is_stale(record, now=now):
        _remove(path)
        return None
    return record


def mark_filled(code: str, *, now: datetime | None = None) -> dict | None:
    """Consume a claim. ``None`` when it is unknown, expired or already filled."""
    moment = now or _now()
    record = peek(code, now=moment)
    if record is None or record.get("status") != STATUS_PENDING:
        return None
    if is_expired(record, now=moment):
        return None
    record["status"] = STATUS_FILLED
    record["filled_at"] = _stamp(moment)
    _write(_path(record["code"]), record)
    return record


def delete(code: str) -> bool:
    """Cancel a claim. Returns whether anything was removed."""
    try:
        path = _path(code)
    except ValueError:
        return False
    if not path.exists():
        return False
    _remove(path)
    return True


def list_records(*, now: datetime | None = None) -> list[dict]:
    """Every live claim: pending first (oldest first), then recently filled.

    Prunes as it reads — an expired or long-filled claim is deleted the moment
    anything looks at the directory.
    """
    moment = now or _now()
    records: list[dict] = []
    for path in sorted(_directory().glob("*.json")):
        record = _read(path)
        if record is None or _is_stale(record, now=moment):
            _remove(path)
            continue
        records.append(record)
    records.sort(key=lambda r: (r.get("status") != STATUS_PENDING, r.get("created_at") or ""))
    return records


def pending(*, now: datetime | None = None) -> list[dict]:
    """Only the claims still waiting for a human."""
    return [r for r in list_records(now=now) if r.get("status") == STATUS_PENDING]


def seconds_remaining(record: dict, *, now: datetime | None = None) -> int:
    """Seconds until a pending claim expires; ``0`` for a filled one."""
    if record.get("status") != STATUS_PENDING:
        return 0
    expires = _parse(record.get("expires_at"))
    if expires is None:
        return 0
    return max(0, int((expires - (now or _now())).total_seconds()))


def filled_seconds_ago(record: dict, *, now: datetime | None = None) -> int | None:
    """How long ago a claim was filled; ``None`` while it is still pending."""
    if record.get("status") != STATUS_FILLED:
        return None
    filled = _parse(record.get("filled_at")) or _parse(record.get("created_at"))
    if filled is None:
        return None
    return max(0, int(((now or _now()) - filled).total_seconds()))
