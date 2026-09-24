"""The claim handoff — shared by the three commands that can create an entry blind.

Two halves in one module:

* **the agent's half** — :func:`create_claim` writes a pending claim and
  :func:`print_claim` renders the only thing an agent may see: the code, the
  family, the deadline and the human's next step. Nothing else, ever.
* **the human's half** — :func:`require_fill_context` refuses a fill from an
  agent shell, :func:`resolve_claim` turns a typed code into the record to fill
  (or refuses, saying *which* failure it was: unknown, expired, already filled),
  and :func:`complete_claim` consumes the code once the entry is really stored.

:func:`require_no_argv_secret` is the other direction of the same guard. The
reveal guardrail stops a secret *leaving*; this stops one *entering* through a
command line, where process listings, shell history and any wrapper that logs a
command line all keep a copy.

Nothing in this module ever handles a plaintext value except
:func:`read_secret_from_file` / :func:`read_env_secret`, which exist so a value
can move from a file or an environment variable into the vault **without being
printed** — their return value goes straight to ``encrypt_*``.
"""
from __future__ import annotations

import os
import re
import time
from pathlib import Path

import typer

import caller
import pending_store as store
from audit import (
    DECISION_CLAIM_CREATED,
    DECISION_CLAIM_FILLED,
    DECISION_DENY,
    record as audit_record,
)
from errors import IngressBlockedError, PsamVaultError

# How long `--wait` sleeps between checks. Patched to something tiny in tests.
POLL_INTERVAL_SECONDS = 1.0

DEFAULT_TIMEOUT_SECONDS = store.DEFAULT_TTL_SECONDS

# The command the human has to run, per family. One place, so the agent's
# instruction and the docs can never disagree.
_FILL_COMMANDS = {
    store.FAMILY_API_KEY: "psamvault ak-add --claim {code}",
    store.FAMILY_CREDENTIAL: "psamvault add --claim {code}",
    store.FAMILY_NOTE: "psamvault note-add --claim {code}",
}

_ENV_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")

_DURATION = re.compile(r"^\s*(\d+)\s*([smh]?)\s*$", re.IGNORECASE)

_DURATION_UNITS = {"": 1, "s": 1, "m": 60, "h": 3600}


# ── classification ───────────────────────────────────────────────────────────


def classify() -> caller.CallerVerdict:
    """Who is asking.

    Ancestry is consulted here too, not only on reveal paths: an ingress
    decision (help the human, or hand the agent a claim) is worth the walk, and
    an ordinary command never reaches this function at all.
    """
    return caller.classify(with_ancestry=True)


def _entry_label(family: str, name: str, service: str | None = None) -> str:
    if family == store.FAMILY_API_KEY:
        return f"{name} ({service})" if service else name
    return name


# ── the agent's half ─────────────────────────────────────────────────────────


def create_claim(
    family: str,
    name: str,
    *,
    service: str | None = None,
    notes: str | None = None,
    login_url: str | None = None,
    category: str | None = None,
    username: str | None = None,
    verdict: caller.CallerVerdict | None = None,
    ttl_seconds: int = store.DEFAULT_TTL_SECONDS,
) -> dict:
    """Write a pending claim and record it in the audit trail."""
    verdict = verdict or classify()
    record = store.create(
        family,
        name,
        service=service,
        notes=notes,
        login_url=login_url,
        category=category,
        username=username,
        ttl_seconds=ttl_seconds,
    )
    audit_record(
        command=_command_name(family),
        decision=DECISION_CLAIM_CREATED,
        caller=verdict.verdict,
        entry=name,
        signals=list(verdict.signals),
        tty=verdict.tty,
    )
    return record


def _command_name(family: str) -> str:
    return {
        store.FAMILY_API_KEY: "ak-add",
        store.FAMILY_CREDENTIAL: "add",
        store.FAMILY_NOTE: "note-add",
    }[family]


def human_instruction(record: dict) -> str:
    """The exact command the human runs to fill this claim."""
    return _FILL_COMMANDS[record["family"]].format(code=record["code"])


def print_claim(record: dict) -> None:
    """Render the agent-facing response. The value is not here and never will be."""
    minutes = max(1, record["ttl_seconds"] // 60)
    label = _entry_label(record["family"], record["name"], record.get("service"))
    typer.echo(f"\n  Pending: {label}")
    typer.echo(f"  Family:  {record['family']}")
    typer.echo(f"  Claim code: {record['code']}        expires in {minutes}m")
    typer.echo("\n  Ask the human to run, in their own terminal:")
    typer.echo(f"      {human_instruction(record)}")
    typer.echo(
        "  Only that command can supply the value — it never reaches this process.\n"
    )


def require_no_argv_secret(
    verdict: caller.CallerVerdict,
    flag: str,
    name: str,
    fill_example: str,
    *,
    command: str,
) -> None:
    """Refuse a value passed on the command line from an agent context.

    Not about the vault's safety — about the copies: argv is visible to process
    listings, survives in shell history, and is logged by any wrapper that
    records command lines. The refusal is recorded like any other denial, so the
    trail shows attempts and not just successes.
    """
    if not verdict.is_agent:
        return
    audit_record(
        command=command,
        decision=DECISION_DENY,
        caller=verdict.verdict,
        entry=name,
        signals=list(verdict.signals),
        tty=verdict.tty,
    )
    raise IngressBlockedError(
        f"psamvault {flag} is blocked in this context (agent terminal detected)",
        details=[
            "a value in argv is visible to process listings, shell history and any wrapper that logs a command line",
            f"{fill_example}   (prints a claim code the human fills in their own terminal)",
            "--from-file / --from-env move a value that is already on this machine without ever putting it on a command line",
        ],
        hint=(
            "Ask the human for the value via the claim flow, or use --from-file / --from-env"
        ),
    )


# ── the human's half ─────────────────────────────────────────────────────────


def require_fill_context(verdict: caller.CallerVerdict, record: dict) -> None:
    """A claim is filled by a human, from a context that is not an agent.

    There is no legitimate agent case for the fill, and a wrong fill is silent
    until the human fails to decrypt their own entry.
    """
    if not verdict.is_agent:
        return
    raise IngressBlockedError(
        "filling a claim is blocked in this context (agent terminal detected)",
        details=[
            "the value must be typed by the human, in their own terminal",
            f"ask them to run:  {human_instruction(record)}",
        ],
        hint="Hand the claim code to the human and let them fill it",
    )


def resolve_claim(code: str, family: str, *, verdict: caller.CallerVerdict | None = None) -> dict:
    """Turn a typed code into the record to fill, or refuse with the reason."""
    verdict = verdict or classify()
    record = store.peek(code)

    if record is None:
        raise PsamVaultError(
            f"No claim matches {code}.",
            hint=(
                "Claims live only on the machine that created them and expire after "
                f"{store.DEFAULT_TTL_SECONDS // 60} minutes — ask for a new one"
            ),
        )

    if record["family"] != family:
        raise PsamVaultError(
            f"Claim {record['code']} is for a {record['family'].replace('_', ' ')} entry, not this command.",
            hint=f"Fill it with:  {human_instruction(record)}",
        )

    if store.is_expired(record):
        raise PsamVaultError(
            f"Claim {record['code']} expired.",
            hint="Nothing was stored — ask the agent for a new claim code",
        )

    if record["status"] == store.STATUS_FILLED:
        raise PsamVaultError(
            f"Claim {record['code']} has already been filled.",
            hint=f"'{record['name']}' is already in your vault — nothing to do",
        )

    require_fill_context(verdict, record)
    return record


def complete_claim(record: dict, *, verdict: caller.CallerVerdict | None = None) -> None:
    """Consume the code — called only after the entry is really stored."""
    verdict = verdict or classify()
    store.mark_filled(record["code"])
    audit_record(
        command=_command_name(record["family"]),
        decision=DECISION_CLAIM_FILLED,
        caller=verdict.verdict,
        entry=record["name"],
        signals=list(verdict.signals),
        tty=verdict.tty,
    )


# ── --wait ───────────────────────────────────────────────────────────────────


def parse_duration(text: str, *, default: int = DEFAULT_TIMEOUT_SECONDS) -> int:
    """``30s`` / ``15m`` / ``1h`` / ``900`` → seconds, clamped to the TTL window."""
    if text is None:
        return default
    match = _DURATION.match(str(text))
    if not match:
        raise PsamVaultError(
            f"'{text}' is not a duration.",
            hint="Use seconds, or a suffix: 30s, 15m, 1h",
        )
    seconds = int(match.group(1)) * _DURATION_UNITS[match.group(2).lower()]
    return max(1, min(store.MAX_TTL_SECONDS, seconds))


def wait_for_fill(
    code: str,
    timeout_seconds: int,
    *,
    sleep=time.sleep,
    monotonic=time.monotonic,
) -> dict | None:
    """Block until the human fills the claim, or the timeout passes.

    Returns the filled record, or ``None`` on timeout / cancellation. The claim
    itself is never touched here: a timeout leaves the code valid, so an agent
    that was cut short by a host's tool-call cap only has to check, not re-ask.
    """
    deadline = monotonic() + max(1, timeout_seconds)
    while True:
        record = store.load(code)
        if record is None:
            return None  # cancelled or expired underneath us
        if record["status"] == store.STATUS_FILLED:
            return record
        if monotonic() >= deadline:
            return None
        sleep(POLL_INTERVAL_SECONDS)


def wait_and_report(record: dict, timeout_seconds: int) -> None:
    """Wait for the fill and render the outcome. Timeout is exit 3: not a failure, not yet."""
    filled = wait_for_fill(record["code"], timeout_seconds)
    if filled is not None:
        typer.echo(f"\n ✓ '{filled['name']}' was filled by the human and is now stored\n")
        return
    still = store.peek(record["code"])
    if still is None:
        typer.echo(f"\n ✗ Claim {record['code']} was cancelled or expired before it was filled.", err=True)
        raise typer.Exit(code=1)
    minutes = max(1, store.seconds_remaining(still) // 60)
    typer.echo(
        f"\n   Claim {record['code']} is still pending — the code is still valid, {minutes}m left.",
        err=True,
    )
    raise typer.Exit(code=3)


# ── moving a value that is already on this machine ───────────────────────────


def read_secret_from_file(path: str, key: str | None = None) -> str:
    """The value from a file, without it ever being printed.

    ``key=None`` means the whole file *is* the secret (a service-account JSON, a
    ``.pem``); ``key="NAME"`` takes one ``NAME=value`` line out of a ``.env``.
    """
    target = Path(path).expanduser()
    try:
        text = target.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise PsamVaultError(
            f"Could not read {target}.",
            hint=str(exc),
        ) from exc

    if key is None:
        return text.rstrip("\n")

    value = parse_env_value(text, key)
    if value is None:
        names = ", ".join(sorted(parse_env_names(text))) or "none"
        raise PsamVaultError(
            f"{target} has no {key}= line.",
            hint=f"Keys in this file: {names}",
        )
    return value


def parse_env_value(text: str, key: str) -> str | None:
    """Pull one ``NAME=value`` out of dotenv-style text (quotes and ``export`` handled)."""
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _ENV_LINE.match(line)
        if not match or match.group(1) != key:
            continue
        return _unquote(match.group(2).strip())
    return None


def parse_env_names(text: str) -> list[str]:
    """The key NAMES in dotenv-style text — names, never values."""
    names: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _ENV_LINE.match(line)
        if match:
            names.append(match.group(1))
    return names


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        inner = value[1:-1]
        if value[0] == '"':
            inner = (
                inner.replace("\\n", "\n")
                .replace("\\t", "\t")
                .replace('\\"', '"')
                .replace("\\\\", "\\")
            )
        return inner
    # unquoted: a trailing comment after whitespace is not part of the value
    return value.split(" #", 1)[0].strip()


def remove_env_line(path: str, key: str) -> tuple[Path, Path]:
    """Delete one line from a dotenv file, keeping the original as ``<file>.bak``.

    Only ever one line, and only when the caller asked for it by name: this is
    the one destructive thing in the feature, so it is deliberately narrow.
    """
    target = Path(path).expanduser()
    try:
        text = target.read_text(encoding="utf-8")
    except OSError as exc:
        raise PsamVaultError(f"Could not read {target} to clean it up.", hint=str(exc)) from exc

    remaining = [
        line
        for line in text.splitlines(keepends=True)
        if not (_ENV_LINE.match(line) and _ENV_LINE.match(line).group(1) == key)
    ]
    backup = target.with_suffix(target.suffix + ".bak")
    backup.write_text(text, encoding="utf-8")
    target.write_text("".join(remaining), encoding="utf-8")
    return target, backup


def read_env_secret(variable: str) -> str:
    """The value of an environment variable, without it ever being printed."""
    value = os.environ.get(variable)
    if not value:
        raise PsamVaultError(
            f"{variable} is not set in this environment.",
            hint="Set it in the process that runs psamvault, or use the claim flow",
        )
    return value
