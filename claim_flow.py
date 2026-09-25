"""The claim handoff — shared by the three commands that can create an entry blind.

Two halves in one module:

* **the agent's half** — :func:`create_claim` writes a pending claim and
  :func:`print_claim` renders the only thing an agent may see: the code, the
  entry it names, the deadline and the one command the human runs.
* **the human's half** — :func:`require_fill_context` refuses a fill from an
  agent shell, :func:`resolve_claim` turns a typed code into the record to fill
  (or refuses, saying *which* failure it was: unknown, expired, wrong family),
  and :func:`complete_claim` spends the code once the entry is really stored.

:func:`require_no_argv_secret` is the other direction of the same guard. The
reveal guardrail stops a secret *leaving*; this stops one *entering* through a
command line, where process listings, shell history and any wrapper that logs a
command line all keep a copy.

Both refusals are recorded in the audit trail, so the trail shows attempts and
not only successes. Nothing in this module ever handles a plaintext value: the
value is typed into the command's own hidden prompt and goes straight to
``encrypt_*``.
"""
from __future__ import annotations

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

# The command the human has to run, per family. One place, so the agent's
# instruction and the docs can never disagree.
_FILL_COMMANDS = {
    store.FAMILY_API_KEY: "psamvault ak-add --claim {code}",
    store.FAMILY_CREDENTIAL: "psamvault add --claim {code}",
    store.FAMILY_NOTE: "psamvault note-add --claim {code}",
}

_COMMAND_NAMES = {
    store.FAMILY_API_KEY: "ak-add",
    store.FAMILY_CREDENTIAL: "add",
    store.FAMILY_NOTE: "note-add",
}


# ── classification ───────────────────────────────────────────────────────────


def classify() -> caller.CallerVerdict:
    """Who is asking — the wave-1 caller check, not a second classifier.

    Ancestry is consulted here too, not only on reveal paths: an ingress
    decision (help the human, or hand the agent a claim) is worth the walk, and
    an ordinary command never reaches this function at all.
    """
    return caller.classify(with_ancestry=True)


def _entry_label(record: dict) -> str:
    """``github-prod (GitHub)`` — the name, plus the service for an API key."""
    name = record.get("name") or ""
    service = record.get("service")
    if record.get("family") == store.FAMILY_API_KEY and service:
        return f"{name} ({service})"
    return name


def _command_name(family: str) -> str:
    return _COMMAND_NAMES[family]


def _deny(verdict: caller.CallerVerdict, record: dict) -> None:
    audit_record(
        command=_command_name(record["family"]),
        decision=DECISION_DENY,
        caller=verdict.verdict,
        entry=record["name"],
        signals=list(verdict.signals),
        tty=verdict.tty,
    )


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


def human_instruction(record: dict) -> str:
    """The exact command the human runs to fill this claim."""
    return _FILL_COMMANDS[record["family"]].format(code=record["code"])


def print_claim(record: dict) -> None:
    """Render the agent-facing response. The value is not here and never will be."""
    minutes = max(1, store.seconds_remaining(record) // 60)
    typer.echo(f"\n  Claim code: {record['code']}        expires in {minutes} minutes")
    typer.echo(f"  Entry:      {_entry_label(record)}")
    typer.echo("\n  Run this in your own terminal:")
    typer.echo(f"      {human_instruction(record)}\n")


def print_fill_header(record: dict) -> None:
    """What the human is about to fill — the name, and the service for a key."""
    typer.echo(f"\n  Claim:  {record['code']}")
    typer.echo(f"  Entry:  {_entry_label(record)}\n")


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
    records command lines.
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
        ],
        hint="Ask the human to fill the claim — the value never passes through this process",
    )


# ── the human's half ─────────────────────────────────────────────────────────


def require_fill_context(verdict: caller.CallerVerdict, record: dict) -> None:
    """A claim is filled by a human, from a context that is not an agent.

    There is no legitimate agent case for the fill, and a wrong fill is silent
    until the human fails to decrypt their own entry.
    """
    if not verdict.is_agent:
        return
    _deny(verdict, record)
    raise IngressBlockedError(
        f"filling claim {record['code']} is blocked in this context (agent terminal detected)",
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

    require_fill_context(verdict, record)
    return record


def complete_claim(record: dict, *, verdict: caller.CallerVerdict | None = None) -> bool:
    """Spend the code — called only after the entry is really stored."""
    verdict = verdict or classify()
    spent = store.consume(record["code"])
    if spent is None:
        return False
    audit_record(
        command=_command_name(record["family"]),
        decision=DECISION_CLAIM_FILLED,
        caller=verdict.verdict,
        entry=record["name"],
        signals=list(verdict.signals),
        tty=verdict.tty,
    )
    return True
