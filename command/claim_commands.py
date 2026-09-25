"""``psamvault pending`` — the claims waiting for a human.

Answers "what has an agent asked for that nobody has filled yet". It is
deliberately NOT gated by the reveal guardrail: it shows codes and names, never
a value, and an agent has to be able to check its own claim.

    psamvault pending                        # everything still waiting, with the time left
    psamvault pending --cancel PV-4F2K-91QX  # drop one
"""
from typing import Optional

import typer

import pending_store as store
from error_ui import exit_error
from errors import PsamVaultError


def _remaining(record: dict) -> str:
    """``14m left`` — the only status a live claim has."""
    minutes = max(1, store.seconds_remaining(record) // 60)
    return f"{minutes}m left"


def _target(record: dict) -> str:
    """The entry this claim will create, with whatever non-secret hint applies."""
    if record["family"] == store.FAMILY_API_KEY and record.get("service"):
        return f"{record['name']} ({record['service']})"
    return record["name"]


def _list_claims() -> None:
    records = store.list_records()
    if not records:
        typer.echo("\n  No claims are waiting. An agent creates one with:")
        typer.echo("      psamvault ak-add <name> --service <service>\n")
        return

    typer.echo(f"\n  {'CODE':<15} {'FAMILY':<11} {'ENTRY':<28} EXPIRES")
    for record in records:
        typer.echo(
            f"  {record['code']:<15} {record['family']:<11} {_target(record):<28} {_remaining(record)}"
        )
    typer.echo("\n  Fill one with the command it printed, e.g.  psamvault ak-add --claim <code>")
    typer.echo("  Cancel one with  psamvault pending --cancel <code>\n")


def _cancel(code: str) -> None:
    record = store.peek(code)
    if record is None:
        raise PsamVaultError(f"No claim matches {code}.", hint="Nothing to cancel")
    if store.is_expired(record):
        raise PsamVaultError(f"Claim {record['code']} has expired.", hint="Nothing to cancel")
    store.delete(record["code"])
    typer.echo(f"\n ✓ Claim {record['code']} cancelled — the code no longer works\n")


def pending(
    cancel: Optional[str] = typer.Option(
        None, "--cancel", help="Cancel an outstanding claim so its code stops working"
    ),
):
    """
    Show the entries an agent has asked for and a human has not filled yet.

    A claim is created when an agent runs an add command without a value; it
    holds no secret, expires after 15 minutes, and is spent the moment the human
    fills it.

    \\b
    Examples:
        psamvault pending
        psamvault pending --cancel PV-4F2K-91QX
    """
    try:
        if cancel:
            _cancel(cancel)
        else:
            _list_claims()
    except PsamVaultError as exc:
        exit_error(exc)
