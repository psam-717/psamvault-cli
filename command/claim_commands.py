"""``psamvault pending`` — the claims waiting for a human.

Answers "what is outstanding, and did the human fill it yet", which is the half
of the handoff an agent cannot see for itself. It is deliberately NOT gated by
the reveal guardrail: it shows codes, names and statuses and never a value, and
an agent must be able to check its own claim.

    psamvault pending                      # everything outstanding + recently filled
    psamvault pending --code PV-4F2K-91QX  # one claim, with its remaining time
    psamvault pending --cancel PV-4F2K-91QX
"""
from typing import Optional

import typer

import pending_store as store
from error_ui import exit_error
from errors import PsamVaultError

_STATUS_LABEL = {
    store.STATUS_PENDING: "pending",
    store.STATUS_FILLED: "filled",
}


def _describe(record: dict, *, now=None) -> str:
    """``pending, 12m left`` / ``filled 3m ago`` — the answer to "did it happen yet"."""
    if record["status"] == store.STATUS_PENDING:
        seconds = store.seconds_remaining(record, now=now)
        return f"pending, {max(1, seconds // 60)}m left"
    ago = store.filled_seconds_ago(record, now=now)
    if ago is None:
        return "filled"
    minutes = ago // 60
    return "filled just now" if minutes < 1 else f"filled {minutes}m ago"


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

    typer.echo(f"\n  {'CODE':<15} {'FAMILY':<11} {'ENTRY':<28} STATUS")
    for record in records:
        typer.echo(
            f"  {record['code']:<15} {record['family']:<11} {_target(record):<28} {_describe(record)}"
        )
    typer.echo("\n  Fill one with the command it printed, e.g.  psamvault ak-add --claim <code>")
    typer.echo("  Cancel one with  psamvault pending --cancel <code>\n")


def _show_one(code: str) -> None:
    record = store.peek(code)
    if record is None:
        raise PsamVaultError(
            f"No claim matches {code}.",
            hint="Claims are local to this machine and expire after 15 minutes",
        )

    typer.echo(f"\n  Claim:  {record['code']}")
    typer.echo(f"  Family: {record['family']}")
    typer.echo(f"  Entry:  {_target(record)}")
    typer.echo(f"  Status: {_describe(record)}")
    for label, field in (("Notes", "notes"), ("Login URL", "login_url"), ("Category", "category")):
        if record.get(field):
            typer.echo(f"  {label}: {record[field]}")
    typer.echo(f"\n  Fill it with:  {_fill_command(record)}\n")


def _fill_command(record: dict) -> str:
    # Imported lazily so this module stays importable without the flow helpers
    # (and so the command's --help does not pull in the whole ingress stack).
    import claim_flow

    return claim_flow.human_instruction(record)


def _cancel(code: str) -> None:
    record = store.peek(code)
    if record is None:
        raise PsamVaultError(
            f"No claim matches {code}.",
            hint="Nothing to cancel",
        )
    if record["status"] == store.STATUS_FILLED:
        raise PsamVaultError(
            f"Claim {record['code']} was already filled — '{record['name']}' is in your vault.",
            hint="Delete the entry itself if you did not want it",
        )
    store.delete(record["code"])
    typer.echo(f"\n ✓ Claim {record['code']} cancelled — the code no longer works\n")


def pending(
    code: Optional[str] = typer.Option(
        None, "--code", help="Show one claim by its code, e.g. --code PV-4F2K-91QX"
    ),
    cancel: Optional[str] = typer.Option(
        None, "--cancel", help="Cancel an outstanding claim so its code stops working"
    ),
):
    """
    Show the entries an agent has asked for and a human has not filled yet.

    A claim is created when an agent runs an add command without a value; it
    holds no secret, expires after 15 minutes, and is replaced by the real entry
    the moment the human fills it.

    \b
    Examples:
        psamvault pending
        psamvault pending --code PV-4F2K-91QX
        psamvault pending --cancel PV-4F2K-91QX
    """
    try:
        if cancel:
            _cancel(cancel)
        elif code:
            _show_one(code)
        else:
            _list_claims()
    except PsamVaultError as exc:
        exit_error(exc)
