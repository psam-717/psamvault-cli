"""``psamvault approve`` — hand an agent ONE reveal, from a real terminal.

This is the human half of the guardrail. The agent cannot reveal a secret, so
when it genuinely needs one it asks; the human runs this command in their own
terminal, sees exactly which entry they are authorising and for how long, and
mints a single-use token. The agent's next reveal of that entry succeeds once.

Why the friction is deliberate:

* ``--for-agent`` is required. Without it the command refuses — the intent to
  hand a secret to a *program* should be typed, not implied by default.
* A real terminal is required (both stdin and stdout on a TTY, the same check
  the classifier uses). A redirected, piped or agent-spawned invocation cannot
  mint a token, so an agent cannot approve itself out of a refusal.
* The approval covers ONE entry for ONE reveal. It is not a mode switch: a token
  for ``github.com`` unlocks nothing else, and no token can authorise a
  whole-vault plaintext dump (see ``reveal_gate``).

Honest limit, stated in ``SECURITY.md`` too: this is tamper-*resistance*, not a
boundary. The token is stored in the OS keychain, which anything running as the
user (including an agent) can read and write. It buys a hard structural stop for
well-behaved callers, plus a real trail of who authorised what.
"""
from typing import Optional

import typer

import api_client
import audit
import caller
import policy
import session
from error_ui import print_error
from errors import NotFoundError, PsamVaultError

# What kind of entry a name resolves to — also what the confirmation names, so
# the human never has to guess whether "github.com" is a site or a note. The
# third item is the api_client reader used to prove the entry exists.
_LOOKUPS = (
    ("site", "site_name", "get_vault_entry"),
    ("API key", "name", "get_api_key_entry"),
    ("note", "title", "get_note_entry"),
)


def _locate_entry(name: str) -> "str | None":
    """Return the entry's kind ("site" / "API key" / "note"), or None if unknown.

    Confirming the entry exists prevents minting an approval for a typo — a
    token nobody can use, which would look to the agent like a live handover.
    Network and session failures propagate as typed errors.
    """
    session_data = api_client.ensure_session()
    for kind, argument, reader in _LOOKUPS:
        try:
            getattr(api_client, reader)(
                access_token=session_data["access_token"],
                refresh_token=session_data["refresh_token"],
                **{argument: name},
            )
            return kind
        except NotFoundError:
            continue
    return None


def approve(
    entry: str = typer.Argument(
        ..., help="Entry to approve: a site, an API key name, or a note title"
    ),
    for_agent: bool = typer.Option(
        False, "--for-agent",
        help="Confirm this reveal is for an agent rather than for you",
    ),
    ttl: Optional[int] = typer.Option(
        None, "--ttl",
        help="Seconds the approval stays live (15-3600, default from policy)",
    ),
):
    """
    Approve ONE reveal of ONE entry for an agent.

    \b
    Examples:
        psamvault approve github.com --for-agent
        psamvault approve openai-prod --for-agent --ttl 60

    \b
    The agent's next `get` / `ak-get` / `note-get` for that entry prints the
    secret once; a second attempt is refused. Nothing else is unlocked.
    """
    if not for_agent:
        print_error(
            PsamVaultError(
                "This mints a one-time reveal of a secret for an agent.",
                hint="Re-run with --for-agent to confirm that is what you want.",
            )
        )
        raise typer.Exit(code=1)

    if not caller.tty_present():
        print_error(
            PsamVaultError(
                "approve needs a real terminal — stdin and stdout must both be a TTY.",
                hint="An agent or a pipe cannot mint its own approval; run this yourself.",
            )
        )
        raise typer.Exit(code=1)

    active_policy = policy.load()
    if ttl is None:
        ttl_seconds = active_policy.approval_ttl_seconds
    else:
        ttl_seconds = policy.clamp_ttl(ttl)
        if ttl_seconds != ttl:
            typer.echo(
                f"  Note: --ttl {ttl} is outside the supported range;"
                f" using {ttl_seconds}s."
            )

    try:
        kind = _locate_entry(entry)
    except PsamVaultError as exc:
        print_error(exc)
        raise typer.Exit(code=1)

    if kind is None:
        print_error(
            PsamVaultError(
                f"No vault entry named '{entry}' was found (checked sites, API keys and notes).",
                hint="Check the name with  psamvault list  /  psamvault ak-list  /  psamvault note-list",
            )
        )
        raise typer.Exit(code=1)

    typer.echo(
        f"\n  About to let an agent reveal {kind} '{entry}' ONCE."
        f"\n  The approval is live for {ttl_seconds}s and covers nothing else.\n"
    )
    if not typer.confirm(f"  Mint this one-time approval for {kind} '{entry}' ({ttl_seconds}s)?"):
        typer.echo("  Cancelled. No approval was minted.\n")
        raise typer.Exit(code=1)

    token = session.mint_approval(entry, ttl_seconds)
    audit.record(
        command="approve",
        decision=audit.DECISION_MINTED,
        caller=caller.VERDICT_HUMAN,
        entry=entry,
        signals=[],
        tty=True,
        token_id=token["token_id"],
        policy_mode=active_policy.reveal,
    )

    typer.echo(f"  ✓ One-time reveal approved for {kind} '{entry}' ({ttl_seconds}s)")
    typer.echo(
        f"  → The agent's next reveal of '{entry}' succeeds once; a second attempt is refused."
    )
    typer.echo("  → Changed your mind?  psamvault logout  drops every pending approval.\n")
