"""``psamvault policy`` — where a stored secret may be sent.

``allow_entries`` in ``policy.json`` is the reveal list: names an agent may
print. ``entries.<name>.allow_hosts`` is the destination list: hosts the MCP
may send that entry's secret to. These commands edit the destination list.

They are a human action. An agent is refused, and a pipe cannot answer the
confirmation, for the same reason ``approve`` requires a real terminal: the
MCP has no tool that grants a host, and the CLI must not grow one an agent
can call. Listing is not a grant. An agent may list.

This does not reveal a secret, and it does not override the MCP's block on
loopback, private, and link-local addresses.
"""
from typing import Optional

import typer

import allow_hosts
import api_client
import audit
import caller
import policy
import session
from error_ui import print_error
from errors import NotFoundError, PsamVaultError

app = typer.Typer(
    name="policy",
    help="Destination hosts a stored secret may be sent to (not the reveal list)",
)

# What kind of entry a name resolves to. The third item is the api_client reader.
# The result is only a kind. The entry body is never printed.
_LOOKUPS = (
    ("site", "site_name", "get_vault_entry"),
    ("API key", "name", "get_api_key_entry"),
    ("note", "title", "get_note_entry"),
)


@app.callback(invoke_without_command=True)
def policy_help(ctx: typer.Context):
    if ctx.invoked_subcommand is None:
        typer.echo("""
psamvault policy — hosts a stored secret may be sent to

  COMMAND                       USAGE
  ──────────────────────────────────────────────────────────────────────────────
  allow-host <entry> <host>     psamvault policy allow-host ledger-key api.ledger.example
  remove-host <entry> <host>    psamvault policy remove-host ledger-key api.ledger.example
  hosts [entry]                 psamvault policy hosts
                                psamvault policy hosts ledger-key

  Use this when psamvault-mcp refuses a destination and a human should allow it.
  A leading '*.' allows that domain and its subdomains (*.ghcr.io).

  This is not the reveal list. allow_entries, and psamvault approve, decide who
  may print a secret. allow-host does not print one, and an agent cannot run it.
""")


def _locate_entry(name: str) -> str | None:
    """Return "site" / "API key" / "note", or None when no entry has this name."""
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


def _entry_note(name: str) -> str | None:
    """Warn when the name is not a vault entry. Never include a secret."""
    if not session.is_logged_in():
        return f"Not logged in, so this did not check whether '{name}' exists."
    try:
        kind = _locate_entry(name)
    except PsamVaultError as exc:
        return (
            f"Could not check whether '{name}' exists ({exc.message}). "
            "The host will still be saved."
        )
    except typer.Exit:
        return f"Could not check whether '{name}' exists. The host will still be saved."
    if kind is None:
        return (
            f"No vault entry named '{name}' was found (checked sites, API keys and notes). "
            "The host is saved anyway and applies when an entry with that name exists."
        )
    return None


def _refuse_agent(action: str, entry: str, host: str | None) -> caller.CallerVerdict:
    """Return the human verdict, or exit when the caller is an agent."""
    verdict = caller.classify(with_ancestry=True)
    if verdict.is_agent:
        active = policy.load()
        audit.record(
            command=f"policy {action}",
            decision=audit.DECISION_DENY,
            caller=verdict.verdict,
            entry=entry,
            host=host,
            signals=list(verdict.signals),
            tty=verdict.tty,
            policy_mode=active.reveal,
        )
        print_error(
            PsamVaultError(
                f"psamvault policy {action} is blocked in this context (agent terminal detected).",
                hint=(
                    "Run it yourself in a terminal. "
                    "There is no flag an agent can pass to grant or remove a host."
                ),
            )
        )
        raise typer.Exit(code=1)
    return verdict


def _require_terminal(action: str) -> None:
    if caller.tty_present():
        return
    print_error(
        PsamVaultError(
            f"policy {action} needs a real terminal — stdin and stdout must both be a TTY.",
            hint="An agent or a pipe cannot change a destination allow list. Run this yourself.",
        )
    )
    raise typer.Exit(code=1)


def _confirm(prompt: str, cancelled: str) -> None:
    try:
        accepted = typer.confirm(prompt)
    except typer.Abort:
        accepted = False
    if not accepted:
        typer.echo(cancelled)
        raise typer.Exit(code=1)


def _record(action: str, decision: str, verdict: caller.CallerVerdict, entry: str, host: str) -> None:
    active = policy.load()
    audit.record(
        command=f"policy {action}",
        decision=decision,
        caller=verdict.verdict,
        entry=entry,
        host=host,
        signals=list(verdict.signals),
        tty=verdict.tty,
        policy_mode=active.reveal,
    )


def _fail(exc: Exception) -> None:
    message = getattr(exc, "message", None) or str(exc)
    print_error(PsamVaultError(message))
    raise typer.Exit(code=1)


@app.command("allow-host")
def allow_host(
    entry: str = typer.Argument(..., help="Vault entry name: a site, an API key name, or a note title"),
    host: str = typer.Argument(
        ...,
        help="Hostname to allow, or *.example.com for that domain and its subdomains",
    ),
):
    """
    Allow one destination host for one entry.

    \b
    Examples:
        psamvault policy allow-host ledger-key api.ledger.example
        psamvault policy allow-host github.com '*.ghcr.io'

    \b
    Writes entries["<entry>"].allow_hosts in ~/.psamvault/policy.json.
    A human runs this in a terminal. It does not reveal the secret, and it
    does not change who may print one (that is allow_entries / approve).
    """
    verdict = allow_hosts.judge(host, strict=True)
    if verdict.problem or not verdict.normalized:
        _fail(policy.HostRejected(verdict.problem or f"{host!r} is not a hostname."))
    normalized = verdict.normalized
    caller_verdict = _refuse_agent("allow-host", entry, normalized)
    _require_terminal("allow-host")

    try:
        data = policy.read_document()
        key, _spec, hosts = policy.entry_spec(data, entry, create=False)
    except policy.PolicyDocumentError as exc:
        _fail(exc)
        return
    if key is not None and hosts is not None and any(
        allow_hosts.same_host(str(item), normalized) for item in hosts
    ):
        typer.echo(f"  {normalized} is already allowed for '{key}'.\n")
        return

    note = _entry_note(entry)
    if note:
        typer.echo(f"  Note: {note}")
    scope = "that host and its subdomains" if normalized.startswith("*.") else "that host"
    typer.echo(
        f"\n  About to allow {normalized} to receive the secret for '{entry}'."
        f"\n  This covers {scope}. It does not reveal the secret."
        f"\n  Loopback, private and link-local addresses stay blocked.\n"
    )
    _confirm(
        f"  Allow '{normalized}' for '{entry}'?",
        "  Cancelled. No host was allowed.\n",
    )
    try:
        stored_key, stored_host, changed = policy.add_allow_host(entry, normalized)
    except (policy.HostRejected, policy.PolicyDocumentError) as exc:
        _fail(exc)
        return
    if not changed:
        typer.echo(f"  {stored_host} is already allowed for '{stored_key}'.\n")
        return
    _record("allow-host", audit.DECISION_GRANTED, caller_verdict, stored_key, stored_host)
    typer.echo(f"  ✓ Allowed {stored_host} for '{stored_key}'.")
    typer.echo(
        "  → psamvault-mcp will send that entry's secret to this host"
        + (" and its subdomains." if stored_host.startswith("*.") else ".")
    )
    typer.echo("  → This does not reveal the secret. Run  psamvault policy hosts  to see the list.\n")


@app.command("remove-host")
def remove_host(
    entry: str = typer.Argument(..., help="Vault entry name the host was allowed for"),
    host: str = typer.Argument(..., help="Hostname to remove from that entry's allow_hosts"),
):
    """
    Remove one destination host from one entry.

    \b
    Examples:
        psamvault policy remove-host ledger-key api.ledger.example

    \b
    A human runs this in a terminal. A value that could not be granted
    (a loopback address, a bare public suffix) can still be removed.
    """
    recorded = allow_hosts.judge(host, strict=False).normalized or host.strip()
    caller_verdict = _refuse_agent("remove-host", entry, recorded)
    _require_terminal("remove-host")
    try:
        key, removed_preview = _peek_removal(entry, host)
    except policy.PolicyDocumentError as exc:
        _fail(exc)
        return
    if not removed_preview:
        print_error(
            PsamVaultError(
                f"{host!r} is not an allow_hosts value for '{entry}'.",
                hint="psamvault policy hosts   lists what is configured.",
            )
        )
        raise typer.Exit(code=1)

    note = _entry_note(entry)
    if note:
        typer.echo(f"  Note: {note}")
    shown = ", ".join(removed_preview)
    typer.echo(
        f"\n  About to stop allowing {shown} for '{key}'."
        f"\n  The secret can no longer be sent there unless the entry already owns that host.\n"
    )
    _confirm(
        f"  Remove '{shown}' from '{key}'?",
        "  Cancelled. No host was removed.\n",
    )
    try:
        stored_key, removed = policy.remove_allow_host(entry, host)
    except policy.PolicyDocumentError as exc:
        _fail(exc)
        return
    if not removed:
        print_error(PsamVaultError(f"{host!r} is not an allow_hosts value for '{entry}'."))
        raise typer.Exit(code=1)
    _record("remove-host", audit.DECISION_REVOKED, caller_verdict, stored_key, recorded)
    typer.echo(f"  ✓ Removed {', '.join(removed)} from '{stored_key}'.\n")


def _peek_removal(entry: str, host: str) -> tuple[str, list[str]]:
    data = policy.read_document()
    key, _spec, hosts = policy.entry_spec(data, entry, create=False)
    if key is None or hosts is None:
        return entry.strip(), []
    removed = [str(item) for item in hosts if allow_hosts.same_host(str(item), host)]
    return key, removed


@app.command("hosts")
def hosts(
    entry: Optional[str] = typer.Argument(
        None, help="Entry to list. Omit to list every entry that has a destination list."
    ),
):
    """
    List destination hosts. Per entry, or every entry.

    \b
    Examples:
        psamvault policy hosts
        psamvault policy hosts ledger-key

    \b
    An agent may run this. It prints hostnames and warnings, never a secret.
    A bad value already in the file is reported here and is not treated as allowed.
    """
    loaded = policy.load()
    for warning in loaded.warnings:
        typer.echo(f"  ! {warning}")

    if entry is not None:
        key = policy.matching_entry_key(loaded.entry_hosts, entry)
        if key is None:
            typer.echo(f"  {entry}")
            typer.echo("    (no hosts)\n")
            return
        _print_entry(key, loaded.entry_hosts.get(key, []))
        return

    if not loaded.entry_hosts:
        typer.echo("  No destination hosts are configured.")
        typer.echo("  A site password can still go to its own domain, and an API key to its service hosts.")
        typer.echo("  allow_entries is the reveal list, not this one.\n")
        return
    for name, allowed in loaded.entry_hosts.items():
        _print_entry(name, allowed)


def _print_entry(name: str, allowed: list[str]) -> None:
    typer.echo(f"  {name}")
    if not allowed:
        typer.echo("    (no hosts)")
    else:
        for host in allowed:
            typer.echo(f"    {host}")
    typer.echo("")
