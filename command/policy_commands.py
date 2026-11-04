"""``psamvault policy`` — where a stored secret may be sent, and which MCP tool may use it.

``allow_entries`` in ``policy.json`` is the reveal list: names an agent may
print. ``entries.<name>.allow_hosts`` is the destination list: hosts the MCP
may send that entry's secret to. ``entries.<name>.allow_tools`` is the MCP
tool list: which tools may use that entry once ``mcp_use`` is ``enforce``.
``ask_each_time`` is the flag a later in-chat question will read.

Grants, revocations, the flag and the mode are a human action. An agent is
refused, and a pipe cannot answer the confirmation, for the same reason
``approve`` requires a real terminal. Listing is not a grant. An agent may
list hosts, tools, and the current mode.

This does not reveal a secret, and it does not override the MCP's block on
loopback, private, and link-local addresses. Granting a tool does not turn
enforcement on. Absent ``mcp_use`` stays ``audit``: an unlisted tool is
recorded and not refused.
"""
from typing import Optional

import typer

import allow_hosts
import api_client
import audit
import caller
import mcp_use
import policy
import session
from error_ui import print_error
from errors import NotFoundError, PsamVaultError

app = typer.Typer(
    name="policy",
    help="Where a secret may be sent, and which MCP tool may use it (not the reveal list)",
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
psamvault policy — where a secret may be sent, and which MCP tool may use it

  COMMAND                              USAGE
  ──────────────────────────────────────────────────────────────────────────────
  allow-host <entry> <host>            psamvault policy allow-host ledger-key api.ledger.example
  remove-host <entry> <host>           psamvault policy remove-host ledger-key api.ledger.example
  hosts [entry]                        psamvault policy hosts
                                       psamvault policy hosts ledger-key
  allow-tool <entry> <tool>            psamvault policy allow-tool ledger-key use_credential
  remove-tool <entry> <tool>           psamvault policy remove-tool ledger-key use_credential
  tools [entry]                        psamvault policy tools
                                       psamvault policy tools ledger-key
  ask-each-time <entry> on|off         psamvault policy ask-each-time ledger-key on
  mcp-use [audit|enforce|off]          psamvault policy mcp-use
                                       psamvault policy mcp-use enforce

  allow-host is where a secret may be sent. allow-tool is which MCP tool may use it.
  mcp-use audit (the default) records an unlisted tool and does not refuse it.
  mcp-use enforce refuses a tool that is not listed. ask-each-time stores the flag
  the MCP will use to ask in chat. It does not ask now, and it does not reveal a secret.

  This is not the reveal list. allow_entries, and psamvault approve, decide who
  may print a secret. An agent cannot grant, revoke, or change the mode.
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


def _entry_note(name: str, *, saved: str = "host") -> str | None:
    """Warn when the name is not a vault entry. Never include a secret."""
    if not session.is_logged_in():
        return f"Not logged in, so this did not check whether '{name}' exists."
    try:
        kind = _locate_entry(name)
    except PsamVaultError as exc:
        return (
            f"Could not check whether '{name}' exists ({exc.message}). "
            f"The {saved} will still be saved."
        )
    except typer.Exit:
        return f"Could not check whether '{name}' exists. The {saved} will still be saved."
    if kind is None:
        return (
            f"No vault entry named '{name}' was found (checked sites, API keys and notes). "
            f"The {saved} is saved anyway and applies when an entry with that name exists."
        )
    return None


def _refuse_agent(
    action: str,
    entry: str | None,
    host: str | None = None,
    *,
    tool: str | None = None,
) -> caller.CallerVerdict:
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
            tool=tool,
            signals=list(verdict.signals),
            tty=verdict.tty,
            policy_mode=active.reveal,
        )
        print_error(
            PsamVaultError(
                f"psamvault policy {action} is blocked in this context (agent terminal detected).",
                hint=(
                    "Run it yourself in a terminal. "
                    "There is no flag an agent can pass to change this."
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


def _record(
    action: str,
    decision: str,
    verdict: caller.CallerVerdict,
    entry: str | None,
    host: str | None = None,
    *,
    tool: str | None = None,
    ask: bool | None = None,
    mcp_mode: str | None = None,
) -> None:
    active = policy.load()
    audit.record(
        command=f"policy {action}",
        decision=decision,
        caller=verdict.verdict,
        entry=entry,
        host=host,
        tool=tool,
        ask=ask,
        mcp_use=mcp_mode,
        signals=list(verdict.signals),
        tty=verdict.tty,
        policy_mode=active.reveal,
    )


def _mode_sentence(mode: str) -> str:
    if mode == mcp_use.MODE_ENFORCE:
        return "A tool that is not listed is refused."
    if mode == mcp_use.MODE_OFF:
        return "The tool list is not consulted. Uses are still recorded."
    return "Unlisted tools are recorded and not refused."


def _mcp_names(loaded: policy.Policy) -> list[str]:
    names: list[str] = []
    for name in list(loaded.entry_tools) + list(loaded.entry_ask):
        if name not in names:
            names.append(name)
    return names


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


@app.command("allow-tool")
def allow_tool(
    entry: str = typer.Argument(..., help="Vault entry name: a site, an API key name, or a note title"),
    tool: str = typer.Argument(..., help="MCP tool that may use this entry, for example use_credential"),
):
    """
    Allow one MCP tool to use one entry.

    \b
    Examples:
        psamvault policy allow-tool ledger-key use_credential
        psamvault policy allow-tool github.com browser_login

    \b
    Writes entries["<entry>"].allow_tools in ~/.psamvault/policy.json.
    A human runs this in a terminal. It does not reveal the secret, and it
    does not turn mcp_use from audit to enforce.
    """
    verdict = mcp_use.judge(tool, strict=True)
    if verdict.problem or not verdict.normalized or verdict.normalized not in mcp_use.TOOLS:
        _fail(policy.ToolRejected(
            verdict.problem or f"{tool!r} is not an MCP tool that uses a stored secret."
        ))
    normalized = verdict.normalized
    assert normalized is not None
    caller_verdict = _refuse_agent("allow-tool", entry, tool=normalized)
    _require_terminal("allow-tool")

    try:
        data = policy.read_document()
        key, spec, _hosts = policy.entry_spec(data, entry, create=False)
        already = False
        if key is not None and spec is not None and isinstance(spec.get("allow_tools", []), list):
            already = any(mcp_use.normalize_tool(str(item)) == normalized for item in spec.get("allow_tools", []) or [])
    except policy.PolicyDocumentError as exc:
        _fail(exc)
        return
    if already and key is not None:
        typer.echo(f"  {normalized} is already allowed for '{key}'.\n")
        return

    note = _entry_note(entry, saved="tool")
    if note:
        typer.echo(f"  Note: {note}")
    typer.echo(
        f"\n  About to allow {normalized} to use the secret for '{entry}'."
        f"\n  This does not reveal the secret, and it does not turn enforcement on.\n"
    )
    _confirm(
        f"  Allow '{normalized}' for '{entry}'?",
        "  Cancelled. No tool was allowed.\n",
    )
    try:
        stored_key, stored_tool, changed = policy.add_allow_tool(entry, normalized)
    except (policy.ToolRejected, policy.PolicyDocumentError) as exc:
        _fail(exc)
        return
    if not changed:
        typer.echo(f"  {stored_tool} is already allowed for '{stored_key}'.\n")
        return
    _record("allow-tool", audit.DECISION_GRANTED, caller_verdict, stored_key, tool=stored_tool)
    loaded = policy.load()
    typer.echo(f"  ✓ Allowed {stored_tool} to use '{stored_key}'.")
    typer.echo(f"  → mcp_use is {loaded.mcp_use}. {_mode_sentence(loaded.mcp_use)}")
    if loaded.mcp_use == mcp_use.MODE_AUDIT:
        typer.echo("  → Run  psamvault policy mcp-use enforce  when an unlisted tool should be refused.")
    typer.echo("  → This does not reveal the secret. Run  psamvault policy tools  to see the list.\n")


@app.command("remove-tool")
def remove_tool(
    entry: str = typer.Argument(..., help="Vault entry name the tool was allowed for"),
    tool: str = typer.Argument(..., help="MCP tool to remove from that entry's allow_tools"),
):
    """
    Remove one MCP tool from one entry.

    \b
    Examples:
        psamvault policy remove-tool ledger-key use_credential

    \b
    A human runs this in a terminal. A value that could not be granted
    can still be removed.
    """
    recorded = mcp_use.normalize_tool(tool) or tool.strip()
    caller_verdict = _refuse_agent("remove-tool", entry, tool=recorded)
    _require_terminal("remove-tool")
    try:
        key, removed_preview = _peek_tool_removal(entry, tool)
    except policy.PolicyDocumentError as exc:
        _fail(exc)
        return
    if not removed_preview:
        print_error(
            PsamVaultError(
                f"{tool!r} is not an allow_tools value for '{entry}'.",
                hint="psamvault policy tools   lists what is configured.",
            )
        )
        raise typer.Exit(code=1)

    note = _entry_note(entry, saved="tool")
    if note:
        typer.echo(f"  Note: {note}")
    shown = ", ".join(removed_preview)
    typer.echo(
        f"\n  About to stop allowing {shown} to use '{key}'."
        f"\n  That tool can no longer use the secret once mcp_use is enforce.\n"
    )
    _confirm(
        f"  Remove '{shown}' from '{key}'?",
        "  Cancelled. No tool was removed.\n",
    )
    try:
        stored_key, removed = policy.remove_allow_tool(entry, tool)
    except policy.PolicyDocumentError as exc:
        _fail(exc)
        return
    if not removed:
        print_error(PsamVaultError(f"{tool!r} is not an allow_tools value for '{entry}'."))
        raise typer.Exit(code=1)
    canonical = mcp_use.normalize_tool(tool) or recorded
    _record("remove-tool", audit.DECISION_REVOKED, caller_verdict, stored_key, tool=canonical)
    typer.echo(f"  ✓ Removed {', '.join(removed)} from '{stored_key}'.\n")


def _peek_tool_removal(entry: str, tool: str) -> tuple[str, list[str]]:
    data = policy.read_document()
    key, spec, _hosts = policy.entry_spec(data, entry, create=False)
    if key is None or spec is None:
        return entry.strip(), []
    tools = spec.get("allow_tools", [])
    if not isinstance(tools, list):
        raise policy.PolicyDocumentError(
            f"entries[{key!r}].allow_tools must be a list — not rewritten"
        )
    removed = [str(item) for item in tools if _stored_tool_matches(item, tool)]
    return key, removed


def _stored_tool_matches(stored, query: str) -> bool:
    if str(stored).strip().casefold() == str(query).strip().casefold():
        return True
    left = mcp_use.normalize_tool(str(stored))
    right = mcp_use.normalize_tool(query)
    return bool(left and right and left == right)


@app.command("tools")
def tools(
    entry: Optional[str] = typer.Argument(
        None, help="Entry to list. Omit to list every entry that has an MCP tool policy."
    ),
):
    """
    List MCP tools allowed to use each entry, and the mcp_use mode.

    \b
    Examples:
        psamvault policy tools
        psamvault policy tools ledger-key

    \b
    An agent may run this. It prints tool names and the ask-each-time flag,
    never a secret. It does not change the file.
    """
    loaded = policy.load()
    _print_mode(loaded)
    if entry is not None:
        _print_tools(loaded, entry)
        return
    names = _mcp_names(loaded)
    if not names:
        typer.echo("  No MCP tools are listed for any entry.\n")
        return
    for name in names:
        _print_tools(loaded, name)


def _print_mode(loaded: policy.Policy) -> None:
    for warning in loaded.warnings:
        typer.echo(f"  ! {warning}")
    typer.echo(f"  mcp_use: {loaded.mcp_use}")
    typer.echo(f"  {_mode_sentence(loaded.mcp_use)}")
    typer.echo("")


def _print_tools(loaded: policy.Policy, entry: str) -> None:
    names = {name: None for name in _mcp_names(loaded)}
    key = policy.matching_entry_key(names, entry)
    allowed = loaded.entry_tools.get(key, []) if key else []
    ask = loaded.entry_ask.get(key, False) if key else False
    typer.echo(f"  {key or entry}")
    if not allowed:
        typer.echo("    (no tools)")
    else:
        for name in allowed:
            typer.echo(f"    {name}")
    typer.echo(f"    ask_each_time: {'yes' if ask else 'no'}")
    typer.echo("")


@app.command("ask-each-time")
def ask_each_time(
    entry: str = typer.Argument(..., help="Vault entry name: a site, an API key name, or a note title"),
    state: str = typer.Argument(..., help="on or off"),
):
    """
    Store whether each MCP use of one entry must be confirmed in chat.

    \b
    Examples:
        psamvault policy ask-each-time ledger-key on
        psamvault policy ask-each-time ledger-key off

    \b
    Writes entries["<entry>"].ask_each_time. A human runs this in a terminal.
    The CLI does not ask at use time. psamvault-mcp will, once it enforces
    this flag. This does not reveal the secret.
    """
    folded = state.strip().lower()
    if folded not in ("on", "off"):
        _fail(policy.McpUseRejected(f"{state!r} is not on or off."))
    enabled = folded == "on"
    caller_verdict = _refuse_agent("ask-each-time", entry)
    _require_terminal("ask-each-time")
    try:
        data = policy.read_document()
        key, spec, _hosts = policy.entry_spec(data, entry, create=False)
    except policy.PolicyDocumentError as exc:
        _fail(exc)
        return
    if key is not None and spec is not None and spec.get("ask_each_time", None) is enabled:
        typer.echo(f"  ask_each_time is already {'on' if enabled else 'off'} for '{key}'.\n")
        return

    note = _entry_note(entry, saved="flag")
    if note:
        typer.echo(f"  Note: {note}")
    if enabled:
        typer.echo(
            f"\n  About to require an in-chat yes before each MCP use of '{entry}'."
            f"\n  psamvault-mcp asks. This command only stores the flag."
            f"\n  A use that is already refused is not asked. This does not reveal the secret.\n"
        )
    else:
        typer.echo(
            f"\n  About to stop requiring an in-chat yes for '{entry}'."
            f"\n  The tool list is unchanged. This does not reveal the secret.\n"
        )
    _confirm(
        f"  Set ask_each_time {'on' if enabled else 'off'} for '{entry}'?",
        "  Cancelled. ask_each_time was not changed.\n",
    )
    try:
        stored_key, stored_flag, changed = policy.set_ask_each_time(entry, enabled)
    except policy.PolicyDocumentError as exc:
        _fail(exc)
        return
    if not changed:
        typer.echo(f"  ask_each_time is already {'on' if stored_flag else 'off'} for '{stored_key}'.\n")
        return
    _record("ask-each-time", audit.DECISION_SET, caller_verdict, stored_key, ask=stored_flag)
    typer.echo(f"  ✓ ask_each_time is {'on' if stored_flag else 'off'} for '{stored_key}'.")
    typer.echo("  → This does not reveal the secret. Run  psamvault policy tools  to see the flag.\n")


@app.command("mcp-use")
def mcp_use_command(
    mode: Optional[str] = typer.Argument(
        None, help="audit, enforce, or off. Omit to show the current mode."
    ),
):
    """
    Show or set whether an unlisted MCP tool is refused.

    \b
    Examples:
        psamvault policy mcp-use
        psamvault policy mcp-use enforce
        psamvault policy mcp-use audit

    \b
    audit (the default when the key is absent) records every use and does not
    refuse an unlisted tool. enforce refuses anything not listed. off does not
    consult the list. Showing the mode is allowed for an agent. Setting it is not.
    """
    if mode is None:
        _print_mode(policy.load())
        return

    normalized = mode.strip().lower()
    if normalized not in mcp_use.MODES:
        _fail(policy.McpUseRejected(
            f"{mode!r} is not an mcp_use mode. Use audit, enforce, or off."
        ))
    caller_verdict = _refuse_agent("mcp-use", None)
    _require_terminal("mcp-use")
    try:
        current = policy.read_document().get("mcp_use", mcp_use.DEFAULT_MODE)
    except policy.PolicyDocumentError as exc:
        _fail(exc)
        return
    if current == normalized:
        typer.echo(f"  mcp_use is already {normalized}.\n")
        return

    loaded = policy.load()
    typer.echo(f"\n  About to set mcp_use to {normalized}.")
    typer.echo(f"  {_mode_sentence(normalized)}")
    if normalized == mcp_use.MODE_ENFORCE and not any(loaded.entry_tools.values()):
        typer.echo("  No entry lists a tool. Every MCP use of a stored secret will be refused until you grant one.")
    typer.echo("  This does not reveal a secret.\n")
    _confirm(
        f"  Set mcp_use to {normalized}?",
        "  Cancelled. mcp_use was not changed.\n",
    )
    try:
        stored, changed = policy.set_mcp_use(normalized)
    except (policy.McpUseRejected, policy.PolicyDocumentError) as exc:
        _fail(exc)
        return
    if not changed:
        typer.echo(f"  mcp_use is already {stored}.\n")
        return
    _record("mcp-use", audit.DECISION_SET, caller_verdict, None, mcp_mode=stored)
    typer.echo(f"  ✓ mcp_use is {stored}.")
    typer.echo(f"  → {_mode_sentence(stored)}")
    typer.echo("  → Run  psamvault policy tools  to see the list.\n")
