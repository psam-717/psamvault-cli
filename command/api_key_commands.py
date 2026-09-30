import threading
import time
from typing import Optional
from spinner import Spinner
 
import pyperclip
import typer
from cryptography.exceptions import InvalidTag
 
import api_client
import claim_flow
import pending_store as store
import reveal_gate
from crypto import decrypt_api_key, encrypt_api_key
from error_ui import exit_error, print_error
from errors import ConflictError, NotFoundError, PsamVaultError, RevealBlockedError
from session import load_session
 
app = typer.Typer(
    name="ak",
    help="API key commands",
)

@app.callback(invoke_without_command=True)
def ak_help(ctx: typer.Context):
    if ctx.invoked_subcommand is None:
        typer.echo("""
    psamvault ak — API key commands
 
  COMMAND    USAGE
  ──────────────────────────────────────────────────────────────────────────────
  add        psamvault ak-add <name> --service <service> --key <api_key>
  add        psamvault ak-add <name> --service <service> --key <api_key> --notes <notes>
  get        psamvault ak-get <name>
  get        psamvault ak-get <name> --copy
  list       psamvault ak-list
  update     psamvault ak-update <name> --key <new_key>
  update     psamvault ak-update <name> --notes <new_notes>
  delete     psamvault ak-delete <name>               
""")
        
        
# Characters not allowed in API key entry names
FORBIDDEN_NAME_CHARS = set('\\/"\' <>|?*&#%')


def _validate_entry_name(name: str) -> None:
    """Raise a user-friendly error if the entry name contains forbidden characters."""
    if not name.strip():
        typer.echo("Error: Entry name cannot be blank.", err=True)
        raise typer.Exit(code=1)
    
    found = [c for c in name if c in FORBIDDEN_NAME_CHARS]
    if found:
        unique = "".join(dict.fromkeys(found))
        typer.echo(
            f"Error: Entry name contains invalid character(s): {' '.join(repr(c) for c in unique)}\n"
            "  Forbidden characters: \\ / \" ' < > | ? * & # %",
            err=True
        )
        raise typer.Exit(code=1)
    
    
def _get_session_and_key() -> tuple[dict, bytes]:
    session = api_client.ensure_session()
    key = bytes.fromhex(session["vek"])
    return session, key


def _search_api_keys(vek: bytes, entries: list[dict], query: str) -> list[dict]:
    """Decrypt and filter API key entries by a search query.

    Searches entry name, decrypted service, and decrypted notes (case-insensitive).
    Does NOT search the raw API key value. Skips entries that fail to decrypt
    or have malformed IVs.

    Args:
        vek:      32-byte Vault Encryption Key.
        entries:  List of API key entry dicts (from export_api_keys()).
        query:    Search query string.

    Returns:
        List of dicts with keys: name, service, api_key, notes.
    """
    from crypto import decrypt_api_key
    from cryptography.exceptions import InvalidTag

    query_lower = query.lower()
    results: list[dict] = []

    for entry in entries:
        try:
            decrypted = decrypt_api_key(
                vek,
                encrypted_blob=entry["encrypted_blob"],
                iv=entry["iv"],
            )
        except (InvalidTag, ValueError):
            continue

        name = entry.get("name") or ""
        service = (decrypted.get("service") or "")
        notes = (decrypted.get("notes") or "")

        if (
            query_lower in name.lower()
            or query_lower in service.lower()
            or query_lower in notes.lower()
        ):
            results.append({
                "name": name,
                "service": service,
                "api_key": decrypted.get("api_key") or "",
                "notes": notes,
            })

    return results


@app.command(name="add")
def ak_add(
    name: Optional[str] = typer.Argument(None, help="A unique label for this key, e.g. xai-prod"),
    service: Optional[str] = typer.Option(None, "--service", "-s", help="Service this key belongs to, e.g. XAI"),
    key: Optional[str] = typer.Option(
        None, "--key", "-k", help="The API key value (omit to be prompted securely)"
    ),
    notes: Optional[str] = typer.Option(None, "--notes", "-n", help="Optional notes e.g. 'read-only key'"),
    claim: Optional[str] = typer.Option(
        None, "--claim", help="Fill a claim code an agent printed (your own terminal only)"
    ),
):
    """
    Store an API key securely in your vault.

    The key is encrypted locally before being sent to the server.
    The server never sees your plaintext key.

    From an agent context this command does not prompt and does not accept the
    key: it prints a claim code, and the human fills that code in their own
    terminal. The value then never passes through the agent.

    \b
    Examples:
        psamvault ak-add xai-prod --service XAI --key sk-...    (your own terminal)
        psamvault ak-add gh-token --service GitHub              (prompts securely)
        psamvault ak-add gh-token --service GitHub              (agent: prints a claim code)
        psamvault ak-add --claim PV-4F2K-91QX                   (human: fills that claim)
    """
    if claim:
        _fill_api_key_claim(claim)
        return

    if not name:
        typer.echo("Error: a name is required (or pass --claim CODE to fill a claim).", err=True)
        raise typer.Exit(code=1)

    _validate_entry_name(name)

    if not service:
        typer.echo("\n ✗ --service is required.", err=True)
        typer.echo(f" → psamvault ak-add {name} --service <service>", err=True)
        raise typer.Exit(code=1)

    verdict = claim_flow.classify()

    if key is not None:
        try:
            claim_flow.require_no_argv_secret(
                verdict,
                "--key",
                name,
                f"psamvault ak-add {name} --service {service}",
                command="ak-add",
            )
        except PsamVaultError as exc:
            exit_error(exc)
    elif verdict.is_agent:
        # An agent asking for an entry it must not see the value of.
        record = claim_flow.create_claim(
            store.FAMILY_API_KEY, name, service=service, notes=notes, verdict=verdict
        )
        claim_flow.print_claim(record)
        return
    else:
        key = typer.prompt(f"API key for {name}", hide_input=True)

    _store_api_key(name, service, key, notes)


def _store_api_key(name: str, service: str, key: str, notes: Optional[str]) -> None:
    """Encrypt and store — the part the human path and the fill path share."""
    typer.echo("")
    session, vek = _get_session_and_key()

    encrypted_blob, iv = encrypt_api_key(
        key=vek,
        service=service,
        api_key=key,
        notes=notes or "",
    )

    with Spinner(f"Saving API key '{name}'"):
        try:
            api_client.add_api_key_entry(
                access_token=session["access_token"],
                refresh_token=session["refresh_token"],
                name=name,
                service_hint=service,
                encrypted_blob=encrypted_blob,
                iv=iv,
                notes=notes,
            )
        except ConflictError:
            typer.echo(
                f"\n ✗ API key '{name}' already exists in your vault.",
                err=True,
            )
            typer.echo(" → Use  psamvault ak-update  to modify it.", err=True)
            raise typer.Exit(code=1)
        except PsamVaultError as exc:
            print_error(exc)
            raise typer.Exit(code=1)
    typer.echo(f" API key '{name}' saved successfully\n")


def _fill_api_key_claim(code: str) -> None:
    """The human's half: type the value here, and the claim is spent."""
    try:
        record = claim_flow.resolve_claim(code, store.FAMILY_API_KEY)
    except PsamVaultError as exc:
        exit_error(exc)

    claim_flow.print_fill_header(record)
    key = typer.prompt(f"API key for {record['name']}", hide_input=True)
    _store_api_key(record["name"], record.get("service") or "", key, record.get("notes"))
    # Only now is the code spent: a failed store leaves the claim fillable again.
    claim_flow.complete_claim(record)


@app.command(name="get")
def ak_get(
    name: str = typer.Argument(..., help="Label of the API key to retrieve"),
    copy: bool = typer.Option(
        False, "--copy", "-c",
        help="Copy the key to clipboard instead of displaying it"
    )
):
    """
    Retrieve and decrypt a stored API key.
 
    \b
    Examples:
        psamvault ak-get openai-prod
        psamvault ak-get openai-prod --copy
    """
    _validate_entry_name(name)
 
    session, vek = _get_session_and_key()

    try:
        with Spinner(f"Fetching API key '{name}'"):
            data = api_client.get_api_key_entry(
                access_token=session["access_token"],
                refresh_token=session["refresh_token"],
                name=name,
            )
    except NotFoundError:
        typer.echo(
            f"\n ✗ API key '{name}' was not found in your vault.",
            err=True,
        )
        typer.echo(" → Use  psamvault ak-list  to see your saved API keys.", err=True)
        raise typer.Exit(code=1)
    except PsamVaultError as exc:
        print_error(exc)
        raise typer.Exit(code=1)

    try:
        decrypted = decrypt_api_key(
            key=vek,
            encrypted_blob=data["encrypted_blob"],
            iv=data["iv"],
        )
    except InvalidTag:
        typer.echo(
            "Error: Decryption failed. Your master password may be incorrect.",
            err=True,
        )
        raise typer.Exit(code=1)  # pylint: disable=raise-missing-from
 
    try:
        reveal_gate.require_reveal(action="ak-get", entry=name)
    except RevealBlockedError as exc:
        exit_error(exc)

    typer.echo(f"\n  Name:     {name}")
    typer.echo(f"  Service:  {decrypted['service']}")
 
    if copy:
        pyperclip.copy(decrypted["api_key"])
        typer.echo("  Key:     [copied to clipboard — clears in 30 seconds]")
 
        def _clear():
            time.sleep(30)
            try:
                if pyperclip.paste() == decrypted["api_key"]:
                    pyperclip.copy("")
            except Exception:
                pass
 
        threading.Thread(target=_clear, daemon=True).start()
    else:
        typer.echo(f"  Key:      {decrypted['api_key']}")
 
    if decrypted.get("notes"):
        typer.echo(f"  Notes:    {decrypted['notes']}")
    typer.echo()



@app.command(name="list")
def ak_list(
    project_name: Optional[str] = typer.Option(
        None, "--project", help="Filter by project name. Shows only keys stored under 'project/.env/KEY_NAME'."
    ),
):
    """
    List all stored API key entries.

    Shows entry names, service hints, and notes — does not decrypt any keys.
    Keys stored via scan_and_protect(project_name=...) are grouped under their
    project name. Use --project <name> to filter by project.

    \b
    Examples:
        psamvault ak-list
        psamvault ak-list --project twitter-bot
    """
    session = api_client.ensure_session()

    with Spinner("Fetching your API keys"):
        data = api_client.list_api_key_entries(
            access_token=session["access_token"],
            refresh_token=session["refresh_token"],
        )

    entries = data["entries"]
    total = data["total"]

    if total == 0:
        typer.echo("No API keys stored. Use  psamvault ak-add  to store one.\n")
        return

    # Build the items with project prefix parsing
    items = []
    for e in entries:
        name = e["name"]
        parts = name.split("/.env/")
        is_project_key = len(parts) == 2

        if project_name:
            if not is_project_key or parts[0] != project_name:
                continue

        items.append({
            "name": name,
            "service_hint": e.get("service_hint", "-") or "-",
            "notes": e.get("notes") or None,
            "updated": e.get("updated_at", "?")[:10],
            "project": parts[0] if is_project_key else None,
            "key_name": parts[1] if is_project_key else name,
        })

    if project_name:
        # Filtered view — simple list
        if not items:
            typer.echo(f"No API keys found for project '{project_name}'.\n")
            return
        typer.echo(f"\n  Project: {project_name}")
        typer.echo(f"  {'NAME':<28} {'PATTERN':<25} {'UPDATED'}")
        typer.echo(f"  {'-'*28} {'-'*25} {'-'*20}")
        for item in items:
            typer.echo(f"  {project_name:<28} {item['key_name']:<25} {item['updated']}")
        typer.echo(f"\n  {len(items)} entr{'y' if len(items) == 1 else 'ies'} in project '{project_name}'.\n")
        return

    # Full view — grouped by project + standalone
    projects: dict[str, list] = {}
    standalone: list = []
    for item in items:
        if item["project"]:
            projects.setdefault(item["project"], []).append(item)
        else:
            standalone.append(item)

    typer.echo()
    for proj_name, proj_items in sorted(projects.items()):
        typer.echo(f"  Project: {proj_name}")
        typer.echo(f"    {'NAME':<28} {'PATTERN':<25} {'UPDATED'}")
        typer.echo(f"    {'-'*28} {'-'*25} {'-'*20}")
        for item in proj_items:
            typer.echo(f"    {proj_name:<28} {item['key_name']:<25} {item['updated']}")
        typer.echo()

    if standalone:
        typer.echo(f"  Standalone Keys")
        typer.echo(f"    {'NAME':<28} {'SERVICE':<22} {'NOTES':<30} {'UPDATED'}")
        typer.echo(f"    {'-'*28} {'-'*22} {'-'*30} {'-'*20}")
        for item in standalone:
            notes_display = (item['notes'] or '')[:27] + '...' if item['notes'] and len(item['notes']) > 30 else (item['notes'] or '')
            typer.echo(f"    {item['key_name']:<28} {item['service_hint']:<22} {notes_display:<30} {item['updated']}")
        typer.echo()

    typer.echo(f"  {len(items)} entr{'y' if len(items) == 1 else 'ies'} found.\n")
    
    
@app.command(name="update")
def ak_update(
    name: str = typer.Argument(..., help="Label of the API key to update"),
    service: Optional[str] = typer.Option(None, "--service", "-s", help="New service name"),
    key: Optional[str] = typer.Option(None, "--key", "-k", help="New API key value"),
    notes: Optional[str] = typer.Option(None, "--notes", "-n", help="New notes"),
):
    """
    Update a stored API key entry.
 
    Fetches the current entry, decrypts it, merges your changes, then
    re-encrypts with a fresh IV and saves it.
 
    \b
    Examples:
        psamvault ak-update xai-prod --key sk-newkey...
        psamvault ak-update stripe-test --notes "deprecated, use stripe-live"
    """
    _validate_entry_name(name)
 
    session, vek = _get_session_and_key()

    try:
        with Spinner(f"Fetching current entry for '{name}'"):
            current_data = api_client.get_api_key_entry(
                access_token=session["access_token"],
                refresh_token=session["refresh_token"],
                name=name,
            )
    except NotFoundError:
        typer.echo(
            f"\n ✗ API key '{name}' was not found in your vault.",
            err=True,
        )
        typer.echo(" → Use  psamvault ak-list  to see your saved API keys.", err=True)
        raise typer.Exit(code=1)
    except PsamVaultError as exc:
        print_error(exc)
        raise typer.Exit(code=1)

    # Reload session — the fetch above may have rotated the tokens.
    session = load_session()

    try:
        current = decrypt_api_key(
            key=vek,
            encrypted_blob=current_data["encrypted_blob"],
            iv=current_data["iv"],
        )
    except InvalidTag:
        typer.echo(
            "Error: Decryption failed. Your master password may be incorrect.",
            err=True,
        )
        raise typer.Exit(code=1)  # pylint: disable=raise-missing-from

    updated_service = service or current["service"]
    updated_key = key or current["api_key"]
    updated_notes = notes if notes is not None else current.get("notes", "")

    encrypted_blob, iv = encrypt_api_key(
        key=vek,
        service=updated_service,
        api_key=updated_key,
        notes=updated_notes,
    )

    with Spinner(f"Updating API key '{name}'"):
        api_client.update_api_key_entry(
            access_token=session["access_token"],
            refresh_token=session["refresh_token"],
            name=name,
            service_hint=updated_service,
            encrypted_blob=encrypted_blob,
            iv=iv,
            notes=updated_notes,
        )
 
    typer.echo(f" API key '{name}' updated successfully\n")
    
    
@app.command(name="delete")
def ak_delete(
    name: str = typer.Argument(..., help="Label of the API key to delete"),
):
    """
    Permanently delete a stored API key entry.
 
    This action cannot be undone.
 
    \b
    Examples:
        psamvault ak-delete openai-prod
    """
    _validate_entry_name(name)
 
    confirm = typer.confirm(
        f"Are you sure you want to permanently delete the API key '{name}'?"
    )
    if not confirm:
        typer.echo("Cancelled")
        raise typer.Exit()
 
    typer.echo("")
    session = api_client.ensure_session()
 
    with Spinner(f"Deleting API key '{name}'"):
        api_client.delete_api_key_entry(
            access_token=session["access_token"],
            refresh_token=session["refresh_token"],
            name=name,
        )
 
    typer.echo(f" API key '{name}' deleted.\n")