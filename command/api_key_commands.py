import threading
import time
from typing import Optional
from spinner import Spinner
 
import pyperclip
import typer
from cryptography.exceptions import InvalidTag
 
import api_client
import reveal_gate
from api_key_names import (
    AmbiguousApiKeyName,
    entry_name_error,
    prepare_list_items,
    resolve_api_key_name,
)
from crypto import decrypt_api_key, encrypt_api_key
from error_ui import exit_error, print_error
from errors import ConflictError, NotFoundError, PsamVaultError, RevealBlockedError
from secret_prompt import secret_prompt
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
        
        
def _validate_entry_name(name: str) -> None:
    """Reject a blank name, or a slash that is not the project/.env/KEY form."""
    error = entry_name_error(name)
    if error is None:
        return
    typer.echo(f"Error: {error}", err=True)
    raise typer.Exit(code=1)


def _lookup_stored_name(session: dict, requested: str) -> str:
    """Map a leaf or a full name to the row the server stored."""
    data = api_client.list_api_key_entries(
        access_token=session["access_token"],
        refresh_token=session["refresh_token"],
    )
    entries = data["entries"] if isinstance(data, dict) else data
    return resolve_api_key_name(requested, entries)


def _print_ambiguous(exc: AmbiguousApiKeyName) -> None:
    lines = "\n".join(f"  {match}" for match in exc.matches)
    typer.echo(
        f"\n ✗ '{exc.requested}' matches more than one API key — pass the full name.\n{lines}",
        err=True,
    )


def _load_api_key(session: dict, name: str) -> tuple[dict, str]:
    """Fetch one key. A leaf that 404s is resolved against the list once."""
    try:
        data = api_client.get_api_key_entry(
            access_token=session["access_token"],
            refresh_token=session["refresh_token"],
            name=name,
        )
        return data, name
    except NotFoundError:
        stored = _lookup_stored_name(session, name)
        if stored.lower() == name.lower():
            raise
        session = load_session()
        data = api_client.get_api_key_entry(
            access_token=session["access_token"],
            refresh_token=session["refresh_token"],
            name=stored,
        )
        return data, stored
    
    
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
    name: str = typer.Argument(..., help="A unique label for this key, e.g. xai-prod"),
    service: str = typer.Option(..., "--service", "-s", help="Service this key belongs to, e.g. XAI"),
    key: Optional[str] = typer.Option(
        None, "--key", "-k", help="The API key value (omit to be prompted securely)"
    ),
    notes: Optional[str] = typer.Option(None, "--notes", "-n", help="Optional notes e.g. 'read-only key")
):
    """
    Store an API key securely in your vault.
 
    The key is encrypted locally before being sent to the server.
    The server never sees your plaintext key.
 
    \b
    Examples:
        psamvault ak-add xai-prod --service XAI --key sk-...
        psamvault ak-add stripe-test --service Stripe --key sk_test_... --notes "test mode only"
        psamvault ak-add gh-token --service GitHub  (prompts for key)
    """
    _validate_entry_name(name)
    
    if key is None:
        key = secret_prompt(f"API key for {name}")
    
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

    A project key can be named in full (``project/.env/KEY``) or by its leaf
    when that leaf matches one live row.
 
    \b
    Examples:
        psamvault ak-get openai-prod
        psamvault ak-get openai-prod --copy
        psamvault ak-get "atlas/.env/MY_CUSTOM_KEY"
    """
    _validate_entry_name(name)
 
    session, vek = _get_session_and_key()

    try:
        with Spinner(f"Fetching API key '{name}'"):
            data, name = _load_api_key(session, name)
    except AmbiguousApiKeyName as exc:
        _print_ambiguous(exc)
        raise typer.Exit(code=1)
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



def _source_label(item: dict) -> str:
    source = item.get("source") or "-"
    if item.get("stale_only"):
        extra = item.get("stale_count") or 0
        suffix = f" +{extra} more" if extra else ""
        return f"{source} (stale){suffix}"
    extra = item.get("stale_count") or 0
    if extra:
        return f"{source} (+{extra} stale)"
    return source


def _print_project_keys(project: str, rows: list[dict]) -> None:
    typer.echo(f"  Project: {project}")
    typer.echo(f"    {'KEY':<28} {'SOURCE':<28} {'UPDATED'}")
    typer.echo(f"    {'-'*28} {'-'*28} {'-'*20}")
    for item in rows:
        typer.echo(f"    {item['key_name']:<28} {_source_label(item):<28} {item['updated']}")
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
    project name. Keys stored with no project are grouped under (unscoped).
    Backup copies of the same key fold onto the live .env row. Use --project
    <name> to filter by project. Pass (unscoped) to see keys stored with no project.

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

    prepared = prepare_list_items(entries, project_name)
    if project_name and prepared["stored"] == 0:
        typer.echo(f"No API keys found for project '{project_name}'.\n")
        return

    typer.echo()
    for proj_name, proj_items in prepared["projects"].items():
        _print_project_keys(proj_name, proj_items)

    standalone = prepared["standalone"]
    if standalone:
        typer.echo("  Standalone Keys")
        typer.echo(f"    {'NAME':<28} {'SERVICE':<22} {'NOTES':<30} {'UPDATED'}")
        typer.echo(f"    {'-'*28} {'-'*22} {'-'*30} {'-'*20}")
        for item in standalone:
            notes_display = (item['notes'] or '')[:27] + '...' if item['notes'] and len(item['notes']) > 30 else (item['notes'] or '')
            typer.echo(f"    {item['key_name']:<28} {item['service_hint']:<22} {notes_display:<30} {item['updated']}")
        typer.echo()

    stored = prepared["stored"]
    shown = prepared["shown"]
    if project_name:
        typer.echo(
            f"  {shown} entr{'y' if shown == 1 else 'ies'} in project '{project_name}'.\n"
        )
        return
    if shown != stored:
        typer.echo(f"  {stored} stored, {shown} shown (stale copies folded).\n")
        return
    typer.echo(f"  {shown} entr{'y' if shown == 1 else 'ies'} found.\n")
    
    
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
            current_data, name = _load_api_key(session, name)
    except AmbiguousApiKeyName as exc:
        _print_ambiguous(exc)
        raise typer.Exit(code=1)
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

    A project key can be named in full (``project/.env/KEY``) or by its leaf
    when that leaf matches one live row. The confirmation names the stored row.
 
    This action cannot be undone.
 
    \b
    Examples:
        psamvault ak-delete openai-prod
        psamvault ak-delete "atlas/.env/MY_CUSTOM_KEY"
    """
    _validate_entry_name(name)

    session = api_client.ensure_session()
    try:
        stored = _lookup_stored_name(session, name)
    except AmbiguousApiKeyName as exc:
        _print_ambiguous(exc)
        raise typer.Exit(code=1)
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

    # The list call may have rotated the tokens.
    session = load_session()

    confirm = typer.confirm(
        f"Are you sure you want to permanently delete the API key '{stored}'?"
    )
    if not confirm:
        typer.echo("Cancelled")
        raise typer.Exit()
 
    typer.echo("")
 
    with Spinner(f"Deleting API key '{stored}'"):
        api_client.delete_api_key_entry(
            access_token=session["access_token"],
            refresh_token=session["refresh_token"],
            name=stored,
        )
    name = stored
 
    typer.echo(f" API key '{name}' deleted.\n")