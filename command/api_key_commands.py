import threading
import time
from typing import Optional
from spinner import Spinner
 
import pyperclip
import typer
from cryptography.exceptions import InvalidTag
 
import api_client
from crypto import decrypt_api_key, encrypt_api_key
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
    session = load_session()
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
        key = typer.prompt(f"API key for {name}", hide_input=True)
    
    typer.echo("")
    session, vek = _get_session_and_key()
    
    encrypted_blob, iv = encrypt_api_key(
        key=vek,
        service=service,
        api_key=key,
        notes=notes or "",
    )
    
    with Spinner(f"Saving API key '{name}'"):
        api_client.add_api_key_entry(
            access_token=session["access_token"],
            refresh_token=session["refresh_token"],
            name=name,
            service_hint=service,
            encrypted_blob=encrypted_blob,
            iv=iv
        )
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
 
    \b
    Examples:
        psamvault ak-get openai-prod
        psamvault ak-get openai-prod --copy
    """
    _validate_entry_name(name)
 
    session, vek = _get_session_and_key()
 
    with Spinner(f"Fetching API key '{name}'"):
        data = api_client.get_api_key_entry(
            access_token=session["access_token"],
            refresh_token=session["refresh_token"],
            name=name,
        )
 
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
def ak_list():
    """
    List all stored API key entries.
 
    Shows entry names and service hints only — does not decrypt any keys.
    Use  psamvault ak-get <name>  to retrieve a specific key.
 
    \b
    Examples:
        psamvault ak-list
    """
    session = load_session()
 
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
 
    typer.echo(f"\n  {'NAME':<30} {'SERVICE':<25} {'UPDATED'}")
    typer.echo(f"  {'-'*30} {'-'*25} {'-'*20}")
 
    for entry in entries:
        updated = entry["updated_at"][:10]
        service = entry["service_hint"] or "-"
        typer.echo(f"  {entry['name']:<30} {service:<25} {updated}")
 
    typer.echo(f"\n  {total} entr{'y' if total == 1 else 'ies'} found.\n")
    
    
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

    with Spinner(f"Fetching current entry for '{name}'"):
        current_data = api_client.get_api_key_entry(
            access_token=session["access_token"],
            refresh_token=session["refresh_token"],
            name=name,
        )

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
    session = load_session()
 
    with Spinner(f"Deleting API key '{name}'"):
        api_client.delete_api_key_entry(
            access_token=session["access_token"],
            refresh_token=session["refresh_token"],
            name=name,
        )
 
    typer.echo(f" API key '{name}' deleted.\n")