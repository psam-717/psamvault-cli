import secrets
import threading
import time
import string
from typing import Optional
from spinner import Spinner

import pyperclip
import typer
from cryptography.exceptions import InvalidTag

import api_client
from crypto import decrypt_credentials, encrypt_credentials
from session import load_session

app = typer.Typer(
    name="vault",
    help="Vault commands",
    
)

@app.callback(invoke_without_command=True)
def vault_help(ctx: typer.Context):
    if ctx.invoked_subcommand is None:
        typer.echo("""
  psamvault vault — credential commands
 
  COMMAND    USAGE
  ──────────────────────────────────────────────────────────────────────────────
  add        psamvault add <site> --user <username> --pass <password>
  add        psamvault add <site> --user <username> --pass <password> --notes <notes>
  get        psamvault get <site>
  get        psamvault get <site> --copy
  list       psamvault list
  update     psamvault update <site> --pass <new_password>
  update     psamvault update <site> --user <new_user> --pass <new_password>
  update     psamvault update <site> --notes <new_notes>
  delete     psamvault delete <site>
  generate   psamvault generate
  generate   psamvault generate --length <number>
  generate   psamvault generate --length <number> --no-symbols
  generate   psamvault generate --save <site> --user <username>              
""")
        
FORBIDDEN_SITE_CHARS = set('\\/"\' <>|?*&#%')

def _validate_site_name(site: str) -> None:
    """Raise a user-friendly error if the site name contains forbidden characters."""
    if not site.strip():
        typer.echo("Error: Site name cannot be blank", err=True)
        raise typer.Exit(code=1)
    
    found = [c for c in site if c in FORBIDDEN_SITE_CHARS]
    if found:
        unique = "".join(dict.fromkeys(found)) # deduplicate, preserve order
        typer.echo(
            f"Error: Site name contains invalid character(s): {' '.join(repr(c) for c in unique)}\n"
            f"  Forbidden characters: \\ / \" ' < > | ? * & # %",
            err=True
        )
        raise typer.Exit(code=1)
    
    
def _get_session_and_key() -> tuple[dict, bytes]:
    """
    Load the session and return the Vault Encryption Key.
    The VEK is stored directly in the session after being decrypted at login —
    no key derivation needed here.
    """
    session = load_session()
    key = bytes.fromhex(session["vek"])
    return session, key


@app.command()
def add(
    site: str = typer.Argument(..., help="Site name, e.g. github.com"),
    user: str = typer.Option(..., "--user", "-u", help="Username or email for the site"),
    password: Optional[str] = typer.Option(
        None, "--pass", "-p", help="Password (omit to be prompted securely)"
    ),
    notes: Optional[str] = typer.Option(None, "--notes", "-n", help="Optional notes")
):
    """
    Add a new credential entry to your vault.
 
    The credentials are encrypted locally before being sent to the server.
    The server never sees your plaintext password.
 
    \b
    Example:
        psamvault add github.com --user me@example.com --pass secret
        psamvault add github.com --user me@example.com --pass secret --notes "2FA enabled"
        psamvault add github.com --user me@example.com   (prompts for password)
    """
    _validate_site_name(site)
    
    if password is None:
        password = typer.prompt(f"Password for {site}", hide_input=True)
    
    typer.echo("")
    session, key = _get_session_and_key()
    
    encrypted_blob, iv = encrypt_credentials(
        key,
        username=user,
        password=password,
        notes=notes or ""
    )
    
    with Spinner(f"Saving credentials for {site}"):
        api_client.add_vault_entry(
            access_token=session["access_token"],
            refresh_token=session["refresh_token"],
            site_name=site,
            encrypted_blob=encrypted_blob,
            iv=iv,
            username_hint=user
        )
    
    typer.echo(f" Credential for {site} saved successfully\n")


@app.command()
def get(
    site: str = typer.Argument(..., help="Site name to retrieve, e.g. github.com"),
    copy: bool = typer.Option(
        False, "--copy", "-c",
        help="Copy the password to clipboard instead of displaying it"
    )
):
    """
    Retrieve and decrypt credentials for a site.
 
    Fetches the encrypted entry from the server and decrypts it locally
    using your master password. The plaintext password is displayed once.
 
    \b
    Example:
        psamvault get github.com
        psamvault vault get github.com
        
    """
    _validate_site_name(site)
    
    session, key = _get_session_and_key()
    
    with Spinner(f"Fetching credentials for {site}"):
        data = api_client.get_vault_entry(
            access_token=session["access_token"],
            refresh_token=session["refresh_token"],
            site_name=site
        )

    
    try:
        credentials = decrypt_credentials(
            key,
            encrypted_blob=data["encrypted_blob"],
            iv=data["iv"]
        )
    except InvalidTag:
        typer.echo(
            "Error: Decryption failed. Your master password may be incorrect",
            err=True
        )
        raise typer.Exit(code=1) # pylint: disable=raise-missing-from
    
    typer.echo(f"\n  Site:      {site}")
    typer.echo(f"  Username:  {credentials['username']}")
    
    if copy:
        pyperclip.copy(credentials["password"])
        typer.echo("  Password: [copied to clipboard - clears in 30 seconds]")
        
        def _clear():
            time.sleep(30)
            try:
                if pyperclip.paste() == credentials["password"]:
                    pyperclip.copy("")
            except Exception:
                pass
        threading.Thread(target=_clear, daemon=True).start()
    else:
        typer.echo(f"  Password:  {credentials['password']}")
    
    if credentials.get("notes"):
        typer.echo(f"  Notes:     {credentials['notes']}")
    typer.echo()
    
    
@app.command(name="list")
def list_entries():
    """
    List all sites stored in your vault.
 
    Shows site names and username hints only — does not decrypt any entries.
    Use  psamvault get <site>  to retrieve the full credentials for a site.
 
    \b
    Example:
        psamvault list
        psamvault vault list
    """
    session = load_session()
    
    with Spinner("Fetching your vault"):
        data = api_client.list_vault_entries(
            access_token=session["access_token"],
            refresh_token=session["refresh_token"]
        )
    
    entries = data["entries"]
    total = data["total"]
    
    if total == 0:
        typer.echo("Your vault is empty. Use psamvault add to store credentials\n")
        return
    
    typer.echo(f"\n  {'SITE':<35} {'USERNAME HINT':<30} {'UPDATED'}")
    typer.echo(f"  {'-'*35} {'-'*30} {'-'*20}")
    
    
    for entry in entries:
        updated = entry["updated_at"][:10] # show date only, trim the time
        hint = entry["username_hint"] or "-"
        typer.echo(f" {entry['site_name']:<35} {hint:<30} {updated}")
        
    typer.echo(f"\n {total} entr{'y' if total == 1 else 'ies'} in your vault.\n")
    
    
@app.command()
def update(
    site: str = typer.Argument(..., help="Site name to update, e.g. github.com"),
    user: Optional[str] = typer.Option(None, "--user", "-u", help="New username or email"),
    password: Optional[str] = typer.Option(None, "--pass", "-p", help="New password"),
    notes: Optional[str] = typer.Option(None, "--notes", "-n", help="New notes")
):
    """
    Update the credentials for an existing vault entry.
 
    Fetches the current entry, decrypts it, merges your changes, then
    re-encrypts and sends the updated blob with a fresh IV.
 
    \b
    Example:
        psamvault update github.com --pass mynewpassword
        psamvault update github.com --user newuser@example.com --pass newpass
        psamvault vault update github.com --notes "2FA disabled"
        
    """
    _validate_site_name(site)
    
    session, key = _get_session_and_key()
    
    with Spinner(f"Fetching current entry for {site}"):
        current_data = api_client.get_vault_entry(
            access_token=session["access_token"],
            refresh_token=session["refresh_token"],
            site_name=site
        )
    
    try:
        current = decrypt_credentials(
            key,
            encrypted_blob=current_data["encrypted_blob"],
            iv=current_data["iv"]
        )
    except InvalidTag:
        typer.echo(
            "Error: Decryption failed. Your master password may be incorrect",
            err=True
        )
        raise typer.Exit(code=1) # pylint: disable=raise-missing-from
    
    # merge - new values should be used where provided else keep existing values otherwise
    updated_user = user or current["username"]
    updated_pass = password or current["password"]
    updated_notes = notes if notes is not None else current.get("notes", "")
    
    # Re-encrypt with a fresh iv
    encrypted_blob, iv = encrypt_credentials(
        key,
        username=updated_user,
        password=updated_pass,
        notes=updated_notes
    )
    
    with Spinner(f"Updating credentials for {site}"):
        api_client.update_vault_entry(
            access_token=session["access_token"],
            refresh_token=session["refresh_token"],
            site_name=site,
            encrypted_blob=encrypted_blob,
            iv=iv,
            username_hint=updated_user
        )
    
    typer.echo(f" Credentials for {site} updated successfully\n")


@app.command()
def delete(
    site: str = typer.Argument(..., help="Site name to delete, e.g. github.com")
):
    """
    Permanently delete a vault entry.
 
    This action cannot be undone.
 
    \b
    Example:
        psamvault delete github.com
        psamvault vault delete github.com
    """
    _validate_site_name(site)
    
    confirm = typer.confirm(
        f"Are you sure you want to permanently delete the entry for '{site}'?"
    )

    if not confirm:
        typer.echo("Cancelled")
        raise typer.Exit()
    
    typer.echo("")
    session = load_session()
    
    with Spinner(f"Deleting entry for {site}"):
        api_client.delete_vault_entry(
            access_token=session["access_token"],
            refresh_token=session["refresh_token"],
            site_name=site,
        )    
    
    typer.echo(f" Entry for '{site}' deleted.\n")
    

@app.command()
def generate(
    length: int = typer.Option(20, "--length", "-l", help="Password length (default 20)"),
    no_symbols: bool = typer.Option(
        False, "--no-symbols", help="Exclude special characters"
    ),
    no_digits: bool = typer.Option(False, "--no-digits", help="Exclude digits"),
    save: Optional[str] = typer.Option(
        None, "--save", "-s",
        help="Site name to save the generated password to (requires --user)"
    ),
    user: Optional[str] = typer.Option(
        None, "--user", "-u",
        help="Username to pair with the generated password (used with --save)"
    )
):
    """
    Generate a cryptographically secure password.
 
    Uses Python's secrets module — suitable for security-sensitive contexts.
    Optionally save the generated password directly to your vault.
 
    \b
    Examples:
        psamvault generate
        psamvault generate --length 32 --no-symbols
        psamvault generate --save github.com --user me@example.com
        psamvault vault generate --length 32 --no-digits
    """
    if length < 8:
        typer.echo("Error: Password length must be at least 8.", err=True)
        raise typer.Exit(code=1)
    
    alphabet = string.ascii_letters
    if not no_digits:
        alphabet += string.digits
    if not no_symbols:
        alphabet += string.punctuation
        
    # secrets.choice is cryptographically secure — uses os.urandom internally
    generated = "".join(secrets.choice(alphabet) for _ in range(length))
    
    typer.echo(f"\n Generated password: {generated}\n")
    
    if save: 
        if not user:
            typer.echo(
                "Error: --user is required when using --save",
                err=True
            )
            raise typer.Exit(code=1)
        
        session, key = _get_session_and_key()
        
        encrypted_blob, iv = encrypt_credentials(
            key,
            username=user,
            password=generated
        )
        
        with Spinner(f"Saving generated password for {save}"):
            api_client.add_vault_entry(
                access_token=session["access_token"],
                refresh_token=session["refresh_token"],
                site_name=save,
                encrypted_blob=encrypted_blob,
                iv=iv,
                username_hint=user,
            )
    
        typer.echo(f" Saved generated password for {save}.")
    
    
    
    
    
    
