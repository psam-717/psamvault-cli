from typing import Optional
from spinner import Spinner

import typer
from cryptography.exceptions import InvalidTag

import api_client
from crypto import encrypt_note, decrypt_note
from session import load_session

app = typer.Typer(
    name="note",
    help="Secure notes commands",
)


@app.callback(invoke_without_command=True)
def note_help(ctx: typer.Context):
    if ctx.invoked_subcommand is None:
        typer.echo("""
  psamvault note — secure notes commands

  COMMAND       USAGE
  ──────────────────────────────────────────────────────────────────────────────
  add           psamvault note-add <title> --content <text>
  add           psamvault note-add <title> --content <text> --category <cat>
  get           psamvault note-get <title>
  list          psamvault note-list
  update        psamvault note-update <title> --content <new_text>
  delete        psamvault note-delete <title>
""")


# Characters not allowed in note titles
FORBIDDEN_TITLE_CHARS = set('\\/"\' <>|?*&#%')


def _validate_title(title: str) -> None:
    """Raise a user-friendly error if the title contains forbidden characters."""
    if not title.strip():
        typer.echo("Error: Note title cannot be blank", err=True)
        raise typer.Exit(code=1)

    found = [c for c in title if c in FORBIDDEN_TITLE_CHARS]
    if found:
        unique = "".join(dict.fromkeys(found))
        typer.echo(
            f"Error: Note title contains invalid character(s): {' '.join(repr(c) for c in unique)}\n"
            "  Forbidden characters: \\ / \" ' < > | ? * & # %",
            err=True,
        )
        raise typer.Exit(code=1)


def _get_session_and_key() -> tuple[dict, bytes]:
    """Load the session and return the Vault Encryption Key."""
    session = load_session()
    key = bytes.fromhex(session["vek"])
    return session, key


# ─── note-add ──────────────────────────────────────────────────────────────────


@app.command(name="add")
def note_add(
    title: str = typer.Argument(..., help="Unique title for this note, e.g. my-ssh-key"),
    content: str = typer.Option(..., "--content", "-c", help="The note content (text to encrypt and store)"),
    category: Optional[str] = typer.Option(None, "--category", help="Optional category, e.g. ssh, wifi, recovery"),
):
    """
    Store a new secure note.

    The content is encrypted locally before being sent to the server.
    The server never sees the plaintext content.

    \b
    Examples:
        psamvault note-add my-ssh-key --content "ssh-rsa AAAAB3NzaC1yc2E..." --category ssh
        psamvault note-add wifi-password --content "Home WiFi: MyNetwork / password123" --category wifi
        psamvault note-add recovery-codes --content "Code 1: ABC... Code 2: DEF..." --category recovery
    """
    _validate_title(title)

    typer.echo("")
    session, key = _get_session_and_key()

    encrypted_blob, iv = encrypt_note(
        key=key,
        content=content,
        category=category or "",
    )

    with Spinner(f"Saving note '{title}'"):
        try:
            api_client.add_note_entry(
                access_token=session["access_token"],
                refresh_token=session["refresh_token"],
                title=title,
                category=category,
                encrypted_blob=encrypted_blob,
                iv=iv,
            )
        except api_client.ApiError:
            typer.echo(
                f"\n ✗ Note '{title}' already exists in your vault.",
                err=True,
            )
            typer.echo("   Use  psamvault note update  to modify it.", err=True)
            raise typer.Exit(code=1)

    typer.echo(f" Note '{title}' saved successfully\n")


# ─── note-get ──────────────────────────────────────────────────────────────────


@app.command(name="get")
def note_get(
    title: str = typer.Argument(..., help="Title of the note to retrieve"),
):
    """
    Retrieve and decrypt a stored secure note.

    \b
    Examples:
        psamvault note-get my-ssh-key
    """
    _validate_title(title)

    session, key = _get_session_and_key()

    try:
        with Spinner(f"Fetching note '{title}'"):
            data = api_client.get_note_entry(
                access_token=session["access_token"],
                refresh_token=session["refresh_token"],
                title=title,
            )
    except api_client.ApiError:
        typer.echo(
            f"\n ✗ Note '{title}' was not found in your vault.",
            err=True,
        )
        typer.echo("   Use  psamvault note-list  to see your saved notes.", err=True)
        raise typer.Exit(code=1)

    try:
        decrypted = decrypt_note(
            key,
            encrypted_blob=data["encrypted_blob"],
            iv=data["iv"],
        )
    except InvalidTag:
        typer.echo(
            "Error: Decryption failed. Your vault encryption key may have changed.",
            err=True,
        )
        raise typer.Exit(code=1)

    typer.echo(f"\n  Title:    {data['title']}")
    if data.get("category"):
        typer.echo(f"  Category: {data['category']}")

    typer.echo(f"\n  {decrypted['content']}\n")


# ─── note-list ─────────────────────────────────────────────────────────────────


@app.command(name="list")
def note_list():
    """
    List all secure notes in your vault.

    Shows titles and categories only — does not decrypt any content.
    Use  psamvault note-get <title>  to retrieve the full note.

    \b
    Examples:
        psamvault note-list
    """
    session = load_session()

    with Spinner("Fetching your notes"):
        data = api_client.list_note_entries(
            access_token=session["access_token"],
            refresh_token=session["refresh_token"],
        )

    entries = data["entries"]
    total = data["total"]

    if total == 0:
        typer.echo("No notes stored. Use  psamvault note-add  to store one.\n")
        return

    typer.echo(f"\n  {'TITLE':<35} {'CATEGORY':<20} {'UPDATED'}")
    typer.echo(f"  {'-'*35} {'-'*20} {'-'*20}")

    for entry in entries:
        updated = entry["updated_at"][:10]
        category = entry.get("category") or "-"
        typer.echo(f"  {entry['title']:<35} {category:<20} {updated}")

    typer.echo(f"\n  {total} note{'s' if total != 1 else ''} in your vault.\n")


# ─── note-update ───────────────────────────────────────────────────────────────


@app.command(name="update")
def note_update(
    title: str = typer.Argument(..., help="Title of the note to update"),
    content: Optional[str] = typer.Option(None, "--content", "-c", help="New content for the note"),
    category: Optional[str] = typer.Option(None, "--category", help="New category for the note"),
    new_title: Optional[str] = typer.Option(None, "--new-title", help="Rename the note to a new title"),
):
    """
    Update an existing secure note.

    Fetches the current note, decrypts it, merges your changes, then
    re-encrypts and sends the updated blob with a fresh IV.

    \b
    Examples:
        psamvault note-update my-ssh-key --content "ssh-ed25519 AAAAC3N..."
        psamvault note-update my-ssh-key --category ssh
        psamvault note-update my-ssh-key --new-title my-new-key
    """
    _validate_title(title)

    if new_title is not None:
        _validate_title(new_title)

    if content is None and category is None and new_title is None:
        typer.echo("Error: At least one of --content, --category, or --new-title must be provided.", err=True)
        raise typer.Exit(code=1)

    session, key = _get_session_and_key()

    try:
        with Spinner(f"Fetching current note '{title}'"):
            current_data = api_client.get_note_entry(
                access_token=session["access_token"],
                refresh_token=session["refresh_token"],
                title=title,
            )
    except api_client.ApiError:
        typer.echo(
            f"\n ✗ Note '{title}' was not found in your vault.",
            err=True,
        )
        raise typer.Exit(code=1)

    # Reload session — the fetch above may have rotated the tokens.
    session = load_session()

    # If content is being updated, re-encrypt with fresh IV
    encrypted_blob: str | None = None
    iv_str: str | None = None

    if content is not None:
        encrypted_blob, iv_str = encrypt_note(
            key=key,
            content=content,
            category=category or "",
        )
    else:
        # Preserve existing content if only metadata is being updated
        try:
            decrypted = decrypt_note(
                key,
                encrypted_blob=current_data["encrypted_blob"],
                iv=current_data["iv"],
            )
        except InvalidTag:
            typer.echo(
                "Error: Decryption failed. Your vault encryption key may have changed.",
                err=True,
            )
            raise typer.Exit(code=1)

        # If category changed but content didn't, re-encrypt with new category
        if category is not None:
            encrypted_blob, iv_str = encrypt_note(
                key=key,
                content=decrypted["content"],
                category=category,
            )

    with Spinner(f"Updating note '{title}'"):
        api_client.update_note_entry(
            access_token=session["access_token"],
            refresh_token=session["refresh_token"],
            title=title,
            category=category,
            encrypted_blob=encrypted_blob,
            iv=iv_str,
            new_title=new_title,
        )

    typer.echo(f" Note '{title}' updated successfully\n")


# ─── note-delete ───────────────────────────────────────────────────────────────


@app.command(name="delete")
def note_delete(
    title: str = typer.Argument(..., help="Title of the note to delete"),
):
    """
    Permanently delete a secure note.

    This action cannot be undone.

    \b
    Examples:
        psamvault note-delete my-ssh-key
    """
    _validate_title(title)

    confirm = typer.confirm(
        f"Are you sure you want to permanently delete the note '{title}'?"
    )

    if not confirm:
        typer.echo("Cancelled")
        raise typer.Exit()

    typer.echo("")
    session = load_session()

    with Spinner(f"Deleting note '{title}'"):
        api_client.delete_note_entry(
            access_token=session["access_token"],
            refresh_token=session["refresh_token"],
            title=title,
        )

    typer.echo(f" Note '{title}' deleted.\n")
