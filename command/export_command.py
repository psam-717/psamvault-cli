"""psamvault export — export all credentials to an encrypted backup file."""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

import typer

import api_client
import reveal_gate
from crypto import (
    decrypt_api_key,
    decrypt_credentials,
    decrypt_note,
    export_encrypt,
)
from error_ui import exit_error
from errors import RevealBlockedError
from session import load_session, is_logged_in
from spinner import Spinner

app = typer.Typer(
    name="export",
    help="Export all credentials to a backup file on the Desktop",
)

_DESKTOP = Path.home() / "Desktop"


@app.callback(invoke_without_command=True)
def export_backup(
    plaintext: bool = typer.Option(
        False, "--plaintext", "-p",
        help="Save credentials in plaintext instead of encrypted (less secure)",
    ),
) -> None:
    """
    Export all vault entries and API keys to a backup file.

    By default the backup is encrypted with a passphrase you choose.
    Use --plaintext to store credentials as-is (anyone with Desktop access
    can read them — use only for testing or temporary backups).
    """
    if not is_logged_in():
        typer.echo(
            "\n  You are not logged in. Run 'psamvault login' first.\n",
            err=True,
        )
        raise typer.Exit(code=1)

    session = api_client.ensure_session()
    vek = bytes.fromhex(session["vek"])

    if plaintext:
        # A plaintext dump is a whole-vault reveal, so it is refused in an agent
        # context — and no approval token can cover it: an entry token that
        # unlocked every secret would make the guardrail decorative. Checked
        # before the fetch, because nothing should be read out of the vault for
        # a dump we are going to refuse.
        try:
            reveal_gate.require_reveal(action="export --plaintext", whole_vault=True)
        except RevealBlockedError as exc:
            exit_error(exc)

    suffix = "-plaintext" if plaintext else ""
    backup_path = _DESKTOP / f"psamvault-backup{suffix}-{datetime.now().strftime('%Y-%m-%d_%H%M%S')}.json"

    # ── Fetch all vault entries ──────────────────────────────────────────
    credentials = []
    with Spinner("Fetching vault entries"):
        try:
            raw_entries = api_client.export_vault(
                access_token=session["access_token"],
                refresh_token=session["refresh_token"],
            )
        except typer.Exit:
            raise
        except Exception as e:
            typer.echo(f"\n  Error: Could not fetch vault entries.\n  {e}\n", err=True)
            raise typer.Exit(code=1)

    # Reload session in case tokens were rotated
    session = load_session()
    vek = bytes.fromhex(session["vek"])

    with Spinner("Decrypting credentials"):
        for entry in raw_entries:
            try:
                decrypted = decrypt_credentials(
                    vek,
                    encrypted_blob=entry["encrypted_blob"],
                    iv=entry["iv"],
                )
            except Exception:
                continue

            cred = {
                "site_name": entry["site_name"],
                "username": decrypted["username"],
                "password": decrypted["password"],
                "notes": decrypted.get("notes", ""),
            }
            if entry.get("login_url"):
                cred["login_url"] = entry["login_url"]
            credentials.append(cred)

    # ── Fetch all API key entries ────────────────────────────────────────
    api_keys = []
    with Spinner("Fetching API key entries"):
        try:
            raw_api_keys = api_client.export_api_keys(
                access_token=session["access_token"],
                refresh_token=session["refresh_token"],
            )
        except typer.Exit:
            raise
        except Exception as e:
            typer.echo(f"\n  Warning: Could not fetch API keys.\n  {e}\n", err=True)
            raw_api_keys = []

    with Spinner("Decrypting API keys"):
        for entry in raw_api_keys:
            try:
                decrypted = decrypt_api_key(
                    vek,
                    encrypted_blob=entry["encrypted_blob"],
                    iv=entry["iv"],
                )
            except Exception:
                continue

            api_keys.append({
                "name": entry["name"],
                "service": decrypted["service"],
                "api_key": decrypted["api_key"],
                "notes": decrypted.get("notes", ""),
            })

    # ── Fetch all secure note entries ────────────────────────────────────
    notes = []
    with Spinner("Fetching secure notes"):
        try:
            raw_notes = api_client.export_notes(
                access_token=session["access_token"],
                refresh_token=session["refresh_token"],
            )
        except typer.Exit:
            raise
        except Exception as e:
            typer.echo(f"\\n  Warning: Could not fetch notes.\\n  {e}\\n", err=True)
            raw_notes = []

    with Spinner("Decrypting secure notes"):
        for entry in raw_notes:
            try:
                decrypted = decrypt_note(
                    vek,
                    encrypted_blob=entry["encrypted_blob"],
                    iv=entry["iv"],
                )
            except Exception:
                continue

            notes.append({
                "title": entry["title"],
                "category": entry.get("category"),
                "content": decrypted.get("content", ""),
            })

    # ── Summary ───────────────────────────────────────────────────────────
    typer.echo(f"\\n  Found: {len(credentials)} credential(s), {len(api_keys)} API key(s), {len(notes)} note(s)\\n")

    if not credentials and not api_keys and not notes:
        typer.echo("  Nothing to export.\n")
        raise typer.Exit()

    # ── Build export data ─────────────────────────────────────────────────
    export_data = {
        "version": 1,
        "exported_at": datetime.utcnow().isoformat() + "Z",
        "plaintext": plaintext,
        "credentials": credentials,
        "api_keys": api_keys,
        "notes": notes,
    }

    # ── Write the file ────────────────────────────────────────────────────
    _DESKTOP.mkdir(parents=True, exist_ok=True)

    if plaintext:
        # ── Plaintext mode ────────────────────────────────────────────────
        # A human's own consent, naming exactly how many secrets this exposes —
        # the plan's rule: an entry token must not become a master key, so this
        # dump gets its own count-naming confirmation instead.
        exposed = len(credentials) + len(api_keys) + len(notes)
        typer.echo(
            f"  ⚠  WARNING: Plaintext mode selected."
            f"\n      {exposed} secret(s) will be written as readable text:"
            f"\n        {len(credentials)} site password(s), "
            f"{len(api_keys)} API key(s), {len(notes)} note(s)."
            f"\n      Anyone with access to this computer can read them."
            f"\n      Only use this for testing or temporary backups.\n"
        )
        proceed = typer.confirm("  Continue with plaintext export?")
        if not proceed:
            typer.echo("  Cancelled.\n")
            raise typer.Exit()

        with Spinner("Writing plaintext backup file"):
            try:
                content = json.dumps(export_data, indent=2, ensure_ascii=False)
                backup_path.write_text(content)
                os.chmod(backup_path, 0o600)
            except Exception as e:
                typer.echo(f"\n  Error: Failed to write backup file.\n  {e}\n", err=True)
                raise typer.Exit(code=1)
    else:
        # ── Encrypted mode (default) ──────────────────────────────────────
        typer.echo("  Choose a passphrase to encrypt your backup.")
        typer.echo("  You'll need this passphrase to import it later.")
        typer.echo("  E.g.  MyDogBarksAtMidnight!23\n")

        while True:
            passphrase = typer.prompt(" Export passphrase")
            if len(passphrase) < 8:
                typer.echo("  Error: passphrase must be at least 8 characters.\n", err=True)
                continue
            confirm = typer.prompt(" Confirm passphrase")
            if passphrase != confirm:
                typer.echo("  Error: passphrases do not match.\n", err=True)
                continue
            break

        with Spinner("Encrypting backup file"):
            try:
                envelope = export_encrypt(export_data, passphrase)
                backup_path.write_text(envelope)
                os.chmod(backup_path, 0o600)
            except Exception as e:
                typer.echo(f"\n  Error: Failed to write backup file.\n  {e}\n", err=True)
                raise typer.Exit(code=1)

    typer.echo(f"  ✓ Backup saved to: {backup_path}")
    if not plaintext:
        typer.echo(
            "\n  Your vault is unchanged — nothing was deleted.\n"
            "  Use 'psamvault import' to restore this backup later.\n"
        )