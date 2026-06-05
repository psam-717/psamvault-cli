"""psamvault export — export all credentials to an encrypted backup file."""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

import typer

import api_client
from crypto import (
    decrypt_api_key,
    decrypt_credentials,
    export_encrypt,
)
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

    session = load_session()
    vek = bytes.fromhex(session["vek"])

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

    # ── Summary ───────────────────────────────────────────────────────────
    typer.echo(f"\n  Found: {len(credentials)} credential(s), {len(api_keys)} API key(s)\n")

    if not credentials and not api_keys:
        typer.echo("  Nothing to export.\n")
        raise typer.Exit()

    # ── Build export data ─────────────────────────────────────────────────
    export_data = {
        "version": 1,
        "exported_at": datetime.utcnow().isoformat() + "Z",
        "plaintext": plaintext,
        "credentials": credentials,
        "api_keys": api_keys,
    }

    # ── Write the file ────────────────────────────────────────────────────
    _DESKTOP.mkdir(parents=True, exist_ok=True)

    if plaintext:
        # ── Plaintext mode ────────────────────────────────────────────────
        typer.echo(
            "  ⚠  WARNING: Plaintext mode selected."
            "\n      Your site passwords and API keys will be stored"
            "\n      as readable text on your Desktop."
            "\n      Anyone with access to this computer can read them."
            "\n      Only use this for testing or temporary backups.\n"
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