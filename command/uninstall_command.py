"""psamvault uninstall — cleanly remove psamvault with a backup of all credentials."""

import json
import os
from datetime import datetime
from pathlib import Path

import keyring
import keyring.errors
import typer

import api_client
from config import CONFIG_DIR, CONFIG_FILE, is_configured
from crypto import (
    decrypt_api_key,
    decrypt_credentials,
    export_encrypt,
)
from session import (
    SESSION_DIR,
    SESSION_FILE,
    _SESSION_KEYS,
    _SERVICE,
    _VERSION_FILE,
    load_session,
)
from spinner import Spinner

app = typer.Typer(
    name="uninstall",
    help="Cleanly remove psamvault with a backup of all your data",
)

_DESKTOP = Path.home() / "Desktop"


def _find_export_path() -> Path:
    """Generate a unique export file path on the Desktop."""
    now = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    return _DESKTOP / f"psamvault-backup-{now}.json"


def _prompt_passphrase(confirm: bool = True) -> str:
    """Prompt for an export passphrase, optionally with confirmation."""
    typer.echo("  E.g.  MyDogBarksAtMidnight!23\n")
    while True:
        passphrase = typer.prompt(
            " Export passphrase",
        )
        if len(passphrase) < 8:
            typer.echo(
                "  Error: passphrase must be at least 8 characters.\n", err=True
            )
            continue
        if confirm:
            confirm_pass = typer.prompt(
                " Confirm export passphrase",
            )
            if passphrase != confirm_pass:
                typer.echo("  Error: passphrases do not match.\n", err=True)
                continue
        return passphrase


def _clear_local_data() -> None:
    """Remove all local psamvault data — keychain, config files, session."""
    # Clear keychain session entries
    for key in _SESSION_KEYS:
        try:
            keyring.delete_password(_SERVICE, key)
        except keyring.errors.PasswordDeleteError:
            pass

    # Clear pepper from keychain
    try:
        keyring.delete_password(_SERVICE, "config.pepper")
    except keyring.errors.PasswordDeleteError:
        pass

    # Remove session.json
    if SESSION_FILE.exists():
        SESSION_FILE.unlink()

    # Remove last_seen_version
    if _VERSION_FILE.exists():
        _VERSION_FILE.unlink()

    # Remove config.env
    if CONFIG_FILE.exists():
        CONFIG_FILE.unlink()

    # Remove .psamvault directory if empty
    try:
        SESSION_DIR.rmdir()
    except OSError:
        pass


@app.callback(invoke_without_command=True)
def uninstall() -> None:
    """
    Cleanly uninstall psamvault.

    Exports all your site credentials and API keys to an encrypted backup
    file on your Desktop, then removes all local psamvault data.

    You can re-import the backup later with: psamvault import
    """
    if not is_configured():
        typer.echo(
            "\n  psamvault is not configured on this machine.\n"
            "  Nothing to uninstall.\n",
            err=True,
        )
        raise typer.Exit(code=1)

    # Check if logged in
    from session import is_logged_in

    if not is_logged_in():
        typer.echo(
            "\n  You are not logged in. Run 'psamvault login' first,\n"
            "  or use 'psamvault import' to import from a backup file.\n",
            err=True,
        )
        raise typer.Exit(code=1)

    typer.echo(
        "\n"
        "  ╔══════════════════════════════════════════════════════════════╗\n"
        "  ║               psamvault Clean Uninstall                     ║\n"
        "  ╠══════════════════════════════════════════════════════════════╣\n"
        "  ║  This will:                                                 ║\n"
        "  ║  ✓ Export all your data to an encrypted backup on Desktop   ║\n"
        "  ║  ✓ Clear your local config, session, and keychain data      ║\n"
        "  ║  ✓ Optionally delete your account from the server           ║\n"
        "  ╚══════════════════════════════════════════════════════════════╝\n"
    )

    proceed = typer.confirm(" Continue?")
    if not proceed:
        typer.echo("  Cancelled.\n")
        raise typer.Exit()

    session = load_session()
    vek = bytes.fromhex(session["vek"])

    export_path = _find_export_path()

    # ── Step 1: Fetch and decrypt all vault entries ─────────────────────
    typer.echo("")
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
                # Skip entries that fail to decrypt — corrupted data
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

    # ── Step 2: Fetch and decrypt all API keys ──────────────────────────
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

    # ── Step 3: Print summary of what will be exported ──────────────────
    typer.echo(f"\n  Found: {len(credentials)} credential(s), {len(api_keys)} API key(s)\n")

    # ── Step 4: Get export passphrase ───────────────────────────────────
    passphrase = _prompt_passphrase(confirm=True)

    # ── Step 5: Encrypt and write the backup file ───────────────────────
    export_data = {
        "version": 1,
        "exported_at": datetime.utcnow().isoformat() + "Z",
        "credentials": credentials,
        "api_keys": api_keys,
    }

    with Spinner("Encrypting backup file"):
        try:
            envelope = export_encrypt(export_data, passphrase)
            _DESKTOP.mkdir(parents=True, exist_ok=True)
            export_path.write_text(envelope)
            os.chmod(export_path, 0o600)
        except Exception as e:
            typer.echo(f"\n  Error: Failed to write backup file.\n  {e}\n", err=True)
            raise typer.Exit(code=1)

    typer.echo(f"  ✓ Backup saved to: {export_path}\n")

    # ── Step 6: Ask about server data ───────────────────────────────────
    delete_server = typer.confirm(
        " Delete your account and all data from the server?"
        "\n  (Your backup file will still work either way)"
    )

    if delete_server:
        with Spinner("Deleting account from server"):
            try:
                api_client.delete_account(
                    access_token=session["access_token"],
                    refresh_token=session["refresh_token"],
                )
                typer.echo("  ✓ Account and all data deleted from server.")
            except typer.Exit:
                raise
            except Exception as e:
                typer.echo(
                    f"  Warning: Could not delete account from server.\n  {e}", err=True
                )

    # ── Step 7: Clear local data ────────────────────────────────────────
    with Spinner("Clearing local psamvault data"):
        _clear_local_data()

    typer.echo(
        "\n"
        "  ────────────────────────────────────────────────────────\n"
        "  ✓ psamvault has been cleanly removed from this machine.\n"
        "\n"
        f"  Your backup is at:\n"
        f"    {export_path}\n"
        "\n"
        "  To restore, run:\n"
        "    1. psamvault configure\n"
        "    2. psamvault login\n"
        "    3. psamvault import\n"
        "\n"
        "  Keep your backup passphrase safe — you'll need it to import.\n"
    )