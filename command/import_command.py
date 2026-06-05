"""psamvault import — restore credentials from a backup file."""

import json
from pathlib import Path
from typing import Optional

import typer

import api_client
from crypto import (
    decrypt_api_key,
    encrypt_credentials,
    encrypt_api_key,
    export_decrypt,
)
from session import load_session, is_logged_in
from spinner import Spinner

app = typer.Typer(
    name="import",
    help="Import credentials from a psamvault backup file",
)

_DESKTOP = Path.home() / "Desktop"


def _find_backup_files() -> list[Path]:
    """Scan the Desktop for psamvault backup files (encrypted and plaintext).

    Returns files sorted so encrypted backups come first, then plaintext.
    Within each group, newest files appear first.
    """
    if not _DESKTOP.exists():
        return []
    all_files = sorted(
        _DESKTOP.glob("psamvault-backup*.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    # Separate encrypted (no "-plaintext" in name) from plaintext
    encrypted = [f for f in all_files if "-plaintext" not in f.name]
    plaintext = [f for f in all_files if "-plaintext" in f.name]
    return encrypted + plaintext


def _pick_backup_file() -> Optional[Path]:
    """Let the user pick from available backup files, or return None."""
    files = _find_backup_files()
    if not files:
        return None

    if len(files) == 1:
        return files[0]

    typer.echo("\n  Found multiple backup files:\n")
    for i, f in enumerate(files, 1):
        size = f.stat().st_size
        typer.echo(f"  {i}. {f.name}  ({size:,} bytes)")

    choice = typer.prompt(
        "\n  Which one to import?",
        default="1",
    )

    try:
        idx = int(choice) - 1
        if 0 <= idx < len(files):
            return files[idx]
    except ValueError:
        pass

    typer.echo("  Invalid choice. Using the most recent one.\n", err=True)
    return files[0]


def _is_encrypted_backup(content: str) -> bool:
    """Detect whether a backup file is encrypted (has envelope fields) or plaintext."""
    try:
        data = json.loads(content)
        # Encrypted envelope has "salt", "iv", "data" — the export_encrypt output
        return "salt" in data and "iv" in data and "data" in data
    except (json.JSONDecodeError, TypeError):
        return False


def _prompt_passphrase() -> str:
    """Prompt for the export passphrase."""
    typer.echo(
        "  Enter the passphrase you used when creating the backup.\n"
    )
    return typer.prompt(" Export passphrase")


def _load_backup(file_path: Path) -> dict:
    """Read and decrypt/parse a backup file, returning the data dict."""
    content = file_path.read_text(encoding="utf-8")

    if _is_encrypted_backup(content):
        # ── Encrypted backup — need passphrase ───────────────────────────
        passphrase = _prompt_passphrase()

        with Spinner("Decrypting backup file"):
            try:
                return export_decrypt(content, passphrase)
            except Exception:
                typer.echo(
                    "\n  Error: Could not decrypt backup."
                    "\n  The passphrase may be incorrect or the file is corrupted.\n",
                    err=True,
                )
                raise typer.Exit(code=1)
    else:
        # ── Plaintext backup — read directly ─────────────────────────────
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            typer.echo(
                "\n  Error: Could not read backup file. The file may be corrupted.\n",
                err=True,
            )
            raise typer.Exit(code=1)

        typer.echo("\n  Detected plaintext backup file (no passphrase needed).")

        if not data.get("plaintext"):
            typer.echo(
                "  ⚠  This file does not appear to be a psamvault backup.\n",
                err=True,
            )
            if not typer.confirm("  Attempt to import anyway?"):
                raise typer.Exit()

        return data


@app.callback(invoke_without_command=True)
def import_backup(
    path: Optional[str] = typer.Argument(
        None,
        help="Path to a backup file (auto-detects on Desktop if omitted)",
    ),
) -> None:
    """
    Restore credentials from a psamvault backup file.

    Supports both encrypted backups (created by default) and plaintext
    backups (created with 'psamvault export --plaintext').

    If no path is given, scans your Desktop for psamvault-backup-*.json
    files and lets you pick one.

    You must be logged in before importing — the credentials are
    re-encrypted with your current vault key.
    """
    if not is_logged_in():
        typer.echo(
            "\n  You must be logged in to import credentials."
            "\n  Run 'psamvault login' first.\n",
            err=True,
        )
        raise typer.Exit(code=1)

    session = load_session()
    vek = bytes.fromhex(session["vek"])

    # ── Step 1: Find the backup file ─────────────────────────────────────
    backup_path: Optional[Path] = None

    if path:
        backup_path = Path(path)
        if not backup_path.exists():
            typer.echo(f"\n  Error: File not found: {backup_path}\n", err=True)
            raise typer.Exit(code=1)
    else:
        backup_path = _pick_backup_file()

    if backup_path is None:
        # Also check current working directory
        cwd = Path.cwd()
        cwd_files = list(cwd.glob("psamvault-backup-*.json"))
        if cwd_files:
            backup_path = cwd_files[0]
        else:
            typer.echo(
                "\n  No backup files found on your Desktop."
                "\n  Specify a path:  psamvault import <path/to/backup.json>\n",
                err=True,
            )
            raise typer.Exit(code=1)

    typer.echo(f"\n  Backup file: {backup_path}")

    # ── Step 2: Load the backup (auto-detect encrypted vs plaintext) ────
    export_data = _load_backup(backup_path)

    credentials = export_data.get("credentials", [])
    api_keys = export_data.get("api_keys", [])

    if not credentials and not api_keys:
        typer.echo("\n  The backup file contains no credentials or API keys.\n")
        raise typer.Exit()

    typer.echo(
        f"\n  Found: {len(credentials)} credential(s), {len(api_keys)} API key(s) to import.\n"
    )

    proceed = typer.confirm(" Start import?")
    if not proceed:
        typer.echo("  Cancelled.\n")
        raise typer.Exit()

    # ── Step 3: Import credentials ───────────────────────────────────────
    imported_creds = 0
    skipped_creds = 0

    if credentials:
        with Spinner("Importing site credentials"):
            for cred in credentials:
                try:
                    encrypted_blob, iv = encrypt_credentials(
                        vek,
                        username=cred["username"],
                        password=cred["password"],
                        notes=cred.get("notes", ""),
                    )

                    api_client.add_vault_entry(
                        access_token=session["access_token"],
                        refresh_token=session["refresh_token"],
                        site_name=cred["site_name"],
                        encrypted_blob=encrypted_blob,
                        iv=iv,
                        username_hint=cred["username"],
                        login_url=cred.get("login_url"),
                    )
                    imported_creds += 1
                except typer.Exit:
                    raise
                except Exception:
                    skipped_creds += 1

            # Reload session in case tokens rotated
            session = load_session()
            vek = bytes.fromhex(session["vek"])

    # ── Step 4: Import API keys ──────────────────────────────────────────
    imported_keys = 0
    skipped_keys = 0

    if api_keys:
        with Spinner("Importing API keys"):
            for ak in api_keys:
                try:
                    encrypted_blob, iv = encrypt_api_key(
                        vek,
                        service=ak["service"],
                        api_key=ak["api_key"],
                        notes=ak.get("notes", ""),
                    )

                    api_client.add_api_key_entry(
                        access_token=session["access_token"],
                        refresh_token=session["refresh_token"],
                        name=ak["name"],
                        service_hint=ak["service"],
                        encrypted_blob=encrypted_blob,
                        iv=iv,
                    )
                    imported_keys += 1
                except typer.Exit:
                    raise
                except Exception:
                    skipped_keys += 1

    # ── Step 5: Summary ──────────────────────────────────────────────────
    parts = []
    if imported_creds:
        parts.append(f"{imported_creds} credential(s)")
    if imported_keys:
        parts.append(f"{imported_keys} API key(s)")

    summary = ", ".join(parts) if parts else "nothing"

    typer.echo(f"\n  ✓ Imported {summary}.\n")

    if skipped_creds or skipped_keys:
        warnings = []
        if skipped_creds:
            warnings.append(f"{skipped_creds} credential(s) skipped (may already exist)")
        if skipped_keys:
            warnings.append(f"{skipped_keys} API key(s) skipped (may already exist)")
        typer.echo(f"  ⚠  {', '.join(warnings)}.\n")

    typer.echo("  Run 'psamvault list' to verify your imported entries.\n")