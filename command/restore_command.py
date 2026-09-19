"""psamvault restore — regain vault access on a machine that has no key material.

The one flow that has to work when everything else does not: a fresh or wiped machine
has no pepper, no VEK and no session, so it cannot even log in. What it *does* have is
the backup passphrase (or a kit file). This module turns that into a working vault:

    passphrase -> unwrap the VEK -> wrap it under a login key derived HERE
               -> the server stores that wrap -> log in -> prove an entry decrypts

Nothing is re-encrypted: the VEK never changes, so the entries on the server stay valid.
"""

from pathlib import Path
from typing import Optional

import typer

import api_client
from config import is_configured
from crypto import (
    decrypt_credentials,
    derive_key,
    derive_master_password,
    encrypt_master_with_code,
    encrypt_vek,
    generate_recovery_codes,
    parse_kit,
    unwrap_vek_with_passphrase,
)
from error_ui import print_error
from errors import PsamVaultError, SessionExpiredError
from session import is_logged_in, load_session, save_session
from spinner import Spinner


def _password_errors(password: str) -> list[str]:
    """Mirror the signup rules so a restored account is never weaker than a new one."""
    errors = []
    if len(password) < 8:
        errors.append("at least 8 characters")
    if not any(c.isupper() for c in password):
        errors.append("at least one uppercase letter")
    if not any(c.isdigit() for c in password):
        errors.append("at least one digit")
    return errors


def _prompt_new_password() -> str:
    typer.echo("\n  Set a new login password for this machine\n")
    while True:
        password = typer.prompt("  New login password", hide_input=True)
        errors = _password_errors(password)
        if errors:
            typer.echo("\n  Error: password does not meet the requirements:", err=True)
            for error in errors:
                typer.echo(f"    • {error}", err=True)
            typer.echo("", err=True)
            continue
        confirm = typer.prompt("  Confirm new login password", hide_input=True)
        if password != confirm:
            typer.echo("\n  Error: passwords do not match\n", err=True)
            continue
        return password


def _prove_vault_opens(session: dict, vek: bytes) -> Optional[str]:
    """Decrypt one real entry and return its site name — the end-to-end proof.

    A restore that cannot open an entry is not a restore, so this reports honestly
    instead of claiming success on the strength of HTTP status codes.
    """
    try:
        listing = api_client.list_vault_entries(
            access_token=session["access_token"],
            refresh_token=session["refresh_token"],
        )
    except PsamVaultError:
        return None

    entries = listing.get("entries") or []
    if not entries:
        return "empty vault"

    site = entries[0]["site_name"]
    try:
        entry = api_client.get_vault_entry(
            access_token=session["access_token"],
            refresh_token=session["refresh_token"],
            site_name=site,
        )
        decrypt_credentials(vek, encrypted_blob=entry["encrypted_blob"], iv=entry["iv"])
    except Exception:  # noqa: BLE001 - any failure here means the key is not the right one
        return None
    return site


def _offer_recovery_codes(vek: bytes, access_token: str) -> None:
    """Print a fresh set of recovery codes so a restore never leaves one single path."""
    from command.recovery_commands import _build_code_payloads, _display_codes

    codes = generate_recovery_codes(8)
    payloads = _build_code_payloads(codes, vek)
    try:
        with Spinner("Storing fresh recovery codes"):
            api_client.generate_recovery_codes_api(
                access_token=access_token, codes=payloads
            )
    except PsamVaultError as exc:
        print_error(exc)
        typer.echo(
            "  → Your vault is restored; run  psamvault generate-codes  later to get codes.\n",
            err=True,
        )
        return
    _display_codes(codes)
    typer.echo("  ✓ 8 fresh recovery codes stored. Each can be used once.\n")


def restore(
    from_kit: Optional[Path] = typer.Option(
        None, "--from-kit", help="Restore from a kit file instead of the server-side slot"
    ),
    force: bool = typer.Option(
        False, "--force", help="Run even though this machine already has a session"
    ),
    no_codes: bool = typer.Option(
        False, "--no-codes", help="Do not offer a fresh set of recovery codes at the end"
    ),
):
    """Restore vault access on a new or wiped machine.

    \b
    You need: your username, your backup passphrase (or a kit file), and a new login
    password. Your entries are not touched — only the key wrap is replaced.

    \b
    Example:
      psamvault configure           # once per machine
      psamvault restore
      psamvault restore --from-kit ~/Desktop/psamvault-key-2026-09-18.json
    """
    if not is_configured():
        typer.echo(
            "\n  psamvault is not configured on this machine."
            "\n  → Run  psamvault configure  first, then  psamvault restore\n",
            err=True,
        )
        raise typer.Exit(code=1)

    if is_logged_in() and not force:
        typer.echo(
            "\n  This machine already has a session, so it does not need restoring."
            "\n  → Use  psamvault login  to sign in, or  --force  to overwrite the session.\n",
            err=True,
        )
        raise typer.Exit(code=1)

    typer.echo("\n  psamvault vault restore\n")
    typer.echo(
        "  This machine gets access back using your backup passphrase."
        "\n  Your entries are not re-encrypted or re-uploaded.\n"
    )

    # ── 1. obtain the VEK + the account salt the new login key needs ────────────
    if from_kit is not None:
        try:
            kit = parse_kit(Path(from_kit).read_text(encoding="utf-8"))
        except OSError as exc:
            typer.echo(f"  Error: could not read {from_kit}: {exc}", err=True)
            raise typer.Exit(code=1)  # pylint: disable=raise-missing-from
        except ValueError as exc:
            typer.echo(f"  Error: {exc}", err=True)
            raise typer.Exit(code=1)  # pylint: disable=raise-missing-from

        username = kit["account"]
        account_kdf_salt = kit.get("account_kdf_salt")
        if not account_kdf_salt:
            typer.echo(
                "\n  Error: this kit has no account salt and cannot be used to restore."
                "\n  → Restore with your passphrase and username instead:\n"
                "     psamvault restore\n",
                err=True,
            )
            raise typer.Exit(code=1)

        slot_id = kit.get("slot_id")
        if slot_id:
            # A kit is self-contained, so only the server can say whether its slot was
            # rotated away. Refuse a retired kit rather than restore with material the
            # user believes is dead — but stay usable offline.
            try:
                check = api_client.validate_key_envelope_slot(slot_id)
                if check.get("exists") and check.get("revoked"):
                    typer.echo(
                        "\n  Error: that kit was revoked (its slot was rotated or removed)."
                        "\n  → Use the current backup passphrase, or ask for a fresh kit.\n",
                        err=True,
                    )
                    raise typer.Exit(code=1)
                if not check.get("exists"):
                    typer.echo(
                        "  Warning: this kit's slot is no longer on the server (it may have been"
                        " revoked).\n           Continuing because the kit still holds the key.\n"
                    )
            except typer.Exit:
                # typer.Exit derives from RuntimeError, so a broad `except Exception` below
                # would swallow the refusal and carry on restoring with a retired kit.
                raise
            except SessionExpiredError:
                typer.echo("  Warning: could not reach the server to check the kit. Continuing.\n")
            except Exception as exc:  # noqa: BLE001 - offline restore must still work
                typer.echo(f"  Warning: could not check the kit ({exc}). Continuing.\n")

        typer.echo(f"  Account: {username}")
        passphrase = typer.prompt("  Backup passphrase for this kit", hide_input=True)
        try:
            vek = unwrap_vek_with_passphrase(
                passphrase,
                kit["wrapped_vek"],
                kit["iv"],
                kit["kdf"]["salt"],
                iterations=kit["kdf"].get("iterations", 600_000),
            )
        except Exception:  # noqa: BLE001
            typer.echo(
                "\n  Error: that passphrase does not open this kit.\n", err=True
            )
            raise typer.Exit(code=1)
    else:
        username = typer.prompt(" Username")
        passphrase = typer.prompt(" Backup passphrase", hide_input=True)
        with Spinner("Verifying backup passphrase"):
            try:
                begun = api_client.begin_key_envelope_restore(username, passphrase)
            except SessionExpiredError:
                typer.echo(
                    "\n  Error: that passphrase does not match any backup slot for this account."
                    "\n  → Check the username and passphrase, or restore with"
                    "  --from-kit <kit.json>\n",
                    err=True,
                )
                raise typer.Exit(code=1)  # pylint: disable=raise-missing-from
            except PsamVaultError as exc:
                print_error(exc)
                raise typer.Exit(code=1)
        try:
            vek = unwrap_vek_with_passphrase(
                passphrase, begun["wrapped_vek"], begun["iv"], begun["kdf_salt"]
            )
        except Exception:  # noqa: BLE001
            typer.echo("\n  Error: the stored slot did not unwrap with that passphrase.\n", err=True)
            raise typer.Exit(code=1)
        slot_id = begun["slot_id"]
        account_kdf_salt = begun["account_kdf_salt"]

    # ── 2. re-wrap the VEK under a login key derived on THIS machine ────────────
    new_password = _prompt_new_password()
    master = derive_master_password(new_password)
    login_key = derive_key(master, account_kdf_salt)
    new_encrypted_vek, new_vek_iv = encrypt_vek(login_key, vek)

    with Spinner("Restoring vault access"):
        try:
            api_client.restore_vault_key(
                username=username,
                passphrase=passphrase,
                new_login_password=master,
                new_encrypted_vek=new_encrypted_vek,
                new_vek_iv=new_vek_iv,
                slot_id=slot_id,
            )
        except PsamVaultError as exc:
            print_error(exc)
            raise typer.Exit(code=1)

    # ── 3. log in and persist the session on this machine ──────────────────────
    with Spinner("Logging in"):
        login_result = api_client.login(username, master)

    save_session(
        access_token=login_result["access_token"],
        refresh_token=login_result["refresh_token"],
        kdf_salt=account_kdf_salt,
        vek=vek.hex(),
        encrypted_vek=login_result["encrypted_vek"],
        vek_iv=login_result["vek_iv"],
    )

    typer.echo(f"  ✓ Restored and logged in as {username}")

    # ── 4. prove it: decrypt a real entry ──────────────────────────────────────
    session = load_session()
    with Spinner("Checking your vault"):
        proof = _prove_vault_opens(session, vek)
    if proof is None:
        typer.echo(
            "\n  ✗ Access was restored, but an entry could not be decrypted with that key."
            "\n  → Do not delete anything: your entries are untouched, but report this."
            "\n     Try  psamvault restore  again with a different backup passphrase.\n",
            err=True,
        )
        raise typer.Exit(code=1)
    if proof == "empty vault":
        typer.echo("  ✓ No entries yet — nothing to open, but the vault is reachable")
    else:
        typer.echo(f"  ✓ Decrypted '{proof}' with the recovered key — your vault is back")

    # ── 5. leave the account with more than one way back in ────────────────────
    if not no_codes:
        typer.echo("")
        if typer.confirm("  Generate a fresh set of 8 recovery codes now?", default=True):
            session = load_session()
            _offer_recovery_codes(vek, session["access_token"])

    typer.echo("  Your entries are unchanged — nothing was re-encrypted or moved.")
    typer.echo("  Run  psamvault list  to see them.\n")
