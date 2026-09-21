"""psamvault backup — back up the vault key so a lost machine is recoverable.

Why this exists: your entries live on the server, encrypted under a key that never
changes. Losing a machine loses the *key*, not the data — so a backup here means a
backup of the key. The commands below wrap that key with a passphrase you choose,
store it as a server-side slot (so a lost kit file is not fatal) and write it to a
portable kit file (so a lost server is not fatal either).
"""

import hmac
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

import typer

import api_client
from crypto import (
    BACKUP_PASSPHRASE_MIN_LENGTH,
    build_kit,
    hash_passphrase,
    kit_to_json,
    parse_kit,
    unwrap_vek_with_passphrase,
    wrap_vek_with_passphrase,
)
from errors import PsamVaultError, SessionExpiredError
from error_ui import print_error
from session import is_logged_in, load_session
from spinner import Spinner

app = typer.Typer(
    name="backup",
    help="Back up your vault key (recovery kit) and check that you are recoverable",
)

_DESKTOP = Path.home() / "Desktop"


@app.callback(invoke_without_command=True)
def backup_help(ctx: typer.Context):
    if ctx.invoked_subcommand is None:
        typer.echo("""
psamvault backup — keep your vault recoverable

  COMMAND                       USAGE
  ──────────────────────────────────────────────────────────────────────────────
  create                        psamvault backup create
  verify                        psamvault backup verify
  status                        psamvault backup status
  rotate                        psamvault backup rotate
  revoke <slot-id>              psamvault backup revoke <slot-id>
  restore                       psamvault restore      (run it on the new machine)

  A backup is two things: a slot on the server, and a kit file you keep off-device.
  Losing either one alone is survivable. Losing both is not.
""")


# ── helpers ─────────────────────────────────────────────────────────────────────


def _require_session() -> dict:
    """Return a live (refreshed) session — a backup needs the VEK from the keychain."""
    if not is_logged_in():
        typer.echo("\n  You are not logged in. Run 'psamvault login' first.\n", err=True)
        raise typer.Exit(code=1)
    return api_client.ensure_session()


def _account_name(session: dict) -> str:
    """Fetch the account name for the kit (kits name the account they belong to)."""
    try:
        profile = api_client.me(session["access_token"])
        return profile.get("username") or "unknown"
    except PsamVaultError:
        return "unknown"


def _default_kit_path() -> Path:
    base = _DESKTOP if _DESKTOP.exists() else Path.home()
    return base / f"psamvault-key-{datetime.now().strftime('%Y-%m-%d_%H%M%S')}.json"


def _write_kit(kit: dict, out: Optional[Path]) -> Path:
    path = Path(out) if out else _default_kit_path()
    if path.parent and str(path.parent) not in ("", "."):
        path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(kit_to_json(kit), encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except Exception:  # noqa: BLE001 - best effort on Windows
        pass
    return path


def _prompt_passphrase(confirm: bool = True) -> str:
    """Prompt for a backup passphrase, enforcing the minimum length."""
    typer.echo(
        "  Choose a backup passphrase. It is the only thing standing between"
        "\n  someone who finds your kit file and your vault, so make it long."
        "\n  Store it somewhere DIFFERENT from the kit file.\n"
    )
    while True:
        passphrase = typer.prompt("  Backup passphrase", hide_input=True)
        if len(passphrase) < BACKUP_PASSPHRASE_MIN_LENGTH:
            typer.echo(
                f"  Error: use at least {BACKUP_PASSPHRASE_MIN_LENGTH} characters.\n", err=True
            )
            continue
        if not confirm:
            return passphrase
        again = typer.prompt("  Confirm passphrase", hide_input=True)
        if passphrase != again:
            typer.echo("  Error: passphrases do not match.\n", err=True)
            continue
        return passphrase


def _print_kit_advice(path: Path) -> None:
    typer.echo(f"  ✓ Kit written to: {path}")
    typer.echo(
        "\n  Now move it OFF this machine (print it, cloud drive, password manager),"
        "\n  and store the passphrase somewhere else again."
        "\n  A kit on the machine you lose is not a backup.\n"
    )


# ── commands ────────────────────────────────────────────────────────────────────


@app.command(name="create")
def backup_create(
    no_upload: bool = typer.Option(
        False, "--no-upload",
        help="Write the kit file only — keep no server-side copy of the wrapped key",
    ),
    out: Optional[Path] = typer.Option(
        None, "--out", help="Where to write the kit file (default: Desktop)"
    ),
):
    """Create a backup slot for your vault key.

    \b
    Example:
      psamvault backup create
      psamvault backup create --no-upload --out ./kit.json
    """
    session = _require_session()
    vek = bytes.fromhex(session["vek"])

    typer.echo("\n  Create a vault backup\n")
    passphrase = _prompt_passphrase()

    wrapped, iv, salt = wrap_vek_with_passphrase(passphrase, vek)

    slot_id: Optional[str] = None
    if no_upload:
        typer.echo("  Skipping the server copy (--no-upload).")
    else:
        with Spinner("Storing backup slot"):
            try:
                result = api_client.create_key_envelope(
                    access_token=session["access_token"],
                    refresh_token=session["refresh_token"],
                    passphrase_hash=hash_passphrase(passphrase),
                    wrapped_vek=wrapped,
                    iv=iv,
                    kdf_salt=salt,
                )
            except SessionExpiredError as exc:
                print_error(exc)
                raise typer.Exit(code=1)
            except PsamVaultError as exc:
                print_error(exc)
                raise typer.Exit(code=1)
        slot_id = result["slot_id"]

    account = _account_name(load_session())
    kit = build_kit(
        account=account,
        wrapped_vek=wrapped,
        iv=iv,
        salt=salt,
        slot_id=slot_id,
        account_kdf_salt=load_session()["kdf_salt"],
    )
    path = _write_kit(kit, out)

    if slot_id:
        typer.echo(f"  ✓ Backup slot stored (id {slot_id[:8]}…)")
    _print_kit_advice(path)
    typer.echo("  Prove it works now, while you still have this machine:")
    typer.echo("      psamvault backup verify\n")


@app.command(name="verify")
def backup_verify(
    kit: Optional[Path] = typer.Option(
        None, "--kit", help="Verify a kit file instead of the server-side slot"
    ),
):
    """Check that your backup passphrase actually restores this vault.

    An unverified backup is not a backup: this unwraps your vault key and compares it,
    byte for byte, with the key this machine is currently using.
    """
    session = _require_session()
    vek = bytes.fromhex(session["vek"])

    typer.echo("\n  Verify vault backup\n")

    from_kit = kit is not None
    if from_kit:
        try:
            parsed = parse_kit(Path(kit).read_text(encoding="utf-8"))
        except OSError as exc:
            typer.echo(f"  Error: could not read {kit}: {exc}", err=True)
            raise typer.Exit(code=1)  # pylint: disable=raise-missing-from
        except ValueError as exc:
            typer.echo(f"  Error: {exc}", err=True)
            raise typer.Exit(code=1)  # pylint: disable=raise-missing-from

        passphrase = typer.prompt("  Backup passphrase for this kit", hide_input=True)
        try:
            recovered = unwrap_vek_with_passphrase(
                passphrase,
                parsed["wrapped_vek"],
                parsed["iv"],
                parsed["kdf"]["salt"],
                iterations=parsed["kdf"].get("iterations", 600_000),
            )
        except Exception:  # noqa: BLE001 - InvalidTag and friends all mean "wrong passphrase"
            typer.echo(
                "\n  ✗ That passphrase does not open this kit."
                "\n  → Check the passphrase, or create a fresh backup with"
                "  psamvault backup create\n",
                err=True,
            )
            raise typer.Exit(code=1)
        slot_label = parsed.get("slot_id")
    else:
        passphrase = typer.prompt("  Backup passphrase", hide_input=True)
        account = _account_name(session)
        try:
            with Spinner("Checking the server-side slot"):
                result = api_client.begin_key_envelope_restore(account, passphrase)
        except SessionExpiredError:
            typer.echo(
                "\n  ✗ That passphrase does not match any stored backup slot."
                "\n  → Use  psamvault backup status  to see your slots, or create one with"
                "  psamvault backup create\n",
                err=True,
            )
            raise typer.Exit(code=1)  # pylint: disable=raise-missing-from
        except PsamVaultError as exc:
            print_error(exc)
            raise typer.Exit(code=1)

        try:
            recovered = unwrap_vek_with_passphrase(
                passphrase, result["wrapped_vek"], result["iv"], result["kdf_salt"]
            )
        except Exception:  # noqa: BLE001
            typer.echo("\n  ✗ The stored slot did not unwrap with that passphrase.\n", err=True)
            raise typer.Exit(code=1)
        slot_label = result["slot_id"]

    if not hmac.compare_digest(recovered, vek):
        typer.echo(
            "\n  ✗ That backup unwraps to a DIFFERENT vault key than this machine is using."
            "\n  → It belongs to another account or was made before a key change."
            "\n     Create a fresh backup with  psamvault backup create\n",
            err=True,
        )
        raise typer.Exit(code=1)

    if slot_label:
        source = "this kit" if from_kit else "this backup"
        typer.echo(f"  ✓ Verified — {source} restores your vault (slot {slot_label[:8]}…)\n")
    else:
        typer.echo(
            "  ✓ Verified — this kit restores your vault (no server-side copy)\n"
        )


@app.command(name="status")
def backup_status():
    """Show your backup slots and recovery codes — i.e. how recoverable you are."""
    session = _require_session()

    try:
        with Spinner("Fetching backup slots"):
            status = api_client.get_key_envelope_status(
                access_token=session["access_token"],
                refresh_token=session["refresh_token"],
            )
    except PsamVaultError as exc:
        print_error(exc)
        raise typer.Exit(code=1)

    session = load_session()
    try:
        codes = api_client.get_remaining_codes(session["access_token"])["remaining_codes"]
    except Exception:  # noqa: BLE001 - status is informational; never fail on this
        codes = None

    slots = status.get("slots") or []
    typer.echo("\n  Backup status\n")
    if not slots:
        typer.echo("  ⚠  No backup slots — a lost machine would lock you out of your vault.")
        typer.echo("  → Run  psamvault backup create\n")
    else:
        typer.echo(f"  {'SLOT':<10} {'KIND':<12} {'CREATED':<22} {'LAST VERIFIED':<22} STATE")
        typer.echo("  " + "─" * 84)
        for slot in slots:
            created = (slot.get("created_at") or "")[:19].replace("T", " ")
            verified = (slot.get("last_verified_at") or "never")[:19].replace("T", " ")
            state = "revoked" if slot.get("revoked") else "active"
            typer.echo(
                f"  {slot['slot_id'][:8]:<10} {slot.get('kind', '?'):<12} "
                f"{created:<22} {verified:<22} {state}"
            )
        typer.echo("")

    active = status.get("active_slots", 0)
    codes_line = "unknown" if codes is None else str(codes)
    typer.echo(f"  Active backup slots : {active}")
    typer.echo(f"  Recovery codes left : {codes_line}")
    if active and codes is not None and codes == 0:
        typer.echo(
            "  ⚠  No recovery codes left — your backup passphrase is now your only other path."
        )
    typer.echo("\n  Reminder: a kit file that still lives on this machine is not backed up.\n")


@app.command(name="rotate")
def backup_rotate(
    out: Optional[Path] = typer.Option(
        None, "--out", help="Where to write the new kit file (default: Desktop)"
    ),
):
    """Replace your backup passphrase with a new one and revoke the old slots."""
    session = _require_session()
    vek = bytes.fromhex(session["vek"])

    typer.echo("\n  Rotate backup passphrase\n")
    typer.echo(
        "  This stores a new slot and revokes every other slot on the server.\n"
        "  Old kit files are refused from now on — but a kit you copied earlier still\n"
        "  contains key material, so destroy the copies you no longer trust.\n"
    )
    if not typer.confirm("  Continue?"):
        typer.echo("  Cancelled.\n")
        raise typer.Exit()

    passphrase = _prompt_passphrase()
    wrapped, iv, salt = wrap_vek_with_passphrase(passphrase, vek)

    with Spinner("Rotating backup slot"):
        try:
            result = api_client.rotate_key_envelope(
                access_token=session["access_token"],
                refresh_token=session["refresh_token"],
                passphrase_hash=hash_passphrase(passphrase),
                wrapped_vek=wrapped,
                iv=iv,
                kdf_salt=salt,
            )
        except PsamVaultError as exc:
            print_error(exc)
            raise typer.Exit(code=1)

    kit = build_kit(
        account=_account_name(load_session()),
        wrapped_vek=wrapped,
        iv=iv,
        salt=salt,
        slot_id=result["slot_id"],
        account_kdf_salt=load_session()["kdf_salt"],
    )
    path = _write_kit(kit, out)

    typer.echo(
        f"  ✓ New slot stored (id {result['slot_id'][:8]}…), "
        f"{result.get('revoked_slots', 0)} old slot(s) revoked"
    )
    _print_kit_advice(path)


@app.command(name="revoke")
def backup_revoke(
    slot_id: str = typer.Argument(..., help="Slot id from  psamvault backup status"),
):
    """Revoke a single backup slot (e.g. a kit file that leaked)."""
    session = _require_session()

    with Spinner("Revoking backup slot"):
        try:
            result = api_client.revoke_key_envelope(
                access_token=session["access_token"],
                refresh_token=session["refresh_token"],
                slot_id=slot_id,
            )
        except PsamVaultError as exc:
            print_error(exc)
            raise typer.Exit(code=1)

    typer.echo(f"\n  ✓ Slot {result['slot_id'][:8]}… revoked. {result['active_slots']} active left.")
    if result.get("warning"):
        typer.echo(f"\n  ⚠  {result['warning']}")
    typer.echo("")


# `psamvault backup restore` is an alias for the top-level `psamvault restore`
# (registered here so the alias lives next to the rest of the backup surface).
from command.restore_command import restore as _restore  # noqa: E402

app.command("restore")(_restore)
