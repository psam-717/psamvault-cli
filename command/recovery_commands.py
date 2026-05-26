import typer
from cryptography.exceptions import InvalidTag

import api_client
from config import is_configured
from crypto import (
    decrypt_master_with_code,
    decrypt_vek,
    derive_key,
    derive_master_password,
    encrypt_master_with_code,
    encrypt_vek,
    generate_recovery_codes,
    hash_recovery_code
)

from session import load_session, save_session, is_logged_in
from spinner import Spinner

app = typer.Typer(
    name="recovery",
    help="Manage recovery codes and reset a forgotten password"
)

@app.callback(invoke_without_command=True)
def recovery_help(ctx: typer.Context):
    if ctx.invoked_subcommand is None:
        typer.echo("""
psamvault recovery - account recovery commands

  COMMAND               USAGE
  ──────────────────────────────────────────────────────────────────────────────
  generate-codes        psamvault generate-codes
  remaining-codes       psamvault remaining-codes
  recover               psamvault recover
""")

RECOVERY_CODE_COUNT = 8


# helpers
def _build_code_payloads(
    raw_codes: list[str],
    vek: bytes
) -> list[dict]:
    """
    For each raw recovery code, encrypt the VEK with it and return the list
    of dicts the server expects:
    [{"code_hash": "...", "encrypted_master": "...", "iv": "...", "kdf_salt": "..."}, ...]

    The column is still named encrypted_master on the server for backwards
    compatibility, but it now holds the encrypted VEK hex string.
    A fresh random per-code PBKDF2 salt is included so two codes with the
    same value produce different AES keys.
    """
    payloads = []
    for code in raw_codes:
        encrypted_vek_hex, iv, kdf_salt = encrypt_master_with_code(code, vek.hex())
        payloads.append({
            "code_hash": hash_recovery_code(code),
            "encrypted_master": encrypted_vek_hex,
            "iv": iv,
            "kdf_salt": kdf_salt,
        })
    return payloads


def _display_codes(raw_codes: list[str]) -> None:
    """Print recovery codes in a clear, copy-friendly format"""
    typer.echo("\n  ╔══════════════════════════════════════════╗")
    typer.echo("  ║          YOUR RECOVERY CODES             ║")
    typer.echo("  ║  Store these somewhere safe. Each code   ║")
    typer.echo("  ║  can only be used once.                  ║")
    typer.echo("  ╠══════════════════════════════════════════╣")
    for i, code in enumerate(raw_codes, 1):
        content = f"   {i}.  {code}"
        typer.echo(f"  ║{content:<42}║")
    typer.echo("  ╚══════════════════════════════════════════╝\n")
    
    
def _warn_if_low(remaining: int) -> None:
    """print a warning message if remaining codes are running low"""
    if remaining == 0:
        typer.echo(
            "  Warning: you have no recovery codes left."
            "\n  Run  psamvault generate-codes  while logged in to create a new set.\n"
        )
    elif remaining <=2:
        typer.echo(
            f"  Warning: only {remaining} recovery code(s) remaining."
            f"\n  Consider running  psamvault generate-codes  to get a fresh set.\n"
        )
        
    
# Commands
@app.command(name="generate-codes")
def generate_codes():
    """
    Generate a fresh set of 8 recovery codes while logged in.
 
    Each code can be used once to reset your login password if you forget it.
    Running this replaces all existing codes — store the new ones before
    closing your terminal.
 
    \b
    Example:
      psamvault generate-codes
      psamvault recovery generate-codes
    """
    if not is_logged_in():
        typer.echo(" You are not logged in. Run psamvault login first", err=True)
        raise typer.Exit(code=1)
    
    session = load_session()
    
    typer.echo(
        "\n  This will replace all your existing recovery codes."
        "\n  Save the new ones before closing your terminal.\n"
    )
    confirm = typer.confirm(" Continue?")
    if not confirm:
        typer.echo(" Cancelled")
        raise typer.Exit()
    
    typer.echo("")
    
    login_password = typer.prompt(
        "  Confirm your current login password",
        hide_input=True
    )

    # Verify the password by attempting to decrypt the stored VEK.
    # If decryption succeeds, the password is correct and we have the VEK.
    master = derive_master_password(login_password)
    login_key = derive_key(master, session["kdf_salt"])

    try:
        vek = decrypt_vek(login_key, session["encrypted_vek"], session["vek_iv"])
    except InvalidTag:
        typer.echo(
            "\n  Error: the password you entered is incorrect."
            "\n  Your recovery codes were NOT updated.\n",
            err=True,
        )
        raise typer.Exit(code=1)
    
    raw_codes = generate_recovery_codes(RECOVERY_CODE_COUNT)
    code_payloads = _build_code_payloads(raw_codes, vek)
    
    with Spinner("Storing recovery codes"):
        api_client.generate_recovery_codes_api(
            access_token=session["access_token"],
            codes=code_payloads
        )
    
    _display_codes(raw_codes)
    
    typer.echo(" 8 recovery codes stored successfully")
    typer.echo(" Each code can be used once. Write them down now\n")
    

@app.command(name="remaining-codes")
def remaining_codes():
    """
    Check how many recovery codes you have left.
 
    Each code is consumed when used to reset your password. Once all
    8 are used, run  psamvault generate-codes  (while logged in) to
    get a fresh set.
 
    \b
    Example:
      psamvault remaining-codes
      psamvault recovery remaining-codes
    """
    if not is_logged_in():
        typer.echo(" You are not logged in. Run psamvault login first.", err=True)
        raise typer.Exit(code=1)
    
    session = load_session()
    
    with Spinner("Checking recovery codes"):
        result = api_client.get_remaining_codes(session["access_token"])
    
    remaining = result["remaining_codes"]
    
    typer.echo(f"\n {remaining} of 8 recovery code(s) remaining.\n")
    _warn_if_low(remaining)
    
    
@app.command(name="recover")
def recover():
    """
    Reset your login password using a recovery code.

    Use this when you have forgotten your login password. You will need
    one of your saved recovery codes. Only that code is consumed — the
    remaining codes stay valid permanently.

    Your vault entries are NOT re-encrypted — the VEK is static and is
    simply re-wrapped with your new login key.

    \b
    Steps:
      1. Verify your recovery code
      2. Recover the Vault Encryption Key (VEK)
      3. Set a new login password
      4. Re-encrypt the VEK with the new login key
      5. Reset the password on the server

    \b
    Example:
      psamvault recover
      psamvault recovery recover
    """
    if not is_configured():
        typer.echo(
            "\n  Error: psamvault is not fully configured."
            "\n  Run  psamvault configure  first to set up your device key."
            "\n  Recovery requires a consistent device key to derive your master password.\n",
            err=True,
        )
        raise typer.Exit(code=1)

    typer.echo("\n psamvault account recovery\n")
    typer.echo(
        "  You will need one of your saved recovery codes."
        "\n  Have it ready before continuing.\n"
    )
    
    username = typer.prompt(" Username")
    recovery_code = typer.prompt("Recovery code (e.g. A1B2-C3D4-E5F6)")
    
    typer.echo("")
    
    # Step 1 — verify the recovery code and get the encrypted VEK
    with Spinner("Verifying recovery code"):
        try:
            result = api_client.recover_with_code(username, recovery_code)
        except Exception as e:
            typer.echo(f"\n Error: {e}", err=True)
            raise typer.Exit(code=1)
    
    # Step 2 — decrypt the VEK using the recovery code
    # encrypted_master column on the server holds the encrypted VEK hex string.
    # code_kdf_salt is the per-code PBKDF2 salt stored alongside each recovery code.
    try:
        recovered_vek_hex = decrypt_master_with_code(
            recovery_code=recovery_code,
            encrypted_master=result["encrypted_master"],
            iv=result["iv"],
            salt=result["code_kdf_salt"],
        )
    except InvalidTag:
        typer.echo(
            "\n  Error: Recovery code is incorrect or has been tampered with.",
            err=True,
        )
        raise typer.Exit(code=1) # pylint: disable=raise-missing-from
    
    kdf_salt = result["kdf_salt"]
    typer.echo(" Recovery code verified.\n")
    
    # Step 3 — set a new login password
    typer.echo(" Set a new login password\n")
    
    new_login_password = typer.prompt(" New login password", hide_input=True)
    new_login_password_confirm = typer.prompt(" Confirm new login password", hide_input=True)
    
    if new_login_password != new_login_password_confirm:
        typer.echo(" \n Error: Passwords do not match", err=True)
        raise typer.Exit(code=1) 
    
    errors = []
    if len(new_login_password) < 8:
        errors.append("  • at least 8 characters")
    if not any(c.isupper() for c in new_login_password):
        errors.append("  • at least one uppercase letter")
    if not any(c.isdigit() for c in new_login_password):
        errors.append("  • at least one digit")

    if errors:
        typer.echo("\n Error: Password does not meet the requirements:", err=True)
        for e in errors:
            typer.echo(e, err=True)
        typer.echo("", err=True)
        raise typer.Exit(code=1)
    
    typer.echo("")

    # Step 4 — re-encrypt the VEK with the new login key
    new_master = derive_master_password(new_login_password)
    new_login_key = derive_key(new_master, kdf_salt)
    new_encrypted_vek, new_vek_iv = encrypt_vek(new_login_key, bytes.fromhex(recovered_vek_hex))

    # Step 5 — reset the password and update the encrypted VEK on the server
    with Spinner("Resetting password on server"):
        api_client.reset_password_api(
            username=username,
            recovery_code=recovery_code,
            new_login_password=new_master,
            new_encrypted_vek=new_encrypted_vek,
            new_vek_iv=new_vek_iv,
        )

    # Step 6 — log in with the new password to get a valid session
    with Spinner("Logging in with new password"):
        login_result = api_client.login(username, new_master)

    # Step 7 — save the session with the recovered VEK
    save_session(
        access_token=login_result["access_token"],
        refresh_token=login_result["refresh_token"],
        kdf_salt=kdf_salt,
        vek=recovered_vek_hex,
        encrypted_vek=login_result["encrypted_vek"],
        vek_iv=login_result["vek_iv"],
    )

    typer.echo("  ✓ Password reset successfully.")
    typer.echo(f"  ✓ Logged in as {username}.")
    typer.echo("  ✓ Your vault is intact — no re-encryption needed.")
    typer.echo("  ✓ Your remaining recovery codes are still valid.\n")