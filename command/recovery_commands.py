import typer
from cryptography.exceptions import InvalidTag

import api_client
from crypto import (
    decrypt_credentials,
    decrypt_master_with_code,
    derive_key,
    derive_master_password,
    encrypt_credentials,
    encrypt_master_with_code,
    generate_recovery_codes,
    hash_recovery_code
)

from session import load_session, save_session, is_logged_in
from spinner import Spinner

app = typer.Typer(
    name="recovery",
    help="Manage recovery codes and reset a forgotten password"
)

RECOVERY_CODE_COUNT = 8


# helpers
def _build_code_payloads(
    raw_codes: list[str],
    master_password: str
) -> list[dict]:
    """
    For each raw recovery code, encrypt the master password with it and
    return the list of dicts the server expects:
    [{"code_hash": "...", "encrypted_master": "...", "iv": "..."}, ...]
    """
    payloads = []
    for code in raw_codes:
        encrypted_master, iv = encrypt_master_with_code(code, master_password)
        payloads.append({
            "code_hash": hash_recovery_code(code),
            "encrypted_master": encrypted_master,
            "iv": iv
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
        typer.echo(f"  ║   {i}.  {code:<36}  ║")
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
        
def _reencrypt_vault(
    access_token: str,
    refresh_token: str,
    old_key: bytes,
    new_key: bytes
) -> int:
    """
    Fetch every vault entry, decrypt with the old key, re-encrypt with the
    new key, and push each updated entry back to the server.
 
    Returns the number of entries successfully re-encrypted.
 
    This is the critical step that makes the vault readable after a password
    reset — without this, the new login password would derive a different
    encryption key and every entry would become unreadable.
 
    Args:
        access_token:  Valid JWT for authenticating vault requests.
        refresh_token: Used for automatic token refresh if needed mid-process.
        old_key:       32-byte AES key derived from the recovered master password.
        new_key:       32-byte AES key derived from the new master password.
 
    Returns:
        Count of entries re-encrypted.
    """
    list_data = api_client.list_vault_entries(access_token, refresh_token)
    entries = list_data.get("entries", [])
    
    if not entries:
        return 0
    
    success_count = 0
    
    for entry in entries:
        site_name = entry["site_name"]
        
        try:
            full_entry = api_client.get_vault_entry(
                access_token, refresh_token, site_name
            )
            
            # decrypt with the old key (derived from the recovered master password)
            credentials = decrypt_credentials(
                old_key,
                encrypted_blob=full_entry["encrypted_blob"],
                iv=full_entry["iv"]
            )   
            
            new_blob, new_iv = encrypt_credentials(
                new_key,
                username= credentials["username"],
                password= credentials["password"],
                notes= credentials.get("notes", "")
            )
            
            api_client.update_vault_entry(
                access_token=access_token,
                refresh_token=refresh_token,
                site_name=site_name,
                encrypted_blob=new_blob,
                iv=new_iv,
                username_hint=full_entry.get("username_hint"),
            )
            
            success_count += 1
            
        except InvalidTag:
            typer.echo(
                f"\n  Warning: could not re-encrypt entry for '{site_name}'. "
                f"It may have been encrypted with a different key. Skipping.\n",
                err=True,
            )
        except Exception as e:
            typer.echo(
                f"\n  Warning: failed to update '{site_name}': {e}. Skipping.\n",
                err=True,
            )
    return success_count


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
    master_password = derive_master_password(login_password)
    
   
    # ------------------------------------------------------------------
    # Verify the derived master password actually decrypts a vault entry
    # before storing recovery codes with it. 
    # ------------------------------------------------------------------
    with Spinner("Verifying password against your vault"):
        test_list = api_client.list_vault_entries(
            session["access_token"], session["refresh_token"]
        )
        test_entries = test_list.get("entries", [])
 
    if test_entries:
        test_site = test_entries[0]["site_name"]
 
        with Spinner(f"Checking key against {test_site}"):
            test_entry = api_client.get_vault_entry(
                session["access_token"], session["refresh_token"], test_site
            )
 
        test_key = derive_key(master_password, session["kdf_salt"])
 
        try:
            decrypt_credentials(
                test_key,
                encrypted_blob=test_entry["encrypted_blob"],
                iv=test_entry["iv"],
            )
        except Exception:
            typer.echo(
                "\n  Error: the password you entered does not match your vault"
                "\n  encryption key. Your recovery codes were NOT updated."
                "\n"
                "\n  Make sure you enter the exact login password you used when"
                "\n  your vault entries were originally created.\n",
                err=True,
            )
            raise typer.Exit(code=1)
   
    
    raw_codes = generate_recovery_codes(RECOVERY_CODE_COUNT)
    code_payloads = _build_code_payloads(raw_codes, master_password)
    
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
    remaining codes stay valid for future use.
 
    Your vault entries are automatically re-encrypted with the new password
    so future logins work normally without needing recovery codes again.
 
    \b
    Steps:
      1. Verify your recovery code
      2. Recover your original vault encryption key
      3. Set a new login password
      4. Re-encrypt all vault entries with the new key
      5. Reset the password on the server
 
    \b
    Example:
      psamvault recover
      psamvault recovery recover
    """
    typer.echo("\n psamvault account recovery\n")
    typer.echo(
        "  You will need one of your saved recovery codes."
        "\n  Have it ready before continuing.\n"
    )
    
    username = typer.prompt(" Username")
    recovery_code = typer.prompt( "Recovery code (e.g. A1B2-C3D4-E5F6)")
    
    typer.echo("")
    
    # Step 1 verify the recovery code and get the encrypted master password
    with Spinner("Verifying recovery code"):
        try:
            result = api_client.recover_with_code(username, recovery_code)
        except Exception as e:
            typer.echo(f"\n Error: {e}", err=True)
            raise typer.Exit(code=1)
    
    # step 2 - decrypt the original master password using the recovery code
    try:
        recovered_master = decrypt_master_with_code(
            recovery_code=recovery_code,
            encrypted_master=result["encrypted_master"],
            iv=result["iv"]
        )
    except InvalidTag:
        typer.echo(
            "\n  Error: Recovery code is incorrect or has been tampered with.",
            err=True,
        )
        raise typer.Exit(code=1) # pylint: disable=raise-missing-from
    
    kdf_salt = result["kdf_salt"]
    
    # derive the old encryption key- the one that protects the vault
    old_key = derive_key(recovered_master, kdf_salt)   
    typer.echo(" Recovery code verified.\n")
    
    # Step 3 set a new login password
    typer.echo(" Set a new login password \n")
    
    new_login_password = typer.prompt(" New login password", hide_input=True)
    new_login_password_confirm = typer.prompt(" Confirm new login password", hide_input=True)
    
    if new_login_password != new_login_password_confirm:
        typer.echo(" \n Error: Passwords do not match", err=True)
        raise typer.Exit(code=1) 
    
    if len(new_login_password) < 8 :
        typer.echo("\n Password should have at least 8 characters")
        raise typer.Exit(code=1)
    
    typer.echo("")
    # derive the new master password and new encryption key from the new 
    # login password
    new_master = derive_master_password(new_login_password)
    new_key = derive_key(new_master, kdf_salt)
    
    
    # Step 4 - reset the password on the server
    
    with Spinner("Resetting password on server"):
        reset_result = api_client.reset_password_api(
            username=username,
            recovery_code=recovery_code,
            new_login_password=new_login_password
        )
        
    
    # Step 5 - log in with the new password to get a valid auth token
    with Spinner("Logging in with new password"):
        login_result = api_client.login(username, new_login_password)
    
    access_token = login_result["access_token"]
    refresh_token = login_result["refresh_token"]
    
   # -----------------------------------------------------------------------
    # Step 6 — re-encrypt every vault entry.
    #
    # old_key (from recovered_master) decrypts the current entries.
    # new_key (from new_master)       re-encrypts them.
    #
    # After this, normal logins with the new password produce new_master
    # → new_key and can read the vault without any recovery codes.
    # -----------------------------------------------------------------------
    typer.echo(" Re-encrypting your vault with the new password...\n")
    
    with Spinner("Re-encrypting vault entries"):
        count = _reencrypt_vault(
            access_token=access_token,
            refresh_token=refresh_token,
            old_key=old_key,
            new_key=new_key
        )
        
    
    # -----------------------------------------------------------------------
    # Step 7 — save the session with the NEW master password so everything
    #          is consistent for all future commands in this session
    # -----------------------------------------------------------------------
    save_session(
        access_token=access_token,
        refresh_token=refresh_token,
        kdf_salt=kdf_salt,
        master_password=new_master # new master matches new login password
    )
    
    remaining = reset_result.get("remaining_codes", 0)
    
    typer.echo("  Password reset successfully.")
    typer.echo(f"  {count} vault entr{'y' if count == 1 else 'ies'} re-encrypted.")
    typer.echo(f"  Logged in as {username}.")
    typer.echo(f"  {remaining} of 8 recovery code(s) remaining.\n")
    typer.echo("Run 'psamvault generate-codes' your other code is nullified")
            
    _warn_if_low(remaining)