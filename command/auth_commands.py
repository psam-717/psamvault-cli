import os
import typer

from crypto import derive_key, derive_master_password, decrypt_vek, encrypt_vek, generate_vek
import api_client
from config import DEFAULT_API_URL, generate_pepper, get_config, is_configured, save_config
from session import clear_session, is_logged_in, load_session, save_session

from spinner import Spinner

app = typer.Typer(
    name="auth",
    help="Manage your psamvault account - signup, login, and logout",
)

@app.callback(invoke_without_command=True)
def auth_help(ctx: typer.Context):
    if ctx.invoked_subcommand is None:
        typer.echo("""
  psamvault auth — account commands

  COMMAND    USAGE
  ─────────────────────────────────────────────────────
  signup     psamvault signup
  login      psamvault login
  logout     psamvault logout
  whoami     psamvault whoami
""")


@app.command()
def configure():
    """
    Set up psamvault on this machine.

    Run this once after installing psamvault. The API URL is pre-filled
    and a secure pepper is generated automatically — just press Enter
    to accept the defaults.

    \b
    Example:
      psamvault configure
      psamvault auth configure
    """
    typer.echo("\n psamvault setup\n")

    current_url = DEFAULT_API_URL
    if is_configured():
        current = get_config()
        pepper = current["PSAMVAULT_PEPPER"]
        current_url = current["PSAMVAULT_API_URL"]
        typer.echo(" Current configuration:")
        typer.echo(f"   API URL : {current_url}")
        typer.echo(f"   Pepper  : {pepper[:8]}...{pepper[-4:]}")
        typer.echo("")
        overwrite = typer.confirm(" Overwrite existing configuration?")
        if not overwrite:
            typer.echo("  Cancelled. Configuration unchanged. \n")
            raise typer.Exit()
        typer.echo("")

    typer.echo(" Press Enter to accept the default value shown in brackets.\n")
    api_url = typer.prompt(
        " API URL",
        default=current_url
    ).strip().rstrip("/")

    if not api_url.startswith("http"):
        typer.echo("\n  Error: API URL must start with http:// or https://", err=True)
        raise typer.Exit(code=1)

    # Pepper is generated automatically - no user input needed
    typer.echo(" Generating a secure pepper for your vault...")
    pepper = generate_pepper()

    typer.echo("")
    with Spinner("Verifying connection to server"):
        try:
            import httpx
            response = httpx.get(f"{api_url}/health", timeout=10)
            response.raise_for_status()
        except Exception:
            typer.echo(f"\n Warning: could not reach {api_url}/health")
            typer.echo(" The config was saved anyway - check the URL if the commands fail. \n")


    save_config(api_url, pepper)

    typer.echo(
        f"  Configuration saved to ~/.psamvault/config.env"
        f"\n  API URL : {api_url}"
        f"\n  Pepper  : {pepper[:8]}...{pepper[-4:]}\n"
    )
    typer.echo(
        "  Important: your pepper is stored in ~/.psamvault/config.env"
        "\n  Back up this file — losing it means losing access to your vault.\n"
    )
    typer.echo("  You are ready. Run  psamvault signup  to create your account.\n")


@app.command(name="config-show")
def config_show():
    """
    Show the current configuration.

    \b
    Example:
      psamvault config-show
      psamvault auth config-show
    """
    if not is_configured():
        typer.echo(
            "\n  Not configured. Run   psamvault configure  to set up. \n",
            err=True
        )
        raise typer.Exit(code=1)

    current = get_config()
    pepper = current["PSAMVAULT_PEPPER"]
    masked = f"{pepper[:8]}...{pepper[-4:]}"

    typer.echo(
        f"\n  API URL  :  {current['PSAMVAULT_API_URL']}"
        f"\n  Pepper   :  {masked}"
        f"\n  Config   :   ~/.psamvault/config.env\n"
    )



@app.command()
def signup():
    """
    Create a new psamvault account.

    \b
    Example:
      psamvault signup
      psamvault auth signup
    """
    if not is_configured():
        typer.echo(
            "\n  psamvault is not configured"
            "\n  Run 'psamvault configure'  first. \n",
            err=True
        )
        raise typer.Exit(code=1)

    typer.echo("Create your psamvault account\n")

    username = typer.prompt("Username")
    email = typer.prompt("Email")

    typer.echo(
        "\n Password requirements:"
        "\n  • At least 8 characters"
        "\n  • At least one uppercase letter"
        "\n  • At least one digit\n"
    )
    login_password = typer.prompt("Login password", hide_input=True)

    # Validate password rules client-side — the server accepts any 64-char hex master
    # password, so validation must happen here before the user sees a confusing error.
    errors = []
    if len(login_password) < 8:
        errors.append("  • at least 8 characters")
    if not any(c.isupper() for c in login_password):
        errors.append("  • at least one uppercase letter")
    if not any(c.isdigit() for c in login_password):
        errors.append("  • at least one digit")

    if errors:
        typer.echo("\n Error: Password does not meet the requirements:", err=True)
        for e in errors:
            typer.echo(e, err=True)
        typer.echo("", err=True)
        raise typer.Exit(code=1)

    login_password_confirm = typer.prompt("Confirm login password", hide_input=True)
    if login_password != login_password_confirm:
        typer.echo("Error: Passwords do not match", err=True)
        raise typer.Exit(code=1)

    typer.echo("")

    # Generate kdf_salt and VEK client-side so we can encrypt everything
    # in one atomic round-trip to the server.
    kdf_salt_bytes = os.urandom(32)
    kdf_salt_hex = kdf_salt_bytes.hex()
    vek = generate_vek()
    master = derive_master_password(login_password)
    login_key = derive_key(master, kdf_salt_hex)
    encrypted_vek_hex, vek_iv_hex = encrypt_vek(login_key, vek)

    try:
        with Spinner("Creating your account"):
            result = api_client.signup(
                username, email, master,
                kdf_salt=kdf_salt_hex,
                encrypted_vek=encrypted_vek_hex,
                vek_iv=vek_iv_hex,
            )
    except typer.Exit:
        raise
    except Exception as e:
        typer.echo(f"\n Error: Could not reach the server. Is it running?\n{e}", err=True)
        raise typer.Exit(code=1)

    typer.echo(f"\n Account created for {result['username']}.")
    typer.echo(
        "\n  Important: your login password also protects your vault encryption."
        "\n  If you lose it, your vault cannot be recovered. Store it safely.\n"
    )
    typer.echo("Run  'psamvault login'  to start using your vault.")


@app.command()
def login():
    """
    Log in to your psamvault account.

    \b
    Example:
      psamvault login
      psamvault auth login
    """
    if not is_configured():
        typer.echo(
            "\n  psamvault is not configured"
            "\n  Run  'psamvault configure'  first. \n",
            err=True
        )
        raise typer.Exit(code=1)

    if is_logged_in():
        overwrite = typer.confirm(
            "You are already logged in. Log in as a different user?"
        )
        if not overwrite:
            raise typer.Exit()

    typer.echo("Log in to psamvault\n")

    username = typer.prompt("Username")
    login_password = typer.prompt("Login password", hide_input=True)

    typer.echo("")

    try:
        with Spinner("Authenticating"):
            master = derive_master_password(login_password)
            result = api_client.login(username, master)
    except typer.Exit:
        raise
    except Exception as e:
        typer.echo(f"Error: Could not reach the server. Is it running?\n{e}", err=True)
        raise typer.Exit(code=1)

    # Derive the login key locally and use it to decrypt the VEK from the server.
    # The VEK is stored in the session so vault commands can use it directly
    # without re-deriving or prompting the user again.
    login_key = derive_key(master, result["kdf_salt"])
    vek = decrypt_vek(login_key, result["encrypted_vek"], result["vek_iv"])

    save_session(
        access_token=result["access_token"],
        refresh_token=result["refresh_token"],
        kdf_salt=result["kdf_salt"],
        vek=vek.hex(),
        encrypted_vek=result["encrypted_vek"],
        vek_iv=result["vek_iv"],
    )

    typer.echo(f"\n Logged in as {username}")
    typer.echo(" Your vault is ready. Try 'psamvault list' to see your entries.")

    if not result["has_recovery_codes"]:
        typer.echo(
            "\n  ⚠  You have no recovery codes set up."
            "\n     If you forget your password, you will not be able to recover your account."
            "\n\n  → Run  psamvault generate-codes  now to protect your account.\n"
        )

    _check_for_backup_after_login()


@app.command()
def migrate():
    """
    One-time account migration to the new authentication scheme.

    Run this once after updating psamvault. It re-hashes your password
    using the new master-password scheme (HMAC + Argon2) and logs you in.
    Your vault data is preserved — nothing is deleted from the server.

    After migration, regenerate your recovery codes with:
      psamvault generate-codes

    \b
    Example:
      psamvault migrate
    """
    if not is_configured():
        typer.echo(
            "\n  psamvault is not configured."
            "\n  Run  'psamvault configure'  first.\n",
            err=True
        )
        raise typer.Exit(code=1)

    typer.echo("\n psamvault account migration\n")
    typer.echo(
        "  This upgrades your account to the new authentication scheme."
        "\n  You will need your current login password.\n"
    )

    username = typer.prompt(" Username")
    old_password = typer.prompt(" Current login password", hide_input=True)

    typer.echo("")

    master = derive_master_password(old_password)

    with Spinner("Migrating account"):
        try:
            api_client.migrate_password(username, old_password, master)
        except typer.Exit:
            raise
        except Exception as e:
            typer.echo(f"\n Error: Could not reach the server. Is it running?\n{e}", err=True)
            raise typer.Exit(code=1)

    typer.echo("  ✓ Account migrated.\n")

    # Log in automatically with the new credentials so the user is ready to go.
    typer.echo("  Logging you in...\n")
    with Spinner("Authenticating"):
        try:
            result = api_client.login(username, master)
        except typer.Exit:
            raise
        except Exception as e:
            typer.echo(f"\n Error: Login after migration failed.\n{e}", err=True)
            raise typer.Exit(code=1)

    login_key = derive_key(master, result["kdf_salt"])
    vek = decrypt_vek(login_key, result["encrypted_vek"], result["vek_iv"])

    save_session(
        access_token=result["access_token"],
        refresh_token=result["refresh_token"],
        kdf_salt=result["kdf_salt"],
        vek=vek.hex(),
        encrypted_vek=result["encrypted_vek"],
        vek_iv=result["vek_iv"],
    )

    typer.echo(f"  ✓ Logged in as {username}.")
    typer.echo("  ✓ Your vault is intact.\n")
    typer.echo(
        "  ⚠  Your old recovery codes are no longer valid."
        "\n  → Run  psamvault generate-codes  now to set up new ones.\n"
    )


@app.command()
def logout():
    """
    Log out and clear your local session.

    Revokes the refresh token on the server and deletes the local session
    file. Your encrypted vault data remains safely stored on the server.

    \b
    Example:
      psamvault logout
      psamvault auth logout
    """
    if not is_logged_in():
        typer.echo("You are not logged in.")
        raise typer.Exit()

    confirm = typer.confirm("Are you sure want to log out?")
    if not confirm:
        typer.echo("Cancelled")
        raise typer.Exit()

    typer.echo("")
    session = load_session()

    try:
        with Spinner("Logging out"):
            api_client.logout(session["access_token"], session["refresh_token"])
    except Exception: # pylint: disable=broad-exception-caught
        # even if the server fails the session will still be cleared
        pass

    clear_session()
    typer.echo(" Logged out. Your vault data remains encrypted on the server")


@app.command()
def whoami():
    """
    Show the currently logged in user.

    Displays your username and email without hitting the vault.
    Useful for confirming which account is active in this session.

    \b
    Example:
      psamvault whoami
      psamvault auth whoami
    """
    if not is_logged_in():
        typer.echo(" You are not logged in. Run psamvault login first")
        raise typer.Exit()

    session = load_session()

    with Spinner("Fetching profile"):
        result = api_client.me(session["access_token"])

    typer.echo(
        f"\n Logged in as: {result['username']} ({result['email']})"
    )


# ── Import detection ────────────────────────────────────────────────────────────


def _check_for_backup_after_login() -> None:
    """After a successful login, check if a backup file exists and offer to import."""
    from pathlib import Path

    desktop = Path.home() / "Desktop"
    if not desktop.exists():
        return

    backups = sorted(
        desktop.glob("psamvault-backup-*.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )

    if not backups:
        return

    latest = backups[0]
    typer.echo(
        f"\n  📂 Found a psamvault backup file: {latest.name}"
    )
    should_import = typer.confirm(
        " Would you like to import your saved credentials now?"
    )

    if should_import:
        import subprocess
        import sys
        typer.echo("")
        subprocess.run([sys.argv[0], "import", str(latest)])