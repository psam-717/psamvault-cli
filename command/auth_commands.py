import typer

from crypto import derive_master_password
import api_client
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
""")

@app.command()
def signup():
    """
    Create a new psamvault account.
 
    You only need one password. Your vault encryption key is derived
    automatically from your login password — no master password to remember.
    """
    typer.echo("Create your psamvault account\n")
    
    username = typer.prompt("Username")
    email = typer.prompt("Email")
    
    login_password = typer.prompt("Login password", hide_input=True)
    login_password_confirm = typer.prompt("Confirm login password", hide_input=True)
    if login_password != login_password_confirm:
        typer.echo("Error: Passwords do not match", err=True)
        raise typer.Exit(code=1)

    typer.echo("")

    
    try:
        with Spinner("Creating your account"):
            result = api_client.signup(username, email, login_password)
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
 
    Your vault encryption key is derived automatically from your login
    password — no separate master password required.
    
    \b
    Example:
      psamvault login
      psamvault auth login
    """
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
        with Spinner("Authentication..."):
            result = api_client.login(username, login_password)
    except Exception as e:
        typer.echo(f"Error: Could not reach the server. Is it running?\n{e}", err=True)
        raise typer.Exit(code=1)
    
    # derive the master password locally from the login password
    # this is never sent to the server - it stays on this machine only
    master_password = derive_master_password(login_password)
    
    save_session(
        access_token=result["access_token"],
        refresh_token=result["refresh_token"],
        kdf_salt=result["kdf_salt"],
        master_password=master_password
    )
    
    typer.echo(f"\n Logged in as {username}")
    typer.echo("Your vault is ready. Try 'psamvault list' to see your entries.")
    
    
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
    