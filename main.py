from config import load_config
load_config()
import importlib.metadata
from typing import Annotated, Optional
import typer

from command.auth_commands import app as auth_app
from command.vault_commands import app as vault_app
from command.recovery_commands import app as recovery_app
from command.api_key_commands import app as apikey_app
from update_check import start_update_check, print_update_notice



app = typer.Typer(
    name="psamvault",
    help=(
        "psamvault — a secure password vault for the terminal.\n\n"
        "Your credentials are encrypted locally before being sent to the server.\n"
        "The server never sees your plaintext passwords.\n\n"
        "Run  psamvault auth  or  psamvault vault  to see grouped commands.\n"
        "Or use the short forms directly — psamvault login, psamvault add, etc."         
    ),
    no_args_is_help=True,
    result_callback= lambda result, **kwargs: print_update_notice() # runs after every command
)


def _version_callback(value: bool) -> None:
    if value:
        try:
            version = importlib.metadata.version("psamvault")
        except importlib.metadata.PackageNotFoundError:
            import tomllib
            from pathlib import Path
            pyproject = Path(__file__).parent / "pyproject.toml"
            with open(pyproject, "rb") as f:
                version = tomllib.load(f)["project"]["version"]
        typer.echo(f"psamvault {version}")
        raise typer.Exit()


@app.callback()
def _main(
    version: Annotated[
        Optional[bool],
        typer.Option("--version", "-V", callback=_version_callback, is_eager=True, help="Show version and exit."),
    ] = None,
) -> None:
    # Kick off the update check in the background - won't block the command
    start_update_check()


# register auth commands
app.add_typer(auth_app, name="auth", invoke_without_command=True)

# register vault commands
app.add_typer(vault_app, name="vault", invoke_without_command=True)

# register recovery commands
app.add_typer(recovery_app, name="recovery", invoke_without_command=True)

# register ak commands
app.add_typer(apikey_app, name="ak", invoke_without_command=True)

from command.auth_commands import login, logout, signup, whoami, config_show, configure
from command.vault_commands import add, delete, generate, get, list_entries, update
from command.recovery_commands import generate_codes, remaining_codes, recover
from command.api_key_commands import ak_add, ak_get, ak_delete, ak_list, ak_update

app.command("configure")(configure)
app.command("config-show")(config_show)
app.command("signup")(signup)
app.command("login")(login)
app.command("logout")(logout)
app.command("whoami")(whoami)
app.command("add")(add)
app.command("get")(get)
app.command("list")(list_entries)
app.command("update")(update)
app.command("delete")(delete)
app.command("generate")(generate)
app.command("generate-codes")(generate_codes)
app.command("remaining-codes")(remaining_codes)
app.command("recover")(recover)
app.command("ak-add")(ak_add)
app.command("ak-get")(ak_get)
app.command("ak-list")(ak_list)
app.command("ak-update")(ak_update)
app.command("ak-delete")(ak_delete)


if __name__ == "__main__":
    app()