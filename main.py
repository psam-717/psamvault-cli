import typer

from command.auth_commands import app as auth_app
from command.vault_commands import app as vault_app




app = typer.Typer(
    name="psamvault",
    help="psamvault - a secure password vault for the terminal",
    no_args_is_help=True
)


# register auth commands
app.add_typer(auth_app, name="auth", invoke_without_command=True)

# register vault commands
app.add_typer(vault_app, name="vault", invoke_without_command=True)

from command.auth_commands import login, logout, signup
from command.vault_commands import add, delete, generate, get, list_entries, update


app.command("signup")(signup)
app.command("login")(login)
app.command("logout")(logout)
app.command("add")(add)
app.command("get")(get)
app.command("list")(list_entries)
app.command("update")(update)
app.command("delete")(delete)
app.command("generate")(generate)


if __name__ == "__main__":
    app()