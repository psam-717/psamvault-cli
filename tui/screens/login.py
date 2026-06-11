"""Login / signup screen for the psamvault TUI."""

from __future__ import annotations

from textual import on
from textual.app import ComposeResult
from textual.containers import Center, Middle, Vertical
from textual.screen import Screen
from textual.widgets import Button, Input, Label, Static


class LoginScreen(Screen):
    """Login or sign up to the vault."""

    CSS = """
    LoginScreen {
        align: center middle;
    }

    #login-box {
        width: 50;
        height: auto;
        padding: 2 3;
        border: solid $primary;
        background: $surface;
    }

    #login-box > Label {
        text-align: center;
        width: 100%;
    }

    #login-title {
        text-style: bold;
        padding-bottom: 1;
    }

    #login-error {
        color: $error;
        text-align: center;
        width: 100%;
        padding: 0 1;
        display: none;
    }

    #login-error.visible {
        display: block;
    }

    Input {
        margin-bottom: 1;
    }

    .button-row {
        height: 3;
        align: center middle;
        margin-top: 1;
    }

    Button {
        margin: 0 1;
    }
    """

    def compose(self) -> ComposeResult:
        with Center():
            with Middle():
                with Vertical(id="login-box"):
                    yield Label("🔐 psamvault", id="login-title")
                    yield Label("", id="login-error")
                    yield Input(
                        placeholder="Username",
                        id="username-input",
                    )
                    yield Input(
                        placeholder="Password",
                        password=True,
                        id="password-input",
                    )
                    with Center():
                        with Vertical(classes="button-row"):
                            yield Button("Login", variant="primary", id="login-btn")
                            yield Button("Sign Up", variant="default", id="signup-btn")
                            yield Button("Quit", variant="error", id="quit-btn")

    def on_mount(self) -> None:
        self.query_one("#username-input", Input).focus()

    @on(Input.Submitted, "#password-input")
    def _on_password_submitted(self) -> None:
        self._do_login()

    @on(Button.Pressed, "#login-btn")
    def _on_login_click(self) -> None:
        self._do_login()

    @on(Button.Pressed, "#signup-btn")
    def _on_signup(self) -> None:
        username = self.query_one("#username-input", Input).value.strip()
        password = self.query_one("#password-input", Input).value
        if not username or not password:
            self._show_error("Username and password required.")
            return
        self.app.push_screen(
            SignupScreen(username, password),
            callback=lambda _: self._check_login(),
        )

    @on(Button.Pressed, "#quit-btn")
    def _on_quit(self) -> None:
        self.app.exit()

    def _show_error(self, msg: str) -> None:
        err = self.query_one("#login-error", Label)
        err.update(msg)
        err.classes = "visible"

    def _do_login(self) -> None:
        username = self.query_one("#username-input", Input).value.strip()
        password = self.query_one("#password-input", Input).value
        if not username or not password:
            self._show_error("Username and password required.")
            return

        err_msg = self.app.state.login(username, password)
        if err_msg:
            self._show_error(f"Login failed: {err_msg}")
        else:
            self._check_login()

    def _check_login(self) -> None:
        if self.app.state.is_authenticated:
            self.dismiss(True)


class SignupScreen(Screen):
    """Sign-up form (inline, no email/confirm fields yet)."""

    CSS = """
    SignupScreen {
        align: center middle;
    }

    #signup-box {
        width: 50;
        height: auto;
        padding: 2 3;
        border: solid $primary;
        background: $surface;
    }

    #signup-box > Label {
        text-align: center;
        width: 100%;
    }

    #signup-error {
        color: $error;
        text-align: center;
        width: 100%;
        display: none;
    }
    #signup-error.visible {
        display: block;
    }

    Input {
        margin-bottom: 1;
    }
    """

    def __init__(self, username: str, password: str) -> None:
        super().__init__()
        self._pre_username = username
        self._pre_password = password

    def compose(self) -> ComposeResult:
        with Center():
            with Middle():
                with Vertical(id="signup-box"):
                    yield Label("🔐 Create Account", id="signup-title")
                    yield Label("", id="signup-error")
                    yield Input(value=self._pre_username, placeholder="Username", id="su-username")
                    yield Input(placeholder="Email", id="su-email")
                    yield Input(value=self._pre_password, placeholder="Password", password=True, id="su-password")
                    yield Input(placeholder="Confirm password", password=True, id="su-confirm")
                    with Center():
                        yield Button("Sign Up", variant="primary", id="su-btn")
                        yield Button("Back", variant="default", id="su-back")

    @on(Button.Pressed, "#su-btn")
    def _do_signup(self) -> None:
        username = self.query_one("#su-username", Input).value.strip()
        email = self.query_one("#su-email", Input).value.strip()
        password = self.query_one("#su-password", Input).value
        confirm = self.query_one("#su-confirm", Input).value

        if not username or not email or not password:
            self._show_error("All fields required.")
            return
        if password != confirm:
            self._show_error("Passwords do not match.")
            return

        # Signup via the existing CLI code path — just login afterwards
        from api_client import signup
        from crypto import (
            derive_master_password,
            derive_key,
            generate_vek,
            encrypt_vek,
        )
        import secrets

        try:
            kdf_salt = secrets.token_hex(16)
            master = derive_master_password(password)
            login_key = bytes(derive_key(master, kdf_salt))

            vek = generate_vek()
            encrypted_vek, vek_iv = encrypt_vek(login_key, vek)

            signup(
                username=username,
                email=email,
                login_password=password,
                kdf_salt=kdf_salt,
                encrypted_vek=encrypted_vek,
                vek_iv=vek_iv,
            )
            # Auto-login after signup
            err = self.app.state.login(username, password)
            if err:
                self._show_error(f"Signup OK but login failed: {err}")
            else:
                self.app.state.load_profile()
                self.dismiss(True)
        except Exception as exc:
            self._show_error(str(exc))

    @on(Button.Pressed, "#su-back")
    def _go_back(self) -> None:
        self.dismiss(False)

    def _show_error(self, msg: str) -> None:
        err = self.query_one("#signup-error", Label)
        err.update(msg)
        err.classes = "visible"