"""
psamvault TUI — a Textual-powered terminal UI for your password vault.

Usage:
    psamvault tui
"""

from __future__ import annotations

from textual.app import App, ComposeResult
from textual.screen import Screen
from textual.widgets import Footer, Header

from tui.screens.dashboard import Dashboard
from tui.screens.detail import EntryDetail
from tui.screens.login import LoginScreen
from tui.state import AppState, SessionExpired


class PsamvaultTUI(App):
    """The psamvault Textual TUI application."""

    CSS = """
    Screen {
        background: $surface;
    }
    """

    SCREENS = {
        "login": LoginScreen,
        "dashboard": Dashboard,
        "entrydetail": EntryDetail,
    }

    TITLE = "psamvault"
    SUB_TITLE = "Secure Password Vault"

    BINDINGS = [
        ("ctrl+q", "app.quit", "Quit"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.state = AppState()

    def on_mount(self) -> None:
        """Start with login or dashboard depending on saved session."""
        if self.state.load_existing_session():
            self._try_refresh_and_enter()
        else:
            self.push_screen("login", callback=self._on_login_result)

    def _try_refresh_and_enter(self) -> None:
        """Refresh the access token, then load the dashboard."""
        try:
            self.state.refresh_session()
            self.state.refresh_vault()
            self.state.refresh_api_keys()
            self.state.load_profile()
            self.push_screen("dashboard")
        except SessionExpired:
            self.push_screen("login", callback=self._on_login_result)

    def _on_login_result(self, result: bool | None) -> None:
        if result:
            self._try_refresh_and_enter()
        else:
            self.app.exit()


def run_tui() -> None:
    """Entry point for ``psamvault tui``."""
    app = PsamvaultTUI()
    app.run()