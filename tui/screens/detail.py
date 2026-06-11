"""Entry detail screen — view, copy, reveal, delete."""

from __future__ import annotations

import webbrowser

import pyperclip
from textual import on
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, ScrollableContainer
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Label, Static, RichLog

from tui.state import DecryptedEntry, DecryptedApiKey


class EntryDetail(Screen):
    """Full detail view for a vault entry or API key."""

    CSS = """
    EntryDetail {
        layout: grid;
        grid-size: 1;
        grid-rows: auto 1fr auto;
    }

    #detail-body {
        height: 100%;
        padding: 1 2;
    }

    #detail-title {
        text-style: bold;
        padding-bottom: 1;
        border-bottom: solid $border;
        margin-bottom: 1;
    }

    .field-row {
        height: 3;
        padding: 0 1;
    }

    .field-label {
        width: 14;
        text-style: bold;
    }

    .field-value {
        width: 1fr;
    }

    #password-reveal {
        visibility: hidden;
    }
    #password-reveal.revealed {
        visibility: visible;
    }

    #detail-actions {
        height: 3;
        padding: 0 1;
        border-top: solid $border;
        align: center middle;
    }
    #detail-actions Button {
        margin: 0 1;
    }

    .password-hidden {
        color: $text-disabled;
    }
    """

    BINDINGS = [
        ("escape", "go_back", "Back"),
        ("c", "copy_password", "Copy Password"),
        ("o", "open_url", "Open URL"),
        ("d", "delete", "Delete"),
    ]

    def __init__(
        self,
        entry: DecryptedEntry | None = None,
        api_key: DecryptedApiKey | None = None,
    ) -> None:
        super().__init__()
        self._entry = entry
        self._api_key = api_key
        self._password_shown = False

    # ── compose ────────────────────────────────────────────────────────────

    def compose(self) -> ComposeResult:
        yield Header()
        yield ScrollableContainer(id="detail-body")
        yield Static(id="detail-actions")

    def on_mount(self) -> None:
        body = self.query_one("#detail-body", ScrollableContainer)

        if self._entry:
            self.sub_title = self._entry.site_name
            body.mount(
                Static(
                    f"[bold]{self._entry.site_name}[/bold]",
                    id="detail-title",
                )
            )
            body.mount(
                Label(
                    f"[bold]URL:[/bold]     {self._entry.login_url or '—'}",
                    classes="field-row",
                )
            )
            body.mount(
                Label(
                    f"[bold]Username:[/bold] {self._entry.username or self._entry.username_hint or '—'}",
                    classes="field-row",
                )
            )
            body.mount(
                Label(
                    "[bold]Password:[/bold]  ••••••••••••",
                    classes="field-row password-hidden",
                    id="password-field",
                )
            )
            if self._entry.notes:
                body.mount(
                    Label(
                        f"[bold]Notes:[/bold]    {self._entry.notes}",
                        classes="field-row",
                    )
                )

        elif self._api_key:
            self.sub_title = self._api_key.name
            body.mount(
                Static(
                    f"[bold]{self._api_key.name}[/bold]  🔑",
                    id="detail-title",
                )
            )
            body.mount(
                Label(
                    f"[bold]Service:[/bold] {self._api_key.service or self._api_key.service_hint or '—'}",
                    classes="field-row",
                )
            )
            body.mount(
                Label(
                    "[bold]API Key:[/bold]  ••••••••••••",
                    classes="field-row password-hidden",
                    id="password-field",
                )
            )
            if self._api_key.notes:
                body.mount(
                    Label(
                        f"[bold]Notes:[/bold]   {self._api_key.notes}",
                        classes="field-row",
                    )
                )

        # Actions bar — mount buttons directly on the already-composed Static
        actions = self.query_one("#detail-actions", Static)
        actions.mount(Button("📋 Copy Password", variant="primary", id="copy-btn"))
        if self._entry and self._entry.login_url:
            actions.mount(Button("🌐 Open in Browser", id="open-btn"))
        actions.mount(Button("👁 Reveal", id="reveal-btn"))
        actions.mount(Button("🗑 Delete", variant="error", id="delete-btn"))
        actions.mount(Button("← Back", id="back-btn"))

    # ── actions ────────────────────────────────────────────────────────────

    def action_go_back(self) -> None:
        self.dismiss()

    def action_copy_password(self) -> None:
        self._do_copy()

    def action_open_url(self) -> None:
        self._do_open()

    def action_delete(self) -> None:
        self._do_delete()

    # ── button handlers ────────────────────────────────────────────────────

    @on(Button.Pressed, "#copy-btn")
    def _on_copy(self) -> None:
        self._do_copy()

    @on(Button.Pressed, "#open-btn")
    def _on_open(self) -> None:
        self._do_open()

    @on(Button.Pressed, "#reveal-btn")
    def _on_reveal(self) -> None:
        self._toggle_reveal()

    @on(Button.Pressed, "#delete-btn")
    def _on_delete(self) -> None:
        self._do_delete()

    @on(Button.Pressed, "#back-btn")
    def _on_back(self) -> None:
        self.dismiss()

    # ── implementations ────────────────────────────────────────────────────

    def _do_copy(self) -> None:
        if self._entry:
            pyperclip.copy(self._entry.password)
        elif self._api_key:
            pyperclip.copy(self._api_key.api_key)
        self.notify("📋 Copied to clipboard!", timeout=2)

    def _do_open(self) -> None:
        if self._entry and self._entry.login_url:
            url = self._entry.login_url
            if not url.startswith("http"):
                url = "https://" + url
            webbrowser.open(url)
            self.notify(f"🌐 Opened {url}", timeout=2)

    def _toggle_reveal(self) -> None:
        pw_field = self.query_one("#password-field", Label)
        if self._password_shown:
            pw_field.update("[bold]Password:[/bold]  ••••••••••••")
            pw_field.classes = "field-row password-hidden"
            self._password_shown = False
        else:
            secret = (
                self._entry.password if self._entry else self._api_key.api_key
            )
            pw_field.update(f"[bold]Password:[/bold]  {secret}")
            pw_field.classes = "field-row"
            self._password_shown = True

    def _do_delete(self) -> None:
        label = self._entry.site_name if self._entry else self._api_key.name
        kind = "vault entry" if self._entry else "API key"

        from textual.screen import ModalScreen

        class ConfirmDelete(ModalScreen[bool]):
            CSS = """
            ConfirmDelete {
                align: center middle;
            }
            #confirm-box {
                width: 40;
                height: auto;
                padding: 2 3;
                border: solid $error;
                background: $surface;
            }
            #btn-row {
                align: center middle;
                height: 3;
                margin-top: 1;
            }
            """
            def compose(self):
                yield Static(
                    f"Delete [bold]{label}[/bold]?\n\nThis cannot be undone.",
                    id="confirm-box",
                )
                with Horizontal(id="btn-row"):
                    yield Button("Yes, delete", variant="error", id="yes-btn")
                    yield Button("Cancel", variant="primary", id="no-btn")

            @on(Button.Pressed, "#yes-btn")
            def _yes(self):
                self.dismiss(True)

            @on(Button.Pressed, "#no-btn")
            def _no(self):
                self.dismiss(False)

        def _on_confirm(result: bool) -> None:
            if not result:
                return
            if self._entry:
                err = self.app.state.delete_entry(self._entry.site_name)
            else:
                err = self.app.state.delete_api_key(self._api_key.name)
            if err:
                self.notify(f"❌ Delete failed: {err}", severity="error", timeout=5)
            else:
                self.notify(f"🗑 Deleted {label}", timeout=3)
                self.dismiss()

        self.app.push_screen(ConfirmDelete(), _on_confirm)