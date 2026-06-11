"""
Dashboard screen — the main vault list with sidebar, search, and quick actions.

Uses DataTable for a clean table-like layout with invisible borders.
"""

from __future__ import annotations

from textual import on
from textual.app import ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.reactive import reactive
from textual.screen import Screen
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    LoadingIndicator,
    Static,
)

from tui.state import DecryptedEntry, DecryptedApiKey
from tui.screens.detail import EntryDetail

# Column keys used to store the original entry object on each row
ROW_KEY = "entry"


class Dashboard(Screen):
    """Main vault dashboard with a table-driven entry list."""

    CSS = """
    Dashboard {
        layout: grid;
        grid-size: 1;
        grid-rows: auto 1fr auto;
    }

    #dash-header {
        height: 3;
        padding: 0 1 0 2;
        background: $primary-background;
    }
    #dash-header > Horizontal {
        height: 100%;
        align: center top;
    }
    #dash-title {
        text-style: bold;
        width: 30;
    }
    #dash-stats {
        width: 40;
        content-align: right middle;
    }

    /* ── main content area ─────────────────────────── */
    #dash-body {
        height: 1fr;
    }

    /* sidebar */
    #dash-sidebar {
        width: 18;
        height: 100%;
        border-right: solid $border;
        background: $surface;
        padding: 1 0;
    }
    #dash-sidebar > Static {
        padding: 0 1 0 2;
        margin-bottom: 1;
    }
    .sidebar-item {
        padding: 0 1 0 2;
        height: 3;
        border: none;
        text-align: left;
        background: transparent;
    }
    .sidebar-item:hover {
        background: $accent 20%;
    }
    .sidebar-item.selected {
        background: $accent 30%;
    }
    .sidebar-item:focus {
        border: none;
    }

    /* list area — DataTable takes full height */
    #dash-list-area {
        height: 100%;
        padding: 0 1;
    }

    #entry-table {
        height: 1fr;
        min-height: 3;
    }

    /* DataTable: no visible borders, subtle cursor */
    #entry-table > .datatable--header {
        background: $surface;
        color: $text;
        text-style: bold;
        border-bottom: solid $border;
    }
    #entry-table > .datatable--cursor {
        background: $accent 35%;
        color: $text;
    }
    #entry-table > .datatable--hover {
        background: $accent 20%;
    }

    /* Search bar at the bottom */
    #search-wrapper {
        height: auto;
        border-top: solid $border;
        padding: 1 0 0 0;
    }
    #search-input {
        margin: 0;
    }
    #search-count {
        height: 1;
        color: $text-disabled;
        text-style: italic;
        padding: 0 0 0 1;
    }

    #loading-wrapper {
        height: 3;
    }

    .empty-label {
        width: 100%;
        height: 3;
        text-align: center;
        color: $text-disabled;
        padding: 1;
    }
    """

    BINDINGS = [
        ("r", "refresh", "Refresh"),
        ("/", "focus_search", "Search"),
        ("q", "app.quit", "Quit"),
    ]

    filter_mode: reactive[str] = reactive("all")

    def __init__(self) -> None:
        super().__init__()
        self._all_items: list[tuple[str, DecryptedEntry | DecryptedApiKey]] = []
        self._filtered_items: list[tuple[str, DecryptedEntry | DecryptedApiKey]] = []
        self._row_data: dict[str, tuple[str, DecryptedEntry | DecryptedApiKey]] = {}
        self._loaded = False
        self._columns_set = False

    # ── compose ────────────────────────────────────────────────────────────

    def compose(self) -> ComposeResult:
        yield Header()

        with Container(id="dash-header"):
            with Horizontal():
                yield Static("🔐 psamvault", id="dash-title")
                yield Static("", id="dash-stats")

        with Horizontal(id="dash-body"):
            with Vertical(id="dash-sidebar"):
                yield Static("[bold]Categories[/bold]")
                yield Button("All", id="filter-all", classes="sidebar-item selected")
                yield Button("Vault", id="filter-vault", classes="sidebar-item")
                yield Button("API Keys", id="filter-ak", classes="sidebar-item")

            with Vertical(id="dash-list-area"):
                with Container(id="loading-wrapper"):
                    yield LoadingIndicator()
                yield DataTable(id="entry-table", show_cursor=True, zebra_stripes=True, cell_padding=2)
                with Vertical(id="search-wrapper"):
                    yield Input(placeholder="Search entries…  (press / to focus)", id="search-input")
                    yield Static("", id="search-count")

        yield Footer()

    # ── mount ──────────────────────────────────────────────────────────────

    def on_mount(self) -> None:
        self._load_data()

    # ── data loading ───────────────────────────────────────────────────────

    def _load_data(self) -> None:
        self.query_one(LoadingIndicator).display = True
        table = self.query_one("#entry-table", DataTable)
        table.clear()
        self._row_data.clear()
        self.set_timer(0.05, self._do_fetch)

    def _do_fetch(self) -> None:
        try:
            state = self.app.state
            state.refresh_vault()
            state.refresh_api_keys()
            state.load_profile()
        except Exception:
            pass
        self._build_items()
        self._render_list()
        self.query_one(LoadingIndicator).display = False
        self._loaded = True
        self._update_stats()

    def _build_items(self) -> None:
        self._all_items = []
        for entry in self.app.state.vault_entries:
            self._all_items.append(("vault", entry))
        for ak in self.app.state.api_keys:
            self._all_items.append(("ak", ak))
        self._apply_filter()

    def _apply_filter(self) -> None:
        match self.filter_mode:
            case "vault":
                self._filtered_items = [(t, e) for t, e in self._all_items if t == "vault"]
            case "ak":
                self._filtered_items = [(t, e) for t, e in self._all_items if t == "ak"]
            case _:
                self._filtered_items = list(self._all_items)

        search = self.query_one("#search-input", Input).value.lower().strip()
        if search:
            self._filtered_items = [
                (t, e) for t, e in self._filtered_items
                if self._item_matches(e, search)
            ]

    def _item_matches(self, item: DecryptedEntry | DecryptedApiKey, query: str) -> bool:
        if isinstance(item, DecryptedEntry):
            return (
                query in item.site_name.lower()
                or query in item.username.lower()
                or query in item.username_hint.lower()
            )
        return (
            query in item.name.lower()
            or query in item.service.lower()
            or query in item.service_hint.lower()
        )

    def _render_list(self) -> None:
        table = self.query_one("#entry-table", DataTable)
        table.clear()

        # Set up columns once
        if not self._columns_set:
            col_keys = table.add_columns("Name", "Username / Service", "URL / Type")
            col_name = table.columns[col_keys[0]]
            col_user = table.columns[col_keys[1]]
            col_url = table.columns[col_keys[2]]
            col_name.auto_width = False
            col_name.width = 40
            col_user.auto_width = False
            col_user.width = 48
            col_url.auto_width = False
            col_url.width = 44
            self._columns_set = True

        if not self._filtered_items:
            table.show_cursor = False
            return

        table.show_cursor = True

        for kind, item in self._filtered_items:
            if kind == "vault":
                entry: DecryptedEntry = item  # type: ignore
                name = entry.site_name
                detail = entry.username_hint or entry.username or "—"
                url = entry.login_url or "—"
            else:
                ak: DecryptedApiKey = item  # type: ignore
                name = ak.name
                detail = ak.service_hint or ak.service or "—"
                url = "🔑  API Key"

            row_key = table.add_row(name, detail, url)
            self._row_data[str(row_key)] = (kind, item)

        self._update_search_count()

    def _update_stats(self) -> None:
        s = self.app.state
        profile = s.profile
        user_part = f" 👤 {profile.username}" if profile else ""
        self.query_one("#dash-stats", Static).update(
            f"{s.entry_count} vault · {s.api_key_count} keys{user_part}"
        )
        self._update_search_count()

    def _update_search_count(self) -> None:
        total = len(self._all_items)
        shown = len(self._filtered_items)
        label = self.query_one("#search-count", Static)
        if shown < total:
            label.update(f"  {shown} of {total} entries")
        elif total == 0:
            label.update("  No entries")
        else:
            label.update(f"  {total} entries")

    # ── search ────────────────────────────────────────────────────────────

    def action_focus_search(self) -> None:
        self.query_one("#search-input", Input).focus()

    @on(Input.Changed, "#search-input")
    def _on_search(self) -> None:
        if self._loaded:
            self._apply_filter()
            self._render_list()

    # ── sidebar filter ─────────────────────────────────────────────────────

    def _select_filter(self, selected_id: str) -> None:
        for fid in ("filter-all", "filter-vault", "filter-ak"):
            self.query_one(f"#{fid}", Button).classes = "sidebar-item"
        self.query_one(f"#{selected_id}", Button).classes = "sidebar-item selected"

    @on(Button.Pressed, "#filter-all")
    def _on_filter_all(self) -> None:
        self._select_filter("filter-all")
        self.filter_mode = "all"
        if self._loaded:
            self._apply_filter()
            self._render_list()

    @on(Button.Pressed, "#filter-vault")
    def _on_filter_vault(self) -> None:
        self._select_filter("filter-vault")
        self.filter_mode = "vault"
        if self._loaded:
            self._apply_filter()
            self._render_list()

    @on(Button.Pressed, "#filter-ak")
    def _on_filter_ak(self) -> None:
        self._select_filter("filter-ak")
        self.filter_mode = "ak"
        if self._loaded:
            self._apply_filter()
            self._render_list()

    # ── open entry detail via row select ───────────────────────────────────

    @on(DataTable.RowSelected, "#entry-table")
    def _on_row_selected(self, event: DataTable.RowSelected) -> None:
        key = str(event.row_key)
        metadata = self._row_data.get(key)
        if metadata is None:
            return
        kind, item = metadata

        def _on_return(result: object) -> None:
            """Returned from detail screen — re-render from cache (fast)."""
            self._load_data()

        self.app.push_screen(
            EntryDetail(entry=item) if kind == "vault" else EntryDetail(api_key=item),
            callback=_on_return,
        )

    # ── refresh ────────────────────────────────────────────────────────────

    def action_refresh(self) -> None:
        """Force a full refresh from the server."""
        self.app.state._vault_needs_refresh = True
        self.app.state._api_keys_needs_refresh = True
        self._load_data()