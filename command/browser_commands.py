import re
import time
import typer

import api_client
from crypto import decrypt_credentials
from session import load_session

app = typer.Typer(name="browser", help="Browser automation commands")


@app.command(name="open")
def open_site(
    site: str = typer.Argument(..., help="Site name as stored in your vault, e.g. github.com"),
    headless: bool = typer.Option(False, "--headless", help="Run browser in headless mode"),
    no_submit: bool = typer.Option(False, "--no-submit", help="Fill credentials but do not click submit"),
) -> None:
    """Open a browser, navigate to the site's login page, and type your saved credentials."""
    from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout
    from cryptography.exceptions import InvalidTag

    session = load_session()
    vek = bytes.fromhex(session["vek"])

    data = api_client.get_vault_entry(
        access_token=session["access_token"],
        refresh_token=session["refresh_token"],
        site_name=site,
    )

    try:
        credentials = decrypt_credentials(vek, data["encrypted_blob"], data["iv"])
    except InvalidTag:
        typer.echo(" Error: Decryption failed. Your session may be corrupted — try logging in again.", err=True)
        raise typer.Exit(code=1)

    login_url: str | None = data.get("login_url")
    base_url = f"https://{site}"
    target = login_url or base_url

    typer.echo(f"\n Opening browser for {site}...")
    typer.echo(" Close the browser tab when you are done.\n")

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless)
        page = browser.new_page()

        try:
            page.goto(target, wait_until="domcontentloaded", timeout=30_000)
            try:
                page.wait_for_load_state("networkidle", timeout=10_000)
            except PlaywrightTimeout:
                pass  # domcontentloaded already fired; detection will poll
        except PlaywrightTimeout:
            typer.echo(f" Error: Timed out loading {target}", err=True)
            browser.close()
            raise typer.Exit(code=1)

        if not login_url:
            current = page.url.rstrip("/")
            if current != base_url.rstrip("/"):
                # Site auto-redirected to its login page
                login_url = page.url
                typer.echo(f" Site redirected to login page: {login_url}")
            else:
                typer.echo(f" No login URL stored — searching for sign-in link on {base_url}...")
                discovered = _discover_login_url(page)
                if discovered and discovered.rstrip("/") != base_url.rstrip("/"):
                    login_url = discovered
                    typer.echo(f" Found login page: {login_url}")
                else:
                    typer.echo(f" Warning: Could not find a sign-in link on {base_url}.")
                    typer.echo(f" Tip: Run  psamvault update {site} --login-url <url>  to save it.\n")

            if login_url:
                session = load_session()
                api_client.update_vault_entry_url(
                    access_token=session["access_token"],
                    refresh_token=session["refresh_token"],
                    site_name=site,
                    login_url=login_url,
                )
                typer.echo(f" Login URL saved for '{site}' — future runs will go directly here.\n")

        username_field = _find_username_field(page)
        password_field = _find_password_field(page)

        if username_field is None:
            typer.echo(" Warning: Could not find username/email field — fill it in manually.", err=True)
        else:
            _fill_field(username_field, credentials["username"])

        if password_field is None:
            typer.echo(" Warning: Could not find password field — fill it in manually.", err=True)
        else:
            _fill_field(password_field, credentials["password"])

        if not no_submit and username_field is not None and password_field is not None:
            submitted = _submit_form(page)
            if not submitted:
                typer.echo(" Warning: Could not find submit button — press Enter to submit manually.")

        typer.echo(" Credentials typed. Browser is open — handle 2FA or CAPTCHA if needed.")
        typer.echo(" Press Ctrl+C here to close the browser and exit.\n")

        try:
            page.wait_for_event("close", timeout=0)
        except KeyboardInterrupt:
            pass
        finally:
            try:
                browser.close()
            except Exception:
                pass


# ── Login URL discovery ───────────────────────────────────────────────────────

def _discover_login_url(page) -> str | None:
    """
    Find and click a sign-in/log-in link on the current page, wait for
    navigation, and return the resulting URL. Returns None if not found.
    """
    text_patterns = [
        r"sign[\s\-]?in",
        r"log[\s\-]?in",
        r"^login$",
        r"^sign up$",
    ]
    css_fallbacks = [
        "[href*='login' i]",
        "[href*='signin' i]",
        "[href*='sign-in' i]",
        "[href*='log-in' i]",
    ]
    for pattern in text_patterns:
        for role in ("link", "button"):
            try:
                loc = page.get_by_role(role, name=re.compile(pattern, re.I))
                if loc.first.is_visible(timeout=1000):
                    loc.first.click()
                    page.wait_for_load_state("domcontentloaded", timeout=15_000)
                    return page.url
            except Exception:
                pass
    for sel in css_fallbacks:
        try:
            loc = page.locator(sel).first
            if loc.is_visible(timeout=500):
                loc.click()
                page.wait_for_load_state("domcontentloaded", timeout=15_000)
                return page.url
        except Exception:
            pass
    return None


# ── Field filling ─────────────────────────────────────────────────────────────

def _fill_field(locator, value: str) -> None:
    """Fill a form field. Falls back to type() if fill() doesn't register."""
    locator.click()
    locator.fill(value)
    try:
        if locator.input_value() != value:
            locator.clear()
            locator.type(value, delay=40)
    except Exception:
        pass


# ── Username / email field detection ─────────────────────────────────────────

def _find_username_field(page):
    """
    Locate the username/email input using semantic locators first (works on
    React/Shadow DOM), then CSS fallbacks. Polls for up to 4 s so async-
    rendered forms are caught after domcontentloaded. If still not found,
    looks for a gateway button ("Sign in with Email") and clicks it, then
    retries for up to 6 s.
    """
    field = _poll_for_username(page, t_ms=4000)
    if field:
        return field

    gateway = _find_gateway_button(page)
    if gateway:
        gateway.click()
        field = _poll_for_username(page, t_ms=6000)

    return field


def _poll_for_username(page, t_ms: int):
    semantic_patterns = ["email", "username", "user name", "login"]
    css_fallbacks = [
        'input[type="email"]',
        'input[name="email"]',
        'input[id="email"]',
        'input[name="username"]',
        'input[id="username"]',
        'input[autocomplete="username"]',
        'input[autocomplete="email"]',
        'input[type="text"]',
    ]
    deadline = time.monotonic() + t_ms / 1000
    while time.monotonic() < deadline:
        for pattern in semantic_patterns:
            for locator in [
                page.get_by_role("textbox", name=re.compile(pattern, re.I)),
                page.get_by_label(re.compile(pattern, re.I)),
            ]:
                try:
                    if locator.first.is_visible(timeout=500):
                        return locator.first
                except Exception:
                    pass
        for sel in css_fallbacks:
            try:
                loc = page.locator(sel).first
                if loc.is_visible(timeout=500):
                    return loc
            except Exception:
                pass
        time.sleep(0.25)
    return None


def _find_gateway_button(page):
    """Find a 'Continue with email' / 'Sign in with email' gateway button."""
    text_patterns = [
        r"continue.?with.?email",
        r"sign.?in.?with.?email",
        r"use.?email",
        r"^email$",
    ]
    for pattern in text_patterns:
        for role in ("button", "link"):
            try:
                loc = page.get_by_role(role, name=re.compile(pattern, re.I))
                if loc.first.is_visible(timeout=500):
                    return loc.first
            except Exception:
                pass
    try:
        loc = page.locator("[data-provider='email']").first
        if loc.is_visible(timeout=500):
            return loc
    except Exception:
        pass
    return None


# ── Password field detection ──────────────────────────────────────────────────

def _find_password_field(page):
    """
    Locate the password input. If not immediately visible (multi-step flow),
    look for a Next/Continue button, click it, then retry for up to 6 s.
    """
    field = _poll_for_password(page, t_ms=2000)
    if field:
        return field

    next_btn = _find_next_button(page)
    if next_btn:
        next_btn.click()
        field = _poll_for_password(page, t_ms=6000)

    return field


def _poll_for_password(page, t_ms: int):
    semantic_patterns = ["password", "pass"]
    css_fallbacks = [
        'input[type="password"]',
        'input[name="password"]',
        'input[id="password"]',
        'input[autocomplete="current-password"]',
    ]
    deadline = time.monotonic() + t_ms / 1000
    while time.monotonic() < deadline:
        for pattern in semantic_patterns:
            for locator in [
                page.get_by_role("textbox", name=re.compile(pattern, re.I)),
                page.get_by_label(re.compile(pattern, re.I)),
            ]:
                try:
                    if locator.first.is_visible(timeout=500):
                        return locator.first
                except Exception:
                    pass
        for sel in css_fallbacks:
            try:
                loc = page.locator(sel).first
                if loc.is_visible(timeout=500):
                    return loc
            except Exception:
                pass
        time.sleep(0.25)
    return None


def _find_next_button(page):
    """Find a Next/Continue button that reveals the password field in step 2."""
    text_patterns = [r"^next$", r"^continue$"]
    for pattern in text_patterns:
        for role in ("button", "link"):
            try:
                loc = page.get_by_role(role, name=re.compile(pattern, re.I))
                if loc.first.is_visible(timeout=500):
                    return loc.first
            except Exception:
                pass
    for sel in ("button[type='submit']", "input[type='submit']"):
        try:
            loc = page.locator(sel).first
            if loc.is_visible(timeout=500):
                return loc
        except Exception:
            pass
    return None


# ── Submit button detection ───────────────────────────────────────────────────

def _submit_form(page) -> bool:
    """Find and click the form submit button using semantic then CSS selectors."""
    text_patterns = [
        r"sign.?in", r"log.?in", r"^login$", r"^continue$", r"^submit$",
    ]
    for pattern in text_patterns:
        for role in ("button", "link"):
            try:
                loc = page.get_by_role(role, name=re.compile(pattern, re.I))
                if loc.first.is_visible(timeout=500):
                    loc.first.click()
                    return True
            except Exception:
                pass
    for sel in ('button[type="submit"]', 'input[type="submit"]'):
        try:
            loc = page.locator(sel).first
            if loc.is_visible(timeout=500):
                loc.click()
                return True
        except Exception:
            pass
    return False
