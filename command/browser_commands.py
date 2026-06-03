import json
import re
import time
from pathlib import Path
from urllib.parse import urlparse

import typer

import api_client
from crypto import decrypt_credentials
from session import load_session

app = typer.Typer(name="browser", help="Browser automation commands")

_CAPTCHA_SELECTORS = [
    "iframe[src*='recaptcha']",
    "iframe[src*='hcaptcha']",
    "iframe[src*='turnstile']",
    ".g-recaptcha",
    "#hcaptcha",
    "[class*='captcha' i]",
    "[id*='captcha' i]",
]

STORAGE_DIR = Path.home() / ".psamvault" / "browser_sessions"


@app.callback(invoke_without_command=True)
def browser_help(ctx: typer.Context):
    if ctx.invoked_subcommand is None:
        typer.echo("""
  psamvault browser — browser automation commands

  COMMAND    USAGE
  ──────────────────────────────────────────────────────────────────────────────
  open       psamvault open <site>
  open       psamvault open <site> --headless
  open       psamvault open <site> --no-submit
""")


# ── Helpers: URL, CAPTCHA, fields ─────────────────────────────────────────────


def _discover_login_url(page) -> str | None:
    """Find and click a sign-in/log-in link, return the resulting URL."""
    text_patterns = [
        r"sign[\s\-]?in", r"log[\s\-]?in", r"^login$", r"^sign up$",
    ]
    css_fallbacks = [
        "[href*='login' i]", "[href*='signin' i]",
        "[href*='sign-in' i]", "[href*='log-in' i]",
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


def _url_origin_path(url: str) -> str:
    """Return scheme+host+path (no trailing slash, query, or fragment)."""
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}{p.path.rstrip('/')}"


def _has_visible_captcha(page, t_ms: int = 1000) -> bool:
    """Check if a CAPTCHA iframe or widget is visible on the page."""
    for _sel in _CAPTCHA_SELECTORS:
        try:
            if page.locator(_sel).first.is_visible(timeout=t_ms):
                return True
        except Exception:
            pass
    return False


def _poll_for_username(page, t_ms: int):
    semantic_patterns = ["email", "username", "user name", "login"]
    css_fallbacks = [
        'input[type="email"]', 'input[name="email"]', 'input[id="email"]',
        'input[name="username"]', 'input[id="username"]',
        'input[autocomplete="username"]', 'input[autocomplete="email"]',
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
    """Find a 'Continue with email' / 'Sign in with email' button."""
    text_patterns = [
        r"continue.?with.?email", r"sign.?in.?with.?email",
        r"use.?email", r"^email$",
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


def _find_username_field(page, timeout_ms: int = 8000):
    """Locate the username/email input, handling multi-step flows."""
    field = _poll_for_username(page, t_ms=min(4000, timeout_ms))
    if field:
        return field
    gateway = _find_gateway_button(page)
    if gateway:
        gateway.click()
        field = _poll_for_username(page, t_ms=min(6000, timeout_ms))
    return field


def _poll_for_password(page, t_ms: int):
    semantic_patterns = ["password", "pass"]
    css_fallbacks = [
        'input[type="password"]', 'input[name="password"]', 'input[id="password"]',
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
    """Find a Next/Continue button that reveals the password field."""
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


def _find_password_field(page, timeout_ms: int = 8000):
    """Locate the password input, handling multi-step flows."""
    field = _poll_for_password(page, t_ms=min(2000, timeout_ms))
    if field:
        return field
    next_btn = _find_next_button(page)
    if next_btn:
        next_btn.click()
        field = _poll_for_password(page, t_ms=min(6000, timeout_ms))
    return field


def _submit_form(page, timeout_ms: int = 8000):
    """Find and return the form submit button."""
    text_patterns = [
        r"sign.?in", r"log.?in", r"^login$", r"^continue$", r"^submit$",
    ]
    for pattern in text_patterns:
        for role in ("button", "link"):
            try:
                loc = page.get_by_role(role, name=re.compile(pattern, re.I))
                if loc.first.is_visible(timeout=500):
                    return loc.first
            except Exception:
                pass
    for sel in ('button[type="submit"]', 'input[type="submit"]'):
        try:
            loc = page.locator(sel).first
            if loc.is_visible(timeout=500):
                return loc
        except Exception:
            pass
    return None


# ── Result builder ────────────────────────────────────────────────────────────


def _build_result(
    *,
    success: bool,
    site: str,
    steps: list[str],
    captcha_detected: bool = False,
    failed_at: str | None = None,
    url: str | None = None,
    title: str | None = None,
    error_text: str | None = None,
    hint: str | None = None,
    login_page_screenshot_path: str | None = None,
    captcha_screenshot_path: str | None = None,
) -> dict:
    """Build the standardised result dict for the login flow."""
    return {
        "success": success,
        "message": f"Successfully logged into {site}." if success else None,
        "captcha_detected": captcha_detected,
        "steps_count": len(steps),
        "failed_at": failed_at,
        "url": url,
        "title": title,
        "error_text": error_text,
        "hint": hint,
        "login_page_screenshot": login_page_screenshot_path,
        "captcha_screenshot": captcha_screenshot_path,
    }


# ── Core login flow (shared by one-shot and daemon modes) ─────────────────


def _login_flow(
    browser,
    site: str,
    credentials: dict,
    login_url: str | None = None,
    username_selector: str | None = None,
    password_selector: str | None = None,
    submit_selector: str | None = None,
    timeout_ms: int = 8000,
    no_submit: bool = False,
    _session: dict | None = None,
    _page_list: list | None = None,
) -> dict:
    """Core login flow. Returns a result dict — does NOT call typer.Exit().

    Shared engine used by both one-shot mode (open_site) and
    daemon mode (_run_daemon).
    """
    _safe_name = re.sub(r'[<>:"/\\|?*\s]', '_', site)
    storage_path = STORAGE_DIR / f"{_safe_name}.json"

    _steps: list[str] = []
    captcha_detected = False
    captcha_screenshot_path: str | None = None
    login_page_screenshot_path: str | None = None
    failed_at: str | None = None

    def _r(*, success: bool, url=None, title=None, error_text=None, hint=None) -> dict:
        return _build_result(
            success=success, site=site, steps=_steps,
            captcha_detected=captcha_detected, failed_at=failed_at,
            url=url, title=title, error_text=error_text, hint=hint,
            login_page_screenshot_path=login_page_screenshot_path,
            captcha_screenshot_path=captcha_screenshot_path,
        )

    base_url = f"https://{site}"
    target = login_url or base_url

    # ── Load saved session state if available ───────────
    context_kwargs: dict = {}
    if storage_path.exists():
        context_kwargs["storage_state"] = str(storage_path)
        _steps.append("loaded_saved_session")

    context = browser.new_context(**context_kwargs)
    page = context.new_page()
    if _page_list is not None:
        _page_list.append(context)
        _page_list.append(page)
    _steps.append("browser_launched")

    try:
        page.goto(target, wait_until="domcontentloaded", timeout=30_000)
        _steps.append("navigated_to_site")

        # ── Login URL discovery ───────────────────────────────────────────
        if not login_url:
            current = page.url.rstrip("/")
            if current != base_url.rstrip("/"):
                login_url = page.url
            else:
                discovered = _discover_login_url(page)
                if discovered and discovered.rstrip("/") != base_url.rstrip("/"):
                    login_url = discovered
                else:
                    if storage_path.exists():
                        _steps.append("session_reused_already_logged_in")
                        return _r(success=True, url=page.url, title=page.title())
                    failed_at = "login_link_not_found"
                    return _r(
                        success=False, url=page.url,
                        hint=f"Could not find a sign-in link on {base_url}. Provide login_url explicitly.",
                    )

            if login_url and _session:
                try:
                    s = _session if _session.get("access_token") else load_session()
                    api_client.update_vault_entry_url(
                        access_token=s["access_token"],
                        refresh_token=s["refresh_token"],
                        site_name=site,
                        login_url=login_url,
                    )
                    _steps.append("login_url_persisted")
                except Exception:
                    pass

        # ── Login page screenshot ─────────────────────────────────────────
        try:
            STORAGE_DIR.mkdir(parents=True, exist_ok=True)
            _screenshot_file = STORAGE_DIR / f"{_safe_name}_login_preview.png"
            page.screenshot(path=str(_screenshot_file), full_page=False)
            login_page_screenshot_path = str(_screenshot_file)
            _steps.append("login_page_screenshot_taken")
        except Exception:
            pass

        # ── Username field ─────────────────────────────────────────────────
        if username_selector:
            username_field = page.locator(username_selector).first
            try:
                username_field.wait_for(state="visible", timeout=timeout_ms)
            except Exception:
                failed_at = "username_selector_not_found"
                return _r(
                    success=False, url=page.url,
                    hint=f"Provided username_selector '{username_selector}' was not visible.",
                )
        else:
            username_field = _find_username_field(page, timeout_ms)

        if username_field is None:
            failed_at = "username_field_not_found"
            return _r(
                success=False, url=page.url,
                hint="Could not detect the username/email field. Provide username_selector explicitly.",
            )

        _fill_field(username_field, credentials["username"])
        _steps.append("filled_username")

        # ── Password field ────────────────────────────────────────────────
        if password_selector:
            password_field = page.locator(password_selector).first
            try:
                password_field.wait_for(state="visible", timeout=timeout_ms)
            except Exception:
                failed_at = "password_selector_not_found"
                return _r(
                    success=False, url=page.url,
                    hint=f"Provided password_selector '{password_selector}' was not visible.",
                )
        else:
            password_field = _find_password_field(page, timeout_ms)

        if password_field is None:
            failed_at = "password_field_not_found"
            return _r(
                success=False, url=page.url,
                hint="Could not detect the password field. Provide password_selector explicitly.",
            )

        _fill_field(password_field, credentials["password"])
        _steps.append("filled_password")

        if no_submit:
            return _r(success=False, url=page.url, hint="Credentials filled but form not submitted.")

        # ── Submit button ──────────────────────────────────────────────────
        if submit_selector:
            submit_btn = page.locator(submit_selector).first
            try:
                submit_btn.wait_for(state="visible", timeout=timeout_ms)
            except Exception:
                failed_at = "submit_selector_not_found"
                return _r(
                    success=False, url=page.url,
                    hint=f"Provided submit_selector '{submit_selector}' was not visible.",
                )
        else:
            submit_btn = _submit_form(page, timeout_ms)

        if submit_btn is None:
            failed_at = "submit_button_not_found"
            return _r(
                success=False, url=page.url,
                hint="Could not detect submit button. Provide submit_selector explicitly.",
            )

        # ── CAPTCHA detection before submit ────────────────────────────────
        if _has_visible_captcha(page):
            captcha_detected = True
            _steps.append("captcha_detected_before_submit")
            try:
                STORAGE_DIR.mkdir(parents=True, exist_ok=True)
                _cap_file = STORAGE_DIR / f"{_safe_name}_captcha.png"
                page.screenshot(path=str(_cap_file), full_page=False)
                captcha_screenshot_path = str(_cap_file)
                _steps.append("captcha_screenshot_taken")
            except Exception:
                pass

        # ── Submit ─────────────────────────────────────────────────────────
        pre_submit_url = page.url
        submit_btn.click()
        _steps.append("submitted_form")

        # Wait for URL change (SPA-friendly)
        _ref_url = pre_submit_url.rstrip("/")
        try:
            page.wait_for_function(
                "ref => window.location.href.replace(/\\/$/, '') !== ref",
                arg=_ref_url, timeout=8000,
            )
            _steps.append("url_changed_after_submit")
        except Exception:
            pass

        try:
            page.wait_for_load_state("networkidle", timeout=5000)
        except Exception:
            pass

        # ── CAPTCHA detection after submit ─────────────────────────────────
        if not captcha_detected and _has_visible_captcha(page):
            captcha_detected = True
            _steps.append("captcha_detected_after_submit")
            try:
                STORAGE_DIR.mkdir(parents=True, exist_ok=True)
                _cap_file = STORAGE_DIR / f"{_safe_name}_captcha.png"
                page.screenshot(path=str(_cap_file), full_page=False)
                captcha_screenshot_path = str(_cap_file)
                _steps.append("captcha_screenshot_taken")
            except Exception:
                pass

        final_url = page.url
        final_title = page.title()

        # ── Detect visible error message ───────────────────────────────────
        error_text = None
        for sel in [
            "[role='alert']", ".error", ".flash-error", "#error",
            ".alert-danger", ".alert-error",
        ]:
            try:
                el = page.locator(sel).first
                if el.is_visible():
                    text = el.inner_text().strip()
                    if len(text) > 5:
                        error_text = text
                        break
            except Exception:
                continue

        # ── Determine success ──────────────────────────────────────────────
        url_changed = _url_origin_path(final_url) != _url_origin_path(pre_submit_url)

        form_fields_disappeared = False
        for _ in range(6):
            try:
                if not username_field.is_visible() and not password_field.is_visible():
                    form_fields_disappeared = True
                    break
            except Exception:
                break
            time.sleep(0.5)

        login_succeeded = (
            error_text is None
            and (url_changed or form_fields_disappeared)
            and not captcha_detected
        )

        if login_succeeded:
            STORAGE_DIR.mkdir(parents=True, exist_ok=True)
            context.storage_state(path=str(storage_path))
            _steps.append("session_state_saved")

        return _r(
            success=login_succeeded,
            url=final_url,
            title=final_title,
            error_text=error_text,
            hint=(
                "Login may have failed — the page did not navigate away from "
                "the login URL after submission."
            ) if not url_changed and error_text is None else None,
        )

    except Exception as e:
        failed_at = failed_at or "unexpected_error"
        return _r(
            success=False, error_text=str(e),
            hint="An unexpected error occurred.",
        )


# ── One-shot mode (regular CLI) ──────────────────────────────────────────


@app.command(name="open")
def open_site(
    site: str | None = typer.Argument(None, help="Site name as stored in your vault, e.g. github.com"),
    headless: bool = typer.Option(False, "--headless", help="Run browser in headless mode"),
    no_submit: bool = typer.Option(False, "--no-submit", help="Fill credentials but do not click submit"),
    json_output: bool = typer.Option(False, "--json", help="Output result as JSON (for programmatic use)"),
    login_url: str | None = typer.Option(None, "--login-url", help="Explicit login page URL"),
    username_selector: str | None = typer.Option(None, "--username-selector", help="CSS selector for the username/email field"),
    password_selector: str | None = typer.Option(None, "--password-selector", help="CSS selector for the password field"),
    submit_selector: str | None = typer.Option(None, "--submit-selector", help="CSS selector for the submit button"),
    timeout_ms: int = typer.Option(8000, "--timeout", help="Per-step detection timeout in milliseconds"),
    daemon: bool = typer.Option(False, "--daemon", hidden=True, help="Run in daemon mode (stdin/stdout protocol)"),
) -> None:
    """Open a browser, navigate to the site's login page, and type your saved credentials."""
    from playwright.sync_api import sync_playwright
    from cryptography.exceptions import InvalidTag

    # ── Daemon mode — no site arg needed (reads from stdin) ────────────────
    if daemon:
        _run_daemon()
        return

    if site is None:
        typer.echo("Error: Missing argument 'SITE'.", err=True)
        raise typer.Exit(code=1)

    # ── URL scheme validation ──────────────────────────────────────────────
    if login_url:
        _parsed = urlparse(login_url)
        if _parsed.scheme not in ("http", "https"):
            msg = f"login_url scheme '{_parsed.scheme}' is not allowed. Only http and https are permitted."
            if json_output:
                typer.echo(json.dumps({"error": msg}))
            else:
                typer.echo(f" Error: {msg}", err=True)
            raise typer.Exit(code=1)

    def _human(msg: str) -> None:
        if not json_output:
            typer.echo(msg)

    # ── Load session and decrypt ───────────────────────────────────────────
    session = load_session()
    vek = bytes.fromhex(session["vek"])
    _session = session

    data = api_client.get_vault_entry(
        access_token=session["access_token"],
        refresh_token=session["refresh_token"],
        site_name=site,
    )

    try:
        credentials = decrypt_credentials(vek, data["encrypted_blob"], data["iv"])
    except InvalidTag:
        msg = "Decryption failed. Your session may be corrupted — try logging in again."
        if json_output:
            typer.echo(json.dumps({"error": msg}))
        else:
            typer.echo(f" Error: {msg}", err=True)
        raise typer.Exit(code=1)

    stored_login_url: str | None = data.get("login_url")
    effective_login_url = login_url or stored_login_url

    _human(f"\n Opening browser for {site}...")
    _human(" Close the browser tab when you are done.\n")

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless)
        try:
            result = _login_flow(
                browser=browser,
                site=site,
                credentials=credentials,
                login_url=effective_login_url,
                username_selector=username_selector,
                password_selector=password_selector,
                submit_selector=submit_selector,
                timeout_ms=timeout_ms,
                no_submit=no_submit,
                _session=_session,
            )

            success = result.get("success", False)

            if json_output:
                typer.echo(json.dumps(result, indent=2))
            else:
                if result.get("hint"):
                    typer.echo(f" Warning: {result['hint']}", err=True)
                if success:
                    _human(f" Successfully logged into {site}.")

            _human(" Credentials typed. Browser is open — handle 2FA or CAPTCHA if needed.")
            _human(" Press Ctrl+C here to close the browser and exit.\n")

            # Keep browser open until user closes the tab or presses Ctrl+C.
            try:
                page = browser.contexts[-1].pages[-1] if browser.contexts else None
                if page:
                    page.wait_for_event("close", timeout=0)
            except (KeyboardInterrupt, Exception):
                pass

            raise typer.Exit(code=0 if success else 1)

        except typer.Exit:
            raise
        except Exception as e:
            failed_at = "unexpected_error"
            err_result = _build_result(
                success=False, site=site, steps=[],
                failed_at=failed_at, error_text=str(e),
                hint="An unexpected error occurred.",
            )
            if json_output:
                typer.echo(json.dumps(err_result))
            else:
                typer.echo(f" Error: {e}", err=True)
            raise typer.Exit(code=1)
        finally:
            try:
                browser.close()
            except Exception:
                pass


# ── Daemon mode (persistent browser, stdin/stdout protocol) ─────────────────


def _run_daemon() -> None:
    """Run in daemon mode: read JSON commands from stdin, write results to stdout.

    Protocol:
      Request (one JSON object per line):
        {"action": "open", "site": "...", "login_url": "...", ...}
        {"action": "shutdown"}
      Response (one JSON object per line):
        {"success": true, "url": "...", ...}
        {"success": true, "message": "Daemon shutting down"}
    """
    from playwright.sync_api import sync_playwright
    from cryptography.exceptions import InvalidTag
    import sys

    session = load_session()
    vek = bytes.fromhex(session["vek"])
    _session = session

    def _fetch_and_decrypt(site_name: str) -> dict | None:
        data = api_client.get_vault_entry(
            access_token=_session["access_token"],
            refresh_token=_session["refresh_token"],
            site_name=site_name,
        )
        try:
            return decrypt_credentials(vek, data["encrypted_blob"], data["iv"])
        except InvalidTag:
            print(json.dumps({
                "success": False,
                "error": "Decryption failed. Session may be corrupted — try logging in again.",
            }), flush=True)
            return None

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        _open_pages: list = []  # keep references so pages don't close

        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                cmd = json.loads(line)
            except json.JSONDecodeError:
                continue

            action = cmd.get("action", "")

            if action == "shutdown":
                print(json.dumps({
                    "success": True, "message": "Daemon shutting down",
                }), flush=True)
                break

            if action == "open":
                site_name = cmd.get("site", "")
                if not site_name:
                    print(json.dumps({
                        "success": False, "error": "Missing 'site' in command",
                    }), flush=True)
                    continue

                credentials = _fetch_and_decrypt(site_name)
                if credentials is None:
                    continue

                result = _login_flow(
                    browser=browser,
                    site=site_name,
                    credentials=credentials,
                    login_url=cmd.get("login_url"),
                    username_selector=cmd.get("username_selector"),
                    password_selector=cmd.get("password_selector"),
                    submit_selector=cmd.get("submit_selector"),
                    timeout_ms=cmd.get("timeout_ms", 8000),
                    no_submit=cmd.get("no_submit", False),
                    _session=_session,
                    _page_list=_open_pages,
                )
                print(json.dumps(result), flush=True)
                continue

            print(json.dumps({
                "success": False, "error": f"Unknown action: {action}",
            }), flush=True)

        browser.close()