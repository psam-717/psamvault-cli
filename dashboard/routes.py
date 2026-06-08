"""
psamvault Web Dashboard — all routes.

Uses Flask sessions to store auth tokens and VEK server-side.
Calls existing api_client.py and crypto.py — no reimplementation needed.
"""

from __future__ import annotations

import sys
from pathlib import Path
import typer

# Ensure the project root is on sys.path so we can import project modules
_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from api_client import (
    add_vault_entry,
    delete_vault_entry,
    get_vault_entry,
    update_vault_entry,
    list_vault_entries,
    add_api_key_entry,
    delete_api_key_entry,
    get_api_key_entry,
    update_api_key_entry,
    list_api_key_entries,
    login as api_login,
    signup as api_signup,
    me as api_me,
)
from crypto import (
    decrypt_credentials,
    decrypt_api_key,
    encrypt_credentials,
    encrypt_api_key,
    derive_master_password,
    derive_key,
    decrypt_vek,
    generate_vek,
    encrypt_vek,
)
from session import (
    is_logged_in,
    load_session,
    save_session,
    clear_session,
)

bp = Blueprint("dashboard", __name__)


# ── Validation constants (mirror CLI) ───────────────────────────────────────
_FORBIDDEN_SITE_CHARS = set('\\/"\'' ' <>|?*&#%')


def _validate_site_name(site: str) -> str | None:
    """Returns an error message if the site name is invalid, or None."""
    if not site.strip():
        return "Site name cannot be blank"
    found = [c for c in site if c in _FORBIDDEN_SITE_CHARS]
    if found:
        unique = "".join(dict.fromkeys(found))
        chars = " ".join(repr(c) for c in unique)
        return f"Site name contains invalid character(s): {chars}"


def _validate_login_url(url: str) -> str | None:
    """Returns an error message if the URL is invalid, or None."""
    if url and not url.startswith(("http://", "https://")):
        return "Login URL must start with http:// or https://"


def _validate_password(password: str) -> str | None:
    """Returns an error message if the password doesn't meet requirements."""
    errors = []
    if len(password) < 8:
        errors.append("at least 8 characters")
    if not any(c.isupper() for c in password):
        errors.append("at least one uppercase letter")
    if not any(c.isdigit() for c in password):
        errors.append("at least one digit")
    if errors:
        return "Password must have: " + ", ".join(errors)
    return None


# ── Helpers ────────────────────────────────────────────────────────────────

def _is_authenticated() -> bool:
    """Check if the Flask session has a valid auth state."""
    if session.get("access_token") and session.get("vek"):
        return True
    # Try auto-login from OS keychain (CLI session)
    return _try_auto_login()


def _try_auto_login() -> bool:
    """Restore session from OS keychain (CLI session).

    Loads tokens from the keychain into the Flask session without
    proactively refreshing them — the individual API calls (list_vault_entries
    etc.) already have built-in refresh-and-retry logic. This avoids a race
    condition where concurrent dashboard requests all try to use (and
    invalidate) the same refresh token at the same time.
    """
    if not is_logged_in():
        return False
    try:
        sess = load_session()
    except Exception:
        return False

    session["access_token"] = sess["access_token"]
    session["refresh_token"] = sess["refresh_token"]
    session["vek"] = sess["vek"]
    session["username"] = "User"

    # Try to fetch the real username from the profile endpoint
    try:
        profile = api_me(session["access_token"])
        session["username"] = profile.get("username", "User")
    except Exception:
        pass

    return True


def _login_user(username: str, password: str) -> str | None:
    """
    Authenticate with the backend, derive the VEK, and store in session.
    Returns None on success, or an error message string.
    """
    try:
        # Ensure pepper is loaded from keychain before any crypto
        from config import load_config
        load_config()

        master = derive_master_password(password)
        data = api_login(username, master)
        access_token = data["access_token"]
        refresh_token = data["refresh_token"]
        kdf_salt = data["kdf_salt"]

        login_key = derive_key(master, kdf_salt)
        vek_bytes = decrypt_vek(
            bytes(login_key),
            data.get("encrypted_vek", ""),
            data.get("vek_iv", ""),
        )

        # Store in Flask session
        session["access_token"] = access_token
        session["refresh_token"] = refresh_token
        session["vek"] = bytes(vek_bytes).hex()
        session["username"] = username

        # Also persist to OS keychain for CLI consistency
        save_session(
            access_token=access_token,
            refresh_token=refresh_token,
            kdf_salt=kdf_salt,
            vek=bytes(vek_bytes).hex(),
            encrypted_vek=data.get("encrypted_vek", ""),
            vek_iv=data.get("vek_iv", ""),
        )

        return None
    except (Exception, typer.Exit, SystemExit) as exc:
        return str(exc)


def _get_vault_entries():
    """Fetch vault entries — returns raw API data, no decryption (matches CLI's site-list)."""
    token = session["access_token"]
    refresh = session["refresh_token"]

    try:
        data = list_vault_entries(token, refresh)
    except BaseException as exc:
        flash(f"Could not load entries: {exc}", "error")
        return []

    entries: list[dict] = data if isinstance(data, list) else data.get("entries", [])
    for e in entries:
        e["updated_at"] = (e.get("updated_at") or "")[:10]
        e["username_hint"] = e.get("username_hint") or "—"
    return entries


def _get_api_keys():
    """Fetch API key entries — returns raw API data, no decryption (matches CLI's list)."""
    token = session["access_token"]
    refresh = session["refresh_token"]

    try:
        data = list_api_key_entries(token, refresh)
    except BaseException as exc:
        flash(f"Could not load API keys: {exc}", "error")
        return []

    entries: list[dict] = data if isinstance(data, list) else data.get("entries", [])
    for e in entries:
        e["updated_at"] = (e.get("updated_at") or "")[:10]
        e["service_hint"] = e.get("service_hint") or "—"
    return entries


def _get_decrypted_entry(site_name: str) -> dict | None:
    """Fetch, decrypt and return a single vault entry (matches CLI's `get` command)."""
    token = session["access_token"]
    refresh = session["refresh_token"]
    vek = bytes.fromhex(session["vek"])

    try:
        data = get_vault_entry(token, refresh, site_name)
    except Exception:
        return None

    try:
        decrypted = decrypt_credentials(vek, data["encrypted_blob"], data["iv"])
    except Exception:
        return None

    return {
        "site_name": data.get("site_name", site_name),
        "username": decrypted.get("username", ""),
        "password": decrypted.get("password", ""),
        "notes": decrypted.get("notes", ""),
        "login_url": data.get("login_url", ""),
        "username_hint": data.get("username_hint", ""),
    }


def _get_decrypted_api_key(name: str) -> dict | None:
    """Fetch, decrypt and return a single API key entry."""
    token = session["access_token"]
    refresh = session["refresh_token"]
    vek = bytes.fromhex(session["vek"])

    try:
        data = get_api_key_entry(token, refresh, name)
    except Exception:
        return None

    try:
        decrypted = decrypt_api_key(vek, data["encrypted_blob"], data["iv"])
    except Exception:
        return None

    return {
        "name": data.get("name", name),
        "service": decrypted.get("service", ""),
        "api_key": decrypted.get("api_key", ""),
        "notes": decrypted.get("notes", ""),
        "service_hint": data.get("service_hint", ""),
    }


# ── Routes ─────────────────────────────────────────────────────────────────

@bp.route("/")
def index():
    """Root — redirect to dashboard if logged in, else login."""
    if _is_authenticated():
        return redirect(url_for("dashboard.dashboard_view"))
    return redirect(url_for("dashboard.login_view"))


@bp.route("/login", methods=["GET", "POST"])
def login_view():
    """Login page — login must be done via the CLI."""
    if _is_authenticated():
        return redirect(url_for("dashboard.dashboard_view"))
    return render_template("login.html")


@bp.route("/signup", methods=["GET", "POST"])
def signup_view():
    """Signup page — disabled in dashboard. Use the CLI to sign up."""
    flash("Sign up is only available via the CLI. Run  pv signup  in your terminal.", "error")
    return redirect(url_for("dashboard.login_view"))


@bp.route("/logout", methods=["POST"])
def logout_view():
    """Log out — clear session and prompt CLI login."""
    clear_session()
    session.clear()
    flash("Signed out. Login can only be done via the CLI. "
          "Close this dashboard, run  pv login  in your terminal, "
          "then restart the dashboard.", "info")
    return redirect(url_for("dashboard.login_view"))


@bp.route("/dashboard")
def dashboard_view():
    """Main dashboard — shows vault entries and API keys."""
    if not _is_authenticated():
        return redirect(url_for("dashboard.login_view"))

    entries = _get_vault_entries()
    api_keys = _get_api_keys()

    return render_template(
        "dashboard.html",
        entries=entries,
        api_keys=api_keys,
        username=session.get("username", ""),
    )


# ── Entries CRUD ───────────────────────────────────────────────────────────

@bp.route("/entries")
def entries_list():
    """HTMX partial — returns just the entries table body."""
    if not _is_authenticated():
        return "", 401

    entries = _get_vault_entries()
    search = request.args.get("search", "").lower().strip()
    if search:
        entries = [
            e for e in entries
            if search in e["site_name"].lower()
            or search in e["username_hint"].lower()
        ]

    return render_template("entries_table.html", entries=entries)


@bp.route("/entries/add", methods=["POST"])
def entries_add():
    """Add a new vault entry."""
    if not _is_authenticated():
        return redirect(url_for("dashboard.login_view"))

    site_name = request.form.get("site_name", "").strip()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    notes = request.form.get("notes", "").strip()
    login_url = request.form.get("login_url", "").strip()

    # ── Validation (mirrors CLI) ──────────────────────────────
    error = _validate_site_name(site_name)
    if error:
        flash(error, "error")
        return redirect(url_for("dashboard.dashboard_view"))

    if not password:
        flash("Password is required", "error")
        return redirect(url_for("dashboard.dashboard_view"))

    error = _validate_password(password)
    if error:
        flash(error, "error")
        return redirect(url_for("dashboard.dashboard_view"))

    error = _validate_login_url(login_url)
    if error:
        flash(error, "error")
        return redirect(url_for("dashboard.dashboard_view"))

    vek = bytes.fromhex(session["vek"])
    blob, iv = encrypt_credentials(vek, username, password, notes)

    try:
        add_vault_entry(
            session["access_token"],
            session["refresh_token"],
            site_name,
            blob,
            iv,
            username_hint=username,
            login_url=login_url or None,
        )
    except Exception as exc:
        flash(f"Failed to save: {exc}", "error")
        return redirect(url_for("dashboard.dashboard_view"))

    flash(f"✓ Credentials for {site_name} saved", "success")
    return redirect(url_for("dashboard.dashboard_view"))


@bp.route("/entries/<path:site_name>/delete", methods=["POST"])
def entries_delete(site_name: str):
    """Delete a vault entry."""
    if not _is_authenticated():
        return redirect(url_for("dashboard.login_view"))

    try:
        delete_vault_entry(session["access_token"], session["refresh_token"], site_name)
        flash(f"✓ Entry for {site_name} deleted", "success")
    except Exception:
        flash(f"Failed to delete {site_name}", "error")

    return redirect(url_for("dashboard.dashboard_view"))


@bp.route("/entries/<path:site_name>/password")
def entries_password(site_name: str):
    """JSON endpoint — decrypt and return just the password for a single entry.

    Called on-demand by the detail page's reveal / copy buttons so the
    plaintext password is never embedded in the HTML source. The password
    is fetched via fetch() on explicit user action and held only in a JS
    closure variable, never in the DOM.
    """
    if not _is_authenticated():
        return {"error": "Not authenticated"}, 401

    entry = _get_decrypted_entry(site_name)
    if not entry:
        return {"error": "Entry not found"}, 404

    return {"password": entry["password"]}


@bp.route("/entries/<path:site_name>")
def entries_detail(site_name: str):
    """View a single entry's details (decrypts and displays — matches CLI's `get`)."""
    if not _is_authenticated():
        return redirect(url_for("dashboard.login_view"))

    entry = _get_decrypted_entry(site_name)
    if not entry:
        return render_template("entry_detail.html", entry=None, error="Entry not found")

    return render_template("entry_detail.html", entry=entry)


@bp.route("/entries/<path:site_name>/edit", methods=["GET", "POST"])
def entries_edit(site_name: str):
    """Edit a vault entry — fetches current, decrypts, merges, re-encrypts."""
    if not _is_authenticated():
        return redirect(url_for("dashboard.login_view"))

    if request.method == "GET":
        entry = _get_decrypted_entry(site_name)
        if not entry:
            return render_template("entry_detail.html", entry=None, error="Entry not found")
        return render_template("entry_edit.html", entry=entry)

    # POST — save changes
    token = session["access_token"]
    refresh = session["refresh_token"]
    vek = bytes.fromhex(session["vek"])

    # Get current decrypted entry to merge
    current = _get_decrypted_entry(site_name)
    if not current:
        return render_template("entry_edit.html", entry=None, error="Entry not found")

    # Merge — empty fields keep original values (matches CLI's merge logic)
    updated_user = request.form.get("username", "").strip() or current["username"]
    updated_pass = request.form.get("password", "").strip() or current["password"]
    updated_notes = request.form.get("notes", "").strip()
    if not updated_notes:
        updated_notes = current.get("notes", "")
    updated_url = request.form.get("login_url", "").strip() or current.get("login_url", "")

    # Validate login URL format
    error = _validate_login_url(updated_url)
    if error:
        return render_template("entry_edit.html", entry=current, error=error)

    blob, iv = encrypt_credentials(vek, updated_user, updated_pass, updated_notes)

    try:
        update_vault_entry(
            token, refresh, site_name, blob, iv,
            username_hint=updated_user,
            login_url=updated_url or None,
        )
    except Exception as exc:
        return render_template("entry_edit.html", entry=current, error=str(exc))

    flash(f"✓ Credentials for {site_name} updated", "success")
    return redirect(url_for("dashboard.entries_detail", site_name=site_name))


# ── API Keys CRUD ──────────────────────────────────────────────────────────

@bp.route("/api-keys")
def api_keys_list():
    """HTMX partial — returns just the API keys table body."""
    if not _is_authenticated():
        return "", 401

    api_keys = _get_api_keys()
    search = request.args.get("search", "").lower().strip()
    if search:
        api_keys = [
            k for k in api_keys
            if search in k["name"].lower()
            or search in k["service_hint"].lower()
        ]

    return render_template("api_keys_table.html", api_keys=api_keys)


@bp.route("/api-keys/add", methods=["POST"])
def api_keys_add():
    """Add a new API key entry."""
    if not _is_authenticated():
        return redirect(url_for("dashboard.login_view"))

    name = request.form.get("name", "").strip()
    service = request.form.get("service", "").strip()
    api_key = request.form.get("api_key", "").strip()
    notes = request.form.get("notes", "").strip()

    if not name:
        flash("Name is required", "error")
        return redirect(url_for("dashboard.dashboard_view"))

    error = _validate_site_name(name)
    if error:
        flash(error, "error")
        return redirect(url_for("dashboard.dashboard_view"))

    if not api_key:
        flash("API key is required", "error")
        return redirect(url_for("dashboard.dashboard_view"))

    vek = bytes.fromhex(session["vek"])
    blob, iv = encrypt_api_key(vek, service, api_key, notes)

    try:
        add_api_key_entry(
            session["access_token"],
            session["refresh_token"],
            name,
            service,
            blob,
            iv,
        )
    except Exception as exc:
        flash(f"Failed to save: {exc}", "error")
        return redirect(url_for("dashboard.dashboard_view"))

    flash(f"✓ API key '{name}' saved", "success")
    return redirect(url_for("dashboard.dashboard_view"))


@bp.route("/api-keys/<path:name>/delete", methods=["POST"])
def api_keys_delete(name: str):
    """Delete an API key entry."""
    if not _is_authenticated():
        return redirect(url_for("dashboard.login_view"))

    try:
        delete_api_key_entry(session["access_token"], session["refresh_token"], name)
        flash(f"✓ API key '{name}' deleted", "success")
    except Exception:
        flash(f"Failed to delete API key '{name}'", "error")

    return redirect(url_for("dashboard.dashboard_view"))


@bp.route("/api-keys/<path:name>/password")
def api_keys_password(name: str):
    """JSON endpoint — decrypt and return just the API key value.

    Called on-demand by the detail page's reveal / copy buttons so the
    plaintext key is never embedded in the HTML source.
    """
    if not _is_authenticated():
        return {"error": "Not authenticated"}, 401

    key = _get_decrypted_api_key(name)
    if not key:
        return {"error": "API key not found"}, 404

    return {"api_key": key["api_key"]}


@bp.route("/api-keys/<path:name>")
def api_keys_detail(name: str):
    """View a single API key's details — decrypts and shows the key."""
    if not _is_authenticated():
        return redirect(url_for("dashboard.login_view"))

    key = _get_decrypted_api_key(name)
    if not key:
        return render_template("api_key_detail.html", key=None, error="API key not found")

    return render_template("api_key_detail.html", key=key)


@bp.route("/api-keys/<path:name>/edit", methods=["GET", "POST"])
def api_keys_edit(name: str):
    """Edit an API key entry."""
    if not _is_authenticated():
        return redirect(url_for("dashboard.login_view"))

    if request.method == "GET":
        key = _get_decrypted_api_key(name)
        if not key:
            return render_template("api_key_detail.html", key=None, error="API key not found")
        return render_template("api_key_edit.html", key=key)

    # POST — save changes
    token = session["access_token"]
    refresh = session["refresh_token"]
    vek = bytes.fromhex(session["vek"])

    current = _get_decrypted_api_key(name)
    if not current:
        return render_template("api_key_edit.html", key=None, error="API key not found")

    updated_service = request.form.get("service", "").strip() or current["service"]
    updated_api_key = request.form.get("api_key", "").strip() or current["api_key"]
    updated_notes = request.form.get("notes", "").strip()
    if not updated_notes:
        updated_notes = current.get("notes", "")

    blob, iv = encrypt_api_key(vek, updated_service, updated_api_key, updated_notes)

    try:
        update_api_key_entry(token, refresh, name, updated_service, blob, iv)
    except Exception as exc:
        return render_template("api_key_edit.html", key=current, error=str(exc))

    flash(f"✓ API key '{name}' updated", "success")
    return redirect(url_for("dashboard.api_keys_detail", name=name))