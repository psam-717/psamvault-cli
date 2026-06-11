"""
psamvault Web Dashboard — Flask app factory.

Usage:
    pv dashboard          # starts the server on localhost:8500
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

import flask_session
from flask import Flask


def create_app() -> Flask:
    """Create and configure the Flask dashboard application."""
    # Load pepper from keychain into env so crypto.py can use it
    from config import load_config
    load_config()

    app = Flask(
        __name__,
        template_folder=str(Path(__file__).parent / "templates"),
        static_folder=str(Path(__file__).parent / "static"),
    )

    # ── Configuration ──────────────────────────────────────────────
    # Persistent secret key stored at ~/.psamvault/flask_secret_key.
    # Generated once on first run, re-read on subsequent starts so
    # flask-session session IDs survive server restarts.
    _secret_key_file = Path.home() / ".psamvault" / "flask_secret_key"
    if _secret_key_file.exists():
        app.secret_key = _secret_key_file.read_text(encoding="utf-8").strip()
    else:
        _secret_key_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        app.secret_key = secrets.token_hex(32)
        _secret_key_file.write_text(app.secret_key, encoding="utf-8")
        _secret_key_file.chmod(0o600)
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=False,  # localhost only
    )

    # ── Server-side sessions ───────────────────────────────────────
    # Keeps the VEK, access_token, and refresh_token on the server
    # filesystem instead of sending them to the client in a signed
    # (but unencrypted) cookie. The client only receives a random
    # session ID, so stealing the cookie yields nothing of value.
    _session_dir = Path.home() / ".psamvault" / "flask_sessions"
    _session_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    app.config["SESSION_TYPE"] = "filesystem"
    app.config["SESSION_FILE_DIR"] = str(_session_dir)
    app.config["SESSION_PERMANENT"] = False
    flask_session.Session(app)

    # ── Register routes ────────────────────────────────────────────
    from dashboard.routes import bp

    app.register_blueprint(bp)

    return app