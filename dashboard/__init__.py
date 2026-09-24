"""
psamvault Web Dashboard — Flask app factory.

Usage:
    pv dashboard          # starts the server on localhost:8500
"""

from __future__ import annotations

from pathlib import Path

from flask import Flask, abort, request, send_from_directory

from dashboard.cache import install_token_hook

# The dashboard is served on 127.0.0.1:8500 over plain HTTP. Only these
# Host values are accepted; any other Host (e.g. an attacker domain that
# DNS-rebinds to 127.0.0.1) is rejected with 403 before any route runs.
# Bare localhost / 127.0.0.1 are accepted so the Flask test client works.
# Browsers on port 8500 send the host with the port, which is also listed.
_ALLOWED_HOSTS = {
    "127.0.0.1:8500",
    "localhost:8500",
    "[::1]:8500",
    "localhost",
    "127.0.0.1",
}

_DIST = Path(__file__).parent / "static" / "app"


def create_app() -> Flask:
    """Create and configure the Flask dashboard application."""
    from config import load_config

    load_config()
    install_token_hook()

    app = Flask(
        __name__,
        static_folder=str(Path(__file__).parent / "static"),
        static_url_path="/static",
    )
    # No cookie session. Tokens and the VEK stay in process memory after one
    # keychain read (dashboard.cache). A signed cookie is not required.
    app.secret_key = "unused-dashboard-has-no-cookie-session"

    from dashboard.api import bp

    app.register_blueprint(bp)

    @app.before_request
    def _enforce_localhost_host():
        host = request.headers.get("Host", "")
        if host not in _ALLOWED_HOSTS:
            return "", 403
        return None

    @app.get("/")
    @app.get("/dashboard")
    @app.get("/login")
    def index():
        index_file = _DIST / "index.html"
        if not index_file.is_file():
            return ("Dashboard UI is not built. From dashboard/frontend run npm install and npm run build.", 503)
        return send_from_directory(_DIST, "index.html")

    @app.get("/<path:path>")
    def spa_fallback(path: str):
        # API routes are registered on the blueprint. This catches browser
        # refreshes on client paths and refuses to serve those as files.
        if path == "api" or path.startswith("api/"):
            abort(404)
        asset = _DIST / path
        if path and asset.is_file():
            return send_from_directory(_DIST, path)
        index_file = _DIST / "index.html"
        if index_file.is_file():
            return send_from_directory(_DIST, "index.html")
        abort(404)

    return app