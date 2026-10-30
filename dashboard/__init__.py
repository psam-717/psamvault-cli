"""
psamvault Web Dashboard — Flask app factory.

Usage:
    pv dashboard          # localhost, port 8500 or the next free port
    pv dashboard --port N

The vault key and the API tokens stay in this process. The browser does not
receive them. ``pv dashboard`` puts a one-time token in the URL fragment. The
page posts that token once to ``/session`` and receives an HttpOnly,
SameSite=Strict cookie. The cookie is a random session id. Every ``/api``
route requires that cookie and the dashboard's own Origin. The Origin is the
port this process bound, not a fixed 8500.
"""

from __future__ import annotations

from pathlib import Path

from flask import Flask, abort, jsonify, request, send_from_directory

import keychain

from dashboard.cache import install_token_hook

# The dashboard is served on 127.0.0.1 over plain HTTP, on the port
# ``create_app`` was given. Only these Host values are accepted; any other
# Host (e.g. an attacker domain that DNS-rebinds to 127.0.0.1) is rejected
# with 403 before any route runs. Bare localhost / 127.0.0.1 are accepted so
# the Flask test client works. Browsers send the host with the bound port.
def hosts_for_port(port: int) -> set[str]:
    return {
        f"127.0.0.1:{port}",
        f"localhost:{port}",
        f"[::1]:{port}",
        "localhost",
        "127.0.0.1",
    }


_ALLOWED_HOSTS = hosts_for_port(8500)

_DIST = Path(__file__).parent / "static" / "app"


def create_app(port: int = 8500) -> Flask:
    """Create and configure the Flask dashboard application.

    ``port`` is the port Waitress will bind. The Host and Origin allow-lists
    use that port, for ``127.0.0.1``, ``localhost`` and ``[::1]``.
    """
    global _ALLOWED_HOSTS
    from config import load_config
    from dashboard.api import configure_listen_port

    allowed_hosts = hosts_for_port(port)
    _ALLOWED_HOSTS = allowed_hosts
    configure_listen_port(port)

    load_config()
    install_token_hook()

    app = Flask(
        __name__,
        static_folder=str(Path(__file__).parent / "static"),
        static_url_path="/static",
    )
    # No Flask session. The VEK and the API tokens stay in process memory
    # (dashboard.cache). The browser cookie set by POST /session is only a
    # random id for this process. It is not written to disk.
    app.secret_key = "unused-dashboard-has-no-flask-session"

    @app.errorhandler(keychain.KeychainUnavailable)
    def _keychain_unavailable(exc: keychain.KeychainUnavailable):
        # The CLI already printed the same sentence. Here the browser needs
        # it as JSON; an unhandled typer.Exit would be an HTML 500.
        return jsonify({"error": exc.message}), 503

    from dashboard.api import _ALLOWED_ORIGINS, bp
    from dashboard.cache import BROWSER_COOKIE, exchange_launch_token, open_browser_gate

    open_browser_gate()
    app.register_blueprint(bp)

    @app.post("/session")
    def exchange_launch_session():
        """Trade the one-time fragment token for the browser session cookie.

        This route is not under ``/api``. Every ``/api`` route requires the
        cookie this sets, so the exchange itself cannot require it.
        """
        origin = request.headers.get("Origin")
        if origin not in _ALLOWED_ORIGINS:
            return jsonify({"error": "Bad origin"}), 403
        data = request.get_json(silent=True)
        token = data.get("token") if isinstance(data, dict) else ""
        if not isinstance(token, str):
            token = ""
        session_id = exchange_launch_token(token)
        if session_id is None:
            return jsonify({"error": "Launch token is invalid"}), 403
        response = jsonify({"ok": True})
        response.headers["Cache-Control"] = "no-store"
        response.set_cookie(
            BROWSER_COOKIE,
            session_id,
            httponly=True,
            samesite="Strict",
            path="/",
        )
        return response

    @app.before_request
    def _enforce_localhost_host():
        host = request.headers.get("Host", "")
        if host not in allowed_hosts:
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