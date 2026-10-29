---
title: Web dashboard
description: The local dashboard — how to start it, the login flow, and how it interacts with the OS keychain.
order: 70
---

# Web Dashboard

psamvault includes a **web dashboard** for browsing and managing your vault entries and API keys in a browser.

```bash
pv dashboard
```

Opens a local web server at `http://localhost:8500` running on [Waitress](https://docs.pylonsproject.org/projects/waitress/) (production-grade WSGI).

## Features

- **Sign-in on this computer** — the logged-out page has Sign in, Forgot password, and Restore. The password, recovery code, or backup passphrase is posted only to `127.0.0.1`. The vault key and the tokens stay in the dashboard process and the OS keychain. They are not in the page. `pv login` in the terminal still works; **I've already signed in with pv login** re-reads that session.
- **One read of the keychain** — tokens and the VEK are loaded from the OS keychain once, into the dashboard process. A tab change or a search does not read the keychain again and does not call the API. The browser cookie is a random session id, not the vault key or the tokens.
- **Loading** — the first paint, and an edit dialog while its row is fetched, show a shimmer in the shape of the page or the form. The highlight stays still if the system asks for reduced motion.
- **On-demand reveal** — passwords, API keys and notes are fetched when you click Reveal or Copy. They are not in the list, and they are not in the page source. The response is marked `Cache-Control: no-store`. A reveal uses the same gate as `psamvault get` and `psamvault ak-get`. The caller is the process that started `pv dashboard`. An agent context is refused, and every reveal writes an audit row.
- **Project keys** — the Keys tab has a type filter: Standalone, Project-scoped, or Project-unscoped. One type is on screen at a time. A project-scoped key (`project/.env/KEY`) is listed under that project by its leaf name. Keys stored with no project are the Project-unscoped type. Backup copies are marked stale. View, Edit, and Delete send the full stored name.
- **Auto-cleanup** — `pv dashboard` automatically kills any stale server process and clears cached bytecode before starting fresh, so you always see the latest code.

## Login flow

1. Run `pv dashboard`. It opens `http://localhost:8500` with a one-time token in the address fragment. The page posts that token once and then removes it from the address bar. Opening the bare address in another window has no session.
2. If you're logged in via CLI, the dashboard loads your entries and API keys
3. If not, sign in on the page. **Forgot password** asks for one recovery code and a new login password. **Restore** is for a new or wiped machine: your backup passphrase, or a recovery kit file, plus a new login password. You can ask it to show 8 new recovery codes once. A terminal session still works — run `pv login`, then click **I've already signed in with pv login**.
4. If a session-expired notice appears while you are already in, click **Retry** (a `pv list` in the terminal can refresh the same keychain session). Or sign in, reset with a recovery code, or restore, on that notice.
5. **Sign out** revokes the refresh token on the server and clears the local session. **Recovery codes** shows how many are left and, after you confirm your login password, replaces the set and shows the new codes once.
6. Switch tabs and search in the browser. Add, edit, delete, reveal and copy each make one request, and the button stays disabled until it returns

> **Security:** The dashboard runs on `127.0.0.1:8500` only. It is not exposed to your network.

Requests are also checked against an allowed-host list (`127.0.0.1:8500`, `localhost:8500`, `[::1]:8500`); anything else is rejected with `403` before a route runs, so a site that DNS-rebinds its hostname to localhost cannot impersonate the dashboard.

Every `/api` route also requires two things the page has and a bare `curl` does not. The Origin must be `http://127.0.0.1:8500`, `http://localhost:8500`, or `http://[::1]:8500`. A missing Origin is rejected. The cookie set by the one-time exchange must be present. The exchange is `POST /session`, which is not under `/api`, and the token is invalid after that one success. The cookie is `HttpOnly` and `SameSite=Strict`. It is not marked `Secure`, because this server is plain HTTP on localhost. The cookie value is not written to disk.

## How it interacts with the keychain

The dashboard never invents its own authentication — it borrows the session the CLI already established.

- **The page can sign you in, and it still does not hold the vault key.** Sign in, password reset, and restore run inside the local server, the same way `pv login`, `pv recover`, and `pv restore` do. The browser receives a username and, when you just generated them, the new recovery codes. It does not receive the vault key or the tokens. A new account (`pv configure`, `pv signup`) and an old-account migration (`pv migrate`) stay in the terminal, because those create the device key.
- **The pepper still comes from the keychain.** On start-up the dashboard loads the configuration the CLI wrote, which pulls `PSAMVAULT_PEPPER` out of the OS keychain into the process environment so decryption works exactly as it does in the terminal.
- **A keychain that cannot be opened is an error on the page.** If a request finds the OS keychain missing, locked, or without a default collection, the response is that reason and what to do next — the same sentence the CLI prints — not an internal server error. The pepper and the tokens are not written to a file.
- **Session state stays in the dashboard process.** The VEK and tokens are not put in the cookie and are not written to `~/.psamvault/flask_sessions/`. They live in memory until you stop `pv dashboard` or sign out. The cookie is only the id that proves this browser exchanged the launch token. A list is reused for about 30 seconds; **Retry** fetches it again. Mutations update the list already on screen. Signing out clears the vault login and leaves the browser cookie in place, so the page can sign in again without a new launch token.
- **Stale processes are cleaned up.** Because `pv dashboard` kills any process already listening on port 8500 and clears the dashboard's cached bytecode, you always get the current code rather than a server from a previous run. Older installs may still have `flask_sessions/` and `flask_secret_key` on disk. This version does not read them.

The paths, permissions and environment variables above are catalogued in the [Configuration reference](../reference/configuration.md#psamvault-layout).

## Related pages

- [Configuration](../reference/configuration.md) — every file, path and environment variable.
- [Commands](../reference/commands.md#web-dashboard-command) — `psamvault dashboard`.
- [The agent reveal guardrail](agent-reveal-guardrail.md) — why a browser surface and a terminal surface are treated the same way.
