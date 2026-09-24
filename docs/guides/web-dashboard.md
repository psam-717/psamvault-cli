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

- **CLI-only authentication** — the dashboard authenticates through your existing CLI session. No manual login form. Run `pv login` in your terminal, then click **I've logged in**.
- **One read of the keychain** — tokens and the VEK are loaded from the OS keychain once, into the dashboard process. A tab change or a search does not read the keychain again and does not call the API. Nothing is written to a browser cookie.
- **On-demand reveal** — passwords, API keys and notes are fetched when you click Reveal or Copy. They are not in the list, and they are not in the page source. The response is marked `Cache-Control: no-store`.
- **Auto-cleanup** — `pv dashboard` automatically kills any stale server process and clears cached bytecode before starting fresh, so you always see the latest code.

## Login flow

1. Open `http://localhost:8500`
2. If you're logged in via CLI, the dashboard loads your entries and API keys
3. If not, a CLI instruction screen appears — run `pv login` in your terminal, then click **I've logged in**
4. Switch tabs and search in the browser. Add, edit, delete, reveal and copy each make one request, and the button stays disabled until it returns

> **Security:** The dashboard runs on `127.0.0.1:8500` only. It is not exposed to your network.

Requests are also checked against an allowed-host list (`127.0.0.1:8500`, `localhost:8500`, `[::1]:8500`); anything else is rejected with `403` before a route runs, so a site that DNS-rebinds its hostname to localhost cannot impersonate the dashboard.

## How it interacts with the keychain

The dashboard never invents its own authentication — it borrows the session the CLI already established.

- **Logging in is the CLI's job.** `pv login` decrypts your VEK locally and stores the tokens, the VEK and the kdf_salt in the **OS keychain**. The dashboard reads that session once; it has no password field of its own. That is why step 3 above is an instruction screen rather than a form.
- **The pepper still comes from the keychain.** On start-up the dashboard loads the configuration the CLI wrote, which pulls `PSAMVAULT_PEPPER` out of the OS keychain into the process environment so decryption works exactly as it does in the terminal.
- **Session state stays in the dashboard process.** The VEK and tokens are not put in a cookie and are not written to `~/.psamvault/flask_sessions/`. They live in memory until you stop `pv dashboard` or sign out. A list is reused for about 30 seconds; **Retry** fetches it again. Mutations update the list already on screen.
- **Stale processes are cleaned up.** Because `pv dashboard` kills any process already listening on port 8500 and clears the dashboard's cached bytecode, you always get the current code rather than a server from a previous run. Older installs may still have `flask_sessions/` and `flask_secret_key` on disk. This version does not read them.

The paths, permissions and environment variables above are catalogued in the [Configuration reference](../reference/configuration.md#psamvault-layout).

## Related pages

- [Configuration](../reference/configuration.md) — every file, path and environment variable.
- [Commands](../reference/commands.md#web-dashboard-command) — `psamvault dashboard`.
- [The agent reveal guardrail](agent-reveal-guardrail.md) — why a browser surface and a terminal surface are treated the same way.
