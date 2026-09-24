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

- **CLI-only authentication** — the dashboard authenticates through your existing CLI session. No manual login form. Run `pv login` in your terminal, then refresh the dashboard.
- **Server-side sessions** — your VEK and tokens live on the filesystem (`~/.psamvault/flask_sessions/`), never in the browser cookie. The cookie is a random session ID only.
- **On-demand password reveal** — passwords are fetched via `fetch()` on click and held in memory. They are **never embedded in the HTML source**, so inspecting the page or viewing cached source won't leak plaintext secrets.
- **Auto-cleanup** — `pv dashboard` automatically kills any stale server process and clears cached bytecode before starting fresh, so you always see the latest code.

## Login flow

1. Open `http://localhost:8500`
2. If you're logged in via CLI, the dashboard auto-authenticates
3. If not, a CLI instruction screen appears — run `pv login` in your terminal, then click **Auto-Login**
4. Manage entries: view, add, edit, delete — all with instant feedback via toast notifications

> **Security:** The dashboard runs on `127.0.0.1:8500` only. It is not exposed to your network.

Requests are also checked against an allowed-host list (`127.0.0.1:8500`, `localhost:8500`, `[::1]:8500`); anything else is rejected with `403` before a route runs, so a site that DNS-rebinds its hostname to localhost cannot impersonate the dashboard.

## How it interacts with the keychain

The dashboard never invents its own authentication — it borrows the session the CLI already established.

- **Logging in is the CLI's job.** `pv login` decrypts your VEK locally and stores the tokens, the VEK and the kdf_salt in the **OS keychain**. The dashboard reads that session; it has no password field of its own. That is why step 3 above is an instruction screen rather than a form.
- **The pepper still comes from the keychain.** On start-up the dashboard loads the configuration the CLI wrote, which pulls `PSAMVAULT_PEPPER` out of the OS keychain into the process environment so decryption works exactly as it does in the terminal.
- **Session state is server-side, on disk.** The VEK and tokens are kept in `~/.psamvault/flask_sessions/` (permissions `0700`) by flask-session, and the browser cookie holds only a random session ID.
- **A persistent Flask secret key.** On first start the dashboard generates a secret key and stores it at `~/.psamvault/flask_secret_key` (`0600`); it is re-read on later starts so session IDs survive a server restart.
- **Stale processes are cleaned up.** Because `pv dashboard` kills any process already listening on port 8500 and clears the dashboard's cached bytecode, you always get the current code rather than a server from a previous run.

The paths, permissions and environment variables above are catalogued in the [Configuration reference](../reference/configuration.md#psamvault-layout).

## Related pages

- [Configuration](../reference/configuration.md) — every file, path and environment variable.
- [Commands](../reference/commands.md#web-dashboard-command) — `psamvault dashboard`.
- [The agent reveal guardrail](agent-reveal-guardrail.md) — why a browser surface and a terminal surface are treated the same way.
