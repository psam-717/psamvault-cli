# Dashboard speed and UI

**Status:** 🟢 BUILT 2026-09-24 on `feat/dashboard-speed-and-ui` — not committed in this note. Decisions below still hold.

**Proposed by:** User (psam)
**Date:** 2026-09-24

---

## Summary

`pv dashboard` feels slow because a tab click or a button press is not a local UI change. Each one re-reads the OS keychain, calls the remote API for the username, then calls the remote API again for the list, then writes the Flask session file to disk. Search is worse: every keystroke throws away the search box and does that whole trip again.

The look lives in one hand-written stylesheet (`dashboard/templates/base.html`). [originui.com](https://originui.com/) now redirects to [coss ui](https://coss.com/ui) (Cal.com acquired Origin UI). [ReUI](https://reui.io/) is a separate shadcn component kit. Both are **React + Tailwind source you copy into a project**. They cannot be dropped into the current Jinja templates. The plan below fixes the request path first, then puts a small prebuilt React screen in front of the same Flask app so those components can actually be used. `pv dashboard` stays a pip command. Node is only needed while building the static files, not when Psam runs the dashboard.

Hermes is working in `D:\Projects\py-projects\psamvault-cli`. This plan and any later build stay in the Orca clone.

## What is slow (read from the code, not timed)

I did not hit the live vault. The path below is what the code does on every interaction.

### The tax on every authenticated request

`_is_authenticated()` in `dashboard/routes.py` calls `_try_auto_login()` whenever `~/.psamvault/session.json` exists:

1. `session.load_session()` does **six** `keyring.get_password` calls, one secret at a time (`session.py`). On Windows that is Credential Manager. `is_logged_in()` exists specifically to avoid the keychain for a cheap check, and the dashboard ignores that and pays the full read anyway.
2. `api_client.me()` does `GET /auth/me` on the remote backend, only to fill `session["username"]`. A failed profile fetch is already treated as non-fatal, so this call is not what keeps the page correct.
3. Writing those session keys marks the Flask filesystem session dirty, so flask-session writes `~/.psamvault/flask_sessions/` at the end of the request.

That runs before the route does its own work. A tab switch, a search, a reveal, and a delete all pay it.

### What each gesture actually does

| Gesture | What the browser does | What the server does after the tax above |
|---|---|---|
| Open `/dashboard` | Full document, including a render-blocking Google Fonts stylesheet | `list_vault_entries` **and** `list_api_keys`, one after the other |
| Click "API Keys" | HTMX `GET /api-keys`, swaps `#tab-content` | Fetches the API-key list again. The vault list already on the page is discarded |
| Click "Vault Entries" | HTMX `GET /entries` | Fetches the vault list again |
| Type in search | HTMX `GET` after 300ms, `hx-target="#tab-content"` | Another full list fetch, then the response **replaces the search input**, so focus and the cursor die |
| View / Edit | Full navigation | `GET` one entry, then `decrypt_credentials` / `decrypt_api_key` (password included) even though the password is fetched a second time when Reveal is clicked |
| Reveal / Copy | `fetch POST` | The tax, plus another `GET` and another decrypt |
| Add / Delete / Save | Full form `POST`, then `redirect` to `/dashboard` | Both lists again, plus a full document reload |

There is no `hx-indicator` and no disabled state on submit. While the remote calls run, the button looks like it did nothing, so the click feels stuck. A double-click can fire the POST twice.

The CSS (row slide-in on every swap, a full-viewport grid overlay, `backdrop-filter` on the modal) adds paint cost. It is not the reason a tab waits on the network.

## Bugs and UX gaps found in the same read

These are in the current templates and routes. The build should cover the ones in the "in this plan" column. The rest stay noted so they are not forgotten.

| Issue | Where | In this plan |
|---|---|---|
| Search replaces its own input, so the box loses focus | `entries_table.html`, `api_keys_table.html` (`hx-target="#tab-content"`) | Yes |
| Empty search result uses the "No vault entries yet" copy, so a miss looks like an empty vault | same templates | Yes |
| List failure flashes an error but still returns HTTP 200 and an empty table, so a network blip looks like an empty vault | `_get_vault_entries`, `_get_api_keys` | Yes |
| Detail `GET` decrypts the password even though the HTML only shows dots. Reveal decrypts it again | `entries_detail`, `entries_password` | Yes. Keep plaintext out of the HTML. Decrypt once, on the reveal/copy POST only, except the edit form which must read the current secret to merge a blank field |
| Username and notes from the decrypted blob are in the detail HTML. The docs only promise that the password is absent | `entry_detail.html`, `docs/guides/web-dashboard.md` | Yes. Notes stay masked until reveal, same as the password. Username can stay visible (it is already the list hint) |
| Edit page crashes if the entry disappeared between GET and POST: the template reads `entry.site_name` / `key.name` before the error branch | `entry_edit.html` line 2, `api_key_edit.html` line 2; routes render them with `entry=None` / `key=None` | Yes |
| Blank notes on edit mean "keep the old notes", so notes cannot be cleared | `entries_edit`, `api_keys_edit` | Yes. An explicit empty textarea clears notes. Password stays "blank means keep" |
| Delete uses `window.confirm`. No pending state, so a slow delete looks ignored | table and detail templates | Yes. ReUI alert dialog, button shows pending, second submit ignored |
| No CSRF token on POST forms. Host allow-list blocks DNS rebinding, not another process on localhost | `dashboard/__init__.py`, every POST form | Yes. Same-origin token checked on POST |
| "← Vault" on the API-key toolbar is a fake tab: it `.click()`s the first tab button | `api_keys_table.html` | Yes. Real tabs |
| Icon buttons are emoji with `title` only | tables, detail | Yes. Named buttons from the component kits |
| Secure notes have CLI commands and no dashboard screen | `command/note_commands.py` | No. Separate plan if wanted |
| Signup route only flashes and redirects | `signup_view` | No change. CLI-only login stays |
| Password rules (8 chars, 1 uppercase, 1 digit) reject long passphrases | `_validate_password` | No. Matches the CLI on purpose |

## Why the two libraries force a frontend choice

| | coss ui (was Origin UI) | ReUI |
|---|---|---|
| Site | https://coss.com/ui (originui.com redirects here) | https://reui.io |
| What you install | Nothing central. `shadcn` CLI copies component source | Same. Copy component source |
| Needs | React, Tailwind CSS v4, Base UI | React, Tailwind, Radix / shadcn |

A Jinja template cannot import either one. Two ways to "use" them:

| Approach | Pros | Cons |
|---|---|---|
| **A. Prebuilt React screen, Flask stays the server.** Recommended. | The components are the real ones. Tab switch and search run in the browser on data the page already has. Secrets still never go to a third party: the React app only talks to `127.0.0.1:8500`. | New `dashboard/frontend/` (Vite + React). The built JS/CSS is committed under `dashboard/static/` so `pv dashboard` does not need Node. A dashboard UI change needs a rebuild before commit. |
| **B. Stay on Jinja and redraw the CSS to look similar.** | No new toolchain. Smaller diff. | Does not use those components. We would be copying screenshots. The speed fix can still land. |
| **C. Browser talks to the vault API directly.** | — | Rejected. The VEK would have to live in the browser. Today it stays in the Flask session file and the OS keychain. |

**Locked: A.** Psam chose the prebuilt React screen on 2026-09-24. Speed work in Flask is still phase 1 and does not depend on React. The component swap is phase 2 and is wasted if phase 1 is skipped, because a prettier tab would still wait on the keychain and `/auth/me`.

### Components to copy (only these)

From **coss ui**: button, tabs, dialog, input, textarea, badge, card, avatar, skeleton, alert, tooltip, scroll area.

From **ReUI**: data grid (or table, if the grid's drag-and-drop is more than we need), empty state, alert dialog for delete, sonner toasts, dropdown menu for the row actions (view, edit, delete).

No calendar, kanban, charts, or command palette.

### Look

**Locked: library default.** Psam chose the coss ui / ReUI neutral theme on 2026-09-24. Do not port the gold obsidian tokens. Ship the design tokens those components already use, including their font stack, so the screens match the docs on coss.com/ui and reui.io. Drop the Google Fonts link and the hand-written gold stylesheet with the React build.

## Target request path

```
first paint of /dashboard
  keychain read once per server process (not once per click)
  GET /auth/me once, then keep the username
  GET /vault and GET /apikeys in parallel
  one JSON payload to the page

tab click, search, sort
  browser only. no request

reveal / copy
  POST the one entry. decrypt that field. Cache-Control: no-store. nothing else

add / edit / delete
  one mutation request
  page updates from the response
  no redirect, no second list fetch
```

The in-memory cache holds **ciphertext lists and the username**, never plaintext passwords. It is invalidated on add, update, and delete. It dies when the process dies (`pv dashboard` already kills the old process on start). A TTL of about 30 seconds is a backstop so a CLI change made in another terminal shows up without a restart.

Tokens keep the existing refresh-on-401 path in `api_client._refresh_and_retry`. The dashboard must write the rotated tokens into the Flask session when that happens, which it does not do today (`_try_auto_login` re-reads the keychain instead, which is why the keychain read got put on every request). After phase 1 the keychain is read once, and a refresh updates both the keychain and the in-process copy.

## Build order (after go-ahead)

Each step is its own commit on a fresh `feat/dashboard-speed-and-ui` branch off current `main`. Not this docs branch. Tests for a step land before the behaviour they pin (`tdd-enforcer`). There are **no dashboard tests today**.

1. **Session gate.** Load the keychain once per process. Call `/auth/me` once. Later requests reuse both. A test with a fake keyring and a fake `me()` asserts a second request does not call either again.
2. **One list payload, local tabs and search.** `/dashboard` returns both ciphertext lists. Switching tabs and typing a search do not hit the server. A test asserts `/entries` is not required for a tab change once the payload is present. Failed list fetch renders an error state, not an empty vault.
3. **Mutations without a reload.** Add, edit, delete return the updated row (or the id removed) and the page applies it. Delete uses a confirm dialog and ignores a second click while the request is in flight. Edit of a missing entry returns an error page, not a template crash. Clearing notes works. CSRF checked on POST.
4. **Reveal stays on demand.** Detail view does not decrypt the password or the API key. Reveal and copy do, once. Notes follow the same reveal. HTML responses do not contain the secret. Existing `Cache-Control: no-store` stays.
5. **React screen.** Vite app, the components listed above, **library-default** tokens (not the gold theme), skeleton while the first payload loads, pending state on every button that waits on the network. Built files committed. `pv dashboard` still serves them through Flask and Waitress. No request to `fonts.googleapis.com`. Screens in this pass: vault entries and API keys only. No secure-notes tab.
6. **Docs.** Update `docs/guides/web-dashboard.md` only for behaviour that changed (local search, notes reveal). Changelog is a separate PR, not this one.

### Out of this plan

- Secure notes UI
- Any change under `D:\Projects\py-projects\psamvault-cli`
- VEK rotation, backup, the reveal guardrail's CLI rules (the dashboard already decrypts for the logged-in human; this plan does not widen who can reveal)
- Rewriting `api_client.py` beyond reading the rotated token back into the dashboard cache

## How we will know it worked

- A second click on a tab, and a search keystroke, produce **no** keyring call and **no** HTTP call. Shown by tests with fakes, then by the browser network panel on a local `pv dashboard`.
- First load still does one keychain read, one `/auth/me`, and the two list calls.
- Add, edit, delete, reveal each do one mutation or one decrypt call, and the button shows a pending state until it returns.
- View-source on a detail screen does not contain a password, an API key, or note text.
- Desktop and a narrow viewport both usable (the current CSS already collapses under 700px; the new layout has to as well).

## Decisions locked 2026-09-24

| # | Question | Choice |
|---|---|---|
| 1 | Frontend | **A. Prebuilt React.** Real coss ui and ReUI components. Node only at build time. |
| 2 | Theme | **Library default.** Neutral coss / ReUI tokens, not the gold vault theme. |
| 3 | Scope | **Vault entries and API keys only.** Secure notes stay on the CLI. |

Build does not start until Psam says to. The branch for the plan file is `docs/dashboard-ui-plan`. Implementation, when approved, goes on a new `feat/dashboard-speed-and-ui` branch off `main`.
