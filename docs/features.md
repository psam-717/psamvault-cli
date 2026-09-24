---
title: Features
description: The feature map — what each psamvault capability is, when to reach for it, and where its full documentation lives.
order: 30
---

# Features

One paragraph per capability: **what it is** and **when you reach for it**, with a link to the guide or reference page that documents the detail.

## Vault credentials (site logins)

Store a site's username, password, optional notes and optional login URL, encrypted locally before they are sent to the server. Reach for `psamvault add` when you create an account somewhere, `psamvault get` when you need the password in front of you, and `psamvault update` / `psamvault delete` when the login changes or the account goes away. `psamvault list` and `psamvault site-list` show what exists without decrypting anything. Full detail: [Vault entry commands](reference/commands.md#vault-entry-commands).

## API keys

The same sealed storage, shaped for secrets that belong to a service rather than a person: a name, a service hint, the key value and optional notes. Reach for `psamvault ak-add` when you mint a token for a tool or a project, `psamvault ak-get` when you need to paste it once, and `psamvault ak-update` / `psamvault ak-delete` when a key is rotated or retired. Full detail: [API key commands](reference/commands.md#api-key-commands).

## Secure notes

Encrypted free text with a title and an optional category — for the things that are not a username/password pair: an SSH key, a Wi-Fi password, a set of recovery codes for something else. Note content is encrypted locally before being sent, and `psamvault note-list` shows titles and categories without decrypting anything. Reach for `psamvault note-add` when a secret has no site attached to it. Full detail: [Secure note commands](reference/commands.md#secure-note-commands).

## Search

`psamvault search <query>` looks across site credentials, API keys and notes, matching case-insensitively against the site/entry name, the username or service, and the notes. Matching entries are decrypted and filtered **locally** — passwords and API key values are never searched. Reach for it when you remember the shape of an entry but not its exact name. Full detail: [Search](reference/commands.md#psamvault-search).

## Secure password generation

`psamvault generate` produces a cryptographically secure password using Python's `secrets` module, with control over length, symbols and digits — and can write the result straight into your vault in one step. Reach for it instead of inventing a password, and when you are setting up a new account and want the credential stored before you can forget it. Full detail: [Generate a secure password](reference/commands.md#psamvault-generate).

## Browser autofill

`psamvault open <site>` opens Chromium, navigates to the entry's stored login URL, and types your saved username and password into the login form. The browser stays open so you can handle 2FA or CAPTCHAs manually. If no login URL is stored, psamvault scans the page for a sign-in link and saves the discovered URL for future runs. Reach for it when typing a long password by hand is the annoying part. Requires the Chromium binary: `playwright install chromium`. Full detail: [Open browser and autofill login](reference/commands.md#psamvault-open).

## Web dashboard

A local web dashboard for browsing and managing your vault entries and API keys in a browser, started with `pv dashboard` and served at `http://localhost:8500`. Authentication is CLI-only. Switching tabs and searching does not call the API. Passwords, API keys and notes are revealed on demand rather than embedded in the page. If the session expires, the page tells you to run `pv list` and click Retry, or `pv login` if you are logged out. Reach for it when you want to see and edit the whole vault at once instead of one `get` at a time. Full detail: [Web dashboard](guides/web-dashboard.md).

## Recovery codes

Eight one-time codes you generate while logged in, each of which encrypts your VEK. One code resets your login password without losing your vault data; running `psamvault generate-codes` replaces all existing codes. Reach for recovery codes the moment you are locked out by a forgotten login password — and generate a fresh set today, before that happens. Full detail: [Recovery code commands](reference/commands.md#recovery-code-commands).

## Backup and recovery

A backup here backs up the **key**, not the data: your entries live on the server, encrypted under a key that never changes. `psamvault backup create` stores a passphrase-protected copy of that key in two independent places — a server-side slot and a portable kit file. Reach for it before you lose a machine, and verify it while you still have one. Full detail: [Backup and recovery](guides/backup-and-recovery.md).

## Export and import (a data dump)

`psamvault export` writes an encrypted copy of **the entries themselves** to your Desktop; `psamvault import` re-encrypts them with your current VEK and stores them on the server. This is the artifact that survives server-side data loss, a deleted account, a provider exit, a migration or a handoff — the non-overlapping disaster that a key backup does not cover. Reach for it when the *data* is what is at risk, not your access to it. Full detail: [Export and import](reference/commands.md#export-and-import).

## The agent reveal guardrail

Four commands can print a secret — `get`, `ak-get`, `note-get` and `export --plaintext` (plus `--copy` on any of them). Each one classifies its caller first and refuses when the caller is a program, with the capability alternatives printed and an audit row recorded. Reach for `psamvault approve <entry> --for-agent` when an agent genuinely needs one secret printed once. Full detail: [The agent reveal guardrail](guides/agent-reveal-guardrail.md).

## Typed errors and verbose diagnostics

Failures are typed (`PsamVaultError`, `SessionExpiredError`) and printed as a message plus a hint rather than a traceback, so a network failure, an expired session and a wrong passphrase each say what they are and what to do next. Reach for the global `--verbose` / `-v` flag when you need the underlying error detail. Full detail: [Global options](reference/commands.md#global-options).

## Safe upgrades

`psamvault upgrade` detects whether you are on a pipx install or a source checkout and takes the matching path. On the source track it snapshots your `~/.psamvault` state first, stashes local changes, pulls, restores the stash — leaving it parked with instructions if it conflicts — then reinstalls and smoke-tests the result. Reach for it when a new version is out; the changelog for any new versions is shown automatically on the next command you run. Full detail: [Upgrading](guides/upgrading.md).

## Changelog

`psamvault changelog` shows what changed between versions — the latest version only, the full history, or a specific version. Reach for it after an upgrade, or before one, to see what you are getting. Full detail: [Maintenance and upgrade commands](reference/commands.md#maintenance-and-upgrade-commands).

## Command groups

Every command is available at the root level and also under grouped sub-commands (`psamvault auth login`, `psamvault vault add`, …). Reach for the grouped form to discover what a command family contains. Full detail: [Command groups](reference/commands.md#command-groups).
