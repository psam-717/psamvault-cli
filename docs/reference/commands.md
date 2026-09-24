---
title: Commands
description: Every psamvault command and subcommand with its flags, examples and when to run it.
order: 80
---

# Command reference

Every command and subcommand, with its flags, examples and **when to run it**. All commands are available at the root level and also under grouped sub-commands (see [Command groups](#command-groups)).

Flags are listed as the CLI presents them; the short form is first where one exists. Verbose error output is available globally — see [Global options](#global-options).

## Global options

Available on every command:

| Option | What it does |
|---|---|
| `--version`, `-V` | Show version and exit |
| `--verbose`, `-v` | Show underlying error details |
| `--agent` | Declare this process an agent caller: the reveal guardrail refuses secrets (`get`/`ak-get`/`note-get`/`export --plaintext`), and a secret passed on the command line to `add`/`ak-add`/`note-add` is refused too |
| `--install-completion` | Install completion for the current shell |
| `--show-completion` | Show completion for the current shell, to copy it or customize the installation |
| `--help` | Show the command's message and exit |

**When to run the global flags:** `--version` when you need to know what you are running (it is also the version-check command); `--verbose` when a command failed and its one-line message was not enough; `--agent` never by hand — it is for integrations that spawn psamvault, and it is exactly what `PSAMVAULT_AGENT=1` does. See [The agent reveal guardrail](../guides/agent-reveal-guardrail.md).

## Auth and setup commands

### psamvault configure

Set up psamvault on this machine. Run this **once** after installing. It generates your pepper and saves the API URL.

```bash
psamvault configure
```

```
 psamvault configure

 Press Enter to accept the default value shown in brackets.

 API URL [https://psam-vault-backend.onrender.com]:
 Generating a secure pepper for your vault...
 Configuration saved.
```

> ⚠️ **Your pepper is stored in the OS keychain** (macOS Keychain, Windows Credential Manager, or Linux Secret Service). It is tied to this device — configuring psamvault on a new machine generates a different pepper, so your login password alone will not get you in there. Keep your recovery codes up to date, and set up a vault backup (`psamvault backup create`) — either one gets you back in on a new machine. See [Backup and recovery](../guides/backup-and-recovery.md).

**When to run it:** once per machine, immediately after installing, and again on any new or wiped machine *before* `psamvault login` or `psamvault restore`. Without it, every other command that needs the API URL or the pepper fails.

### psamvault config-show

Show the current configuration.

```bash
psamvault config-show
```

**When to run it:** to review the API URL this machine is pointed at, or to confirm `configure` actually completed.

### psamvault signup

Create a new psamvault account.

```bash
psamvault signup
```

Creates your account. Your VEK is generated locally, encrypted with your login key, and only the encrypted copy is sent to the server.

Password requirements:
- At least 8 characters
- At least one uppercase letter
- At least one digit

Signup then offers to set up a vault backup — the cheapest moment to do it. Decline with `--no-backup`; a non-interactive signup prints a reminder instead of prompting.

```bash
psamvault signup              # offers a backup passphrase before it finishes
psamvault signup --no-backup  # skip it; run 'psamvault backup create' later
```

| Option | What it does |
|---|---|
| `--no-backup` | Skip the vault backup prompt (you can run `psamvault backup create` later) |

**When to run it:** once, on a brand-new account. If your *machine* was lost while the account still exists, do **not** sign up again — run `psamvault configure` and then `psamvault restore`.

### psamvault login

Log in to your psamvault account.

```bash
psamvault login
```

Decrypts your VEK locally using your login password. All sensitive session data — tokens, VEK, and kdf_salt — are stored in the **OS keychain**, not on disk. A lightweight presence marker (`~/.psamvault/session.json`) lets psamvault detect that you are logged in without reading any secrets from disk. All vault commands use this session — you won't be prompted for your password again until the session expires.

On a **new machine** your password alone is not enough: this device has its own pepper, so the login cannot derive the key that opens your vault, and `login` says so instead of blaming the network. Run `psamvault configure` and then `psamvault restore` — see [Backup and recovery](../guides/backup-and-recovery.md).

**When to run it:** on a machine that has already been configured and whose session has expired or been logged out. Every vault command needs a session.

### psamvault whoami

Show the currently logged in user.

Displays your username and email without hitting the vault. Useful for confirming which account is active in this session.

```bash
psamvault whoami
```

**When to run it:** before a destructive or account-level command, or when you are not sure which account this terminal is holding.

### psamvault migrate

One-time account migration to the new authentication scheme.

Run this once after updating psamvault. It re-hashes your password using the new master-password scheme (HMAC + Argon2) and logs you in. Your vault data is preserved — nothing is deleted from the server.

After migration, regenerate your recovery codes with:

```bash
psamvault generate-codes
```

```bash
psamvault migrate
```

**When to run it:** once, and only if you created your account before the master-password scheme was introduced.

## Vault entry commands

### psamvault add

Add a new credential entry to your vault. The credentials are encrypted locally before being sent to the server. The server never sees your plaintext password.

```bash
psamvault add github.com --user me@example.com --pass mysecret
psamvault add github.com --user me@example.com --pass mysecret --notes "2FA enabled"
psamvault add github.com --user me@example.com --login-url https://github.com/login
psamvault add github.com --user me@example.com   # prompts for password
```

The optional `--login-url` flag stores the login page URL for use with `psamvault open`.

| Argument / option | What it does |
|---|---|
| `site` | Site name, e.g. `github.com` — not needed with `--claim` |
| `--user`, `-u` | Username or email for the site. Required when you supply the password; with `--claim`, a username the agent recorded is used as-is |
| `--pass`, `-p` | Password (omit to be prompted securely). Refused in an agent context — see [Credential-blind ingress](../guides/agent-credential-blind-ingress.md) |
| `--notes`, `-n` | Optional notes |
| `--login-url` | Login page URL for use with `psamvault open` (e.g. `https://github.com/login`) |
| `--claim` | Fill a claim code an agent printed, in your own terminal |
| `--wait` | After creating a claim, wait until the human fills it |
| `--timeout` | How long `--wait` waits: `30s`, `15m`, `1h` |

**When to run it:** when you create an account somewhere and want the credential stored now. Omit `--pass` to be prompted instead of putting the password in your shell history. Run it with no value from an agent context and it creates a claim instead of prompting.

### psamvault get

Retrieve and decrypt credentials for a site.

```bash
psamvault get github.com
psamvault get github.com --copy   # copies password to clipboard, clears after 30s
```

Output includes site, username, password, and notes. If a login URL is stored for the entry, it is also shown as a clickable terminal hyperlink (Ctrl+Click to open in the browser).

| Option | What it does |
|---|---|
| `--copy`, `-c` | Copy the password to clipboard instead of displaying it |

**When to run it:** when you need to type the password somewhere. This is one of the [gated commands](#agent-guardrail-commands) — it refuses when the caller is a program.

### psamvault list

List all entries.

```bash
psamvault list
```

Shows all stored entries in two labelled sections — **Site Credentials** and **API Keys** — with name/username hint and last-updated date. Does not decrypt entries.

> The command's own `--help` describes it as listing site credentials, API keys **and secure notes** (`psamvault note-list` for notes only). Either way it decrypts nothing.

**When to run it:** to see what exists before a `get`, or to check that an `add`/`import` landed.

### psamvault site-list

List site credentials only.

```bash
psamvault site-list
```

Shows only site credential entries (same columns as above). Shows site names and username hints only — does not decrypt any entries. Use `psamvault get <site>` to retrieve the full credentials for a site.

**When to run it:** when you want sites without API keys and notes in the way.

### psamvault search

Search your vault entries — decrypts and filters locally.

```bash
psamvault search github
psamvault search "work email"
psamvault vault search 2FA
```

Searches across both **site credentials** and **API keys**. Matching entries are decrypted and filtered locally — passwords and API key values are never searched. Matches are case-insensitive and checked against:

- **Site name** or **API key name**
- **Username** or **service**
- **Notes**

| Argument | What it does |
|---|---|
| `query` *(required)* | Search term — matches site name, username, and notes |

**When to run it:** when you remember what an entry is *about* but not its exact name. Note that matching entries are decrypted, so it is a read of your secrets — but nothing is printed.

### psamvault update

Update the credentials for an existing vault entry. Fetches the current entry, decrypts it, merges your changes, then re-encrypts and sends the updated blob with a fresh IV.

```bash
psamvault update github.com --pass mynewpassword
psamvault update github.com --user newuser@example.com --pass newpass
psamvault update github.com --notes "2FA disabled"
psamvault update github.com --login-url https://github.com/login
```

All flags are optional — only the provided fields are changed. Omitting `--login-url` leaves any existing URL unchanged.

| Option | What it does |
|---|---|
| `--user`, `-u` | New username or email |
| `--pass`, `-p` | New password |
| `--notes`, `-n` | New notes |
| `--login-url` | New login page URL for use with `psamvault open` |

**When to run it:** when a password is rotated, a username changes, or you need to add the login URL that `psamvault open` uses.

### psamvault delete

Permanently delete a vault entry.

```bash
psamvault delete github.com
```

Permanent — prompts for confirmation first.

**When to run it:** when the account is gone. There is no undo; the entry is removed on the server.

### psamvault generate

Generate a cryptographically secure password. Uses Python's `secrets` module — suitable for security-sensitive contexts. Optionally save the generated password directly to your vault.

```bash
psamvault generate                          # 20-char password with symbols
psamvault generate --length 32
psamvault generate --length 16 --no-symbols
psamvault generate --length 20 --no-digits
psamvault generate --save github.com --user me@example.com  # generate and save
```

Uses Python's `secrets` module (cryptographically secure).

| Option | What it does |
|---|---|
| `--length`, `-l` | Password length (default 20) `[default: 20]` |
| `--no-symbols` | Exclude special characters |
| `--no-digits` | Exclude digits |
| `--save`, `-s` | Site name to save the generated password to (requires `--user`) |
| `--user`, `-u` | Username to pair with the generated password (used with `--save`) |

**When to run it:** when you are setting a new password — generate it, then store it in the same command with `--save`/`--user` so it never has to pass through your memory.

### psamvault open

Open a browser, navigate to the site's login page, and type your saved credentials.

```bash
psamvault open github.com
psamvault open github.com --no-submit     # fill fields but don't click submit
psamvault open github.com --headless      # run browser without a visible window
```

Opens a Chromium browser, navigates to the stored login URL, and types your saved username and password directly into the login form. The browser stays open so you can handle 2FA or CAPTCHAs manually.

If no login URL is stored for the site, psamvault automatically scans the page for a sign-in link, navigates to it, and saves the discovered URL for future runs. If no link can be found, a warning is shown with a tip to set it manually via `psamvault update <site> --login-url <url>`. You can also store the URL upfront when adding or updating an entry with `--login-url`.

> **One-time setup:** After installing psamvault, run the following once to download the Chromium browser binary:
> ```bash
> playwright install chromium
> ```

| Argument / option | What it does |
|---|---|
| `site` | Site name as stored in your vault, e.g. `github.com` |
| `--headless` | Run browser in headless mode |
| `--no-submit` | Fill credentials but do not click submit |
| `--json` | Output result as JSON (for programmatic use) |
| `--login-url` | Explicit login page URL |
| `--username-selector` | CSS selector for the username/email field |
| `--password-selector` | CSS selector for the password field |
| `--submit-selector` | CSS selector for the submit button |
| `--timeout` | Per-step detection timeout in milliseconds `[default: 8000]` |

**When to run it:** when you want to log in somewhere without typing the password. Use the selector flags when the site's form defeats autodetection.

## API key commands

### psamvault ak-add

Store an API key securely in your vault. The key is encrypted locally before being sent to the server. The server never sees your plaintext key.

```bash
psamvault ak-add xai-prod --service XAI --key sk-...
psamvault ak-add stripe-test --service Stripe --key sk_test_... --notes "test mode only"
psamvault ak-add gh-token --service GitHub   # prompts for key
psamvault ak-add gh-token --service GitHub   # agent: prints a claim code
psamvault ak-add --claim PV-4F2K-91QX        # you: fills that claim
```

| Argument / option | What it does |
|---|---|
| `name` | A unique label for this key, e.g. `xai-prod` — not needed with `--claim` |
| `--service`, `-s` | Service this key belongs to, e.g. `XAI` |
| `--key`, `-k` | The API key value (omit to be prompted securely). Refused in an agent context |
| `--notes`, `-n` | Optional notes e.g. 'read-only key' |
| `--claim` | Fill a claim code an agent printed, in your own terminal |
| `--wait` | After creating a claim, wait until the human fills it |
| `--timeout` | How long `--wait` waits: `30s`, `15m`, `1h` |
| `--from-file` | Store the key from a file, without it ever being printed |
| `--from-key` | With `--from-file`: which `NAME=` line to take out of a `.env` |
| `--from-env` | Store the key from an environment variable |
| `--delete-source` | With `--from-file --from-key`: delete that line afterwards (original kept at `<file>.bak`) |

**When to run it:** when you mint a token for a tool or a project and want it stored encrypted rather than in a `.env` — or, from an agent context with no value, when an agent needs the key stored without ever holding it. Migrating a key that is already in a file is `--from-file`; see [Credential-blind ingress](../guides/agent-credential-blind-ingress.md).

### psamvault ak-get

Retrieve and decrypt a stored API key.

```bash
psamvault ak-get openai-prod
psamvault ak-get openai-prod --copy   # copies key to clipboard, clears after 30s
```

| Option | What it does |
|---|---|
| `--copy`, `-c` | Copy the key to clipboard instead of displaying it |

**When to run it:** when a tool needs the key pasted once. Gated in an agent context — use the capability alternative instead.

### psamvault ak-list

List all stored API key entries.

```bash
psamvault ak-list
```

Shows entry name, service hint, notes, and last-updated date. Standalone keys
display a **NOTES** column (truncated to 30 chars). Project-grouped keys show
name, pattern, and updated date. Does not decrypt entries.

Keys stored via `scan_and_protect(project_name=...)` are grouped under their project name. Use `--project <name>` to filter by project.

| Option | What it does |
|---|---|
| `--project` | Filter by project name. Shows only keys stored under `project/.env/KEY_NAME` |

```bash
psamvault ak-list
psamvault ak-list --project twitter-bot
```

**When to run it:** to see which keys exist, or to check one project's keys before rotating them.

### psamvault ak-update

Update a stored API key entry. Fetches the current entry, decrypts it, merges your changes, then re-encrypts with a fresh IV and saves it.

```bash
psamvault ak-update xai-prod --key sk-newkey...
psamvault ak-update stripe-test --notes "deprecated, use stripe-live"
```

| Option | What it does |
|---|---|
| `--service`, `-s` | New service name |
| `--key`, `-k` | New API key value |
| `--notes`, `-n` | New notes |

**When to run it:** when a key is rotated or its notes change. Only the provided fields are changed.

### psamvault ak-delete

Permanently delete a stored API key entry.

```bash
psamvault ak-delete openai-prod
```

Permanent — prompts for confirmation first. This action cannot be undone.

**When to run it:** when a key is retired. There is no undo.

## Secure note commands

Secure notes store encrypted free text under a title, with an optional category — the things that are not a username/password pair. The content is encrypted locally before being sent to the server. The server never sees the plaintext content.

### psamvault note-add

Store a new secure note.

```bash
psamvault note-add my-ssh-key --content "ssh-rsa AAAAB3NzaC1yc2E..." --category ssh
psamvault note-add wifi-password --content "Home WiFi: MyNetwork / password123" --category wifi
psamvault note-add recovery-codes --content "Code 1: ABC... Code 2: DEF..." --category recovery
```

| Argument / option | What it does |
|---|---|
| `title` | Unique title for this note, e.g. `my-ssh-key` — not needed with `--claim` |
| `--content`, `-c` | The note content (omit to be prompted securely). Refused in an agent context |
| `--category` | Optional category, e.g. `ssh`, `wifi`, `recovery` |
| `--claim` | Fill a claim code an agent printed, in your own terminal |
| `--wait` | After creating a claim, wait until the human fills it |
| `--timeout` | How long `--wait` waits: `30s`, `15m`, `1h` |

**When to run it:** when a secret has no site attached to it — a private key, a Wi-Fi password, a set of codes for something else — or, from an agent context with no content, when an agent needs it stored without ever holding it.

### psamvault note-get

Retrieve and decrypt a stored secure note.

```bash
psamvault note-get my-ssh-key
```

**When to run it:** when you need the note's content. Gated in an agent context, like `get` and `ak-get`.

### psamvault note-list

List all secure notes in your vault.

```bash
psamvault note-list
```

Shows titles and categories only — does not decrypt any content. Use `psamvault note-get <title>` to retrieve the full note.

**When to run it:** to see what notes exist without revealing any of them.

### psamvault note-update

Update an existing secure note. Fetches the current note, decrypts it, merges your changes, then re-encrypts and sends the updated blob with a fresh IV.

```bash
psamvault note-update my-ssh-key --content "ssh-ed25519 AAAAC3N..."
psamvault note-update my-ssh-key --category ssh
psamvault note-update my-ssh-key --new-title my-new-key
```

| Option | What it does |
|---|---|
| `--content`, `-c` | New content for the note |
| `--category` | New category for the note |
| `--new-title` | Rename the note to a new title |

**When to run it:** when the content changes — a rotated SSH key, a new Wi-Fi password — or to re-file a note under a different title or category.

### psamvault note-delete

Permanently delete a secure note.

```bash
psamvault note-delete my-ssh-key
```

This action cannot be undone.

**When to run it:** to remove a note you no longer need, before handing the machine on.

## Recovery code commands

There are two independent ways back into an account: **recovery codes** (below) — eight one-time codes you generate while logged in — and a **vault backup** (`psamvault backup`), a passphrase-protected copy of the vault key that also works on a machine with no key material at all. See [Backup and recovery](../guides/backup-and-recovery.md). Set up both so no single sheet of paper, file or machine is your only way in.

### psamvault generate-codes

Run this while logged in to protect your account against a forgotten password.

```bash
psamvault generate-codes
```

Generates **8 one-time recovery codes**. Each code encrypts your VEK — store them somewhere safe. Running this replaces all existing codes.

**When to run it:** right after signup or a restore, and any time you have used codes or lost the sheet they were on. It asks you to confirm your current login password before replacing the old set.

### psamvault remaining-codes

Check how many recovery codes you have left.

```bash
psamvault remaining-codes
```

Each code is consumed when used to reset your password. Once all 8 are used, run `psamvault generate-codes` (while logged in) to get a fresh set.

**When to run it:** as a checkpoint — `psamvault backup status` shows the same number next to your backup slots.

### psamvault recover

Recover your account (forgotten password).

```bash
psamvault recover
```

Use one of your saved recovery codes to reset your login password without losing your vault data. The VEK is recovered and re-wrapped with your new login key — no vault re-encryption needed.

What it walks you through:

1. Verify your recovery code
2. Recover the Vault Encryption Key (VEK)
3. Set a new login password
4. Re-encrypt the VEK with the new login key
5. Reset the password on the server

Only that code is consumed — the remaining codes stay valid permanently. Your vault entries are NOT re-encrypted — the VEK is static and is simply re-wrapped with your new login key. It needs the machine to be configured, because recovery derives your master password from this device's pepper.

**When to run it:** when you have forgotten your **login password** and hold a recovery code.

> #### `recover` vs `restore` — two different locked doors
>
> | You have lost | You hold | Run |
> |---|---|---|
> | Your login password | one of your 8 recovery codes | `psamvault recover` |
> | The machine (wiped laptop, new device) | your backup passphrase | `psamvault restore` |
> | The machine | a backup kit file | `psamvault restore --from-kit <file>` |
> | The account itself (deleted by `uninstall`) | a `psamvault-backup-<date>.json` export | `psamvault import` |

## Backup and recovery commands

See [Backup and recovery](../guides/backup-and-recovery.md) for the full runbook. What follows is the command surface.

### psamvault backup create

Create a backup slot for your vault key.

```bash
psamvault backup create
psamvault backup create --out ./psamvault-key.json   # write the kit somewhere specific
psamvault backup create --no-upload                  # kit only, keep no server-side copy
```

Prompts for a backup passphrase (minimum 12 characters, confirmed) and writes the kit to your Desktop, or to your home directory on a machine that has no `Desktop` folder:

| OS | Default kit path |
|---|---|
| Windows | `%USERPROFILE%\Desktop\psamvault-key-<date>.json` |
| macOS / Linux | `~/Desktop/psamvault-key-<date>.json`, or `~/psamvault-key-<date>.json` when there is no Desktop folder |

The file is written owner-only (`0600`, best effort on Windows). It contains key material only — no entry plaintext, no ciphertext, and never the pepper or the passphrase.

| Option | What it does |
|---|---|
| `--no-upload` | Write the kit file only — keep no server-side copy of the wrapped key |
| `--out` | Where to write the kit file (default: Desktop) |

> The passphrase protects the wrapped vault key with PBKDF2-HMAC-SHA256 (600,000 iterations) and AES-256-GCM. Anyone who finds both the kit file and the passphrase has your vault, so make the passphrase long and keep the two apart.

**When to run it:** as soon as you have a working vault — signup offers it — and again when you want a kit on a second machine. It adds a slot and revokes nothing.

### psamvault backup verify

Check that your backup passphrase actually restores this vault.

```bash
psamvault backup verify
psamvault backup verify --kit ~/Desktop/psamvault-key-2026-09-18.json
```

Unwraps the backup and compares the recovered key with the one this machine is using right now,
byte for byte. An unverified backup is not a backup — run this while you still have the machine.

| Option | What it does |
|---|---|
| `--kit` | Verify a kit file instead of the server-side slot |

**When to run it:** after every `backup create` or `backup rotate`, and periodically thereafter. It changes nothing — this is the safe alternative to rehearsing a real restore.

### psamvault backup status

Check how recoverable you are.

```bash
psamvault backup status
```

Lists your slots (id, kind, created, last verified, active/revoked) next to your remaining
recovery codes, and warns when there is only one path back in.

**When to run it:** before you travel, before you wipe a machine, or any time you want the honest answer to "how many ways back in do I have?".

### psamvault backup rotate

Rotate or revoke — replace your backup passphrase with a new one and revoke the old slots.

```bash
psamvault backup rotate                 # new passphrase; every other slot is revoked
psamvault backup revoke <slot-id>       # retire a single slot
```

Which one you want depends on what you stopped trusting:

| What happened | What to run |
|---|---|
| You want another backup, or a kit on a second machine | `psamvault backup create` — adds a slot and revokes nothing |
| The **passphrase** was exposed or is weak, or someone you shared it with no longer needs access | `psamvault backup rotate` — new passphrase, every other slot revoked, new kit |
| **One** kit file leaked and you know which one | `psamvault backup revoke <slot-id>`, using the id from `psamvault backup status` |
| The **kit file** itself leaked — whoever holds it holds your key | neither, which is the limitation below |

`rotate` never asks for the old passphrase (your session already holds the vault key), so it is
also how you replace a passphrase you have forgotten.

| Option | What it does |
|---|---|
| `--out` | Where to write the new kit file (default: Desktop) |

> **Known limitation:** rotation revokes the *server-side* copy, but the vault key itself never
> changes — so a kit file you already copied still holds key material that works. Destroy the
> copies you no longer trust. True revocation needs the key itself rotated and every entry
> re-encrypted, which is not implemented yet.

**When to run it:** when the passphrase is weak or exposed, when someone you shared it with no longer needs access, or when you have forgotten it and still have a working machine.

### psamvault backup revoke

Revoke a single backup slot (e.g. a kit file that leaked).

```bash
psamvault backup revoke <slot-id>
```

| Argument | What it does |
|---|---|
| `slot_id` *(required)* | Slot id from `psamvault backup status` |

**When to run it:** when one kit file leaked and you know which slot it came from.

### psamvault restore

Restore vault access on a new or wiped machine.

```bash
psamvault configure      # once per machine — generates this device's pepper
psamvault restore
```

It asks for your username, your backup passphrase and a new login password. Or restore straight
from the kit file:

```bash
psamvault restore --from-kit ~/Desktop/psamvault-key-2026-09-18.json
psamvault restore --from-kit ./psamvault-key.json --no-codes   # skip the recovery-code offer
psamvault restore --force                                      # overwrite an existing session
```

You need: your username, your backup passphrase (or a kit file), and a new login password. Your entries are not touched — only the key wrap is replaced.

| Option | What it does |
|---|---|
| `--from-kit` | Restore from a kit file instead of the server-side slot |
| `--force` | Run even though this machine already has a session |
| `--no-codes` | Do not offer a fresh set of recovery codes at the end |

`psamvault backup restore` is the same command under the grouped form. The full runbook — what the command does in order, what changes the moment you restore, and the failure modes — is in [Backup and recovery](../guides/backup-and-recovery.md).

**When to run it:** on a machine that has nothing, after `psamvault configure`. Not for a deleted account, and not for a forgotten password on a working machine.

> #### Backup vs. data dump — two different disasters
>
> | | `psamvault backup` (key escrow) | `psamvault export` (data dump) |
> |---|---|---|
> | What it is | a copy of the **key** to data that still exists on the server | a copy of **the data** itself |
> | Restores | *access* — new machine, wiped laptop, forgotten login password | the entries themselves |
> | Covers | lost/wiped machine, a second machine, a server you can still reach | server-side data loss, deleted account, provider exit, migration, handoff |
> | File | `psamvault-key-<date>.json` — key material only | `psamvault-backup-<date>.json` — encrypted entries |
>
> They cover non-overlapping failures, so keep both. Neither one replaces the other.

## Export and import

### psamvault export

Export (a data dump — not a key backup). Export all your vault entries and API keys to an encrypted file on the Desktop.

```bash
psamvault export
```

This is a **data dump** — the file contains your entries. Use it if the server's data were ever lost, if you deleted your account, or if you are moving to another password manager. It is *not* the same as `psamvault backup`, which escrows the **key** to data that stays on the server. Different disasters, different artifacts: keep both.

You will be prompted for a passphrase to encrypt the export (e.g. `MyDogBarksAtMidnight!23`). The same passphrase is required to import the file later. It is saved as `psamvault-backup-<date>.json` on your Desktop (`%USERPROFILE%\Desktop` on Windows).

> Your vault is left **unchanged** — nothing is deleted.

| Option | What it does |
|---|---|
| `--plaintext`, `-p` | Save credentials in plaintext instead of encrypted (less secure) |

**When to run it:** when the *data* is what is at risk — a provider you no longer trust, a migration, a handoff, or a deleted account you may want to rebuild later.

#### Plaintext export (testing only)

```bash
psamvault export --plaintext
```

Saves credentials as readable JSON without encryption. A warning is shown before proceeding because anyone with Desktop access can read the file. Only use this for testing or temporary backups. Plaintext files are saved as `psamvault-backup-plaintext-<date>.json`.

Before writing, it names exactly what it is about to expose (how many site passwords, API keys and notes) and asks you to confirm. Plaintext export is one of the [gated commands](#agent-guardrail-commands): in an agent context it is refused, and no approval token can cover it.

### psamvault import

Import credentials from an export file created with `psamvault export` or `psamvault uninstall` — the `psamvault-backup-<date>.json` data dump. This is not the `psamvault-key-<date>.json` kit file; that one belongs to `psamvault restore`.

```bash
psamvault import
# scans Desktop for backup files and lets you pick one

psamvault import ./psamvault-backup-2026-06-05_120000.json
# specify a path directly
```

Supports both encrypted backups (prompts for passphrase) and plaintext backups (reads directly). If both types exist on the Desktop, encrypted backups are preferred.

You must be logged in before importing — each credential is re-encrypted with your current VEK before being stored on the server. That is also why `import` is not a recovery path for a lost machine: use `psamvault restore` for that.

| Argument | What it does |
|---|---|
| `path` | Path to a backup file (auto-detects on Desktop if omitted) |

**When to run it:** to bring an export dump into the account you are logged into now — a reinstall, a migration, or a rebuild after a deleted account.

#### Auto-detect after login

After `psamvault login`, if a backup file is found on the Desktop, you will be prompted:

> 📂 Found a psamvault backup file: psamvault-backup-2026-06-05_120000.json
> Would you like to import your saved credentials now?

## Log out

### psamvault logout

```bash
psamvault logout
```

Revokes the refresh token on the server and deletes the local session file. Your encrypted vault data remains safely on the server.

**When to run it:** on a shared machine, before walking away from a session you no longer need, or to drop a pending agent approval — `psamvault logout` drops every pending approval.

## Web dashboard command

### psamvault dashboard

```bash
pv dashboard
```

Launch the web dashboard for psamvault (fresh — kills stale servers and clears cache). Opens a local web server at `http://localhost:8500` running on Waitress (production-grade WSGI).

The dashboard is not part of a command group — it is available at the root only. See [Web dashboard](../guides/web-dashboard.md) for the features, the login flow and the keychain interaction.

**When to run it:** when you want to browse and edit the whole vault at once, or when `get` one entry at a time is the wrong shape.

## Maintenance and upgrade commands

### psamvault changelog

View what's changed between versions.

```bash
psamvault changelog              # latest version only
psamvault changelog latest       # same as above
psamvault changelog all          # full version history
psamvault changelog show 0.3.0   # specific version
```

| Subcommand | What it does |
|---|---|
| `latest` | Show only the latest version's changelog |
| `all` | Show the full changelog for all versions |
| `show <version>` | Show the changelog for a specific version |

**When to run it:** after an upgrade (though the notice is automatic — see below), or before one, to see what you would be getting.

After every `pipx upgrade psamvault`, the changelog for any new versions is shown automatically on the next command you run — you never need to remember to check.

### psamvault upgrade

Check for and install the latest version from PyPI.

```bash
psamvault upgrade
```

Uses `pipx` under the hood. If pipx is not on your PATH, instructions are printed instead.

The command detects whether you are on a pipx install or a source checkout and takes the matching path — including a pre-update snapshot of your psamvault state, stashing of local changes, and rollback hints. See [Upgrading](../guides/upgrading.md).

**When to run it:** when a new version is out, or when the update notice tells you one is.

### psamvault uninstall

Cleanly remove psamvault from your machine with an encrypted backup of all credentials.

```bash
psamvault uninstall
```

**What it does:**

1. Fetches all vault entries and API keys from the server
2. Decrypts them locally with your VEK
3. Prompts for a passphrase and saves an encrypted export to `~/Desktop/psamvault-backup-<date>.json`
4. Optionally deletes your account and all data from the server
5. Clears your local session, keychain entries, and config files

> If you have **no** backup slot, uninstall warns you before deleting the account: the export file would then be the only surviving copy of your data, and the vault key that decrypts it would be gone with the account.

#### Reinstall + import your data

If uninstall deleted your account, the entries are gone from the server, so you rebuild from the export file:

```bash
pipx install psamvault
psamvault configure
psamvault signup       # creates a fresh account with a new VEK
psamvault login        # auto-detects the export on the Desktop
# → then import your credentials
```

Or manually: `psamvault import ./psamvault-backup-2026-06-05_120000.json`

That path is for a **deleted account**. If instead your *machine* was lost while the account still exists, do not sign up again: install, `configure`, then `psamvault restore` with your backup passphrase — see [Backup and recovery](../guides/backup-and-recovery.md).

**When to run it:** when you are leaving psamvault, or moving the vault to another machine deliberately. Run it while logged in, and keep the export it writes.

## Agent guardrail commands

The four commands that print a secret (`get`, `ak-get`, `note-get`, `export --plaintext`, plus `--copy` on any of them) ask *who is calling* first and refuse when the caller is a program. The guide is [The agent reveal guardrail](../guides/agent-reveal-guardrail.md); this is the command surface.

### psamvault approve

Approve ONE reveal of ONE entry for an agent.

```bash
# you, in your own terminal — names the entry, the window, and asks once
psamvault approve github.com --for-agent
psamvault approve openai-prod --for-agent --ttl 60

# the agent's next reveal of that ONE entry
psamvault get github.com
```

The next reveal of that entry succeeds **once**; a second attempt is refused. The approval covers nothing else — not another entry, and never a whole-vault dump. `approve` requires a real terminal (both stdin and stdout), so an agent cannot approve itself out of a refusal, and `--for-agent` is required so the intent to hand a secret to a *program* is typed rather than assumed. `psamvault logout` drops every pending approval.

| Argument / option | What it does |
|---|---|
| `entry` *(required)* | Entry to approve: a site, an API key name, or a note title |
| `--for-agent` | Confirm this reveal is for an agent rather than for you |
| `--ttl` | Seconds the approval stays live (15–3600, default from policy) |

`approve` checks that the entry exists (sites, then API keys, then notes) before minting, so a typo cannot produce a token that looks live but unlocks nothing. The window defaults to `approval_ttl_seconds` in [policy.json](configuration.md#policyjson); a `--ttl` outside 15–3600 is clamped and the command tells you which value it used.

**When to run it:** when an agent has been refused and genuinely needs one secret printed once. Never automatically, and never from inside the agent.

### Global `--agent` flag

```bash
psamvault --agent get github.com
```

Declares the process an agent caller: the reveal guardrail refuses secrets (`get`/`ak-get`/`note-get`/`export --plaintext`), and the ingress guardrail refuses a secret passed on the command line to `add`/`ak-add`/`note-add` — those commands return a claim code instead. It sets `PSAMVAULT_AGENT=1` before any command body runs, which is the same thing the MCP server does for its subprocesses.

**When to run it:** when you are writing an integration and want to be honest about what you are, rather than relying on the guardrail's marker detection. A human at a terminal never needs it.

## Agent ingress commands

The reveal guardrail decides *who may print* a secret. This is the other direction: an agent that has to **create** an entry must not be given the value, so it creates a claim and the human fills it. The guide is [Credential-blind ingress](../guides/agent-credential-blind-ingress.md); this is the command surface.

### psamvault pending

Show the claims waiting for a human — and cancel one.

```bash
psamvault pending                              # everything outstanding
psamvault pending --code PV-4F2K-91QX          # one claim in full
psamvault pending --cancel PV-4F2K-91QX        # stop a claim
```

A claim appears when `add`, `ak-add` or `note-add` runs without a value in an agent context: instead of prompting, the CLI prints `PV-XXXX-XXXX` and the exact command you run to fill it.

```text
  CODE            FAMILY      ENTRY                  STATUS
  PV-4F2K-91QX    api_key     github-prod (GitHub)   pending, 12m left
  PV-7B3M-02ZC    credential  github.com             filled 3m ago
```

| Option | What it does |
|---|---|
| `--code` | Show one claim in full: family, name, service or category, notes, time left |
| `--cancel` | Delete one claim, so its code stops working |

Claims live in `~/.psamvault/pending/`, owner-only, hold **metadata only** — never a value — are single-use, and expire 15 minutes after they are created. `pending` is never gated: an agent must always be able to see the claim it created, and it cannot fill one. A claim is not tied to your session, so `psamvault logout` leaves the list alone — they expire on their own, or you cancel them.

**When to run it:** when an agent says it created a claim for you, when `--wait` is blocking and you want to know why, to sweep up claims you never filled, and to cancel one you no longer want.

### Filling a claim

| The agent ran | You run |
|---|---|
| `psamvault ak-add rh-token --service "Red Hat"` | `psamvault ak-add --claim PV-4F2K-91QX` |
| `psamvault add github.com` | `psamvault add --claim PV-4F2K-91QX` |
| `psamvault note-add ssh-key --category ssh` | `psamvault note-add --claim PV-4F2K-91QX` |

Each asks for the value with hidden input, stores the entry encrypted, and only then spends the code. A fill from an agent context is refused; a fill that fails (say the name already exists) leaves the claim fillable, so a typo does not cost you the code.

## Command groups

All commands are available at the root level and also under grouped sub-commands:

| Root shorthand | Grouped form |
|---|---|
| `psamvault login` | `psamvault auth login` |
| `psamvault add` | `psamvault vault add` |
| `psamvault site-list` | `psamvault vault site-list` |
| `psamvault generate-codes` | `psamvault recovery generate-codes` |
| `psamvault ak-add` | `psamvault ak add` |
| `psamvault open` | `psamvault browser open` |
| `psamvault changelog` | `psamvault changelog latest` |
| `psamvault upgrade` | `psamvault upgrade` |
| `psamvault export` | `psamvault export` |
| `psamvault import` | `psamvault import` |
| `psamvault uninstall` | `psamvault uninstall` |
| `psamvault backup create` | `psamvault backup create` |
| `psamvault restore` | `psamvault backup restore` |
| `psamvault approve` | `psamvault approve` |
| `psamvault pending` | — |
| `psamvault dashboard` | — |

Run any group without a subcommand to see its full command table:

```bash
psamvault auth
psamvault vault
psamvault recovery
psamvault ak
psamvault browser
psamvault changelog
psamvault upgrade
psamvault export
psamvault import
psamvault backup
psamvault uninstall
psamvault approve --help
```

### Grouped forms available in each group

Every command in this reference is also reachable through its group:

| Group | Subcommands |
|---|---|
| `psamvault auth` | `signup`, `login`, `logout`, `whoami`, `configure`, `config-show` |
| `psamvault vault` | `add`, `get`, `list`, `site-list`, `update`, `delete`, `generate`, `search` |
| `psamvault recovery` | `generate-codes`, `remaining-codes`, `recover` |
| `psamvault ak` | `add`, `get`, `list`, `update`, `delete` |
| `psamvault browser` | `open` |
| `psamvault note` | `add`, `get`, `list`, `update`, `delete` |
| `psamvault changelog` | `latest`, `all`, `show` |
| `psamvault backup` | `create`, `verify`, `status`, `rotate`, `revoke`, `restore` |

`export`, `import`, `uninstall`, `upgrade`, `restore`, `approve`, `pending` and `dashboard` are root-level commands with no group of their own; `psamvault backup restore` is the one grouped alias for `psamvault restore`.

## Related pages

- [Configuration](configuration.md) — every file, path and environment variable.
- [Backup and recovery](../guides/backup-and-recovery.md) — the runbook behind `backup` and `restore`.
- [Credential-blind ingress](../guides/agent-credential-blind-ingress.md) — letting an agent create an entry without ever holding the secret.
- [Upgrading](../guides/upgrading.md) — the two upgrade tracks in full.
- [Web dashboard](../guides/web-dashboard.md) — the dashboard in full.
