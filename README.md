# psamvault

A secure command-line password vault for the terminal — **with a web dashboard**.

Your credentials are **encrypted locally** before being sent to the server — the server never sees your plaintext passwords or your encryption key.

## Demo

[▶️ Watch CLI walkthrough](media/tui-demo.mp4)

A quick walkthrough of the CLI in action.

```bash
psamvault --version     # or -V — show the installed version
```

---

## How it works

```
login password
      │
      ▼
HMAC-SHA256 + pepper  →  master password
                                │
                                ▼
              PBKDF2 (600k rounds) + kdf_salt  →  login key
                                                        │
                                                        ▼
                                              decrypt VEK (AES-256-GCM)
                                                        │
                                                        ▼
                                              VEK encrypts every vault entry
```

- **Pepper** — unique per device, stored in the OS keychain (macOS Keychain, Windows Credential Manager, Linux Secret Service). Never sent to the server.
- **VEK (Vault Encryption Key)** — a random 32-byte key generated at signup. Stored encrypted on the server; decrypted locally at login.
- **kdf_salt** — stored on the server, tied to your account. Ensures two users with the same password get different keys.
- **Backup passphrase** (optional) — wraps that same vault key a second time so a machine with no key material at all can get back in. See [Backup & recovery](#backup--recovery-new-machine-wiped-laptop).

---

## Installation

[pipx](https://pipx.pypa.io) installs psamvault in an isolated environment and exposes it as a global command — the recommended way to install CLI tools.

```bash
pipx install psamvault
```

After installation, you can use either `psamvault` or the shorter `pv` alias:

```bash
psamvault --version
pv --version              # same thing, shorter to type
```

If you don't have pipx yet:

```bash
pip install pipx
pipx ensurepath
```

Then restart your terminal and run `pipx install psamvault`.

Or install from source:

```bash
git clone https://github.com/psam-717/psamvault-cli
cd psamvault-cli/cli
pipx install -e .
```

**Browser autofill setup (one-time):** if you plan to use `psamvault open`, install the Chromium browser binary after installation:

```bash
playwright install chromium
```

---

## Workflow

### 1. Configure

Run this **once** after installing. It generates your pepper and saves the API URL.

```bash
psamvault configure
```

```
 psamvault setup

 Press Enter to accept the default value shown in brackets.

 API URL [https://psam-vault-backend.onrender.com]:
 Generating a secure pepper for your vault...
 Configuration saved.
```

> ⚠️ **Your pepper is stored in the OS keychain** (macOS Keychain, Windows Credential Manager, or Linux Secret Service). It is tied to this device — configuring psamvault on a new machine generates a different pepper, so your login password alone will not get you in there. Keep your recovery codes up to date, and set up a vault backup (`psamvault backup create`) — either one gets you back in on a new machine. See [Backup & recovery](#backup--recovery-new-machine-wiped-laptop).

To review your current config:

```bash
psamvault config-show
```

---

### 2. Sign up

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

---

### 3. Log in

```bash
psamvault login
```

Decrypts your VEK locally using your login password. All sensitive session data — tokens, VEK, and kdf_salt — are stored in the **OS keychain**, not on disk. A lightweight presence marker (`~/.psamvault/session.json`) lets psamvault detect that you are logged in without reading any secrets from disk. All vault commands use this session — you won't be prompted for your password again until the session expires.

On a **new machine** your password alone is not enough: this device has its own pepper, so the login cannot derive the key that opens your vault, and `login` says so instead of blaming the network. Run `psamvault configure` and then `psamvault restore` — see [Backup & recovery](#backup--recovery-new-machine-wiped-laptop).

---

### 4. Check who's logged in

```bash
psamvault whoami
```

---

### Migrate (one-time upgrade)

If you created your account before the master-password scheme was introduced, run this once to upgrade your authentication:

```bash
psamvault migrate
```

Your vault data is preserved. After migrating, regenerate your recovery codes with `psamvault generate-codes`.

---

## Web Dashboard

psamvault includes a **web dashboard** for browsing and managing your vault entries and API keys in a browser.

```bash
pv dashboard
```

Opens a local web server at `http://localhost:8500` running on [Waitress](https://docs.pylonsproject.org/projects/waitress/) (production-grade WSGI).

### Features

- **CLI-only authentication** — the dashboard authenticates through your existing CLI session. No manual login form. Run `pv login` in your terminal, then refresh the dashboard.
- **Server-side sessions** — your VEK and tokens live on the filesystem (`~/.psamvault/flask_sessions/`), never in the browser cookie. The cookie is a random session ID only.
- **On-demand password reveal** — passwords are fetched via `fetch()` on click and held in memory. They are **never embedded in the HTML source**, so inspecting the page or viewing cached source won't leak plaintext secrets.
- **Auto-cleanup** — `pv dashboard` automatically kills any stale server process and clears cached bytecode before starting fresh, so you always see the latest code.

### Login flow

1. Open `http://localhost:8500`
2. If you're logged in via CLI, the dashboard auto-authenticates
3. If not, a CLI instruction screen appears — run `pv login` in your terminal, then click **Auto-Login**
4. Manage entries: view, add, edit, delete — all with instant feedback via toast notifications

> **Security:** The dashboard runs on `127.0.0.1:8500` only. It is not exposed to your network.

---

## Vault commands

### Add a credential

```bash
psamvault add github.com --user me@example.com --pass mysecret
psamvault add github.com --user me@example.com --pass mysecret --notes "2FA enabled"
psamvault add github.com --user me@example.com --login-url https://github.com/login
psamvault add github.com --user me@example.com   # prompts for password
```

The optional `--login-url` flag stores the login page URL for use with `psamvault open`.

### Retrieve a credential

```bash
psamvault get github.com
psamvault get github.com --copy   # copies password to clipboard, clears after 30s
```

Output includes site, username, password, and notes. If a login URL is stored for the entry, it is also shown as a clickable terminal hyperlink (Ctrl+Click to open in the browser).

### List all entries

```bash
psamvault list
```

Shows all stored entries in two labelled sections — **Site Credentials** and **API Keys** — with name/username hint and last-updated date. Does not decrypt entries.

### List site credentials only

```bash
psamvault site-list
```

Shows only site credential entries (same columns as above).

### Search vault entries

```bash
psamvault search github
psamvault search "work email"
psamvault vault search 2FA
```

Searches across both **site credentials** and **API keys**. Matching entries are decrypted and filtered locally — passwords and API key values are never searched. Matches are case-insensitive and checked against:

- **Site name** or **API key name**
- **Username** or **service**
- **Notes**

### Update a credential

```bash
psamvault update github.com --pass mynewpassword
psamvault update github.com --user newuser@example.com --pass newpass
psamvault update github.com --notes "2FA disabled"
psamvault update github.com --login-url https://github.com/login
```

All flags are optional — only the provided fields are changed. Omitting `--login-url` leaves any existing URL unchanged.

### Delete a credential

```bash
psamvault delete github.com
```

Permanent — prompts for confirmation first.

### Generate a secure password

```bash
psamvault generate                          # 20-char password with symbols
psamvault generate --length 32
psamvault generate --length 16 --no-symbols
psamvault generate --length 20 --no-digits
psamvault generate --save github.com --user me@example.com  # generate and save
```

Uses Python's `secrets` module (cryptographically secure).

### Open browser and autofill login

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

---

## Recovery commands

There are two independent ways back into an account: **recovery codes** (below) — eight one-time codes you generate while logged in — and a **vault backup** (`psamvault backup`), a passphrase-protected copy of the vault key that also works on a machine with no key material at all. See [Backup & recovery](#backup--recovery-new-machine-wiped-laptop). Set up both so no single sheet of paper, file or machine is your only way in.

### Generate recovery codes

Run this while logged in to protect your account against a forgotten password.

```bash
psamvault generate-codes
```

Generates **8 one-time recovery codes**. Each code encrypts your VEK — store them somewhere safe. Running this replaces all existing codes.

### Check remaining codes

```bash
psamvault remaining-codes
```

### Recover your account (forgotten password)

```bash
psamvault recover
```

Use one of your saved recovery codes to reset your login password without losing your vault data. The VEK is recovered and re-wrapped with your new login key — no vault re-encryption needed.

---

## Backup & recovery (new machine, wiped laptop)

Your entries live on the server, encrypted under a key that never changes — so losing a machine
loses the **key**, not the data. A backup here therefore backs up the *key*:

```bash
psamvault backup create     # choose a passphrase; stores a server slot + writes a kit file
psamvault backup verify     # prove the backup actually restores THIS vault
psamvault backup status     # what you have: slots, last verified, recovery codes left
```

A backup is two things, and losing either one alone is survivable:

| Half | Where it lives | Covers |
|---|---|---|
| **Backup slot** | on the server (wrapped key + an Argon2id hash of your passphrase) | a lost, deleted or destroyed kit file |
| **Kit file** | a file you keep off-device (`psamvault-key-<date>.json`) | losing server/account access, or a slipped passphrase |

Losing **both** is not survivable. Note also that a kit still sitting on the machine you lose is
not a backup — move it somewhere else (printed, a cloud drive, a password manager) and store the
passphrase somewhere different again.

### Create a backup

```bash
psamvault backup create
psamvault backup create --out ./psamvault-key.json   # write the kit somewhere specific
psamvault backup create --no-upload                  # kit only, keep no server-side copy
```

Prompts for a backup passphrase (minimum 12 characters, confirmed) and writes the kit to your
Desktop, or to your home directory on a machine that has no `Desktop` folder:

| OS | Default kit path |
|---|---|
| Windows | `%USERPROFILE%\Desktop\psamvault-key-<date>.json` |
| macOS / Linux | `~/Desktop/psamvault-key-<date>.json`, or `~/psamvault-key-<date>.json` when there is no Desktop folder |

The file is written owner-only (`0600`, best effort on Windows). It contains key material only —
no entry plaintext, no ciphertext, and never the pepper or the passphrase.

> The passphrase protects the wrapped vault key with PBKDF2-HMAC-SHA256 (600,000 iterations) and
> AES-256-GCM. Anyone who finds both the kit file and the passphrase has your vault, so make the
> passphrase long and keep the two apart.

### Verify it now, not when you need it

```bash
psamvault backup verify
psamvault backup verify --kit ~/Desktop/psamvault-key-2026-09-18.json
```

Unwraps the backup and compares the recovered key with the one this machine is using right now,
byte for byte. An unverified backup is not a backup — run this while you still have the machine.

### Check how recoverable you are

```bash
psamvault backup status
```

Lists your slots (id, kind, created, last verified, active/revoked) next to your remaining
recovery codes, and warns when there is only one path back in.

### Rotate or revoke

```bash
psamvault backup rotate                 # new passphrase; every other slot is revoked
psamvault backup revoke <slot-id>       # retire a single slot
```

> **Known limitation:** rotation revokes the *server-side* copy, but the vault key itself never
> changes — so a kit file you already copied still holds key material that works. Destroy the
> copies you no longer trust. True revocation needs the key itself rotated and every entry
> re-encrypted, which is not implemented yet.

### Restore on a new machine

Run this on the machine that has nothing:

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

What happens:

1. Your passphrase unwraps the vault key — from the server slot, or from the kit file.
2. The key is re-wrapped under a login key derived on **this** machine, and the server stores the
   new wrap. The old password no longer opens the vault, and existing sessions are revoked.
3. It **proves the restore by decrypting one of your real entries** — an HTTP 200 is not evidence.
4. It offers a fresh set of 8 recovery codes, so a restored account never walks away with a
   single way back in.

Nothing is re-encrypted, re-uploaded or moved: the entries on the server are untouched. A kit
whose slot was rotated away is refused while you are online (a courtesy check) and still used
offline.

### Backup vs. data dump — two different disasters

| | `psamvault backup` (key escrow) | `psamvault export` (data dump) |
|---|---|---|
| What it is | a copy of the **key** to data that still exists on the server | a copy of **the data** itself |
| Restores | *access* — new machine, wiped laptop, forgotten login password | the entries themselves |
| Covers | lost/wiped machine, a second machine, a server you can still reach | server-side data loss, deleted account, provider exit, migration, handoff |
| File | `psamvault-key-<date>.json` — key material only | `psamvault-backup-<date>.json` — encrypted entries |

They cover non-overlapping failures, so keep both. Neither one replaces the other.

---

## Changelog

View what's changed between versions.

```bash
psamvault changelog              # latest version only
psamvault changelog latest       # same as above
psamvault changelog all          # full version history
psamvault changelog show 0.3.0   # specific version
```

After every `pipx upgrade psamvault`, the changelog for any new versions is shown automatically on the next command you run — you never need to remember to check.

---

## Upgrade

Check for and install the latest version from PyPI.

```bash
psamvault upgrade
```

Uses `pipx` under the hood. If pipx is not on your PATH, instructions are printed instead.

---

## API key commands

### Add an API key

```bash
psamvault ak-add xai-prod --service XAI --key sk-...
psamvault ak-add stripe-test --service Stripe --key sk_test_... --notes "test mode only"
psamvault ak-add gh-token --service GitHub   # prompts for key
```

### Retrieve an API key

```bash
psamvault ak-get openai-prod
psamvault ak-get openai-prod --copy   # copies key to clipboard, clears after 30s
```

### List all API key entries

```bash
psamvault ak-list
```

Shows entry name, service hint, notes, and last-updated date. Standalone keys
display a **NOTES** column (truncated to 30 chars). Project-grouped keys show
name, pattern, and updated date. Does not decrypt entries.

### Update an API key entry

```bash
psamvault ak-update xai-prod --key sk-newkey...
psamvault ak-update stripe-test --notes "deprecated, use stripe-live"
```

### Delete an API key entry

```bash
psamvault ak-delete openai-prod
```

Permanent — prompts for confirmation first.

---

## Log out

```bash
psamvault logout
```

Revokes the refresh token on the server and deletes the local session file. Your encrypted vault data remains safely on the server.

---

## Export (a data dump — not a key backup)

Export all your vault entries and API keys to an encrypted file on the Desktop.

```bash
psamvault export
```

This is a **data dump** — the file contains your entries. Use it if the server's data were ever lost, if you deleted your account, or if you are moving to another password manager. It is *not* the same as [`psamvault backup`](#backup--recovery-new-machine-wiped-laptop), which escrows the **key** to data that stays on the server. Different disasters, different artifacts: keep both.

You will be prompted for a passphrase to encrypt the export (e.g. `MyDogBarksAtMidnight!23`). The same passphrase is required to import the file later. It is saved as `psamvault-backup-<date>.json` on your Desktop (`%USERPROFILE%\Desktop` on Windows).

> Your vault is left **unchanged** — nothing is deleted.

### Plaintext export (testing only)

```bash
psamvault export --plaintext
```

Saves credentials as readable JSON without encryption. A warning is shown before proceeding because anyone with Desktop access can read the file. Only use this for testing or temporary backups. Plaintext files are saved as `psamvault-backup-plaintext-<date>.json`.

---

## Import

Import credentials from an export file created with `psamvault export` or `psamvault uninstall` — the `psamvault-backup-<date>.json` data dump. This is not the `psamvault-key-<date>.json` kit file; that one belongs to [`psamvault restore`](#backup--recovery-new-machine-wiped-laptop).

```bash
psamvault import
# scans Desktop for backup files and lets you pick one

psamvault import ./psamvault-backup-2026-06-05_120000.json
# specify a path directly
```

Supports both encrypted backups (prompts for passphrase) and plaintext backups (reads directly). If both types exist on the Desktop, encrypted backups are preferred.

You must be logged in before importing — each credential is re-encrypted with your current VEK before being stored on the server. That is also why `import` is not a recovery path for a lost machine: use `psamvault restore` for that.

### Auto-detect after login

After `psamvault login`, if a backup file is found on the Desktop, you will be prompted:

> 📂 Found a psamvault backup file: psamvault-backup-2026-06-05_120000.json
> Would you like to import your saved credentials now?

---

## Uninstall

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

### Reinstall + import your data

If uninstall deleted your account, the entries are gone from the server, so you rebuild from the export file:

```bash
pipx install psamvault
psamvault configure
psamvault signup       # creates a fresh account with a new VEK
psamvault login        # auto-detects the export on the Desktop
# → then import your credentials
```

Or manually: `psamvault import ./psamvault-backup-2026-06-05_120000.json`

That path is for a **deleted account**. If instead your *machine* was lost while the account still exists, do not sign up again: install, `configure`, then `psamvault restore` with your backup passphrase — see [Backup & recovery](#backup--recovery-new-machine-wiped-laptop).

---

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
```

---

## Configuration files

| File | Purpose |
|---|---|
| `~/.psamvault/config.env` | Non-sensitive API URL only |
| `~/.psamvault/session.json` | Empty presence marker `{}` — no secrets |
| `~/.psamvault/flask_sessions/` | Server-side Flask session data (VEK, tokens) — permissions `0700` |

All sensitive values (pepper, tokens, VEK) live exclusively in the OS keychain or in the server-side session directory. The recovery kit file (`psamvault-key-<date>.json`) is written where you point it — the Desktop by default — never inside `~/.psamvault`.

Both `.json` and `.env` files are restricted to owner read/write only (`chmod 600`). The `flask_sessions/` directory is restricted to owner (`chmod 700`).

---

## Security notes

- Your **login password** is never stored or transmitted in plaintext
- Your **VEK** is stored locally only during an active session
- The server stores only **encrypted blobs** — it cannot decrypt your vault
- **AES-256-GCM** is used for all encryption (authenticated — detects tampering)
- **PBKDF2-HMAC-SHA256** with 600,000 iterations for key derivation (NIST recommended minimum)
- **Argon2id** is used to hash recovery codes and backup passphrases server-side (memory-hard, brute-force resistant)
- **Backup kit files** hold key material only — never the pepper, the passphrase, entry plaintext or ciphertext — and are written owner-only (`0600`)
- **A backup passphrase** wraps your vault key with PBKDF2-HMAC-SHA256 (600,000 iterations) + AES-256-GCM; a restore re-wraps that key on the new machine rather than re-encrypting entries
- **Restore is proof-checked** — it decrypts one of your real entries and reports honestly if it cannot
- **Server-side sessions** — the dashboard stores your VEK and tokens on the filesystem, never in the browser cookie. The cookie is a random session ID only.

### OS keychain storage

All sensitive session and config values are stored in the OS keychain — never written to disk in plaintext:

| Value | Keychain key |
|---|---|
| HMAC pepper | `psamvault / config.pepper` |
| Access token (JWT) | `psamvault / session.access_token` |
| Refresh token | `psamvault / session.refresh_token` |
| KDF salt | `psamvault / session.kdf_salt` |
| Vault Encryption Key | `psamvault / session.vek` |
| Encrypted VEK (server copy) | `psamvault / session.encrypted_vek` |
| VEK IV | `psamvault / session.vek_iv` |

Key material, the backup threat model and the known limits of rotation are documented in [SECURITY.md](SECURITY.md).

---

*psamvault — your vault, your keys, your control.*