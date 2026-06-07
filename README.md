# psamvault

A secure command-line password vault for the terminal.

Your credentials are **encrypted locally** before being sent to the server — the server never sees your plaintext passwords or your encryption key.

## Demo

<video src="media/tui-demo.mp4" controls width="100%"></video>

A quick walkthrough of the TUI dashboard — login, browsing vault entries, and viewing entry details.

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

> ⚠️ **Your pepper is stored in the OS keychain** (macOS Keychain, Windows Credential Manager, or Linux Secret Service). It is tied to this device — configuring psamvault on a new machine generates a different pepper. Keep your recovery codes up to date so you can always regain vault access.

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

---

### 3. Log in

```bash
psamvault login
```

Decrypts your VEK locally using your login password. All sensitive session data — tokens, VEK, and kdf_salt — are stored in the **OS keychain**, not on disk. A lightweight presence marker (`~/.psamvault/session.json`) lets psamvault detect that you are logged in without reading any secrets from disk. All vault commands use this session — you won't be prompted for your password again until the session expires.

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

Shows entry name, service hint, and last-updated date. Does not decrypt entries.

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

## Export

Export all your vault entries and API keys to an encrypted backup file on the Desktop.

```bash
psamvault export
```

You will be prompted for a passphrase to encrypt the backup (e.g. `MyDogBarksAtMidnight!23`). The same passphrase is required to restore the backup later. The file is saved as `psamvault-backup-<date>.json` on your Desktop.

> Your vault is left **unchanged** — nothing is deleted.

### Plaintext export (testing only)

```bash
psamvault export --plaintext
```

Saves credentials as readable JSON without encryption. A warning is shown before proceeding because anyone with Desktop access can read the file. Only use this for testing or temporary backups. Plaintext files are saved as `psamvault-backup-plaintext-<date>.json`.

---

## Import

Restore credentials from a backup file created with `psamvault export` or `psamvault uninstall`.

```bash
psamvault import
# scans Desktop for backup files and lets you pick one

psamvault import ./psamvault-backup-2026-06-05_120000.json
# specify a path directly
```

Supports both encrypted backups (prompts for passphrase) and plaintext backups (reads directly). If both types exist on the Desktop, encrypted backups are preferred.

You must be logged in before importing — each credential is re-encrypted with your current VEK before being stored on the server.

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
3. Prompts for a passphrase and saves an encrypted backup to `~/Desktop/psamvault-backup-<date>.json`
4. Optionally deletes your account and all data from the server
5. Clears your local session, keychain entries, and config files

### Reinstall + restore

After uninstalling, to restore your data:

```bash
pipx install psamvault
psamvault configure
psamvault signup       # creates a fresh account with a new VEK
psamvault login        # auto-detects the backup on Desktop
# → then import your credentials
```

Or manually: `psamvault import`

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
psamvault uninstall
```

---

## Configuration files

| File | Purpose |
|---|---|
| `~/.psamvault/config.env` | Non-sensitive API URL only |
| `~/.psamvault/session.json` | Empty presence marker `{}` — no secrets |

All sensitive values (pepper, tokens, VEK) live exclusively in the OS keychain.

Both files are restricted to owner read/write only (`chmod 600`).

---

## Security notes

- Your **login password** is never stored or transmitted in plaintext
- Your **VEK** is stored locally only during an active session
- The server stores only **encrypted blobs** — it cannot decrypt your vault
- **AES-256-GCM** is used for all encryption (authenticated — detects tampering)
- **PBKDF2-HMAC-SHA256** with 600,000 iterations for key derivation (NIST recommended minimum)
- **Argon2id** is used to hash recovery codes server-side (memory-hard, brute-force resistant)

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

On **macOS** this is the system Keychain. On **Windows** it is the Credential Manager (`%LOCALAPPDATA%\Microsoft\Credentials`). On **Linux** it is the Secret Service (GNOME Keyring or KWallet).

`~/.psamvault/session.json` contains only `{}` — an empty presence marker. `~/.psamvault/config.env` contains only the non-sensitive API URL. Both files are restricted to owner read/write only (`chmod 600`).
