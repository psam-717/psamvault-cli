# psamvault

A secure command-line password vault for the terminal.

Your credentials are **encrypted locally** before being sent to the server — the server never sees your plaintext passwords or your encryption key.

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

- **Pepper** — unique per device, stored in `~/.psamvault/config.env`. Never sent to the server.
- **VEK (Vault Encryption Key)** — a random 32-byte key generated at signup. Stored encrypted on the server; decrypted locally at login.
- **kdf_salt** — stored on the server, tied to your account. Ensures two users with the same password get different keys.

---

## Installation

[pipx](https://pipx.pypa.io) installs psamvault in an isolated environment and exposes it as a global command — the recommended way to install CLI tools.

```bash
pipx install psamvault
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
 Configuration saved to ~/.psamvault/config.env
```

> ⚠️ **Back up `~/.psamvault/config.env`** — it contains your pepper. Losing it means losing access to your vault.

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

Decrypts your VEK locally using your login password and saves it to a local session file (`~/.psamvault/session.json`). All vault commands use this session — you won't be prompted for your password again until the session expires.

---

### 4. Check who's logged in

```bash
psamvault whoami
```

---

## Vault commands

### Add a credential

```bash
psamvault add github.com --user me@example.com --pass mysecret
psamvault add github.com --user me@example.com --pass mysecret --notes "2FA enabled"
psamvault add github.com --user me@example.com   # prompts for password
```

### Retrieve a credential

```bash
psamvault get github.com
psamvault get github.com --copy   # copies password to clipboard, clears after 30s
```

### List all entries

```bash
psamvault list
```

Shows site name, username hint, and last-updated date. Does not decrypt entries.

### Update a credential

```bash
psamvault update github.com --pass mynewpassword
psamvault update github.com --user newuser@example.com --pass newpass
psamvault update github.com --notes "2FA disabled"
```

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

## Log out

```bash
psamvault logout
```

Revokes the refresh token on the server and deletes the local session file. Your encrypted vault data remains safely on the server.

---

## Command groups

All commands are available at the root level and also under grouped sub-commands:

| Root shorthand | Grouped form |
|---|---|
| `psamvault login` | `psamvault auth login` |
| `psamvault add` | `psamvault vault add` |
| `psamvault generate-codes` | `psamvault recovery generate-codes` |

Run any group without a subcommand to see its full command table:

```bash
psamvault auth
psamvault vault
psamvault recovery
```

---

## Configuration files

| File | Purpose |
|---|---|
| `~/.psamvault/config.env` | API URL and pepper — **back this up** |
| `~/.psamvault/session.json` | Active session tokens and decrypted VEK |

Both files are restricted to owner read/write only (`chmod 600`).

---

## Security notes

- Your **login password** is never stored or transmitted in plaintext
- Your **VEK** is stored locally only during an active session
- The server stores only **encrypted blobs** — it cannot decrypt your vault
- **AES-256-GCM** is used for all encryption (authenticated — detects tampering)
- **PBKDF2-HMAC-SHA256** with 600,000 iterations for key derivation (NIST recommended minimum)
