---
title: Installation
description: Install psamvault on Windows, macOS or Linux and get to a working vault.
order: 20
---

# Installation

## Requirements

- **Python 3.11 or higher**
- [pipx](https://pipx.pypa.io) — the recommended installer for CLI tools

## Install with pipx (recommended)

[pipx](https://pipx.pypa.io) installs psamvault in an isolated environment and exposes it as a global command — the recommended way to install CLI tools.

```bash
pipx install psamvault
```

After installation, you can use either `psamvault` or the shorter `pv` alias:

```bash
psamvault --version
pv --version              # same thing, shorter to type
```

If you don't have pipx yet, Debian, Ubuntu and other [PEP 668](https://peps.python.org/pep-0668/) distributions refuse `pip install pipx` (`externally-managed-environment`). Install the distro package instead:

```bash
sudo apt install pipx
pipx ensurepath
```

On a distribution that still allows user-site installs:

```bash
pip install pipx
pipx ensurepath
```

If there is no distro package and pip refuses, bootstrap pipx in its own virtual environment:

```bash
python3 -m venv ~/.pipx-bootstrap
~/.pipx-bootstrap/bin/pip install pipx
~/.pipx-bootstrap/bin/pipx ensurepath
```

Then restart your terminal and run `pipx install psamvault`. Do not pass `--break-system-packages`.

### Not using pipx?

psamvault is published on PyPI, so any PyPI-aware installer works — `pip install psamvault`, or `uv tool install psamvault`. `psamvault upgrade` drives whichever of pipx or `uv tool` owns the install, and pipx remains the documented default (see [Upgrading](guides/upgrading.md)).

## Install from source

```bash
git clone https://github.com/psam-717/psamvault-cli
cd psamvault-cli
pipx install -e .
```

A source checkout gets its own upgrade track — `psamvault upgrade` detects the install type automatically. See [Upgrading](guides/upgrading.md).

## Linux Secret Service

The pepper and the session tokens live in the OS keychain. `--version` and `--help` do not need it, and neither do `psamvault changelog` or `psamvault generate` (without `--save`). Any command that reads or writes a secret does.

Linux uses the Secret Service (gnome-keyring over D-Bus). A desktop session usually starts one and unlocks it at login. A headless machine, a container, or an SSH login does not. Without a service, or with the collection still locked, the command stops on one line instead of a traceback or a prompt that never returns:

```text
✗ No OS keychain is available — on Linux install gnome-keyring, dbus-user-session and libsecret-tools, start a D-Bus session and unlock the keyring; on macOS or Windows unlock the login keychain (see the installation guide)
```

```text
✗ The OS keychain is locked — unlock it and run this command again (on Linux: echo -n '<password>' | gnome-keyring-daemon --unlock --components=secrets; see the installation guide)
```

psamvault does not write the pepper or the tokens to a file when the keychain cannot take them.

A headless setup that works on Debian and Ubuntu:

```bash
sudo apt install gnome-keyring dbus-user-session libsecret-tools
export DBUS_SESSION_BUS_ADDRESS=$(dbus-daemon --session --fork --print-address)
echo -n '<unlock-password>' | gnome-keyring-daemon --unlock --components=secrets
python3 -c 'import keyring; print(keyring.get_keyring())'
```

`python3 -c` should print `keyring.backends.SecretService.Keyring`. Export `DBUS_SESSION_BUS_ADDRESS` in every shell that runs psamvault; without it the keyring is not found and the "no OS keychain" line comes back. If `XDG_RUNTIME_DIR` is unset (a non-login shell), the daemon falls back to `~/.cache/keyring-*`. After `psamvault configure`, `secret-tool search --all service psamvault` shows the pepper entry.

## Browser autofill setup (one-time)

**Browser autofill setup (one-time):** if you plan to use `psamvault open`, install the Chromium browser binary after installation. pipx only puts `psamvault` and `pv` on `PATH`. The `playwright` executable stays inside the pipx environment, so `playwright install chromium` fails with `command not found`. Run that environment's binary — it is the same Playwright the installed CLI imports:

```bash
"$(pipx environment --value PIPX_LOCAL_VENVS)/psamvault/bin/playwright" install chromium
```

```powershell
& "$(pipx environment --value PIPX_LOCAL_VENVS)\psamvault\Scripts\playwright.exe" install chromium
```

A virtualenv or a plain `pip install` uses that environment's Python instead: `python -m playwright install chromium`.

On a bare Linux server the browser also needs system libraries:

```bash
sudo "$(pipx environment --value PIPX_LOCAL_VENVS)/psamvault/bin/playwright" install-deps chromium
```

## Version check

```bash
psamvault --version     # or -V — show the installed version
```

## First-run setup

### 1. Configure

Run this **once** after installing. It generates your pepper and saves the API URL.

```bash
psamvault configure
```

```
 psamvault configure

 Press Enter to accept the default value shown in brackets.

 API URL [https://psam-vault-backend.onrender.com]:
 Generating a secure pepper for your vault...
 Configuration saved.
 API URL : https://psam-vault-backend.onrender.com
 Config  : ~/.psamvault/config.env (API URL only)
 Pepper  : stored in the OS keychain
```

> ⚠️ **Your pepper is stored in the OS keychain** (macOS Keychain, Windows Credential Manager, or Linux Secret Service). It is tied to this device — configuring psamvault on a new machine generates a different pepper, so your login password alone will not get you in there. Keep your recovery codes up to date, and set up a vault backup (`psamvault backup create`) — either one gets you back in on a new machine. See [Backup and recovery](guides/backup-and-recovery.md).

To review your current config:

```bash
psamvault config-show
```

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

### 3. Log in

```bash
psamvault login
```

Decrypts your VEK locally using your login password. All sensitive session data — tokens, VEK, and kdf_salt — are stored in the **OS keychain**, not on disk. A lightweight presence marker (`~/.psamvault/session.json`) lets psamvault detect that you are logged in without reading any secrets from disk. All vault commands use this session — you won't be prompted for your password again until the session expires.

On a **new machine** your password alone is not enough: this device has its own pepper, so the login cannot derive the key that opens your vault. That is one of three reasons a login fails — the other two are a typo (a leading or trailing space is a different password) and an account password replaced by a restore on another machine — and `login` names all three instead of blaming the network. On a machine with no access yet, run `psamvault configure` and then `psamvault restore`; on a machine that still holds a session, `psamvault restore --force` — see [Backup and recovery](guides/backup-and-recovery.md).

### 4. Check who's logged in

```bash
psamvault whoami
```

### Migrate (one-time upgrade)

If you created your account before the master-password scheme was introduced, run this once to upgrade your authentication:

```bash
psamvault migrate
```

Your vault data is preserved. After migrating, regenerate your recovery codes with `psamvault generate-codes`.

## Where state lives

Everything psamvault writes on this machine lives under your home directory. Nothing sensitive is written to disk in plaintext — the pepper, the tokens and the VEK live in the OS keychain.

| Path | What it is |
|---|---|
| `~/.psamvault/config.env` | Non-sensitive API URL only |
| `~/.psamvault/session.json` | Empty presence marker `{}` — no secrets |
| `~/.psamvault/policy.json` | Reveal policy — absent means the safe default |
| `~/.psamvault/audit.jsonl` | Every reveal decision: who asked, the matched signal, allow/deny |
| OS keychain | The pepper and all session material |
| `psamvault-key-<date>.json` | A backup kit, written where you point it — the Desktop by default, never inside `~/.psamvault` |

The full layout, the keychain keys, the environment variables and the per-OS paths are in the [Configuration reference](reference/configuration.md).

## Upgrading a stale install

```bash
psamvault upgrade
```

Upgrades in place through the tool that owns the install — pipx, or `uv tool`. If the owning tool is not on your PATH, instructions are printed instead.

After every upgrade — `psamvault upgrade`, `pipx upgrade psamvault` or `uv tool upgrade psamvault` — the changelog for any new versions is shown automatically on the next command you run — you never need to remember to check. The upgrade tracks, pre-update snapshots and rollback hints are documented in [Upgrading](guides/upgrading.md).

## Uninstall

```bash
psamvault uninstall
```

Cleanly remove psamvault from your machine with an encrypted backup of all credentials. It fetches your entries, decrypts them locally, prompts for a passphrase and saves an encrypted export to `~/Desktop/psamvault-backup-<date>.json`, optionally deletes your account, then clears your local session, keychain entries and config files.

> If you have **no** backup slot, uninstall warns you before deleting the account: the export file would then be the only surviving copy of your data, and the vault key that decrypts it would be gone with the account.

The step-by-step list, the reinstall-and-import path, and the difference between a deleted account and a lost machine are in the [command reference](reference/commands.md#psamvault-uninstall).

## Next

- [Features](features.md) — what you can do once you are logged in.
- [Backup and recovery](guides/backup-and-recovery.md) — set up your way back in *before* you need it.
- [Commands](reference/commands.md) — every command, flag and example.
