# psamvault

A secure command-line password vault for the terminal — **with a web dashboard**.

Your credentials are **encrypted locally** before being sent to the server — the server never sees your plaintext passwords or your encryption key.

Your entries live on the server, encrypted under a key that never changes, and the key material stays on your device: the pepper is generated per machine, kept in the OS keychain, and never sent anywhere. That one design choice explains everything that is unusual about using psamvault — what a lost laptop costs you (the *key*, not the data), why a login password alone will not get you in on a new machine, and why a backup here means a backup of the key rather than a copy of your entries.

**Full documentation:** [docs/README.md](docs/README.md).

## Demo

[▶️ Watch CLI walkthrough](media/tui-demo.mp4)

A quick walkthrough of the CLI in action.

```bash
psamvault --version     # or -V — show the installed version
```

## Features

- **Vault credentials** — site logins (username, password, notes, login URL) encrypted locally before they reach the server. [Guide](docs/reference/commands.md#vault-entry-commands)
- **API keys** — the same sealed storage for service tokens, with service hints, notes and project grouping. [Guide](docs/reference/commands.md#api-key-commands)
- **Secure notes** — encrypted free text for the secrets that are not a username/password pair. [Guide](docs/reference/commands.md#secure-note-commands)
- **Search** — find an entry by site, username/service or notes; matching entries are decrypted and filtered locally, and passwords are never searched. [Guide](docs/reference/commands.md#psamvault-search)
- **Secure password generation** — `secrets`-based passwords with length/symbol/digit control, and an option to store the result in one step. [Guide](docs/reference/commands.md#psamvault-generate)
- **Browser autofill** — open the site's login page and type the saved credentials into the form, leaving the window open for 2FA. [Guide](docs/reference/commands.md#psamvault-open)
- **Web dashboard** — browse and edit the whole vault in a browser, after authenticating through your existing CLI session. [Guide](docs/guides/web-dashboard.md)
- **Recovery codes** — eight one-time codes, each encrypting your vault key, for a forgotten login password. [Guide](docs/reference/commands.md#recovery-code-commands)
- **Backup & recovery** — a passphrase-protected copy of the vault key, stored as a server slot *and* a portable kit file, with verification that proves it restores your actual vault. [Runbook](docs/guides/backup-and-recovery.md)
- **Export & import** — the other artifact: a data dump of the entries themselves, for server-side data loss, a deleted account, a migration or a handoff. [Guide](docs/reference/commands.md#export-and-import)
- **Agent reveal guardrail** — the four commands that print a secret classify their caller and refuse when the caller is a program, with capabilities and a one-shot human approval as the way through. [Guide](docs/guides/agent-reveal-guardrail.md)
- **Safe upgrades** — install-type detection, a pre-update snapshot of your state, stashed local changes and rollback hints. [Guide](docs/guides/upgrading.md)
- **Typed errors** — network failures, expired sessions and wrong passphrases each say what they are and what to do next, with `-v` for the underlying detail. [Guide](docs/reference/commands.md#global-options)
- **Command groups** — every root command also works under its group (`psamvault auth login`, `psamvault vault add`, `psamvault ak get`, …). [Guide](docs/reference/commands.md#command-groups)
- **Changelog** — the latest version, the full history, or one specific version, plus an automatic notice after every upgrade. [Guide](docs/reference/commands.md#maintenance-and-upgrade-commands)

The documentation map — overview, guides and reference — is in [docs/README.md](docs/README.md).

## Installation

```bash
pipx install psamvault
```

[pipx](https://pipx.pypa.io) installs psamvault in an isolated environment and exposes it as a global command — the recommended way to install CLI tools. After installation you can use either `psamvault` or the shorter `pv` alias.

Windows, macOS, Linux — plus the pip/uv and source paths, the one-time browser-autofill setup, first-run configuration, where state lives, upgrading and uninstall — are all in **[docs/installation.md](docs/installation.md)**.

## Quick start

```bash
psamvault configure                    # once per machine — generates this device's pepper
psamvault signup                       # create an account (it offers a vault backup before it finishes)
psamvault add github.com --user me@example.com
psamvault get github.com
psamvault backup create                # do this while you still have the machine
```

`psamvault login` replaces `signup` on a machine where the account already exists, and `psamvault restore` replaces it on a machine that has nothing but a backup passphrase.

The full first-run walkthrough — the pepper prompt, the password rules, and what `configure` writes where — is in [docs/installation.md](docs/installation.md).

Every command, every flag, and — importantly — **when** to run each one: [docs/reference/commands.md](docs/reference/commands.md).

## Security

- Your **login password** is never stored or transmitted in plaintext
- The server stores only **encrypted blobs** — it cannot decrypt your vault
- **AES-256-GCM** for all encryption (authenticated — detects tampering); **PBKDF2-HMAC-SHA256** with 600,000 iterations for key derivation; **Argon2id** server-side for recovery codes and backup passphrases
- **Backup kit files** hold key material only — never the pepper, the passphrase, entry plaintext or ciphertext — and are written owner-only
- **A backup protects against losing a machine, not against a compromised one**, and rotating a backup passphrase does not disarm a kit file that was already copied — a kit is not a data backup either
- The **reveal guardrail is a guardrail, not a boundary**: an agent with your shell *and* your keychain can read the credential anyway. The real boundary is running the agent as a different OS user
- Your **VEK** is stored locally only during an active session, and **restore is proof-checked** — it decrypts one of your real entries and reports honestly if it cannot
- **Server-side sessions** — the dashboard keeps your VEK and tokens on the filesystem, never in the browser cookie, which holds a random session ID only

The threat model, the key-material table, the guardrail's measured limits and the known limitations of rotation are documented in [SECURITY.md](SECURITY.md). The file-by-file and variable-by-variable detail is in [docs/reference/configuration.md](docs/reference/configuration.md).

## Documentation

| Page | What it covers |
|---|---|
| [docs/overview.md](docs/overview.md) | What psamvault is, how the client-side encryption model works, and what the server can and cannot see |
| [docs/installation.md](docs/installation.md) | Install on Windows, macOS or Linux; first-run setup; where state lives; upgrading and uninstall |
| [docs/features.md](docs/features.md) | The feature map — what each capability is, and when you reach for it |
| [docs/guides/backup-and-recovery.md](docs/guides/backup-and-recovery.md) | The runbook for a new machine or a wiped laptop, and the failure modes |
| [docs/guides/agent-reveal-guardrail.md](docs/guides/agent-reveal-guardrail.md) | Who may print a secret, the three policy modes, and the measured limits |
| [docs/guides/upgrading.md](docs/guides/upgrading.md) | The pipx and source upgrade tracks, state snapshots, stashing and rollback |
| [docs/guides/web-dashboard.md](docs/guides/web-dashboard.md) | The dashboard: features, login flow and how it interacts with the keychain |
| [docs/reference/commands.md](docs/reference/commands.md) | Every command and subcommand, with flags, examples and when to run it |
| [docs/reference/configuration.md](docs/reference/configuration.md) | Every file, path and environment variable |

The pages are grouped the way you would use them: **Introduction** (what it is, how to install it, what it does), **Guides** (the runbooks — backup and recovery first), and **Reference** (every command, every file). The index is [docs/README.md](docs/README.md).

## What psamvault is not

- **Not a boundary against a compromised machine.** The reveal guardrail is a guardrail, not a boundary, and a backup protects against *losing* a machine, not against a *compromised* one.
- **Not true key revocation.** Rotating a backup passphrase revokes the server-side copy, but the vault key itself never changes — a kit file you already copied still holds key material that works.
- **Not a data backup.** A kit file restores *access* to data that still lives on the server; `psamvault export` is the artifact that carries the entries.
- **Not a single point of failure, by design.** Recovery codes and a vault backup are independent paths back in — set up both.
- **Not a way to recover a deleted account.** If `uninstall` deleted the account, the entries are gone from the server; an export dump is what rebuilds them.

## Requirements

- **Python 3.11 or higher**
- [pipx](https://pipx.pypa.io) — the recommended installer
- An OS keychain psamvault can write to — Windows Credential Manager, macOS Keychain or Linux Secret Service
- The Chromium browser binary if you want browser autofill (a one-time step covered in the [installation page](docs/installation.md))

## Contributing

Contributions are welcome. [CONTRIBUTING.md](CONTRIBUTING.md) covers local setup, the branch and commit conventions, and how to submit a change. Please report security issues privately through [GitHub Security Advisories](https://github.com/psam-717/psamvault-cli/security/advisories/new) rather than in a public issue — see [SECURITY.md](SECURITY.md).

## Licence

MIT — see [LICENSE](LICENSE).

---

*psamvault — your vault, your keys, your control.*
