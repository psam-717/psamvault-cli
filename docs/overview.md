---
title: Overview
description: What psamvault is, the problem it solves, and how the client-side encryption model works.
order: 10
---

# Overview

## What psamvault is

A secure command-line password vault for the terminal — **with a web dashboard**.

Your credentials are **encrypted locally** before being sent to the server — the server never sees your plaintext passwords or your encryption key.

Your entries live on the server, encrypted under a key that never changes — so losing a machine loses the **key**, not the data. That single sentence explains most of what is unusual about psamvault: what you back up, what you restore, and what the server is allowed to know.

## The problem it solves

Two separate things have to survive a lost laptop: **access to your account**, and **the key to your entries**. They are not the same thing, and they fail independently.

psamvault keeps the key material on your device — the pepper lives in the OS keychain and is never sent to the server — and stores only encrypted blobs on the server. On a machine that has nothing, access comes back from *either* of two independent places:

- **Recovery codes** — eight one-time codes you generate while logged in, each of which encrypts your VEK.
- **A vault backup** (`psamvault backup`) — a passphrase-protected copy of the vault key that also works on a machine with no key material at all.

Set up both so no single sheet of paper, file or machine is your only way in.

## Demo

[▶️ Watch CLI walkthrough](../media/tui-demo.mp4)

A quick walkthrough of the CLI in action.

```bash
psamvault --version     # or -V — show the installed version
```

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
- **Backup passphrase** (optional) — wraps that same vault key a second time so a machine with no key material at all can get back in. See [Backup and recovery](guides/backup-and-recovery.md).

The full key chain, including where each piece of material lives, is documented in [SECURITY.md](../SECURITY.md).

### What the server can see

- The server stores only **encrypted blobs** — it cannot decrypt your vault.
- It stores your **kdf_salt**, tied to your account.
- It stores an encrypted copy of your **VEK** — decrypted locally at login, never sent in the clear.
- It stores an **Argon2id hash** of your backup passphrase, which exists solely to verify a restore attempt.
- It never sees your **pepper**, your **login password**, your entry **plaintext**, or your **backup passphrase**.

## Encryption at a glance

- Your **login password** is never stored or transmitted in plaintext
- Your **VEK** is stored locally only during an active session
- The server stores only **encrypted blobs** — it cannot decrypt your vault
- **AES-256-GCM** is used for all encryption (authenticated — detects tampering)
- **PBKDF2-HMAC-SHA256** with 600,000 iterations for key derivation (NIST recommended minimum)
- **Argon2id** is used to hash recovery codes and backup passphrases server-side (memory-hard, brute-force resistant)
- **Backup kit files** hold key material only — never the pepper, the passphrase, entry plaintext or ciphertext — and are written owner-only (`0600`)
- **A backup passphrase** wraps your vault key with PBKDF2-HMAC-SHA256 (600,000 iterations) + AES-256-GCM; a restore re-wraps that key on the new machine rather than re-encrypting entries
- **Restore is proof-checked** — it decrypts one of your real entries and reports honestly if it cannot
- **Server-side sessions** — the dashboard keeps your VEK and tokens in the local server process, never in the browser.

## What it is not for

- **Not a defence against a compromised machine.** A backup protects against *losing* a machine, not against a *compromised* one. Code running as you can read the OS keychain, the session state, and anything the CLI prints.
- **Not a security boundary around agents.** The reveal guardrail (see [The agent reveal guardrail](guides/agent-reveal-guardrail.md)) is a guardrail, not a boundary. An agent that already has your shell *and* your keychain can read the credential straight out of Windows Credential Manager, decrypt the vault itself, or install a pristine copy of the CLI.
- **Not true key revocation.** `psamvault backup rotate` revokes the *server-side* copy, but the vault key itself never changes — so a kit file you already copied still holds key material that works. True revocation needs the key itself rotated and every entry re-encrypted, which is not implemented yet.
- **Not a data backup.** A kit file is not a data backup. If the server's data were lost, the kit would restore access to nothing — keep a [data dump](reference/commands.md#export-and-import) as well.
- **Not a way to recover a deleted account.** If `psamvault uninstall` deleted your account, the entries are gone from the server; you rebuild from the export file with `psamvault import`. `psamvault restore` is for a lost or wiped *machine* while the account still exists. See [Backup and recovery](guides/backup-and-recovery.md#a-deleted-account-is-a-different-disaster).

## Next

- [Installation](installation.md) — get a working vault on this machine.
- [Features](features.md) — what each capability is for, and when you reach for it.
- [Backup and recovery](guides/backup-and-recovery.md) — do this while you still have the machine.
