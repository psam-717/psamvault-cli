---
title: Backup and recovery
description: The runbook for a new machine or a wiped laptop — back up the vault key, verify it, restore access, and know the failure modes.
order: 40
---

# Backup and recovery (new machine, wiped laptop)

This page is a standalone runbook. Read it once *before* you need it: the moment you need it, you will be on a machine that has nothing.

## What a backup actually backs up

Your entries live on the server, encrypted under a key that never changes — so losing a machine
loses the **key**, not the data. A backup here therefore backs up the *key*:

```bash
psamvault backup create     # choose a passphrase; stores a server slot + writes a kit file
psamvault backup verify     # prove the backup actually restores THIS vault
psamvault backup status     # what you have: slots, last verified, recovery codes left
```

The opposite artifact — a copy of **the data** itself — is `psamvault export`. They cover non-overlapping failures; see [Backup vs. data dump](#backup-vs-data-dump).

## The two halves — and why one of them is enough

A backup is two things, and losing either one alone is survivable:

| Half | Where it lives | Covers |
|---|---|---|
| **Backup slot** | on the server (wrapped key + an Argon2id hash of your passphrase) | a lost, deleted or destroyed kit file |
| **Kit file** | a file you keep off-device (`psamvault-key-<date>.json`) | losing server/account access, or a slipped passphrase |

Losing **both** is not survivable. Note also that a kit still sitting on the machine you lose is
not a backup — move it somewhere else (printed, a cloud drive, a password manager) and store the
passphrase somewhere different again.

## What the new machine needs — and what it does not

**It needs:**

- psamvault installed on it — see [Installation](../installation.md).
- `psamvault configure` run once on it. This generates **this** device's pepper.
- Your **username**.
- Your **backup passphrase** *or* your **kit file** (either half is enough).
- A **new login password** you choose: at least 8 characters, at least one uppercase letter, at least one digit — the same rules signup enforces.

**It does not need:**

- **The old device's pepper.** The pepper is generated per device and never sent to the server, so your login password alone cannot derive the key that opens your vault on a new machine. `psamvault configure` gives this machine a pepper of its own, and that is the point of the restore.
- **The old machine's `~/.psamvault`.** Nothing in it is required. `configure` writes a fresh `config.env` and pepper, the restore writes a fresh session, and the key you need comes from your passphrase or your kit.
- **Your old login password.** The restore sets a new one — and the old one stops working.
- **The old machine still existing.** The restore talks to the server, not to the old device.

## The restore runbook

### Step 1 — configure the machine

Run this on the machine that has nothing:

```bash
psamvault configure      # once per machine — generates this device's pepper
```

If you skip it, `restore` stops immediately and tells you to run `configure` first. Nothing else on the machine needs to exist beforehand.

### Step 2 — restore

```bash
psamvault restore
```

It asks for your username, your backup passphrase and a new login password. Or restore straight
from the kit file:

```bash
psamvault restore --from-kit ~/Desktop/psamvault-key-2026-09-18.json
psamvault restore --from-kit ./psamvault-key.json --no-codes   # skip the recovery-code offer
psamvault restore --force                                      # overwrite an existing session
```

`psamvault backup restore` runs this same command under the grouped form — see [Command groups](../reference/commands.md#command-groups).

`restore` refuses to run on a machine that already has a session ("This machine already has a session, so it does not need restoring") unless you pass `--force`.

A kit carries the account it belongs to, so `--from-kit` does not ask for a username. If the kit carries no account salt it cannot be used to restore, and the command says so and points you at `psamvault restore` with your passphrase and username instead.

### What happens, in order

What happens:

1. Your passphrase unwraps the vault key — from the server slot, or from the kit file.
2. The key is re-wrapped under a login key derived on **this** machine, and the server stores the new wrap. The old password no longer opens the vault, and existing sessions are revoked.
3. It **proves the restore by decrypting one of your real entries** — an HTTP 200 is not evidence.
4. It offers a fresh set of 8 recovery codes, so a restored account never walks away with a single way back in.

Nothing is re-encrypted, re-uploaded or moved: the entries on the server are untouched. A kit
whose slot was rotated away is refused while you are online (a courtesy check) and still used
offline.

Behind those four steps, concretely:

- **Unwrapping.** Without `--from-kit`, your username and passphrase are verified against your backup slot on the server and the wrapped vault key comes back from it. With `--from-kit`, the kit file is read locally and your passphrase unwraps the key from the file — no server copy of the key is needed. A passphrase that does not open the slot or the kit is reported as exactly that, and the command exits non-zero with nothing half-done.
- **A kit whose slot was revoked** (its slot was rotated away or removed) is refused while you are online. If the slot is merely *missing* from the server, or the server cannot be reached, you get a warning and the restore continues, because the kit still holds the key.
- **Re-wrapping.** Your new login password is prompted twice, hidden, and checked against the signup rules. The master password is derived on **this** machine, the login key is derived with your account's `kdf_salt`, and the vault key is re-wrapped under it. The server stores that new wrap, and the restore then logs in and writes this machine's session (tokens, `kdf_salt`, VEK) to the OS keychain.
- **The proof.** It lists your entries and decrypts one real entry. Success prints `✓ Decrypted '<site>' with the recovered key — your vault is back`. A vault with nothing in it prints `✓ No entries yet — nothing to open, but the vault is reachable`. If nothing can be decrypted it says so, tells you **not to delete anything** (your entries are untouched), suggests trying a different backup passphrase, and exits non-zero — it does not claim success on the strength of an HTTP status code.
- **The codes.** You are asked `Generate a fresh set of 8 recovery codes now?` (default yes); `--no-codes` skips the offer. If storing them fails, your vault is still restored and it tells you to run `psamvault generate-codes` later.

It finishes with `Your entries are unchanged — nothing was re-encrypted or moved.` and `Run psamvault list to see them.`

### What changes the moment you restore

- **Your old login password stops working.** The wrap it opened is gone; the server now holds a wrap made from your new password on this machine.
- **Existing sessions are revoked.** A successful restore revokes every live refresh token so an old session cannot outlive the rotation.
- **Your entries are untouched.** Nothing is re-encrypted, re-uploaded or moved.
- **This machine gets its own pepper and its own session** — the pepper from `configure`, the tokens and VEK in the OS keychain.
- **The account ends with 8 fresh recovery codes**, unless you passed `--no-codes`.
- **Another machine is not a way back in.** Every device generates its own pepper, so the same login password derives a different login key on each one. On a second machine, the way in is the same as it was here: the backup passphrase, or a kit file.

## The other independent path: recovery codes

There are two independent ways back into an account: **recovery codes** — eight one-time codes you generate while logged in — and a **vault backup** (`psamvault backup`), a passphrase-protected copy of the vault key that also works on a machine with no key material at all. Set up both so no single sheet of paper, file or machine is your only way in.

A recovery code is not tied to a machine. After `psamvault configure`, `psamvault recover` verifies one of your saved codes, recovers the VEK, re-wraps it with a login key derived on that machine and resets your password — so a machine with nothing can get back in that way too. Only that code is consumed; your remaining codes stay valid. Details: [Recovery code commands](../reference/commands.md#recovery-code-commands).

## Verify it now, not when you need it

```bash
psamvault backup verify
psamvault backup verify --kit ~/Desktop/psamvault-key-2026-09-18.json
```

Unwraps the backup and compares the recovered key with the one this machine is using right now,
byte for byte. An unverified backup is not a backup — run this while you still have the machine.

This is the safe way to prove a backup: it recovers the key and compares it, and it changes nothing — no session is replaced, no password is rotated, no entry is re-wrapped. Do this instead of rehearsing a real `psamvault restore` on a machine that already works.

- Without `--kit` it verifies the **server slot**: you are prompted for your backup passphrase, the slot is fetched, and the key it unwraps is compared with the vault key this machine currently holds. You must be logged in, because the comparison needs the key you already have.
- With `--kit` it verifies a **kit file**: the passphrase unlocks the file locally and the recovered key is compared the same way.
- If the recovered key does not match, it refuses with `That backup unwraps to a DIFFERENT vault key than this machine is using. → It belongs to another account or was made before a key change.` That is a real failure, not a warning: a backup for another vault is not your backup.

## Create a backup

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

`create` needs you logged in — it reads the vault key from the keychain. Signup offers to do this before it finishes, which is the cheapest moment to get it done (`psamvault signup --no-backup` skips it, and a non-interactive signup prints a reminder instead of prompting).

## Check how recoverable you are

```bash
psamvault backup status
```

Lists your slots (id, kind, created, last verified, active/revoked) next to your remaining
recovery codes, and warns when there is only one path back in.

The count of active backup slots and remaining recovery codes is printed at the bottom, with `⚠  No recovery codes left — your backup passphrase is now your only other path.` when the codes have run out. When there are no slots at all it says so instead: `⚠  No backup slots — a lost machine would lock you out of your vault.`

## Rotate or revoke

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

> **Known limitation:** rotation revokes the *server-side* copy, but the vault key itself never
> changes — so a kit file you already copied still holds key material that works. Destroy the
> copies you no longer trust. True revocation needs the key itself rotated and every entry
> re-encrypted, which is not implemented yet.

## Forgot the passphrase, but you still have a working machine

Do **not** go looking for the old passphrase, and do not rehearse a restore:

```bash
psamvault backup rotate                 # asks only for a NEW passphrase
```

`backup rotate` never asks for the old passphrase — your session already holds the vault key — so it is the supported way to replace a passphrase you have forgotten. It stores a new slot, revokes every other slot on the server, and writes a new kit file (with `--out` to put it where you want). Run `psamvault backup verify` afterwards, and move the new kit off the machine.

## Failure modes — the ways this does not save you

- **Losing both halves of the backup is not survivable** *as a backup*: with no kit *and* no passphrase, the backup is gone. A **recovery code** is the only other independent way back in, which is why you keep both ([the other path](#the-other-independent-path-recovery-codes)).
- **A kit left on the machine you lose was never a backup.** A kit on the machine you lose is not a backup — that includes the default location on your Desktop.
- **No kit, no passphrase, no recovery code → there is no way back.** The server cannot unwrap the VEK — it holds no key — so nothing on the server can reconstruct your vault key for you.
- **There is no working machine to rotate from.** `rotate` and `create` both need a live session (the vault key, read from your keychain). Lose every working machine without a kit or a passphrase and neither command can help you.
- **A rotated-away kit is refused online.** Restoring with a kit whose slot was revoked fails while you have connectivity, with a pointer to the current passphrase or a fresh kit. Offline it is still used, because the kit still holds the key.
- **A backup is not a data backup.** If the server's data were lost, the kit would restore access to nothing — keep an [export dump](#backup-vs-data-dump) as well.
- **A backup protects against *losing* a machine, not against a *compromised* one.** Anyone holding the kit file *and* the passphrase has your vault, and code running as you can read the OS keychain. See [SECURITY.md](../../SECURITY.md).

## Backup vs. data dump

Two different disasters, two different artifacts:

| | `psamvault backup` (key escrow) | `psamvault export` (data dump) |
|---|---|---|
| What it is | a copy of the **key** to data that still exists on the server | a copy of **the data** itself |
| Restores | *access* — new machine, wiped laptop, forgotten login password | the entries themselves |
| Covers | lost/wiped machine, a second machine, a server you can still reach | server-side data loss, deleted account, provider exit, migration, handoff |
| File | `psamvault-key-<date>.json` — key material only | `psamvault-backup-<date>.json` — encrypted entries |

They cover non-overlapping failures, so keep both. Neither one replaces the other.

## A deleted account is a different disaster

That restore path is for a lost or wiped **machine** while the account still exists. If instead `psamvault uninstall` **deleted your account**, the entries are gone from the server and you rebuild from your export file with `psamvault import` — do not sign up again expecting the vault to come back. The step-by-step for that path is in [the uninstall section of the command reference](../reference/commands.md#psamvault-uninstall).

## Related pages

- [Recovery code commands](../reference/commands.md#recovery-code-commands) — `generate-codes`, `remaining-codes`, `recover`.
- [Backup and recovery commands](../reference/commands.md#backup-and-recovery-commands) — every flag of `backup create`, `verify`, `status`, `rotate`, `revoke` and `restore`.
- [Configuration](../reference/configuration.md) — where the kit, the slots and the keychain entries live.
- [SECURITY.md](../../SECURITY.md) — the backup threat model and the known limits of rotation.
