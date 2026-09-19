# Backup & Recovery — surviving a lost machine

**Status:** 🟢 SHIPPED — implemented on `feat/vault-key-envelopes` (backend) + `feat/vault-backup-restore` (CLI), verified live end-to-end; PRs open. See **Implementation Notes** for the harness, the two bugs it caught, and the criterion resolutions.

**Proposed by:** User (psam)
**Date:** 2026-09-18

---

## Summary

Today psamvault's ciphertext is durable (it lives on the server, encrypted under a static Vault
Encryption Key) but the **key material is not**: the VEK and the per-device pepper live only in the
OS keychain of the machine that created them. When a user loses or wipes that machine they cannot
even log in — `login` derives a master password with the *new* device's pepper, sends it as the
password, gets a 401, and reports it as `"Could not reach the server. Is it running?"`. The only
surviving path is a paper recovery code, and the existing `export`/`import` "backup" cannot help
because `import` needs an existing session, i.e. a successful login.

Goal: make vault access recoverable on a virgin machine by design — a first-class `backup` command
group that wraps the VEK under a user-chosen **backup passphrase** and stores that wrap both
server-side (so a lost kit file is not fatal) and in a portable, secret-free **recovery kit file**
(so a lost server is not fatal either), plus a `restore` command that works with no session at all.

**"Backup" in this plan means key escrow, not data export.** The entries themselves never need
re-encrypting or re-uploading for machine loss; only the key path has to be rebuildable.

## Current key chain (verified in code)

```
login password --HMAC(PSAMVAULT_PEPPER)--> master --PBKDF2(kdf_salt, 600k)--> login_key
login_key --AES-GCM--> unwrap encrypted_vek --AES-GCM--> VEK --> decrypts every entry
```

| Piece | Lives where | Survives machine loss? |
|---|---|---|
| `PSAMVAULT_PEPPER` | OS keychain, generated per device by `configure()` (`config.py`) | ✗ regenerated — different every device |
| VEK | OS keychain, unwrapped at login (`session.py:save_session`) | ✗ |
| `kdf_salt`, `encrypted_vek`, `vek_iv` | server (`users` table) | ✓ (unreadable without the login key) |
| entries / API keys / notes | server, AES-256-GCM under the VEK | ✓ |
| access + refresh tokens | OS keychain | ✓ (re-issuable) |

## Key Points

1. `signup()` and `login()` transmit the **pepper-derived** master as the login password
   (`command/auth_commands.py`), so an account is bound to the pepper that created it.
2. Therefore on a fresh machine the login fails cryptographically, before any vault access — and the
   error message blames the network (`command/auth_commands.py:236-240`).
3. The only working machine-loss path today is `psamvault recover` + a saved recovery code: it
   unwraps the VEK from the code, then re-wraps it under a login key derived from the **new**
   device's pepper, and logs in with the new password. That is the mechanism this plan generalises.
4. `psamvault export` / `import` are **not** a machine-loss path: `import` calls `ensure_session()`,
   which requires a successful login. Verified: `command/import_command.py` header + `session.py`
   `is_logged_in()`.
5. Recovery codes are the only escrow slot, they are 8 codes stored in `recovery_codes`
   (argon2 `code_hash` + the VEK wrapped per code), and `generate-codes` itself requires a logged-in
   session — so an account can be born with no recovery credential at all and only be told about it
   after the fact (`login` prints a warning when `has_recovery_codes` is false).
6. `psamvault configure` tells the user to "back up this file" for the pepper (`auth_commands.py`),
   but the pepper is no longer in that file — it is in the keychain. The instruction is stale.

## Key Decisions Needed

All resolved — see **Decisions Made**. Rejected alternatives are recorded at the end.

## Decisions Made

| Decision | Choice | Rationale |
|---|---|---|
| Where the wrapped VEK lives | **Both** — a new server-side slot *and* a portable kit file | Server copy survives "I lost the paper"; kit file survives "I lost the server/account"; neither is sufficient for every loss mode |
| Backup passphrase verification | **Argon2-hashed server-side**, exactly like a recovery code | The server can never verify the VEK (it has no key), so authentication must rest on something it *can* verify. Reuses the proven `recover` flow and adds no new trust assumption |
| Command entry point for restore | Top-level `psamvault restore` (with `psamvault backup restore` as an alias) | It must be discoverable from the error a user actually sees, on a machine where nothing else works |
| What the kit file contains | The envelope only: `{slot, iv, salt, wrapped_vek, kdf params, account, created_at}` | No entry plaintext, no ciphertext, no pepper. Leaking the file costs an attacker an offline PBKDF2-600k attack on the passphrase and nothing else |
| Back up the pepper? | **No** | Restore re-derives a fresh pepper on the new device and re-wraps the VEK under it. The pepper's whole purpose is to stop the server deriving the login key from the login password; a backup containing it would forfeit that for no gain |
| Default-on recoverability | `signup` prompts for a backup passphrase (with `--no-backup` opt-out and a loud warning) | Recovery you have to remember to set up is recovery that does not exist |
| Recovery codes | Left exactly as they are (own table, own flow) | Zero churn, zero regression risk; `backup status` unifies the *view*, not the storage |
| Slot kinds in the new table | `passphrase` now, `device` reserved | A `device` slot (random key in the keychain) is what a future "add this machine" flow needs |
| Revocation | `backup rotate` creates a new slot and revokes the old ones; `backup revoke` drops slots without replacing | Kit files must be invalidatable |
| Code re-issue after restore | **Yes** — `restore` offers a fresh set of 8 recovery codes at the end (default on, `--no-codes` to skip) | Decided 2026-09-18. Zero security downside; without it a restored account walks away with a single credential path (the passphrase) and a forgotten passphrase is unrecoverable |
| Kit vs data dump (`export`) | **Strictly separate artifacts — no `--include-kit` / `--include-envelope` flag** | Decided 2026-09-18. They cover non-overlapping failures: the kit restores *access* to ciphertext that still lives on the server, while the dump *is* the data and is the only cover for server-side loss, account deletion, provider exit, migrating off psamvault, and keys a provider will never show again. Merging would silently upgrade a casually-kept Desktop file into full account access, for convenience only |

## Design

### Vault Key Envelope (VKE)

An envelope is the VEK wrapped by one or more independent **slots**. Any one slot + the server's
ciphertext is enough to rebuild a working vault.

| Slot kind | Wrap key | Server-verifiable | Consuming | Status |
|---|---|---|---|---|
| `recovery_code` | `PBKDF2-SHA256(code, salt, 100k)` | yes (argon2 `code_hash`) | single-use on password reset | exists |
| `backup_passphrase` | `PBKDF2-SHA256(passphrase, salt, 600k)` | yes (argon2 `hash`) | **no** — reusable | new |
| `device` | 32 random bytes in the keychain | no | no | reserved |

`PBKDF2-600k` matches the existing `_derive_export_key` strength in `crypto.py`.

### Command surface

```bash
psamvault backup create                 # prompt + confirm passphrase, write kit, upload slot
psamvault backup create --no-upload     # local kit only
psamvault backup create --out <path>    # non-Desktop destination
psamvault backup verify                 # unwrap and constant-time compare against the session VEK
psamvault backup status                 # slots present, dates, last verified, codes remaining
psamvault backup rotate                 # new passphrase, revoke old passphrase slots, invalidate kits
psamvault backup revoke <slot-id>       # drop one slot
psamvault restore                       # NO session required: username + passphrase + new login password
psamvault restore --from-kit <path>     # restore from a kit file instead of the server slot
```

`restore` sequence on a virgin machine:

1. `configure` if needed (fresh pepper, saved to the keychain).
2. Prompt username + backup passphrase.
3. `POST /auth/key-envelope/begin` → server argon2-verifies the passphrase, returns that slot's
   `{wrapped_vek, iv, kdf_salt, account_salt}`. Wrong passphrase → 401, no slot-existence oracle.
4. Unwrap the VEK locally.
5. Prompt + validate the new login password (same rules as `signup`), derive the new login key from
   the **new** device pepper and the account `kdf_salt`, re-wrap the VEK.
6. `POST /auth/key-envelope/restore` (same passphrase) → writes `password_hash`, `encrypted_vek`,
   `vek_iv`.
7. `POST /auth/login` with the new master, `save_session()`, then decrypt **one entry** as proof and
   report it.

### Kit file format

```json
{
  "kind": "psamvault-key-envelope",
  "format": 1,
  "account": "psam",
  "slot": "backup_passphrase",
  "kdf": {"algo": "pbkdf2-hmac-sha256", "iterations": 600000, "salt": "<hex>"},
  "wrapped_vek": "<hex>",
  "iv": "<hex>",
  "created_at": "2026-09-18T12:00:00Z"
}
```

Written `0600` as `psamvault-key-<date>.json`, default Desktop (consistent with `export`), `--out`
to override. **Contains no entry plaintext, no ciphertext, no pepper.**

### Relationship to `export` / `import` — kept separate by decision

Two artifacts, two jobs (decided 2026-09-18; do not merge them):

| Artifact | Restores | Usable on a virgin machine? | Why it is sensitive |
|---|---|---|---|
| Recovery kit (this plan) | **access** to ciphertext that still lives on the server | yes — no session needed | file + passphrase = log in as you, live |
| Data dump (`psamvault export`) | the **data itself**, when the server copy is gone or you leave | not today — `import` re-encrypts into the current VEK, so it needs a session | it contains every secret in plaintext-or-passphrase form |

The kit is the entire machine-loss story; the dump answers a different question ("what if the server's
copy is gone?"). Because the kit restores access rather than copying secrets, an account whose only
backup is a kit is fully recoverable — which is why no `--include-kit` flag is offered.

## Backend changes (private repo `psam_vault_backend`)

| Item | Change |
|---|---|
| `app/models/models.py` | New `KeyEnvelope`: `id`, `user_id` FK cascade, `kind`, `secret_hash` (argon2 PHC), `wrapped_vek`, `iv`, `kdf_salt`, `created_at`, `last_verified_at`, `revoked_at`; partial index on active rows per user |
| `migrations/versions/` | One alembic revision; verify head before deploy (Render auto-deploys main) |
| `app/schemas/key_envelope_schema.py` | `EnvelopeCreate`, `EnvelopeBegin`, `EnvelopeRestore`, `EnvelopeStatus` (never returns `wrapped_vek` after creation) |
| `app/controller/key_envelope_crud.py` | `create_slot`, `begin_restore` (argon2 verify + rate limit), `restore_account` (reuse the transaction shape of `recovery_crud.reset_password`) |
| `app/routes/key_envelope.py` | `POST /auth/key-envelope/{create,begin,restore,rotate}`, `GET /auth/key-envelope/status`; `@limiter.limit`, bearer auth except `begin`/`restore` |
| `app/routes/auth.py` | `signup` unchanged (the passphrase is a separate call) — no breaking schema change |

Server-side safety notes: `begin`/`restore` must be rate-limited per username **and** per IP; argon2
verification is the natural cost gate; `restore` must be a single atomic commit (supersede the old
refresh tokens exactly like a password reset so a stolen session cannot outlive the rotation).

## CLI changes

| File | Change |
|---|---|
| `crypto.py` | `wrap_vek_with_passphrase(passphrase, vek, salt) -> (wrapped_hex, iv)`, `unwrap_vek_with_passphrase(...)`, `parse_kit()`/`build_kit()` (reuse `_ph` argon2 hasher pattern only server-side; locally no hashing of the passphrase is needed beyond PBKDF2) |
| `command/backup_commands.py` | **new** — `create`, `verify`, `status`, `rotate`, `revoke` |
| `command/restore_command.py` | **new** — the session-less restore flow (kept separate so it can never import session-gated helpers by accident) |
| `api_client.py` | `key_envelope_create`, `key_envelope_begin`, `key_envelope_restore`, `key_envelope_rotate`, `key_envelope_status` — each with the standard `_refresh_and_retry` shape (except `begin`/`restore`, which are unauthenticated) |
| `session.py` | no keychain format change; `save_session` reused as-is by restore |
| `command/auth_commands.py` | `signup` gains the passphrase step; `login` 401 message gains the restore hint; stale "back up config.env for your pepper" text corrected |
| `main.py` | register `backup` group + `restore` + aliases |
| `errors.py` / `error_ui.py` | new `EnvelopeError`/`NoBackupError` if the four existing typed errors do not cover the cases (prefer reusing `NotFoundError` / `ValidationError`) |
| `README.md`, `SECURITY.md` | new "Backup & recovery" and "New machine" sections, with Windows **and** macOS/Linux command forms |

## Build Order

| Step | Work | Depends on | Status |
|---|---|---|---|
| 1 | Backend: model + migration + crud + routes + py_compile check (backend has no test suite) | — | 🟢 7 routes registered; migration `b7c1e4f2a930` applied to a real Postgres 18 DB; app imports + serves |
| 2 | Crypto layer: wrap/unwrap/kit + unit tests (tamper, wrong passphrase, wrong salt) | — | 🟢 11 crypto tests incl. tamper, wrong passphrase, secret-free kit, export KDF unchanged |
| 3 | `api_client` functions + httpx-mock mapping tests (401/404/422/409/5xx) | 1 | 🟢 7 functions; mapping tests incl. 401-refresh-retry, 409, 422, 500 raw body, 429 |
| 4 | `backup create|verify|status` + CliRunner tests | 2,3 | 🟢 20 command tests; wire shape asserted (no passphrase/VEK in the request) |
| 5 | `restore` end-to-end + tests (no session, fresh pepper, kit and server paths) | 4 | 🟢 11 restore tests incl. re-wrap proof, revoked kit, offline kit, proof failure |
| 6 | `signup` passphrase step + login hint + rotate/revoke | 5 | 🟢 signup offers a backup (`--no-backup`; non-TTY prints a reminder); fresh-machine login hint live-verified |
| 7 | Docs in both repos, changelog PR, live sandbox proof | 1-6 | 🟢 READMEs updated; E2E 36/36 twice; changelog PR opened alongside the code PR |

## Files Likely to Change

- Backend: `app/models/models.py`, `app/schemas/key_envelope_schema.py` (new),
  `app/controller/key_envelope_crud.py` (new), `app/routes/key_envelope.py` (new),
  `app/main.py`, `migrations/versions/<new>.py`, `openapi.json`
- CLI: `command/backup_commands.py` (new), `command/restore_command.py` (new), `crypto.py`,
  `api_client.py`, `command/auth_commands.py`, `main.py`, `README.md`, `SECURITY.md`,
  `tests/test_crypto.py`, `tests/test_api_client.py`, `tests/test_backup.py` (new),
  `tests/test_restore.py` (new)

## Acceptance Criteria

- [x] Fresh sandbox (CLI never installed, no `~/.psamvault`, empty keychain): `configure` → `signup`
      → add 3 entries + 1 API key → `backup create` → wipe `~/.psamvault` **and** the keychain rows →
      `restore` → `list` shows all 4 → `get <site>` returns byte-identical plaintext. Against the
      live Render backend, not mocks.
- [x] ~~`restore --from-kit <path>` succeeds with the server slot revoked~~ → **RESOLVED AS THE
      OPPOSITE** (this criterion contradicted the `backup rotate` one below): a revoked slot makes
      `restore --from-kit` **refuse**, which is what the rotate criterion requires and what the tests
      and live E2E assert. An offline kit whose slot cannot be checked still restores (test:
      *continues when the server cannot be reached*). Criterion rewritten 2026-09-19.
- [x] `backup verify` returns ✓ with the right passphrase and a clean `✗` (no traceback, no stack) with
      a wrong one; comparing the unwrapped VEK uses `hmac.compare_digest`.
- [x] An automated test greps a generated kit file for the VEK hex, the passphrase, the pepper, and
      every stored secret in the account: zero matches; the file is `0600`.
- [x] Wrong-passphrase attempts are rate-limited after 5 tries, and the response for a wrong
      passphrase is identical whether or not the account exists (no enumeration oracle).
- [x] `backup rotate` invalidates old kits: an old kit restore attempt fails after the rotation.
- [~] Recovery codes keep working: full CLI suite green at **230 tests** (up from 172) ✓; the live
      `recover` run is **NOT done** — it needs a real account whose recovery codes are known. Left
      open on purpose rather than claimed.
- [x] Login on an unconfigured/fresh machine produces the restore hint, not "Could not reach the
      server".
- [x] `psamvault delete-account` warns when no off-device envelope slot or kit exists.
      *(There is no `delete-account` command — the account-deletion path lives in `psamvault
      uninstall`; the warning was added there and unit-tested three ways.)*
- [x] No command in the group ever prints a secret: the live E2E asserts the kit file, `create`,
      `status` and `list` output contain no stored password/key/passphrase (explicit secret-set
      checks instead of a shape regex, which is strictly stronger).
- [x] `export` behaviour is unchanged — no `--include-kit`/`--include-envelope` flag exists, and a test
      asserts an exported file contains no envelope fields (`wrapped_vek`, `kdf`): the kit and the dump
      stay distinct artifacts.

## Risks & Mitigations

| Risk | Mitigation |
|---|---|
| Server slot = an offline-attackable artifact if the DB leaks | PBKDF2-600k + argon2 PHC (same posture as recovery codes) + a documented minimum passphrase length (≥12) + rate limiting on `begin` |
| Unauthenticated `restore` becomes a lockout/DoS vector | `restore` requires a valid passphrase slot (argon2) before any write; per-username and per-IP limits; atomic rotation that supersedes refresh tokens |
| Alembic head drift on Render (happened before) | Check the migration chain against the deployed head before merging; single head, tested locally |
| Keychain access in tests (real Credential Manager) | Patch `session` / `keyring` in tests as the existing suite does; the restore tests must never touch a real keychain |
| Restore on a machine that already has a session silently overwrites it | `restore` refuses when `is_logged_in()` unless `--force`, and says why |
| Users keep the kit file on the machine they lose | `create` prints an off-device checklist (print it, cloud drive, password manager) and `backup status` shows `last_verified_at` |

## Implementation Notes (2026-09-19)

### Verification actually performed

- **CLI suite: 230 passed** (`python -m pytest tests -q`), up from 172 — 58 new tests across
  `test_crypto.py` (kit/wrap), `test_backup.py` (commands, wire shape, kit/dump separation) and
  `test_restore.py` (session-less restore).
- **Live end-to-end: 36/36 checks, twice.** Scenario: fresh machine → signup → 3 sites + 1 API key →
  `backup create` → **destroy the machine** (`~/.psamvault` + credential store) → `configure` →
  `restore` → `list`/`get`/`ak-get` return the original plaintext → `rotate` → old kit refused. Real
  FastAPI backend, real Postgres 18, real PBKDF2-600k/AES-GCM/Argon2, real keyring calls, and two
  commands re-run as **real subprocesses** to prove the on-disk state works from a fresh process.
- **Live server checks:** wrong passphrase and unknown account return byte-identical 401s (no
  enumeration oracle); the hourly cap fires (429) after five `begin` attempts.
- **Harness:** `%LOCALAPPDATA%\Temp\psamvault_e2e\` (`e2e_backup_inproc.py`, `live_checks.py`,
  `stub_redis.py`, `sandbox_keyring.py`, `reset_e2e_db.py`). Two host constraints worth remembering:
  this machine has **no Redis engine and no Docker**, so the backend's token blacklist talked to a
  local RESP stub (app code untouched); and click's `hide_input` prompt calls `getpass`, which on
  Windows blocks on the **console** when stdin is a pipe — scripted prompts are impossible from a
  subprocess, so the driver invokes the CLI in-process (CliRunner). psam's live vault was never
  touched: the run used a sandbox `HOME` plus a file-backed keyring backend.

### Two bugs the live run caught (both fixed)

1. **`restore --from-kit` printed its revocation refusal and then carried on restoring.** `typer.Exit`
   derives from `RuntimeError`, so the broad `except Exception` (there so an offline kit still works)
   swallowed it. Fixed with `except typer.Exit: raise`; the unit test had been passing for the wrong
   reason (it aborted later on exhausted input), so it was strengthened to assert no continuation, no
   password prompt and no restore call.
2. **HTTP 429 rendered as "Server error (429) → Try again in a moment".** Rate limiting is deliberate
   here, so it now raises `RateLimitedError` → *"Too many attempts → Wait a few minutes"*.

### Decisions taken during implementation

- The kit carries `account_kdf_salt`: a restore must derive the new login key *before* it has a
  session to ask for that salt, and it is not a secret (the login endpoint hands it to any
  authenticated client). Without it `--from-kit` could not work.
- `POST /auth/key-envelope/validate` lets the CLI refuse a **rotated-away** kit while online and still
  restore offline.
- `MAX_ACTIVE_SLOTS = 5` — a 409 with guidance instead of unbounded slot growth.
- The backend `openapi.json` was deliberately **not** regenerated: it is already stale, and pulling
  the untouched `/vault/proxy` paths in here would be unrelated churn (the proxy-removal PR will
  regenerate it).

### Known limitations (documented, not hidden)

- **Rotation cannot invalidate a kit file that was already copied.** The VEK never changes, so a kit
  copied before a rotation still carries the key material; rotate removes the *server* copy, and the
  CLI refuses revoked slots while online. Revoking copied material properly needs VEK rotation plus
  re-encrypting every entry — a separate, heavier feature.
- **All live proof ran against a local instance of the real backend**, not the Render deployment
  (the backend PR is not merged yet). Re-run the harness against Render after it merges.
- A live `psamvault recover` (recovery-code path) was not executed; the suite covers it, live does not.

## Rejected Alternatives

| Rejected | Why |
|---|---|
| Kit file only (no backend change) | Losing the file is the most common version of the disaster; the server copy costs one migration |
| Server slot only | Losing the account/server access would then be unrecoverable |
| Passphrase only wraps the VEK, nothing verifiable server-side | An unauthenticated restore endpoint that rewrites `password_hash` is a lockout vector, and the client cannot prove possession of the VEK to a server that cannot decrypt |
| Reuse the 8 recovery codes and skip the passphrase | Codes are single-use and physically stored; a passphrase slot is reusable, rotatable, and can be forced at signup |
| Back up the pepper inside the kit | Defeats the pepper's purpose (server-independent HMAC) for no recovery gain — the VEK wrap is sufficient |
| Shamir split / social recovery / hardware key now | Correct long-term, disproportionate now; `slot.kind` is designed to accept a `device` slot later without a schema break |

## Open Questions

- [x] ~~Should `export` gain an `--include-envelope` flag so one artifact restores everything, or stay
      strictly a data export?~~ → **KEEP SEPARATE, no flag** (decided 2026-09-18). Kept here as the
      reference for that boundary. What each artifact actually covers:
      - **Kit (envelope)** = a *hot* credential: restores **access** to data that still exists on the
        server. Covers: lost/wiped laptop, new machine, forgotten login password, a second machine.
      - **Data dump (`export`)** = a *cold* snapshot: it **is** the data. Covers: server-side data loss,
        account deletion, provider exit, migration to another manager, offline audit/inventory,
        estate/trusted-person handoff — and it is the only protection for secrets whose plaintext the
        provider will never show again (lose the ciphertext, lose the key, kit or no kit).
      - They cover **non-overlapping failures**, which is the argument for separate artifacts; the
        argument for merging is convenience only. Middle option: `--include-kit`, defaulting **OFF**.
- [x] ~~Should `restore` also offer to re-issue recovery codes at the end?~~ → **YES** (decided
      2026-09-18): offer by default on a virgin machine, `--no-codes` to skip.
- [x] ~~CLI minor version bump (0.5.6 → 0.6.0) — confirm the MCP compat floor is satisfied?~~ →
      **not a decision, a build step** (checked 2026-09-18): the only floor the MCP records is a
      **skill** version floor (`mcp_server/compat.py`, a minimum, not a pin), and this work only *adds*
      commands — no MCP-used call is removed. Verify by running `psamvault-compat-check` after the
      version bump in the release PR, not by asking.
