# Vault Key Rotation — make a leaked kit stop working

**Status:** 🟡 READY — decisions locked 2026-09-21, no code written yet

**Proposed by:** User (psam)
**Date:** 2026-09-21

---

## Summary

`psamvault backup rotate` changes the **lock**, never the **key**. The Vault Encryption Key (VEK)
is generated at signup and has never changed, because nothing in either repo can re-encrypt a
vault under a different key. A kit file is that VEK wrapped in your passphrase, so a kit copied
before a rotation still holds a key that opens every entry — our CLI refuses it politely, but the
key material in it is alive. The same is true of an old recovery-code sheet and an old backup slot.

This feature adds `psamvault rotate-key`: it generates a **new** VEK, re-encrypts every entry under
it, replaces every wrap that pointed at the old key (the login wrap, the recovery codes, the backup
slots), and does the swap in **one server transaction**. After it completes, every artifact that
held the old key holds a key that decrypts nothing. Revocation becomes real instead of advisory.

**It is not hygiene.** Routine passphrase changes stay in `psamvault backup rotate` (one prompt, no
re-encryption). `rotate-key` is the "something that holds my key may be out in the world" button:
a kit file exposed, a copy given to someone that should no longer work, a machine or drive leaving
your control.

## Key Points (current state, verified in code 2026-09-20)

1. **The entries are all client-encrypted rows with per-row material.** `vault_entries`,
   `api_key_entries` and `note_entries` each store `encrypted_blob` + `iv` (12 bytes); the user row
   stores `encrypted_vek` + `vek_iv` (the wrap under the login key). AES-256-GCM with a fresh IV per
   call (`crypto.encrypt_credentials` / `encrypt_api_key` / `encrypt_note`).
2. **Ciphertext can already be re-uploaded with no backend change**: `PUT /vault/{site_name}`,
   `PUT /apikeys/{name}` and `PUT /notes/{title}` all accept a raw `encrypted_blob` + `iv`
   (`api_client.update_vault_entry` / `update_api_key_entry` / `update_note_entry`), and
   `/vault/export/all`, `/apikeys/export/all`, `/notes/export/all` return every row with its blob
   and IV. Bulk **read** exists; bulk **write** does not.
3. **The wrap cannot be swapped today.** Only `signup`, the public `/auth/key-envelope/restore` and
   the public recovery flow write `users.encrypted_vek` (verified: `auth_crud.py:126`,
   `key_envelope_crud.py:358`, `recovery_crud.py:190`). There is no authenticated endpoint that can
   replace a logged-in user's wrap — so some backend work is unavoidable.
4. **The login key is never stored.** `session.save_session` keeps tokens, `kdf_salt`, the VEK and
   its wrap; the login key itself exists only for the duration of a login. Re-wrapping a new VEK
   under the login key therefore *requires* the login password to be re-entered. That gate is forced
   by the design, and it doubles as a pre-flight check.
5. **Every wrap of the old VEK is a trap after a rotation.** A stale wrap does not fail loudly — the
   recovery flow would "recover" the old key, log in fine, and then fail to open entries. Wraps are:
   `users.encrypted_vek`, every `recovery_codes` row (column is still named `encrypted_master` and
   holds the wrapped VEK), every active `key_envelopes` row, and the dashboard's
   `~/.psamvault/flask_sessions/*` files, which hold VEK_old in plaintext on disk.
6. **Existing recovery codes cannot be re-wrapped.** The client sends `code_hash` + a per-code wrap
   at generation time (`_build_code_payloads`) and never stores the code plaintext, so the codes
   must be replaced, not migrated.
7. **Slots can only be re-wrapped by someone who knows their passphrase** — the server holds
   `wrapped_vek` + an Argon2id hash, never the passphrase. Decision 2 resolves this by replacing
   slots instead of migrating them.
8. **A kit is a wrap of the VEK, not of the pepper.** Rotation leaves the pepper, the login password
   and `kdf_salt` untouched: login keeps working with the same password, and only the wrap changes.

## Decisions Made

| # | Decision | Choice | Rationale |
|---|---|---|---|
| 1 | Rotation mechanics | **Atomic swap (option A)** | Everything is prepared locally, then one request swaps the wrap and every row in a single transaction. An interruption leaves the vault exactly as it was; the only failure mode is "the rotation did not happen". A client-side item-by-item rotation would leave a half-old/half-new vault that no other machine can untangle — the failure mode worth paying to avoid. |
| 2 | Backup slots | **Revoke every old slot, create one fresh slot under a new passphrase** (prompted once) | Removing the old slots is the point of the feature; re-wrapping them would need every slot's passphrase and would keep the old passphrases alive. One prompt, one new slot, one new kit file. |
| 3 | Recovery codes | **Auto-generate 8 fresh codes and print them at the end** | The old codes cannot be re-wrapped (Key Point 6) and leaving them would leave a wrap of a dead key that "recovers" successfully and then opens nothing. The new codes are generated client-side against VEK_new inside the same transaction. |
| 4 | Command name | **`psamvault rotate-key`** (top level, beside `restore`) | Distinct from `psamvault backup rotate`, which only changes the backup passphrase. The heavier, rarer act gets its own verb and its own place in `--help`. |
| 5 | Sessions after a rotation | **Revoke every refresh token; the CLI re-logs in immediately with the password it already has** | No per-device token identity exists, so "revoke all others" is not expressible. Re-login mirrors the restore flow, gives the rotating machine a session bound to the new wrap, and forces every other machine to re-login (loudly, not silently stale). |
| 6 | Backend surface | **New `POST /auth/rotate-key` + a dedicated controller, no schema change** | No migration is needed: the payload rewrites existing columns. The endpoint is bearer-authenticated, rate-limited, and validates *completeness* (it cannot validate the key — it has none). |

### The swap endpoint (contract sketch)

```
POST /auth/rotate-key            Authorization: Bearer <access token>
{
  "new_encrypted_vek": "<hex>",
  "new_vek_iv": "<hex>",
  "expected_generation": null,     // reserved: lets a future chunked/resumable rotation
                                   // (rejected option B) be added without a breaking change
  "vault":   [{"site_name": "...", "encrypted_blob": "...", "iv": "..."}],
  "api_keys":[{"name": "...", "service_hint": "...", "encrypted_blob": "...", "iv": "..."}],
  "notes":   [{"title": "...", "encrypted_blob": "...", "iv": "..."}],
  "envelope": {"passphrase_hash": "...", "wrapped_vek": "...", "iv": "...", "kdf_salt": "..."},
  "recovery_codes": [{"code_hash": "...", "encrypted_master": "...", "iv": "...", "kdf_salt": "..."}]
}
```

Server, in one transaction:

1. **Completeness check first** — the set of names in each list must match the user's rows exactly
   (`409` naming the counts it expected and received). The server cannot verify the key, so it
   verifies that nothing was left behind; this is also what catches an entry created by another
   machine between the client's read and the swap.
2. Replace `encrypted_blob`/`iv` for every listed row (keyed by `user_id` + name/title).
3. `user.encrypted_vek`, `user.vek_iv` = the new wrap; `updated_at` bumped.
4. Delete **all** previous `recovery_codes` rows; insert the 8 new ones.
5. Revoke every active `key_envelopes` row; insert the new slot.
6. Revoke every refresh token for the user (`_revoke_refresh_tokens`, reused).
7. Commit. Any failure rolls the whole thing back — the client reports "nothing changed".

## Build Order

| Step | Work | Depends on | Done when |
|---|---|---|---|
| 1 | Backend: `rotate_schema.py`, `rotate_crud.py`, `routes/rotate.py`, register in `main.py` | — | app imports with `JWT_SECRET_KEY` + `DATABASE_URL` set and `[r.path for r in app.routes]` shows the new path; `py_compile` clean (the backend has no test suite) |
| 2 | Backend: apply to a real Postgres 18 and hand-drive the endpoint (create rows, rotate, verify counts + old wraps gone) | 1 | a hand-driven swap on real data, and a `409` on a deliberately short payload |
| 3 | CLI: `api_client.rotate_vault_key(...)` + httpx-mock mapping tests (401 refresh-retry, 409, 422, 429, 5xx) | 1 | mapping tests pass; the request body carries no plaintext |
| 4 | CLI: `command/rotate_key_command.py` — pre-flight (session, password, decrypt-all, abort) + `--dry-run` | 3 | CliRunner tests: undecryptable item aborts with no request; wrong password aborts with no request; `--dry-run` makes no write |
| 5 | CLI: the swap + re-login + full verify + new kit + printed codes + dashboard session clear | 4 | command tests for the happy path, the failure-injection no-op and the re-login |
| 6 | Docs: README `rotate-key` section (Windows **and** macOS/Linux forms), SECURITY.md "real revocation" paragraph, and the plan's limitation marked resolved | 5 | docs read correctly against the shipped code, anchors checked |
| 7 | Live proof in the sandbox harness + changelog PR | 1-6 | see Acceptance Criteria 2, 3, 4 |

## Files Likely to Change

Backend (`psam_vault_backend`): `app/schemas/rotate_schema.py` (new), `app/controller/rotate_crud.py`
(new), `app/routes/rotate.py` (new), `app/main.py`, and a decision recorded about `openapi.json`
(it is already stale; the proxy-removal PR owns regenerating it). **No migration.**

CLI (`psamvault-cli`): `command/rotate_key_command.py` (new), `api_client.py`,
`command/backup_commands.py` (reuse `_prompt_passphrase` / `_write_kit` / `_print_kit_advice`),
`command/recovery_commands.py` (reuse `_build_code_payloads` / `_display_codes`), `main.py`,
`README.md`, `SECURITY.md`, `tests/test_rotate_key.py` (new), `CHANGELOG.unreleased.md` (separate PR,
merged first).

## Acceptance Criteria

1. `psamvault rotate-key` on a vault with N site credentials, M API keys and K notes rewrites all
   N+M+K rows and the wrap; the console reports the counts; the exit code is 0.
2. **A kit created before the rotation is dead, in both senses.** Proven live, not by a unit test:
   sandbox machine → entries → kit → rotate → (a) online, `restore --from-kit` on the OLD kit is
   refused because its slot is revoked, and (b) the key material inside it is provably useless —
   unwrapped offline it no longer matches the live VEK and cannot decrypt a re-read entry (the
   comparison `backup verify` already performs). Both halves must be shown; a revocation that only
   hides the file would not be a fix.
3. **A recovery code issued before the rotation is gone** (server no longer lists it) and cannot
   produce a working vault.
4. **Failure injection leaves nothing changed**: with the swap forced to fail (500 / dropped
   connection), every row's `encrypted_blob` hash and the user's wrap hash are byte-identical to
   the pre-run values, and the command exits non-zero with a clear message.
5. **Completeness is enforced**: a payload missing one entry is refused with `409` and the expected
   vs received counts; the vault is untouched.
6. **Pre-flight refuses to run on a partially readable vault**: if any item cannot be decrypted with
   the current VEK, the command aborts *before any request* and says which item failed.
7. **A wrong login password is refused before any crypto or request** (the password is checked by
   unwrapping the session's own wrap).
8. **Other machines are locked out and can get back in**: their refresh tokens are revoked, and a
   fresh `psamvault login` on the same password works and decrypts entries.
9. The rotating machine keeps working immediately (automatic re-login), its `~/.psamvault/flask_sessions`
   is cleared, and a new kit file plus 8 new printed codes exist at the end.
10. The suite is green in full (not just the new file), CI passes on 3.11/3.12/3.13, and the live
    sandbox harness reruns the whole scenario end to end against the real backend.

## Risks & Mitigations

| Risk | Mitigation |
|---|---|
| Swap request is large (a big vault, one payload) | Guard: measure the payload and refuse above a documented ceiling with a clear message (default ~5 MB) rather than a half-applied rotation; the endpoint reserves an `expected_generation` field so a chunked/resumable version (rejected option B) can be added without a breaking change |
| An entry is created/updated by another machine mid-rotation | The completeness check fails the swap with `409` and a count; nothing changes. A concurrent *update* to a row we already re-encrypted is overwritten by the swap |
| Rotation succeeds but the process dies before the new kit/codes are shown | The passphrase the user typed governs the new slot, so `psamvault restore` still recovers the vault; the printed codes are lost and `psamvault generate-codes` regenerates them. Deliberate: the kit is a convenience, the slot is the durable copy |
| Other machines hold a stale VEK in memory/keychain | Their refresh tokens are revoked, so their next request fails; a fresh `login` picks up the new wrap. Documented in README |
| `~/.psamvault/flask_sessions` keeps VEK_old on disk | The command clears that directory on success |
| A **database backup** taken before the rotation plus the login password can still reconstruct the old key | Not fixable by rotation and not hidden: stated in SECURITY.md as a limitation of what rotation buys |
| Rotation is destructive and irreversible | Atomic swap (failure changes nothing), a `y/N` confirmation that prints the counts, password re-entry as the real gate, and `--dry-run` to show exactly what would be re-encrypted |
| Rate limits / huge request bodies on Render | The endpoint is rate-limited like its siblings; the payload guard keeps the body bounded |

## Rejected Alternatives

| Rejected | Why |
|---|---|
| Client-side item-by-item rotation with the wrap swapped last (option C) | Smallest requests, but a mid-run failure leaves some rows under the old key and some under the new one, and only the crashed machine knows which. A half-rotated vault is indistinguishable from a damaged one on any other machine |
| Generation-tagged resumable rotation (option B) | Safe and resumable, and the only design that keeps other machines working mid-rotation — but it needs a migration, a login response carrying several generations, and every decrypt path aware of two keys. Disproportionate for a single-user vault where an interruption costs one retry |
| Don't build it; document export → delete account → signup → import | Works today with no code, but it needs a brand-new account (username/email are only free again after deletion), leaves the entire vault sitting in one export file during the operation, and is a multi-step manual procedure that fails exactly when someone is already handling a leak |
| Store the login key in the keychain so rotation needs no password | It would trade the one gate that proves the person rotating is the owner for convenience, and would leave the login key on disk for any process running as the user |
| Server-side re-encryption | Impossible by construction: the server holds no key and cannot decrypt a single entry |
| Keep the existing recovery codes by re-wrapping them | Impossible: the client sent code hashes and per-code wraps at generation time and never stored the code plaintext |
| Re-wrap the existing backup slots instead of replacing them | Needs each slot's own passphrase (up to 5 prompts) and keeps old passphrases alive — the opposite of the goal (Decision 2) |
| Rotate the login password as part of this | Out of scope and orthogonal: the password re-wraps the *same* VEK, which is exactly the confusion this feature exists to fix |

## Open Questions

- [ ] Build-time verification, not a decision: the payload ceiling (~5 MB) — confirm against a real
      vault and a Render request-size limit before freezing the number.
- [ ] Build-time verification: whether the endpoint belongs under `/auth` (it is account-level, like
      `key-envelope`) or `/vault` (it rewrites vault rows too). Current default: `/auth/rotate-key`,
      matching the other wrap-changing endpoints.
- [ ] Build-time verification: `openapi.json` in the backend repo is already stale — decide in the
      backend PR whether to regenerate it here or leave it to the pending proxy-removal PR.
- [ ] Documentation follow-up: once this ships, the known limitation recorded in
      `PLAN_backup_recovery.md` and in `SECURITY.md` ("rotation cannot invalidate a kit copied
      earlier") must be rewritten to point at `psamvault rotate-key`.
