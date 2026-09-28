# Session Resilience — refresh-race hardening, session profiles, honest failure surfaces

**Status:** 🟢 DECISIONS LOCKED (4/4 forks resolved 2026-09-28) — no code yet

**Proposed by:** Atlas (from psam's cron-failure report), decisions by psam
**Date:** 2026-09-28
**Repos:** `psamvault-cli` (primary) · `psamvault-mcp` · `psam_vault_backend` · `HERMES_HOME/scripts` (ops only)

---

## Summary

The gbrain cron jobs failed **nine consecutive scheduled runs** between 2026-09-18 and 2026-09-27, surfacing as three different errors — `Your session has expired` (CLI era), `psamvault ak-get is blocked in this context` (after 0.6.0's reveal guardrail), and `psamvault session not found` (after the capability re-plumb). All three were one condition: **the vault session was unusable**. Two mechanisms produced it — two clients racing a single-use refresh token, and an explicit `logout` revoking the one chain every consumer shares.

This plan fixes the race, isolates the scheduler from the logout with session profiles, and makes any future session death visible within hours instead of after a six-run failure streak. The credential itself never moves: `hermes_atlas_gbrain_embedder` stays in the vault and the scheduler keeps reaching it through the existing `run_with_credential` capability.

## Key Points (verified state, 2026-09-27/28)

1. **Two mechanisms, one symptom.**
   - *Race*: `/auth/refresh` (`app/controller/auth_crud.py:223-262`) rotates on every call — select the non-revoked row → `record.revoked = True` → insert the successor → single commit — with **no `with_for_update()`**, so two concurrent refreshes can both pass the check (observed: two tokens minted 3 ms apart, `2026-09-25T11:46:14.107517Z` / `.110398Z`). A serialized loser gets `401 Refresh token is invalid or has expired`, which both clients render as *"Your session has expired"* after a **single** attempt (`psamvault-cli/api_client.py:141-173`, `psamvault-mcp/mcp_server/api_client.py:43-56`).
   - *Logout*: `logout` (`auth_crud.py:265-290`) revokes **only the presented** token and blacklists that access token's `jti` — but CLI, MCP server, dashboard and cron share **one** keychain entry, so "only the presented token" is every token in practice. The `2026-09-26T12:54:52Z` logout left `refresh_tokens` with zero live rows.
2. **The sharing is structural, and small.** `_SERVICE = "psamvault"` plus one `_SESSION_KEYS` list in exactly two files: `psamvault-cli/session.py:9-18` and `psamvault-mcp/mcp_server/session.py:12`. The dashboard imports the same module (`dashboard/api.py:25`, `dashboard/cache.py:18`).
3. **A profile costs one login, not a new secret.** Decryption is local (VEK and `PSAMVAULT_PEPPER` both in the OS keychain); only the **fetch** needs a session.
4. **`is_logged_in()` is a file-existence check** (`cli/session.py:164`), so "logged in" outlives a dead session and `login` asks "log in as a different user?" while nothing works. Profiles force this decision rather than create it.
5. **`run_with_credential` collapses every failure into one message** (`mcp/mcp_server/tools.py:758-763`): `session not found`, a 401, a network error and a genuinely absent key all print *"Credential 'X' not found in API keys or vault entries."* That conflation cost a day of diagnosis, twice.
6. **Restore/recover end every session by design.** `key_envelope_crud._revoke_refresh_tokens(user_id)` (line 142, called from the restore path at line 363) revokes **all** live tokens for the user — including a `cron` profile's. Correct behaviour, and it becomes a documented boundary rather than a bug to work around.

## Key Decisions Needed

### Decision 1 — Race fix reach

| # | Option | Pros | Cons |
|---|--------|------|------|
| 1 | **Client re-read-and-retry + server `with_for_update()`** | The loser self-heals from the winner's stored token; the server stops double-minting | Needs a backend deploy (Render, merge to main) |
| 2 | Client retry only | No backend deploy | The double-mint TOCTOU remains; two live chains drift |
| 3 | Retry + server lock + local single-flight lock file | Removes the race rather than healing it | Lock file needs stale-lock/steal semantics and platform branches for a rare event |
| 4 | Server lock only | Smallest client diff | The loser still dies with "session expired" — the observed symptom |

**Chosen: 1.**

### Decision 2 — Session profile granularity

| # | Option | Pros | Cons |
|---|--------|------|------|
| 1 | **Default + one `cron` profile** | One extra login; removes the logout class; the retry covers the residual CLI↔MCP race | CLI and MCP still share the default chain |
| 2 | Per-consumer profiles (cli / mcp / dashboard / cron) | Race eliminated by construction | Four one-time logins, four VEK copies; the dashboard is another agent's surface |
| 3 | One automation profile shared by cron + MCP | One login for all automation | The MCP is spawned per Hermes session — the same concurrency returns |
| 4 | Env-var profile with no login flow | No new UX | No chain to point at, so nothing is actually isolated |

**Chosen: 1.**

### Decision 3 — `logout` semantics once profiles exist

| # | Option | Pros | Cons |
|---|--------|------|------|
| 1 | **Scoped by default + `--all` + warn when another profile is live** | Honest: logout means the session you are in; the warning keeps the old mental model intact | One more line of output |
| 2 | Keep logout global + `session logout <name>` | Backwards-compatible reflex | A routine logout still stops the scheduler — the failure being fixed |
| 3 | Scoped only | Smallest surface | No single command ends everything |
| 4 | Scoped + `--all`, silent | — | The user cannot tell a second chain survived |

**Chosen: 1.**

### Decision 4 — Health-check surface

| # | Option | Pros | Cons |
|---|--------|------|------|
| 1 | **Error-fidelity fix + a Hermes-side detector script** | No MCP contract/skill-floor bump, no new tool to document; the detector is ours to change | The probe stays a script rather than a tool other agents can call |
| 2 | New MCP `session_status` tool + detector | Structured and discoverable | 13 → 14 tools: contract entry, skill table, floor bump, release |
| 3 | CLI `psamvault session status` only | No MCP release | The consumer that dies (the cron) is not a CLI caller |
| 4 | Both a new MCP tool and a CLI command | Complete | Two surfaces to document and release for one check |

**Chosen: 1.**

## Decisions Made

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Race fix reach | Client retry + server `with_for_update()` | Only the client can heal a lost rotation (the server stores hashes, never the successor's plaintext); the lock stops the double-mint that healing cannot undo |
| Profile granularity | Default + `cron` | One extra login buys the whole logout class; the retry covers the residual CLI↔MCP race |
| `logout` | Scoped + `--all` + warning | Logout must mean the session you are in; the warning preserves the "am I fully out?" answer |
| Health check | Error fidelity + Hermes detector | No new tool ⇒ no contract bump; the detector is the piece that must change fastest |
| `is_logged_in()` | Keychain-backed, per profile | A file marker that outlives a dead session already misleads `login`; profiles make it ambiguous |
| Profile name | `cron` | Matches the consumer; set via `PSAMVAULT_SESSION` in the capability harness |
| Restore/recover | Ends every profile's chain (unchanged) | Deliberate and human-initiated; documented boundary plus a re-login ops step |

## Build Order

| Step | Feature | Repo | Depends on | Status |
|------|---------|------|-----------|--------|
| 1.1 | `with_for_update()` on the refresh select + a distinct 401 body (`already rotated`) | `psam_vault_backend` | — | 🔴 |
| 1.2 | Re-read the store + one retry on 401 in `ensure_session` / `refresh_access_token`, with typed tests | `psamvault-cli` | — | 🔴 |
| 1.3 | The same retry in `_refresh_and_retry` | `psamvault-mcp` | — | 🔴 |
| 2.1 | Profile store: `session.<name>.*` keys, `PSAMVAULT_SESSION`, `--session` global option, per-profile `is_logged_in()` | `psamvault-cli` | 1.2 | 🔴 |
| 2.2 | Scoped `logout` + `--all` + the other-profile warning | `psamvault-cli` | 2.1 | 🔴 |
| 2.3 | MCP honours `PSAMVAULT_SESSION`; the capability harness sets it to `cron` | `psamvault-mcp`, `HERMES_HOME/scripts` | 2.1 | 🔴 |
| 2.4 | Ops: create the `cron` profile (one human login), verify, flip both gbrain jobs onto it | host | 2.3 | 🔴 |
| 3.1 | `run_with_credential` returns a `reason` (session_missing / session_dead / network / not_found / decrypt_failed) instead of one message | `psamvault-mcp` | — | 🔴 |
| 3.2 | `session-health.py` detector + cron job; the alert names the exact fix (`psamvault --session cron login`) | `HERMES_HOME/scripts` | 3.1, 2.3 | 🔴 |
| 3.3 | Docs: profiles, the logout warning and the restore boundary across CLI docs, the MCP docs tree and the installed usage skill | all | 2.x, 3.x | 🔴 |

## Files Likely to Change

**`psamvault-cli`**

- `session.py` — profile-aware key names, profile argument on load/save/clear, `is_logged_in`, logout helpers
- `main.py` — root callback gains the `--session` global option
- `api_client.py` — refresh re-read + one retry; profile plumbing through `ensure_session`
- `command/auth_commands.py` — `login` / `logout` / `whoami` become profile-aware; `logout --all`; the warning line
- `docs/reference/commands.md`, `docs/reference/configuration.md` (`PSAMVAULT_SESSION`), `docs/features.md`, `SECURITY.md` (what logout does and does not end), `README.md` section
- `tests/` — profile isolation, retry-after-401, logout scoping, `is_logged_in` semantics
- `CHANGELOG.unreleased.md` — separate `feat/changelog-pr-<N>` PR merged into the code branch FIRST

**`psamvault-mcp`**

- `mcp_server/session.py` (profile from env), `mcp_server/api_client.py` (retry), `mcp_server/tools.py` (error reasons)
- `mcp_server/compatibility.json`, version bump, docs tree, `scripts/docs-sync-check.py` run

**`psam_vault_backend`**

- `app/controller/auth_crud.py` (row lock + distinct 401 body). `openapi.json` needs regeneration only if the route surface changes — it does not

**Host (ops, not repo code)**

- `HERMES_HOME/scripts/psamvault_capability.py` (set `PSAMVAULT_SESSION=cron`), `gbrain-sync-backup.py` and `gbrain-dream.py` (alert text), new `session-health.py` + its cron job

## Acceptance Criteria

**Wave 1 — race**

- [ ] A refresh presented after another client rotated it succeeds by re-reading the store — proven by a test that writes a newer refresh token into the store between the 401 and the retry
- [ ] Two concurrent refreshes of the same token leave exactly one successor (real Postgres, not a mock)
- [ ] A genuinely dead chain still prints exactly one clean line and exits 1, never a traceback
- [ ] Full suites green in `psamvault-cli` and `psamvault-mcp`, plus `scripts/check-docs-surface.py`

**Wave 2 — profiles**

- [ ] `psamvault --session cron login` creates `session.cron.*` and leaves `session.*` untouched
- [ ] Every command reads the profile named by `--session` / `PSAMVAULT_SESSION`, defaulting to today's keys — no migration for existing installs
- [ ] `logout` in the default profile leaves the `cron` profile working and prints the other-profile warning
- [ ] `logout --all` revokes every profile's chain server-side (verified: zero live `refresh_tokens` rows afterwards)
- [ ] The MCP with `PSAMVAULT_SESSION=cron` completes a `run_with_credential` while the default profile is logged out
- [ ] **Live proof:** with the default profile logged out, both gbrain jobs run green off the `cron` profile

**Wave 3 — visibility**

- [ ] `run_with_credential` distinguishes session_missing / session_dead / network / not_found (one test per branch)
- [ ] The detector alerts on a dead or near-expiry `cron` chain without an LLM turn
- [ ] A deliberately broken profile produces an alert naming `psamvault --session cron login` within one detector interval

## Risks & Mitigations

- **Profile drift** — a second chain silently expires after 90 idle days → the cron refreshes four times a day, and the detector alerts on refresh expiry as a leading indicator
- **`restore`/`recover` kills the `cron` chain too** → documented boundary plus an ops step to re-login the profile; the detector's alert names it
- **Two VEK copies in one keychain** → same user, same machine, a secret already present there; no new exposure, but stated plainly in `SECURITY.md`
- **Changing `is_logged_in()` breaks the "already logged in" prompt** → per-profile keychain check plus regression tests on `login` / `logout` / `whoami`
- **The backend has no test suite** → verify with `py_compile` and a real-Postgres concurrency probe; Render deploys on merge, so the lock ships last within wave 1
- **A second agent (Grok) owns `dashboard/*`** → the dashboard stays on the default profile and no `dashboard/*` file is edited by this plan

## Rejected Alternatives

- **A dedicated credential for the scheduler** (agent-scoped key or long-lived token) — psam's constraint is that the credential stays in the vault; it would also duplicate a secret that already exists.
- **Device-bound unlock via the reserved `kind="device"` envelope** (`app/models/models.py`) — the right long-term shape for unattended re-login, but it is a credential class of its own and needs new server endpoints plus client support. Deferred, not rejected on merit.
- **An offline ciphertext cache** so injection survives a dead session — makes revocation non-immediate; the VEK is already local, and this trades a real security property for an outage removed by other means.
- **A keepalive heartbeat** — the failures were never idle expiry: 60-minute access tokens are refreshed on demand and 90-day refresh tokens rotate four times a day.
- **Storing the login password for auto re-login** — it unlocks the vault, not one key.
- **Per-consumer profiles** — cost (four logins, four chains) outweighed once the retry removes the residual race's harm.

## Open Questions

- [ ] Does `psamvault session list` (names + validity) ship with wave 2, or is the `logout` warning enough for discovery?
- [ ] Does `--session` belong on the root callback only, or also on the `auth` sub-app for symmetry?
- [ ] After a `restore`, should the CLI offer to re-create the `cron` profile, or only document it?
- [ ] Should the detector also alert on refresh-token age (for example >60 days without rotation) as a leading indicator?
