# Token Lifecycle — longer expiry + proactive refresh on major commands

**Status:** 🟡 EXPLORING

**Proposed by:** User (psam)
**Date:** 2026-09-06

---

## Summary

Sessions today use a short-lived access JWT (15 min) + long-lived refresh token (30 days), per server defaults. Access tokens are refreshed **lazily**: a wrapped API call gets a 401, `_refresh_and_retry` rotates the tokens, and the request retries — which is why `psamvault list` "refreshes the session" (it merely triggers that path on its first call). Two goals: (1) extend the token expiry windows, and (2) make refresh happen **proactively** when major commands run (`psamvault get`, `search`, `ak-get`, `ak-list`, etc.) so users never hit the expiry wall mid-command, and when the refresh token itself is dead the error is clear and immediate.

## Key Points

1. **Server-set TTLs:** access JWT ~15 min, refresh ~30 days (comments in `session.py`). Expiry is enforced by `psam_vault_backend` (private repo) — the CLI cannot extend it alone.
2. **Client already auto-refreshes on 401** for every endpoint that passes `refresh_token` (all entries/keys/notes CRUD + export). Only `me` and `get_remaining_codes` take access-token-only and lack auto-refresh.
3. **Refresh is lazy, not proactive:** no command refreshes *before* the access token dies, so the first request after expiry still incurs a 401 round-trip, and if the refresh token is also dead the user gets `Session expired` — sometimes misattributed to the operation (see PLAN_error_handling).
4. **No JWT decode today:** deps have no PyJWT. JWT `exp` can be read with stdlib `base64.urlsafe_b64decode` + `json` — no new dependency needed for proactive checks.
5. The confusing `Run psamvault list to refresh your session` hint (api_client.py) should become an accurate, automatic behavior + message.

## Key Decisions Needed

### Decision 1: Where does "extend expiry" live?

**Context:** Token TTLs are created by the backend at login/refresh time. psam owns `psam_vault_backend` (private). Extending expiry means a backend change (e.g. access 15m → 60m, refresh 30d → 90d, ideally env-configurable).

| # | Option | Pros | Cons |
|---|--------|------|------|
| 1 | **[Backend + CLI]** — extend server TTLs (env-configurable) *and* add client proactive refresh | Real fix: fewer expiries *and* no expiry-wall UX | Requires touching the private backend repo + redeploy |
| 2 | **CLI only (proactive refresh)** — keep server TTLs, refresh before expiry so 15-min access tokens never surface | No backend work; big UX win by itself | Refresh-token (30d) expiry still forces periodic re-login |
| 3 | **Backend only** — just lengthen TTLs | Minimal CLI churn | Lazy 401 refresh + expiry-wall UX remains |

### Decision 2: Proactive refresh mechanism

**Context:** To refresh before the access token dies, the CLI must know its expiry.

| # | Option | Pros | Cons |
|---|--------|------|------|
| 1 | **[Decode JWT exp with stdlib]** — base64-decode the JWT payload, refresh when `exp - now < threshold` (e.g. 5 min) or already expired | No new dependency; simple | Manual decode is a small amount of code; relies on exp claim being present |
| 2 | **Add PyJWT dependency** — proper decode/verify | Robust, standard | New dep for a token that is verified server-side anyway |
| 3 | **Keep lazy-only** — rely on 401+refresh, just fix messages | Zero code | Expiry wall + round-trip stays |

### Decision 3: Which commands refresh, and how

**Context:** Every authed command currently loads the session and passes tokens per call.

| # | Option | Pros | Cons |
|---|--------|------|------|
| 1 | **[Central `ensure_session` wrapper]** — one function called by every authed command (incl. `me`, codes, `search`, export): loads session, proactively refreshes if near/expired, returns fresh tokens | One choke point; no command can be missed again | Touches every command entry point |
| 2 | **Explicit list** — add proactive refresh to get/search/ak-get/ak-list/ak-add/ak-update/ak-delete/export (the "major" commands) | Matches the ask literally | Less-common commands keep the expiry wall |
| 3 | **Per-command opt-in flag** | Maximum control | Easy to forget; reintroduces inconsistency |

## Open Questions

- [x] ~~Where does "extend expiry" live?~~ → Backend + CLI
- [x] ~~Proactive refresh mechanism?~~ → Decode JWT exp with stdlib; refresh if expiring within 300s or expired
- [x] ~~Which commands refresh?~~ → Central `ensure_session()` wrapper on every authed command
- [ ] Threshold for proactive refresh — **decided: 300s**
- [ ] Backend TTL values — **decided: access 60m default, refresh 90d default, env-configurable** (`ACCESS_TOKEN_EXPIRE_MINUTES`, `REFRESH_TOKEN_EXPIRE_DAYS`)
- [ ] Refresh failure (dead refresh token) — **default: keep clear `SessionExpiredError` message + `psamvault login` hint** (guided re-login flow deferred)

## Build Order

| Step | Task | Depends On | Status |
|------|------|-----------|--------|
| 1 | 🟡 Backend: PR #23 open (psam_vault_backend) — env TTLs 60m/90d, awaiting merge+deploy; make env-configurable with defaults access 60m / refresh 90d; PR + deploy | — | 🔴 |
| 2 | ✅ CLI: JWT `exp` reader (stdlib base64url + json) in `session.py` (or `token_utils.py`), defensive when `exp` missing | — | 🔴 |
| 3 | ✅ CLI: `ensure_session()` — load session; if access token expiring (<300s) or expired → `refresh_access_token` + `update_tokens`; return fresh session; dead refresh → `SessionExpiredError` (typed, feature 2) | 2 | 🔴 |
| 4 | ✅ Replace `load_session()` call sites (18 initial sites + daemon fallback) in authed commands with `ensure_session()` (incl. `me`, codes, search, export, browser paths) | 3 | 🔴 |
| 5 | ✅ Tests: exp decode, refresh-before-expiry, expired+valid-refresh success, dead-refresh error, missing-exp fallback | 2–4 | 🔴 |

## Files Likely to Change

- `session.py` (CLI) — `ensure_session()`, JWT exp reader
- `command/*.py` (CLI) — swap `load_session()` → `ensure_session()` at entry points
- `api_client.py` (CLI) — if needed for refresh error typing (shares feature 2's refactor)
- Backend: auth router/security module + `.env.example` + config (private repo)
- `tests/test_session.py` / `tests/test_token.py` (new)
- `CHANGELOG.unreleased.md` — entries per workflow

## Acceptance Criteria

- [ ] Backend honors `ACCESS_TOKEN_EXPIRE_MINUTES` / `REFRESH_TOKEN_EXPIRE_DAYS` env; defaults 60 / 90
- [ ] Fresh login yields access token valid ~60 min, refresh ~90 days (verified via decoded exp)
- [ ] `psamvault ak-get/get/search` with access token inside the 300s window → silently refreshes, command succeeds, keyring updated
- [ ] Expired access token + valid refresh → command succeeds with no "Session expired" wall
- [ ] Dead refresh token → one clean `✗ Your session has expired → psamvault login` (typed SessionExpiredError), never misattributed
- [ ] Commands that previously lacked auto-refresh (`me`, codes) now work across expiry
- [ ] Unit tests green for decode/refresh paths

## Risks & Mitigations

- Backend deploy required for TTL change; already-issued tokens keep old TTL until next login/refresh — acceptable, note in release
- JWT without `exp` (old tokens) — fall back to lazy 401 refresh
- `ensure_session()` touching every command risks regressions — keep it a thin wrapper over `load_session()` + refresh; full suite after swap
- Render deploy of private backend: psam_vault_backend service is live; deploy via merge to main (autoDeploy) — verify post-deploy
