# Error Handling — audit & improve

**Status:** 🟢 READY — implemented on feat/typed-errors (PR pending)

**Proposed by:** User (psam)
**Date:** 2026-09-06

---

## Summary

Improve error messages across psamvault-cli, starting with the specific case of fetching an API key that is not in the vault, then auditing the whole codebase for error paths that are misattributed, misleading, duplicated, or silently swallowed. A codebase read already found concrete defects (below) that this plan will fix systematically.

## Key Points

1. **Found bug (misattribution):** `ak-get` (and sibling get/update/delete commands) wrap the API call in a single `except ApiError:` and always print `✗ API key '<name>' was not found in your vault.` — but `ApiError` is raised for **session expiry, network/5xx errors, and 409s too**. A user whose session died gets told their key doesn't exist. This is exactly the confusing output seen in the GBrain cron failure.
2. **Found bug (noise + lie):** `_handle_error` prints `Session timed out after inactivity. → Run psamvault list to refresh your session` on any 401 — even inside wrapped calls where `_refresh_and_retry` then silently refreshes and *succeeds*. Users see a scary expiry message followed by success. The hint is also misleading: `psamvault list` doesn't do anything special — any wrapped command refreshes.
3. **Inconsistent UX:** mix of `Error: …`, `✗ …`, `⚠` prefixes; some paths echo then raise then the command echoes again (double print); several `except Exception: pass` sinks; raw `response.text` leaks into user-facing errors on 5xx.
4. Commands are the user-facing shell; `api_client.py` + `session.py` are where errors originate. Fixing requires touching all three layers, plus tests that assert the *right* message per failure class.

## Key Decisions Needed

### Decision 1: Error architecture

**Context:** The root cause of the misattribution bug is a single exception type (`ApiError`) with no class distinction. Fixing messages alone patches symptoms.

| # | Option | Pros | Cons |
|---|--------|------|------|
| 1 | **[Typed exceptions]** — introduce `NotFoundError`, `SessionExpiredError`, `NetworkError`, `ValidationError`, `DecryptionError` (subclassing a common base); commands catch the specific type and print the right message | Fixes the whole class of misattribution bugs; dashboard/TUI consumers benefit too | Touches many call sites |
| 2 | **Message-only fixes** — keep one exception, improve each site's text | Small diff | Next new command repeats the same bug |
| 3 | **Full framework** — typed exceptions + central error→message registry + plugin hook | Cleanest long-term | Overkill for a CLI this size |

### Decision 2: Audit scope

**Context:** How far does the sweep go?

| # | Option | Pros | Cons |
|---|--------|------|------|
| 1 | **[Commands + api_client + session, with tests]** — audit every user-facing path in `command/*.py`, fix origins in `api_client.py`/`session.py`, add unit tests for each failure class | Complete; regression-proof | Largest effort |
| 2 | **Commands only** — fix messages where printed | Fast | Leaves double-prints/origins in api_client |
| 3 | **Critical paths only** — ak-* + vault get/update/delete + auth | Smallest meaningful set | Search/export/dashboard gaps remain |

### Decision 3: Output conventions

**Context:** psam's Telegram-style rules (verdict-first, actionable hints, no raw tracebacks) mirror what a good CLI should do.

| # | Option | Pros | Cons |
|---|--------|------|------|
| 1 | **[Unify format]** — `✗ <what happened>` + one actionable `→` hint line, never raw traceback; add `--verbose` to show the underlying exception | Consistent, debuggable | Touches every message |
| 2 | **Keep current style, just fix wrong/misleading texts** | Minimal churn | Inconsistency remains |
| 3 | **Rich error panel** — colored block with cause + fix + issue link | Pretty | More code than value for a CLI |

## Decisions Made

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Error architecture | Typed exceptions (`NotFoundError`, `SessionExpiredError`, `NetworkError`, `ValidationError`, `DecryptionError`) sharing a common base; commands catch specific types | Fixes the whole misattribution class, not single messages |
| Audit scope | Commands + api_client + session, with unit tests per failure class | Complete and regression-proof |
| Output conventions | Unify `✗ what happened` + one `→` actionable hint; `--verbose` for underlying exception; no raw tracebacks | Consistent, debuggable UX |

## Open Questions

- [x] ~~Error architecture?~~ → Typed exceptions
- [x] ~~Audit scope?~~ → Commands + api_client + session, with tests
- [x] ~~Output conventions?~~ → Unified ✗ + → hint, --verbose, no raw tracebacks
- [ ] Should network/5xx errors suggest `psamvault doctor`-style diagnostics, or is one hint line enough? — **default: one hint line**
- [ ] Are there error paths in the `dashboard/` (Flask) sub-app in scope, or CLI-only? — **default: CLI-only for this pass**; dashboard errors reviewed only if the typed exceptions refactor touches its imports

## Build Order

| Step | Task | Depends On | Status |
|------|------|-----------|--------|
| 1 | ✅ New `errors.py`: typed hierarchy (`PsamVaultError` base → `NotFoundError`, `SessionExpiredError`, `NetworkError`, `ValidationError`, `DecryptionError`), each carrying a user message + optional hint | — | 🟢 |
| 2 | ✅ `api_client.py`: `_handle_error` raises typed errors instead of echoing + raising one generic `ApiError`; stop origin-side printing (single print site = command layer); map 401→SessionExpired, 404→NotFound, 422→Validation, network/timeout→Network, 409→Conflict | 1 | 🟢 |
| 3 | ✅ `_refresh_and_retry`: dead refresh token → `SessionExpiredError`; remove the misleading "Run psamvault list" message from the auto-refresh path | 2 | 🟢 |
| 4 | ✅ Commands: replace broad `except ApiError` with typed catches; unified `✗ <what> + → <hint>`; fix ak-get misattribution (NotFound vs Session vs Network) | 2 | 🟢 |
| 5 | ✅ `--verbose` global flag to surface underlying exception detail | — | 🟢 |
| 6 | ✅ Sweep: audit remaining `except Exception: pass` sinks, double-prints, raw `response.text` leaks across `command/*.py` | 4 | 🟢 |
| 7 | ✅ Tests per failure class: NotFound/Session/Network/Validation/Conflict/Decrypt against mocked httpx | 1–6 | 🟢 |

## Files Likely to Change

- `errors.py` (new) — typed exception hierarchy
- `api_client.py` — raise typed, stop origin echo, refresh semantics
- `command/*.py` — typed catches + unified message format (ak-*, vault, notes, search, export, auth)
- `main.py` — `--verbose` option wiring
- `tests/test_errors.py` (new) + existing command tests updated
- `CHANGELOG.unreleased.md` — entries per workflow

## Acceptance Criteria

- [ ] `ak-get <missing>` → `✗ API key 'x' was not found in your vault. → psamvault ak-list to see saved keys` (NotFoundError)
- [ ] Expired/dead session during `ak-get` → `✗ Your session has expired → psamvault login` — **never** "key not found"
- [ ] Network down → `✗ Could not reach the server → check your connection / PSAMVAULT_API_URL`
- [ ] 422 validation → clean bulleted messages (current behavior preserved)
- [ ] No double-printed errors anywhere (origin no longer echoes)
- [ ] `--verbose` shows the underlying exception; default shows none
- [ ] Unit tests assert the correct type + message for each failure class

## Risks & Mitigations

- Typed-exception refactor touches every command — mitigation: run full test suite after each command file
- Dashboard/Flask imports `ApiError` — keep `ApiError` as an alias base for backward compat or update dashboard imports
- Changing origin echo behavior could hide info for non-CLI consumers — exceptions carry full message; `--verbose` exposes detail
