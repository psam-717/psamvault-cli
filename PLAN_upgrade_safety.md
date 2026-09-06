# Upgrade Safety — Hermes-style local-change handling

**Status:** 🟢 READY — implemented on feat/upgrade-safety (PR pending)

**Proposed by:** User (psam)
**Date:** 2026-09-06

---

## Summary

`psamvault upgrade` currently runs `git pull --ff-only` on source installs (which **aborts outright** when the user has local modifications or unpushed commits) and `pipx upgrade` on PyPI installs (which silently replaces the package, destroying any local edits). For an open-source tool whose users legitimately customize their checkout, this is the #1 upgrade failure mode. Goal: adopt the Hermes update model — detect dirty state, stash local changes safely, pull, restore or park them with a clear path back, take a pre-update snapshot, refresh dependencies, validate the result, and report what changed — so an upgrade never breaks or silently destroys a user's work.

## Key Points

1. **Source track today:** `git fetch` → count behind → `git pull --ff-only` → `pip install -e .` (return code ignored). A dirty tree or local commit makes `--ff-only` fail with a bare "git pull failed" message and zero guidance.
2. **PyPI/pipx track today:** plain `pipx upgrade psamvault`; an editable/patch-local install is not detected, and local edits are overwritten without warning.
3. **No pre-update snapshot** of `~/.psamvault` state (session marker, `last_seen_version`) is taken before the tree is touched.
4. **No post-update validation** — a half-installed dependency sync or failed pull leaves the user stranded without a rollback hint.
5. Hermes's model (auto-stash → pull → restore-or-park, syntax check + rollback, dep refresh, gateway restart + post-verify) is the reference behavior users are asking for.

## Key Decisions Needed

### Decision 1: Dirty-tree policy on the source track

**Context:** When `git pull --ff-only` can't proceed because of local changes, what should upgrade do?

| # | Option | Pros | Cons |
|---|--------|------|------|
| 1 | **[Auto-stash → pull → auto-restore]** — stash local changes, pull, then `stash pop`. If restore conflicts, leave the stash parked with exact restore instructions | Hermes-like, zero-touch for the common case | Restore can conflict; needs careful conflict messaging |
| 2 | **Auto-stash → pull → keep parked** — never auto-restore; print how to `git stash pop` | Zero risk of clobbering user work | User must remember to restore; two-step UX |
| 3 | **Refuse when dirty** — tell the user to commit/stash manually first | Simplest, safest | Annoying; the main reason users dislike upgrades |

### Decision 2: Pre-update snapshot

**Context:** Before modifying the checkout, capture enough state to recover.

| # | Option | Pros | Cons |
|---|--------|------|------|
| 1 | **[Quick snapshot of ~/.psamvault state]** — copy session marker, `last_seen_version`, config (keyring secrets stay put) into a timestamped backup | Cheap, covers the state files the CLI owns | Doesn't cover the venv/package (git does) |
| 2 | **No snapshot** — git is the safety net | Simplest | Loses `last_seen_version`/session-marker state on a botched upgrade |
| 3 | **Full backup** — snapshot + copy the whole install dir's pyproject/lockfile + git stash refs | Maximum recovery | Heavy; most of it is git-recoverable anyway |

### Decision 3: Post-pull dependency refresh + validation

**Context:** The source track already runs `pip install -e .` but ignores its result; the pipx track leaves dependencies to pipx.

| # | Option | Pros | Cons |
|---|--------|------|------|
| 1 | **[Reinstall deps + smoke-test]** — run editable install, check return code, then verify `psamvault --version` / import works; on failure print rollback hint | Catches half-installed states like Hermes's post-pull syntax check | Slower upgrade (few seconds) |
| 2 | **Reinstall deps, ignore failures** (current) | Fast | Silent breakage exactly when deps change |
| 3 | **Skip reinstall unless pyproject changed** | Fastest | Can strand on changed deps |

### Decision 4: PyPI/pipx track and local edits

**Context:** pipx upgrades replace the whole venv. Local edits only survive if we detect them first.

| # | Option | Pros | Cons |
|---|--------|------|------|
| 1 | **[Detect editable/source-linked install]** — check `pipx list --json` before upgrading; if editable, explain and route appropriately | Honest about what pipx can't preserve | More moving parts in the PyPI track |
| 2 | **Warn generically before pipx upgrade** — "pipx replaces the install; local edits will be lost" | Simple, one message | Doesn't actually detect anything |
| 3 | **Leave as-is** | Zero change | Silent edit destruction continues |

## Decisions Made

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Dirty-tree policy | Auto-stash → pull → auto-restore; park in stash if restore conflicts, with instructions | Hermes-like zero-touch for the common case; conflicts never clobber user work |
| Pre-update snapshot | Quick snapshot of ~/.psamvault state files (timestamped) | Cheap recovery of CLI-owned state; git covers the checkout |
| Post-pull validation | Reinstall deps + smoke-test (`psamvault --version`/import) with clear failure report | Catches half-installed states |
| pipx/local edits | Detect editable/source-linked installs before pipx upgrade; route/warn properly | Honest about what pipx can't preserve |

## Open Questions

- [x] ~~Dirty-tree policy?~~ → Auto-stash → pull → auto-restore (park on conflict)
- [x] ~~Pre-update snapshot?~~ → Quick snapshot of ~/.psamvault state
- [x] ~~Post-pull dependency refresh + validation?~~ → Reinstall deps + smoke-test, report failure
- [x] ~~PyPI/pipx track + local edits?~~ → Detect editable installs first
- [ ] Should the source track also offer `--branch` style pinning (upgrade to a specific tag/commit)? — **deferred** (not needed for first cut)
- [ ] Should a failed post-pull validation offer automatic `git reset --hard` rollback to the pre-pull SHA (Hermes does), or just instructions? — **default: instructions only** (no auto-reset; too destructive for a CLI without Hermes's guard rails)

## Build Order

| Step | Task | Depends On | Status |
|------|------|-----------|--------|
| 1 | ✅ Snapshot helper: copy `~/.psamvault` state files (session marker, `last_seen_version`) to timestamped `~/.psamvault/backups/` (keep last 5) | — | 🟢 |
| 2 | ✅ Dirty-tree detection: `git status --porcelain` + ahead/behind count | — | 🟢 |
| 3 | ✅ Auto-stash → pull → auto-restore flow; on restore conflict, leave parked + print `git stash pop` instructions | 2 | 🟢 |
| 4 | ✅ Post-pull: `pip install -e .` with return-code check + smoke-test (`psamvault --version`) + clear failure message | 3 | 🟢 |
| 5 | ✅ pipx editable detection via `pipx list --json`; route/warn before `pipx upgrade` | — | 🟢 |
| 6 | ✅ Tests for 1–5 (dirty tree, conflict park, offline, editable detect, smoke failure) | 1–5 | 🟢 |

## Files Likely to Change

- `command/upgrade_command.py` — stash/pull/restore flow, snapshot call, smoke test
- `session.py` or new `upgrade_utils.py` — snapshot + stash helpers (keep upgrade_command readable)
- `update_check.py` — expose editable-install detection helpers if not already there
- `tests/test_upgrade.py` (new) — unit tests with a temp git repo fixture
- `CHANGELOG.unreleased.md` — entries per workflow

## Acceptance Criteria

- [ ] Source install with local tracked-file edits: upgrade stashes → pulls → restores → reports success, edits intact
- [ ] Source install with a local *commit* ahead: handled without losing the commit (parked with instructions if it conflicts)
- [ ] Restore conflict: upgrade parks the stash and prints exact `git stash pop` instructions; never clobbers user work
- [ ] Offline / git failure: clear error, tree untouched, no partial pull
- [ ] Pre-update snapshot dir exists before any pull; old snapshots pruned to last 5
- [ ] pipx editable install: detected before upgrade; user told what will/won't survive
- [ ] Post-pull dep failure: message says upgrade incomplete + safe re-run hint, exit code non-zero

## Risks & Mitigations

- `git stash pop` conflict leaves conflict markers — mitigation: park + instructions, never auto-resolve
- Windows CRLF autocrlf interacts with stash/restore — test on Windows; use `git stash push` semantics carefully
- Snapshot accumulation — prune to last 5
- pip editable detection formats vary by pipx version — parse defensively, fall back to generic warning
