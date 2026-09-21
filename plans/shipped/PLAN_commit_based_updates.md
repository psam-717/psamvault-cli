# Commit-Based Update Notifications for psamvault CLI

**Status:** 🟡 EXPLORING

**Proposed by:** User
**Date:** 2026-06-20

---

## Summary

Replace the current version-only update check with a dual-track system: users on the stable PyPI release see version-based update notices, while users who install via git (source installs) see how many commits behind `origin/main` they are. Version bumps (`pyproject.toml`) are reserved for major releases only — all minor updates ship as regular commits without a version bump.

## Key Points

1. **Dual track** — PyPI users get version-based notices (existing behaviour, improved). Source/git users get commit-count notices.
2. **Version bumps reserved** — `pyproject.toml` version only changes for major features. Minor fixes/improvements ship as commits.
3. **Seamless upgrade path** — Source users run `git pull`, PyPI users run `pipx upgrade psamvault`.
4. **Upgrade command** — The existing `psamvault upgrade` command should work for both tracks.

## Key Decisions Needed

### Decision 1: How to detect source vs PyPI install

**Context:** We need to know whether the user installed via `pipx install psamvault` (PyPI) or `git clone && pip install -e .` (source). The update notice and upgrade path differ for each.

| # | Option | Pros | Cons |
|---|--------|------|------|
| 1 | **Check if `.git` directory exists** inside the installed package directory | ✓ Reliable indicator of source install ✓ Simple — just check for a dir | ✗ Might not work if `.git` is pruned/moved ✗ Harder to find the right directory programmatically |
| 2 | **Use `importlib.metadata` to find package location, then check for `.git`** | ✓ Same approach as existing code ✓ Well-documented Python APIs | ✗ Slightly more complex ✓ Still straightforward |
| 3 | **Check for `PSAMVAULT_SOURCE_INSTALL` env var (opt-in)** | ✓ User explicitly opts in ✓ Zero false positives | ✗ Requires user action to enable ✗ Less seamless |

### Decision 2: How to count commits behind

**Context:** For source installs, we need to tell the user how many commits they're behind the main branch of the GitHub repo.

| # | Option | Pros | Cons |
|---|--------|------|------|
| 1 | **Run `git rev-list --count HEAD..origin/main`** | ✓ The standard git approach ✓ Works offline ✓ Accurate | ✗ Requires git in PATH ✗ Requires `origin/main` to be present (might be stale without fetch) |
| 2 | **Fetch from GitHub API (`/repos/psam-717/psamvault-cli/compare/main...HEAD`)** | ✓ No git dependency ✓ Can show more detail (SHA, titles) | ✗ Requires network ✗ More complex ✗ Can hit rate limits |
| 3 | **Cache a `LAST_CHECKED_COMMIT` file + compare against stored value** | ✓ No git/network needed ✓ Fast | ✗ Stale data ✗ Only updates when user runs a command ✗ More complex for first-time setup |

### Decision 3: How should the upgrade command work for source users

**Context:** Currently `psamvault upgrade` likely runs `pipx upgrade psamvault`. For source installs, it should `git pull` instead.

| # | Option | Pros | Cons |
|---|--------|------|------|
| 1 | **Auto-detect install type, then run appropriate upgrade** | ✓ Seamless — one command works for everyone ✓ Best UX | ✗ Need to detect install type first ✗ Upgrade takes different actions depending on context |
| 2 | **Separate subcommands: `psamvault upgrade` (pip) and `psamvault upgrade --source` (git)** | ✓ Clear separation ✓ No auto-detection needed | ✗ User has to remember which one ✗ More CLI surface |
| 3 | **Keep `psamvault upgrade` as-is (pipx), add `psamvault upgrade --git` for source** | ✓ Backward compatible ✓ Source users only need one extra flag | ✗ Auto-detection would be better |

### Decision 4: What should the notice look like for each track

**Context:** The format of the update notification should clearly tell the user what state they're in.

| # | Track | Example Notice |
|---|-------|----------------|
| 1 | **PyPI (behind)** | `💡 Update available: v0.5.3 → v0.6.0. Run  pipx upgrade psamvault` |
| 2 | **PyPI (up to date)** | *(no notice)* |
| 3 | **Source (behind)** | `💡 You are 12 commits behind main. Run  git pull  to update.` |
| 4 | **Source (up to date)** | *(no notice)* |

## Open Questions

- [x] ~~Detect source vs PyPI install?~~ → Auto-detect via `.git` folder inside package directory
- [x] ~~Count commits how?~~ → `git rev-list --count HEAD..origin/main` (app runs it automatically in background)
- [x] ~~Upgrade command for source?~~ → Auto-detect: `psamvault upgrade` does the right thing for both tracks
- [x] ~~Notice format?~~ → Source: "N commits behind" / PyPI: "v0.5.3 → v0.6.0". Both suggest `psamvault upgrade`. No notice if up to date. Never blocks output.

## Decisions Made

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Source vs PyPI detection | Walk up from package dir looking for `.git` | If `.git` found at any ancestor → source install. Otherwise → PyPI. Works for cloned repos. |
| Commit counting | `git rev-list --count HEAD..origin/main` (background thread) | Offline-capable, standard git approach, non-blocking |
| Upgrade command | Single `psamvault upgrade` auto-detects path | Best UX — one command, works for both |
| Notice style | Source: "N commits behind, run upgrade" / PyPI: "v0.x → v0.y, run upgrade" | Same action for user regardless of track |

## Build Order

| Step | Feature | Depends On | Est. Time | Status |
|------|---------|-----------|-----------|--------|
| 1 | Refactor `update_check.py` — extract install detection logic | Nothing | 20 min | 🔴 |
| 2 | Add commit-count check for source installs | Step 1 | 30 min | 🔴 |
| 3 | Update `print_update_notice()` for dual-track output | Step 2 | 15 min | 🔴 |
| 4 | Update `upgrade` command to handle git pull | Nothing (separate file) | 20 min | 🔴 |
| 5 | Tests for new functionality | Step 2, 3, 4 | 30 min | 🔴 |
| 6 | Full integration verification | Step 5 | 15 min | 🔴 |

## Files Likely to Change

- `update_check.py` — Core logic: install type detection, commit counting, dual-track notice
- `command/upgrade_command.py` — Auto-detect install type, run `git pull` or `pipx upgrade`
- `tests/test_update_check.py` — Tests for new paths
- `main.py` — May need minor wiring changes

## Acceptance Criteria

- [ ] Source installs show: "You are N commits behind. Run psamvault upgrade to update."
- [ ] PyPI installs show: "Update available: v0.5.3 → v0.6.0. Run psamvault upgrade to update."
- [ ] Up to date — no notice shown
- [ ] `psamvault upgrade` auto-detects install type and runs correct upgrade command
- [ ] Notice never blocks command output (runs in background)
- [ ] Notice printed after command result, not before

## Risks & Mitigations

- `git rev-list` may fail if `origin/main` is stale — Mitigation: run `git fetch` first (or catch error gracefully)
- `.git` detection walks up from wrong starting dir — Mitigation: start from `importlib.metadata` package path, then walk up
- If `.git` exists but is from a different project (unlikely) — Mitigation: verify it has an `origin` remote pointing to the right repo
- Background thread may race with exit — Mitigation: same pattern as existing `_checker_thread.join()`
