# Plans

Every psamvault-cli plan lives here — past, current, and future. One file per feature, named
`PLAN_<feature>.md` (older files use `SDK_PLAN.md` / `SKILL_PLAN.md` and keep their names).

This index is the **source of truth for status**. The `**Status:**` line inside each file is a
snapshot from the moment it was written and is often stale (several files still say "PR pending" for
work that merged weeks ago) — status here is verified against git history and the code in this repo.

## Layout

| Folder | Meaning | When a plan moves |
|---|---|---|
| `active/` | Decisions locked, build not finished | New plans are created here |
| `shipped/` | Implemented and merged (or shipped as a separate artifact) | Move here when the PR merges |
| `archive/` | Historical / event-scoped plans, kept for the record | Never — archived plans are frozen |

Workflow: plan starts in `active/` → its feature PR merges → `git mv` it into `shipped/` → update the
tables below. Plans are committed with their feature's PR, not on their own.

## active/ — decided, not yet built

| Plan | Feature | Domain | State | Next step |
|---|---|---|---|---|
| [PLAN_agent_safe_vault.md](active/PLAN_agent_safe_vault.md) | Reveal guardrail (caller classification, policy, TTY-only approval tokens, audit log) + credential-blind ingress (claim codes, `--from-file`) + use-side policy/leases | agent security | **wave 1 (the reveal guardrail) merged in PR #54, shipped in v0.6.0**; **wave 2 decisions locked 2026-09-24 — blind ingress not started** | Wave 2 = blind ingress for all three families (`ak-add`/`add`/`note-add` claim codes, `ak-pending`, opt-in `--wait`, `--from-file`/`--from-env`) — one CLI PR, docs in the same PR. Wave 3 = loopback form + use-side policy (fail-open default). Independent: backend `/vault/proxy` → `410 Gone` |
| [PLAN_vek_rotation.md](active/PLAN_vek_rotation.md) | Vault key rotation — re-wrap the VEK under a new passphrase so a leaked kit file stops working (`rotate-key`) | cryptography / recovery | decisions locked, no code | Build order in the plan; reuses the envelope machinery shipped for backup (#49) |
| [PLAN_dashboard_ui.md](active/PLAN_dashboard_ui.md) | Dashboard speed and UI — stop per-click keychain and API work, then use coss ui (Origin UI) and ReUI components | dashboard | built on `feat/dashboard-speed-and-ui`, not merged | Move to `shipped/` when the PR merges |

## shipped/ — implemented

| Plan | Feature | Domain | Evidence (verified) |
|---|---|---|---|
| [PLAN_error_handling.md](shipped/PLAN_error_handling.md) | Typed error hierarchy, single print site in the command layer, `error_ui`, no origin echo | CLI UX / errors | PR #38 (typed errors), #34, #36; `errors.py` (8 exception classes) + `error_ui.py` present |
| [PLAN_secure_notes.md](shipped/PLAN_secure_notes.md) | Secure notes — encrypted `note-add/get/list/update/delete` | feature surface | PR #37 (client) + backend PR #21 (`/notes`); `command/note_commands.py` present |
| [PLAN_token_refresh.md](shipped/PLAN_token_refresh.md) | Token lifecycle — proactive refresh at ≤300s, JWT `exp` reader, rotation persisted | auth / session crypto | PR #40 + backend PR #23 (TTL env); `session.REFRESH_THRESHOLD_SECONDS`, `get_access_token_expiry`, `api_client.ensure_session` present |
| [PLAN_upgrade_safety.md](shipped/PLAN_upgrade_safety.md) | Upgrade safety — snapshot, stash/pull/restore, post-pull smoke test, pipx editable + pinned-version force reinstall | release / upgrade | PR #43, follow-up #47; `upgrade_utils.py` present, `pipx list --json` detection live |
| [PLAN_commit_based_updates.md](shipped/PLAN_commit_based_updates.md) | Dual-track update check with commit-based notices for source installs | release / upgrade | merge `de13899` (`feat/commit-based-updates`); `update_check._count_commits_behind` + `_commit_update_notice` present |
| [SDK_PLAN.md](shipped/SDK_PLAN.md) | `pv-dotenv` runtime SDK — resolves `psamvault:` placeholders so `.env` files hold no secrets | SDK / distributables | shipped as a separate repo/package: `pv-dotenv 0.1.0` on PyPI (verified with `pip index versions pv-dotenv`) |
| [SKILL_PLAN.md](shipped/SKILL_PLAN.md) | Standalone MCP skill teaching agents to use psamvault-mcp correctly | agent integration | delivered in the `psamvault-mcp` repo: `SKILL.md`, `mcp_server/agent_guide.py`, MCP prompts |
| [PLAN_backup_recovery.md](shipped/PLAN_backup_recovery.md) | Backup & restore: Vault Key Envelope (server slot + portable kit file), `psamvault backup *`, session-less `psamvault restore` | cryptography / recovery | PR #49 (`backup create/verify/status/rotate/revoke` + `restore`), #51 (snapshot-dir collision on a coarse clock), backend PR #24 (key-envelope endpoints); `crypto.wrap_vek_with_passphrase` / `unwrap_vek_with_passphrase` / `build_kit` + `command/backup_commands.py`, `command/restore_command.py` present |

## archive/

| Plan | What it is | Why archived |
|---|---|---|
| [hackathon-2026/PLAN.md](archive/hackathon-2026/PLAN.md) | psamvault × Hermes hackathon build plan (Nous × NVIDIA × Stripe, deadline 2026-06-30) — multi-workstream: proxy/`use_credential`, `scan_and_protect`, project grouping, redaction | Event-scoped; the hackathon is over and most of its workstreams shipped (see `shipped/`). Its submission checklist is a historical record, not a backlog |

`hackathon/DEMO_SCRIPT.md` stayed in `hackathon/` — it is a demo script, not a plan.

## Notes

- `.gitignore` carried a stale `plans` entry (added 2026-05-06) that would have hidden this folder and
  every future plan from git. It was removed on 2026-09-18 so plans are versioned like the files they
  replaced. Revert that one line if you would rather keep plans local-only.
- The root-level `PLAN_*.md` convention is retired: create new plans in `plans/active/`.
