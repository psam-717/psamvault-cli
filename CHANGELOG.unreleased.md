# Unreleased Changes

<!--
  This file tracks changes merged to main but not yet published to PyPI.
  When preparing a release:
    1. Copy entries into CHANGELOG.md under the new version header
    2. Clear this file's content (keep the header)
    3. Bump version and publish
-->

## Added

- feat(backup): `psamvault backup create|verify|status|rotate|revoke` — back up your vault key under a passphrase, as a server-side slot plus a portable kit file you keep off-device
- feat(restore): `psamvault restore` regains vault access on a new or wiped machine with no session at all
- feat(auth): signup offers to set up a vault backup (`--no-backup` to skip)
- feat(errors): HTTP 429 now raises a typed rate-limit error and tells you to wait, not to retry
- feat(uninstall): warns when deleting your account would remove the last copy of your vault key
- feat(guardrail): the four commands that print a secret — `get`, `ak-get`, `note-get` and `export --plaintext`, plus `--copy` on any of them — now refuse when the caller is an agent, printing the capability alternatives instead of the value
- feat(guardrail): `psamvault approve <entry> --for-agent [--ttl N]` lets you hand an agent ONE reveal of ONE entry from your own terminal — single use, 15s-1h, dropped on logout, and never a whole-vault dump
- feat(guardrail): `~/.psamvault/policy.json` chooses who may reveal a secret — `human-only` (default), `strict` or `open` — plus a per-entry allowlist for agents
- feat(guardrail): `~/.psamvault/audit.jsonl` records one row per reveal decision, naming the caller, the matched signal and the outcome; it never contains a secret
- feat(guardrail): a global `--agent` flag and `PSAMVAULT_AGENT` for hosts that set no marker of their own

## Fixed

- fix(restore): a revoked kit file is now actually refused — a broad exception handler was swallowing the exit and continuing with the restore
- fix(backup): `backup verify --kit` on a kit with no server-side copy printed a sliced placeholder (`slot kit-only…`); it now names the real slot id, or states that the kit has no server-side copy
- fix(upgrade): a pre-update state snapshot can no longer be written into an existing snapshot directory — the clock stamp is microsecond-precise but Windows' granularity is ~15 ms, so back-to-back snapshots got the same name and silently merged, losing one

## Changed

- feat(auth): logging in on a new machine now explains the device-key mismatch and points at `psamvault restore`
- chore(gitignore): `plans/` is no longer ignored, so plans are versioned
- `upgrade` (pipx track): reinstalls from PyPI with a pinned force install (`pipx install --force psamvault==<version>`) instead of `pipx upgrade` — repairs URL/TestPyPI/editable install sources so future upgrades track the registry
- feat(guardrail): `get`, `ak-get` and `note-get` are gated at the emit point — after the fetch and the decrypt — so a failed lookup never consumes an approval
- feat(guardrail): `export --plaintext` now names how many secrets it is about to expose before asking to continue, and a whole-vault dump can never be approved for an agent
- feat(guardrail): `psamvault logout` drops every pending approval, so a token cannot outlive the session it was minted for

## Tests

- test(backup): 20 command tests plus wire-shape assertions (the passphrase and the vault key never appear on the wire)
- test(restore): 11 session-less restore tests, including the re-wrap proof and revoked/offline kits
- test(crypto): kit wrap/unwrap, tamper and parse-failure coverage, and an assertion that a kit file contains no secret value
- test(guardrail): 98 new tests — the caller ladder (one per measured marker), the ancestry matching rules driven by fake chains, the policy matrix, the audit row schema, the gate's every allow/deny path, and the approval lifecycle
- test(guardrail): the four gated commands are driven through the real Typer app with the real classifier, policy, gate and audit writer — only the session and HTTP are faked, because a unit-tested gate that no command calls would still leak
- test(guardrail): the suite no longer inherits the agent environment it is usually run from, and the policy file and audit trail are redirected to a tmp dir so tests never touch the live trail

## Docs

- docs(readme): a "Backup & recovery (new machine, wiped laptop)" section — create, verify,
  status, rotate/revoke, `restore --from-kit`, per-OS kit paths, a backup-vs-data-dump table, and
  a trigger table for when to reach for create, rotate or revoke (another backup / passphrase
  leaked / one kit leaked / the kit file itself leaked)
- docs(readme): `export`/`import` are now described as a **data dump** rather than a "backup",
  so the two artifacts are no longer confused
- docs(security): key material and where it lives, what a kit file contains, why the restore
  endpoints are authenticated on the passphrase hash, the threat model and the rotation limit
- docs(plans): plans moved into `plans/{active,shipped,archive}` with a verified-status index
- docs(plans): the backup and recovery plan records its live verification, the bugs it caught and its known limitations
- docs(readme): an "Agents and the reveal guardrail" section — a when-to-use trigger table (your terminal / an agent / your own pipe / the agent needs the value / the agent needs it printed / you were blocked wrongly / you want it off), the three policy modes with what each does to whom, the one-shot approval flow, and both new config files
- docs(security): what the guardrail stops, and — measured — what it does not: keychain access, reinstalling the CLI, editing `policy.json`, truncating the trail, and an `env -i` invocation routed through a re-parenting stub. The OS-user split is named as the actual boundary
- docs(plans): the agent-safe vault plan records wave 1 with its live evidence, marks each acceptance criterion proven or pending, and corrects the one criterion the measurement disproved
