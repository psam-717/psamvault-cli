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

## Fixed

- fix(restore): a revoked kit file is now actually refused — a broad exception handler was swallowing the exit and continuing with the restore

## Changed

- feat(auth): logging in on a new machine now explains the device-key mismatch and points at `psamvault restore`
- chore(gitignore): `plans/` is no longer ignored, so plans are versioned
- `upgrade` (pipx track): reinstalls from PyPI with a pinned force install (`pipx install --force psamvault==<version>`) instead of `pipx upgrade` — repairs URL/TestPyPI/editable install sources so future upgrades track the registry

## Tests

- test(backup): 20 command tests plus wire-shape assertions (the passphrase and the vault key never appear on the wire)
- test(restore): 11 session-less restore tests, including the re-wrap proof and revoked/offline kits
- test(crypto): kit wrap/unwrap, tamper and parse-failure coverage, and an assertion that a kit file contains no secret value

## Docs

- docs(plans): plans moved into `plans/{active,shipped,archive}` with a verified-status index
- docs(plans): the backup and recovery plan records its live verification, the bugs it caught and its known limitations
