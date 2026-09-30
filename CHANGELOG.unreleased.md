# Unreleased Changes

<!--
  This file tracks changes merged to main but not yet published to PyPI.
  When preparing a release:
    1. Copy entries into CHANGELOG.md under the new version header
    2. Clear this file's content (keep the header)
    3. Bump version and publish
-->

## Added

- feat(dashboard): tabs and search stay in the browser, and `pv dashboard` reads the OS keychain once per process instead of on every click

## Changed

- refactor(dashboard): the dashboard is a React screen on the same local server. Passwords, API keys and notes stay hidden until Reveal or Copy

## Fixed

- fix(ak): `ak-get`, `ak-update`, and `ak-delete` accept a project key stored as `project/.env/KEY`. A leaf name resolves to the one live row, including when backup copies share that leaf. `ak-list` groups those keys by project, labels keys stored with no project as `(unscoped)`, and folds backup copies onto the live row
- fix(dashboard): the Keys tab groups project keys by project and marks backup copies stale. View, Edit, and Delete send the stored name
- fix(api-client): the API key list walks every server page, so a key past the first page is still found
- fix(dashboard): an expired session tells you to run `pv list` and click Retry, or `pv login` if you are logged out. Retry reads the keychain again
- fix(session): a refresh that lost the token rotation to another client no longer reports the session as expired - the CLI re-reads the keychain store and retries with the newer token, and only an unchanged store is treated as a dead chain

## Docs

- docs(commands): `ak-get`, `ak-list`, and `ak-delete` describe project key names and folded stale copies
- docs(dashboard): the web dashboard guide says the Keys tab groups project keys
- docs(dashboard): the web dashboard guide, the overview and the configuration reference describe the in-memory session and how to restore it with `pv list` or `pv login`
- docs: the user documentation moved out of the README into `docs/` — overview, installation, a feature map, a guide per feature (backup & recovery, the agent reveal guardrail, upgrading, the web dashboard) and complete command and configuration references, so a site can populate from the repo
- docs(readme): the README is now a landing page that links the docs tree instead of duplicating it — one source of truth per topic
- docs(guides): a backup & recovery runbook that states what a new machine needs and does not need, what restore changes, and how to prove a backup without a destructive real restore
- docs(fix): the docs showed `psamvault setup` for first-run setup — the command is `psamvault configure`
- docs(fix): the source-install instructions said `cd psamvault-cli/cli`; the clone root is the package root
