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
- feat(dashboard): the logged-out page can sign in, reset a forgotten password with one recovery code, and restore a new or wiped machine from a backup passphrase or a kit file. Sign out revokes the server session as well as the local one. Recovery codes can be replaced after the login password is confirmed, and the new codes are shown once. The vault key and the tokens stay on this computer
- feat(prompts): one helper reads every hidden secret prompt, and `PSAMVAULT_SHOW_SECRETS=1` makes the login password, the backup passphrase and the other fifteen hidden prompts visible instead of hidden

## Changed

- refactor(dashboard): the dashboard is a React screen on the same local server. Passwords, API keys and notes stay hidden until Reveal or Copy

## Fixed

- fix(ak): `ak-get`, `ak-update`, and `ak-delete` accept a project key stored as `project/.env/KEY`. A leaf name resolves to the one live row, including when backup copies share that leaf. `ak-list` groups those keys by project, labels keys stored with no project as `(unscoped)`, and folds backup copies onto the live row
- fix(dashboard): the Keys tab filters by Standalone, Project-scoped, or Project-unscoped, and shows one type at a time. Project-scoped keys are grouped under their project. Backup copies are marked stale. View, Edit, and Delete send the stored name
- fix(dashboard): the first load, and an edit dialog while its row is fetched, show a shimmer in the shape of the page or the form. The highlight stays still when reduced motion is on
- fix(api-client): the API key list walks every server page, so a key past the first page is still found
- fix(dashboard): an expired session can be retried, or signed in, reset with a recovery code, or restored on the page. Retry still re-reads the keychain
- fix(session): a refresh that lost the token rotation to another client no longer reports the session as expired - the CLI re-reads the keychain store and retries with the newer token, and only an unchanged store is treated as a dead chain
- fix(login): a failed login names the real causes - a typo (a leading or trailing space is a different password), an account password replaced by a restore on another machine, or a pepper changed on this machine - and the way out, `psamvault restore --force` or `psamvault logout` first, instead of presuming a new machine
- fix(login): the saved session is checked before anything is asked - one that can no longer refresh goes straight to the username and password prompts, and declining to replace a working one prints what was kept plus `psamvault logout`, instead of exiting 0 in silence
- fix(restore): the warning that a restore replaces the login password for the whole account and signs out every other machine now prints before the first change and again in the success text
- fix(prompts): a hidden prompt with no terminal to read from fails immediately with a non-zero exit and says it cannot be answered, instead of blocking for ever printing nothing

## Docs

- docs(commands): `ak-get`, `ak-list`, and `ak-delete` describe project key names and folded stale copies
- docs(dashboard): the web dashboard guide describes the API key type filter and the loading shimmer
- docs(dashboard): the web dashboard guide, the feature map, and the dashboard command describe sign-in, a forgotten password, and restore on the page
- docs(dashboard): the web dashboard guide, the overview and the configuration reference describe the in-memory session and how to restore it with `pv list` or `pv login`
- docs: the user documentation moved out of the README into `docs/` — overview, installation, a feature map, a guide per feature (backup & recovery, the agent reveal guardrail, upgrading, the web dashboard) and complete command and configuration references, so a site can populate from the repo
- docs(readme): the README is now a landing page that links the docs tree instead of duplicating it — one source of truth per topic
- docs(guides): a backup & recovery runbook that states what a new machine needs and does not need, what restore changes, and how to prove a backup without a destructive real restore
- docs(fix): the docs showed `psamvault setup` for first-run setup — the command is `psamvault configure`
- docs(fix): the source-install instructions said `cd psamvault-cli/cli`; the clone root is the package root
- docs(reference): the command reference records the account-wide effect of a restore and the real login-failure causes, and the configuration reference documents `PSAMVAULT_SHOW_SECRETS`
