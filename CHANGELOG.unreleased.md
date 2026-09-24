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
- feat(ingress): when an agent runs `add`, `ak-add`, or `note-add` without a value, the CLI writes a 15-minute claim and prints a code (`PV-XXXX-XXXX`) instead of prompting. The human fills it in their own terminal with `--claim CODE` and hidden input. The value never reaches the agent. The code is spent only after the entry is stored.
- feat(ingress): `psamvault pending` lists claims that are still waiting, with the time left. `psamvault pending --cancel CODE` drops one. The claim file is metadata only.
- feat(ingress): a secret passed on the command line (`--key`, `--pass`, `--content`) is refused when the caller is an agent, and so is an agent filling `--claim`. Both refusals are audited.

## Changed

- refactor(dashboard): the dashboard is a React screen on the same local server. Passwords, API keys and notes stay hidden until Reveal or Copy

## Fixed

- fix(dashboard): an expired session tells you to run `pv list` and click Retry, or `pv login` if you are logged out. Retry reads the keychain again

## Docs

- docs(ingress): the credential-blind ingress guide — the claim code, the human fill, and what the guarantee does not cover
- docs(config): the pending claim store — `~/.psamvault/pending/`, metadata only, `0600`, single-use, 15-minute lifetime — and the `claim-created` / `claim-filled` audit lines
- docs(dashboard): the web dashboard guide, the overview and the configuration reference describe the in-memory session and how to restore it with `pv list` or `pv login`
- docs: the user documentation moved out of the README into `docs/` — overview, installation, a feature map, a guide per feature (backup & recovery, the agent reveal guardrail, upgrading, the web dashboard) and complete command and configuration references, so a site can populate from the repo
- docs(readme): the README is now a landing page that links the docs tree instead of duplicating it — one source of truth per topic
- docs(guides): a backup & recovery runbook that states what a new machine needs and does not need, what restore changes, and how to prove a backup without a destructive real restore
- docs(fix): the docs showed `psamvault setup` for first-run setup — the command is `psamvault configure`
- docs(fix): the source-install instructions said `cd psamvault-cli/cli`; the clone root is the package root
