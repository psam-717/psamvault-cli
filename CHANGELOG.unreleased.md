# Unreleased Changes

<!--
  This file tracks changes merged to main but not yet published to PyPI.
  When preparing a release:
    1. Copy entries into CHANGELOG.md under the new version header
    2. Clear this file's content (keep the header)
    3. Bump version and publish
-->

## Docs

- docs: the user documentation moved out of the README into `docs/` — overview, installation, a feature map, a guide per feature (backup & recovery, the agent reveal guardrail, upgrading, the web dashboard) and complete command and configuration references, so a site can populate from the repo
- docs(readme): the README is now a landing page that links the docs tree instead of duplicating it — one source of truth per topic
- docs(guides): a backup & recovery runbook that states what a new machine needs and does not need, what restore changes, and how to prove a backup without a destructive real restore
- docs(fix): the docs showed `psamvault setup` for first-run setup — the command is `psamvault configure`
- docs(fix): the source-install instructions said `cd psamvault-cli/cli`; the clone root is the package root
