# Unreleased Changes

<!--
  This file tracks changes merged to main but not yet published to PyPI.
  When preparing a release:
    1. Copy entries into CHANGELOG.md under the new version header
    2. Clear this file's content (keep the header)
    3. Bump version and publish
-->

## Changed

- `upgrade` (pipx track): reinstalls from PyPI with a pinned force install (`pipx install --force psamvault==<version>`) instead of `pipx upgrade` — repairs URL/TestPyPI/editable install sources so future upgrades track the registry
