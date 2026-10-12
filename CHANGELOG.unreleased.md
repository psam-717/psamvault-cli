# Unreleased Changes

<!--
  This file tracks changes merged to main but not yet published to PyPI.
  When preparing a release:
    1. Copy entries into CHANGELOG.md under the new version header
    2. Clear this file's content (keep the header)
    3. Bump version and publish
-->

## Fixed

- fix(upgrade): the registry track upgrades in place through the tool that owns the install — `pipx upgrade psamvault`, or `uv tool upgrade psamvault` for a uv tool install — instead of a pinned force install that rebuilt the environment, which on Windows either died on the locked interpreter (pipx, `os error 32`) or left psamvault unimportable (uv, `os error 5`)
- fix(upgrade): an install that neither pipx nor uv tool owns is refused with guidance instead of being re-installed with pipx, which left two copies of the command shadowing each other on PATH
- fix(upgrade): the upgrade is confirmed by reading the version back from the owning tool, so a recorded source that is not the PyPI registry — or a uv install uv reports as pinned, where uv prints nothing to upgrade and exits 0 — is reported instead of passed off as success

## Tests

- test(upgrade): pin both in-place routes (pipx and uv tool) and the guard that stops the environment from being rebuilt while psamvault is running from it
- test(upgrade): cover install-manager detection, the version read-back and the environment guard

## Docs

- docs(upgrading): document the registry track (pipx / uv tool), the `os error 32` and `os error 5` causes, and the situations in which the rebuilding reinstall is reached
