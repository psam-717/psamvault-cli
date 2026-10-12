# Unreleased Changes

<!--
  This file tracks changes merged to main but not yet published to PyPI.
  When preparing a release:
    1. Copy entries into CHANGELOG.md under the new version header
    2. Clear this file's content (keep the header)
    3. Bump version and publish
-->

## Fixed

- fix(upgrade): the PyPI track upgrades in place (`pipx upgrade psamvault`) instead of a pinned force install — the force install recreated the venv, rewriting the `python.exe` psamvault was running from, and failed on Windows with `os error 32`; the pinned reinstall now runs only from outside that venv, or is printed to run once the process exits
- fix(upgrade): the upgrade is confirmed by reading the version back from pipx, so an install whose recorded source is not the PyPI registry reports what it found instead of reporting success

## Tests

- test(upgrade): pin the in-place pipx track — no venv-recreating install from inside the venv, the after-exit command, and the version read-back
- test(upgrade): cover the pipx introspection helpers (recorded version, venv dir, running from the venv)

## Docs

- docs(upgrading): document the in-place pipx track, the `os error 32` cause, and the two situations where the pinned reinstall is still reached
