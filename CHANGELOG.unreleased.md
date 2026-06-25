# Unreleased Changes

<!--
  This file tracks changes merged to main but not yet published to PyPI.
  When preparing a release:
    1. Copy entries into CHANGELOG.md under the new version header
    2. Clear this file's content (keep the header)
    3. Bump version and publish
-->

## Added

- feat: login url detection for improved login flow
- feat: formatting table for project-based .env keys
- feat(update): dual-track update check with commit-based notices
- feat(upgrade): auto-detect install type and run correct upgrade path
- feat: add run_with_credential MCP tool
- feat(cli): add psamvault search <query> command for local decrypt-and-filter search

## Fixed

- fix(commands): improve error message when API key not found
- fix: update tests to expect ApiError instead of SystemExit

## Tests

- test(update): cover install detection, commit counting, notices
- test(commands): verify ak-get and ak-update handle missing key gracefully

## Docs

- docs: add search command section to README
- docs: add PLAN.md for commit-based update notifications
- docs: add run_with_credential to PLAN.md, SKILL_PLAN.md, DEMO_SCRIPT.md
