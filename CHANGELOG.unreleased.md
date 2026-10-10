# Unreleased Changes

<!--
  This file tracks changes merged to main but not yet published to PyPI.
  When preparing a release:
    1. Copy entries into CHANGELOG.md under the new version header
    2. Clear this file's content (keep the header)
    3. Bump version and publish
-->

## Fixed

- fix(list): the API KEYS section groups keys under their project and folds backup copies onto the live row, using the same renderer as `ak-list`; it printed every stored name - `env/.env.bak-.../KEY` and all - in one flat table

## Docs

- docs(reference): the `list` entry records its three sections and the API key grouping it shares with `ak-list`
