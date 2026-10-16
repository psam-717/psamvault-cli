# Unreleased Changes

<!--
  This file tracks changes merged to main but not yet published to PyPI.
  When preparing a release:
    1. Copy entries into CHANGELOG.md under the new version header
    2. Clear this file's content (keep the header)
    3. Bump version and publish
-->

## Fixed

- `psamvault --version` and `--help` no longer read the OS keychain, so on Linux they print instead of crashing with `NoKeyringError` or hanging on a locked Secret Service prompt. `changelog` and `generate` (without `--save`) do not need the keychain either
- a command that needs the keychain and finds it missing or locked stops with one line (`✗ what failed — what to do next`) instead of a traceback. A locked Secret Service collection is reported before keyring can block on a GUI unlock prompt. The pepper and the tokens are never written to a file when the keychain cannot keep them
- `psamvault configure` no longer says the pepper is in `~/.psamvault/config.env` or to back that file up, and it no longer prints any of the pepper. The pepper is in the OS keychain; the file holds the API URL only. A legacy pepper left in the file is removed only after the keychain read-back matches

## Docs

- Linux install: PEP 668 (`sudo apt install pipx` — `pip install pipx` is refused), a headless Secret Service setup, and Chromium via the pipx environment's `playwright` because that executable is not on `PATH`
- CONTRIBUTING: the test dependencies (the `dev` group) and the three environment variables the suite expects (`PYTHON_KEYRING_BACKEND`, `PSAMVAULT_PEPPER`, `PSAMVAULT_API_URL`)
