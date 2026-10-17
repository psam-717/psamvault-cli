# Unreleased Changes

<!--
  This file tracks changes merged to main but not yet published to PyPI.
  When preparing a release:
    1. Copy entries into the CHANGELOG dict in changelog.py (scripts/release.py checks that dict; there is no CHANGELOG.md)
    2. Clear this file's content (keep the header)
    3. Bump version and publish
-->

## Fixed

- fix(keyring): `psamvault --version` and `--help` no longer read the OS keychain, so on Linux they print instead of crashing with `NoKeyringError` or hanging on a locked Secret Service prompt. `changelog` and `generate` (without `--save`) do not need the keychain either
- fix(keyring): a command that needs the keychain and finds it missing or locked stops with one line (`✗ what failed — what to do next`) instead of a traceback. A locked Secret Service collection is reported before keyring can block on a GUI unlock prompt. A Secret Service with no default collection (gnome-keyring running, login keyring never created) stops the same way, before `create_collection` can block on a prompt. The check reuses one Secret Service connection instead of opening a new one on every keyring read. The pepper and the tokens are never written to a file when the keychain cannot keep them
- fix(dashboard): the local dashboard returns that same keychain sentence as JSON when a request needs a keychain that is missing, locked, or has no default collection, instead of an HTML 500. Signing in from the page does the same
- fix(config): a legacy `PSAMVAULT_PEPPER` line that disagrees with the pepper already in the OS keychain is left in `config.env` and a notice is printed once per command. It is no longer deleted without saying so. The keychain pepper stays the one in use
- fix(login): `psamvault login` no longer treats a locked or missing keychain as a saved session that cannot be refreshed. The keychain error is the one that stops the command
- fix(configure): `psamvault configure` no longer says the pepper is in `~/.psamvault/config.env` or to back that file up, and it no longer prints any of the pepper. The pepper is in the OS keychain; the file holds the API URL only. A legacy pepper left in the file is removed only after the keychain read-back matches

## Tests

- test(conftest): set `PYTHON_KEYRING_BACKEND`, `PSAMVAULT_PEPPER` and `PSAMVAULT_API_URL` when they are unset, so a bare pytest does not touch the developer keychain

## Docs

- docs(installation): Linux install covers PEP 668 (`sudo apt install pipx` — `pip install pipx` is refused), a headless Secret Service setup, and Chromium via the pipx environment's `playwright` because that executable is not on `PATH` (a virtualenv uses that environment's `python -m playwright`). The no-default-collection error is documented, including `--replace` so unlock creates the keyring on a daemon that is already running
- docs(contributing): the test dependencies (the `dev` group) and the three environment variables the suite expects (`PYTHON_KEYRING_BACKEND`, `PSAMVAULT_PEPPER`, `PSAMVAULT_API_URL`)
