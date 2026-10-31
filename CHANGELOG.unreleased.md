# Unreleased Changes

<!--
  This file tracks changes merged to main but not yet published to PyPI.
  When preparing a release:
    1. Copy entries into the CHANGELOG dict in changelog.py (scripts/release.py checks that dict; there is no CHANGELOG.md)
    2. Clear this file's content (keep the header)
    3. Bump version and publish
-->

## Added

- feat(policy): `psamvault policy allow-host <entry> <host>` adds one hostname to `entries.<name>.allow_hosts` in `~/.psamvault/policy.json`, the destination list psamvault-mcp reads. `policy remove-host` takes one off. `policy hosts` lists one entry or every entry. `pv policy` is the same command. A grant or a removal is refused when the caller is classified as an agent, needs a terminal a pipe cannot answer, and writes an audit row. Listing is allowed for an agent. The grant normalises case, a trailing dot, and IDNA, and refuses a scheme, a path, a port, an IP literal, a wildcard other than a leading `*.`, an internal name, and a bare public suffix such as `com` or `co.uk`. Loopback, private, and link-local addresses stay blocked. Loading the file reports a bad `allow_hosts` value and leaves every other key as it was. `allow_entries` stays the reveal list. No command prints a secret
- feat(dashboard): `pv dashboard --port` chooses the listen port. The default is 8500. If 8500 is busy and `--port` was not given, the dashboard binds a free port and prints that URL. An explicit `--port` that is busy stops and names the port. The Origin allow-list is `http://127.0.0.1`, `http://localhost` and `http://[::1]` on the port that was actually bound

## Fixed

- fix(keyring): `psamvault --version` and `--help` no longer read the OS keychain, so on Linux they print instead of crashing with `NoKeyringError` or hanging on a locked Secret Service prompt. `changelog` and `generate` (without `--save`) do not need the keychain either
- fix(keyring): a command that needs the keychain and finds it missing or locked stops with one line (`✗ what failed — what to do next`) instead of a traceback. A locked Secret Service collection is reported before keyring can block on a GUI unlock prompt. A Secret Service with no default collection (gnome-keyring running, login keyring never created) stops the same way, before `create_collection` can block on a prompt. The check reuses one Secret Service connection instead of opening a new one on every keyring read. The pepper and the tokens are never written to a file when the keychain cannot keep them
- fix(dashboard): the local dashboard returns that same keychain sentence as JSON when a request needs a keychain that is missing, locked, or has no default collection, instead of an HTML 500. Signing in from the page does the same
- fix(config): a legacy `PSAMVAULT_PEPPER` line that disagrees with the pepper already in the OS keychain is left in `config.env` and a notice is printed once per command. It is no longer deleted without saying so. The keychain pepper stays the one in use
- fix(login): `psamvault login` no longer treats a locked or missing keychain as a saved session that cannot be refreshed. The keychain error is the one that stops the command
- fix(configure): `psamvault configure` no longer says the pepper is in `~/.psamvault/config.env` or to back that file up, and it no longer prints any of the pepper. The pepper is in the OS keychain; the file holds the API URL only. A legacy pepper left in the file is removed only after the keychain read-back matches
- fix(keyring): the Linux hint for a locked keychain, and for a gnome-keyring daemon with no login keyring, is `echo -n '<password>' | gnome-keyring-daemon --replace --unlock --components=secrets`. Plain `--unlock` exits 0 and starts a second daemon; the daemon that owns the Secret Service stays locked or empty. `--replace` quits that daemon and this process unlocks the login keyring, or creates it when the store is empty
- fix(dashboard): `pv dashboard` puts a one-time token in the URL fragment. The page exchanges it once for an HttpOnly, SameSite=Strict cookie. Every `/api` route requires that cookie and the dashboard Origin. A password or API-key reveal uses the same gate as `psamvault get` and `psamvault ak-get`, for the process that started the dashboard, and writes an allow or deny audit row
- fix(dashboard): list and detail GETs return `has_notes` and do not return notes text. Notes are a separate reveal route that calls `require_reveal`, and both the allow and the deny write an audit row. Saving an entry does not replace notes that were never revealed, including a body that sends an empty notes field. The edit form keeps notes hidden behind Reveal and omits them from the save until then. A same-origin GET may omit Origin, which is what the browser does; a POST with no Origin is still rejected

## Tests

- test(conftest): set `PYTHON_KEYRING_BACKEND`, `PSAMVAULT_PEPPER` and `PSAMVAULT_API_URL` when they are unset, so a bare pytest does not touch the developer keychain
- test(policy): destination allow hosts cover normalisation, the grant-versus-load split, an agent refusal, a pipe that cannot confirm, `127.0.0.1` and a bare public suffix, a missing entry, and that a secret returned by the entry lookup is never printed
- test(dashboard): list and detail GETs carry `has_notes` and not the notes text, the notes route audits allow and deny, a save before that reveal keeps the stored notes, and `--port` either binds the named port or falls back only when the default was left busy

## Docs

- docs(installation): Linux install covers PEP 668 (`sudo apt install pipx` — `pip install pipx` is refused), a headless Secret Service setup, and Chromium via the pipx environment's `playwright` because that executable is not on `PATH` (a virtualenv uses that environment's `python -m playwright`). The no-default-collection error is documented, including `--replace` so unlock creates the keyring on a daemon that is already running
- docs(contributing): the test dependencies (the `dev` group) and the three environment variables the suite expects (`PYTHON_KEYRING_BACKEND`, `PSAMVAULT_PEPPER`, `PSAMVAULT_API_URL`)
- docs(installation): `sudo apt update` comes before `sudo apt install pipx`, because a fresh box otherwise reports `Unable to locate package pipx`
- docs(installation): the Secret Service check runs the pipx environment's Python (`pipx environment --value PIPX_LOCAL_VENVS`), not system `python3`, which has no `keyring`. The printed line is `keyring.backends.SecretService.Keyring (priority: 5)`
- docs(installation): the headless unlock command is `gnome-keyring-daemon --replace --unlock`, for a locked daemon and for an empty store. `--replace` quits a daemon that is already running; with no daemon running it starts normally
- docs(policy): the command reference, the configuration reference, the agent reveal guardrail, the feature map, installation, the README, and SECURITY.md say when to grant a destination host and what that command is not for. `allow_entries` stays the reveal list, and `allow_hosts` does not override the block on loopback, private, and link-local addresses
- docs(dashboard): the README, SECURITY.md, the dashboard guide, the guardrail guide, and the configuration reference describe the in-memory vault session and the browser cookie as a session id
- docs(dashboard): SECURITY.md and the web dashboard guide say the single-use launch token appears on the browser launch command line until the page exchanges it, and why that is accepted. The command reference, the feature map, and the README describe `--port` and that notes stay hidden until reveal
