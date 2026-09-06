# Unreleased Changes

<!--
  This file tracks changes merged to main but not yet published to PyPI.
  When preparing a release:
    1. Copy entries into CHANGELOG.md under the new version header
    2. Clear this file's content (keep the header)
    3. Bump version and publish
-->

## Changed

- `whoami`: suppress traceback on session timeout — shows clean message instead of Python exception (`ApiError` caught, `typer.Exit` raised)
- `search`: hide passwords and API key values from search results — shows `********` instead of plaintext values
  - Site password field now displays `Password:  ********`
  - API key value field now displays `Key:      ********`
- `get`: suppress traceback when fetching a non-existent entry — shows clean ✗ message with hint to use `pv list`
- `update`: same fix — `ApiError` caught on non-existent entries, shows clean ✗ message with hint
- `delete`: same fix — `ApiError` caught on non-existent entries, shows clean ✗ message with hint
- `browser open` / `browser daemon`: same fix — `ApiError` caught on missing entries, clean JSON/CLI error instead of traceback
- `add`: improved site name validation error — now includes valid name examples (e.g. `github.com`, `my-site_1`, `email@gmail.com`)
- `add`: (vault/note/api-key) duplicate entry now shows clean ✗ message — catches `ApiError` (409 Conflict) and shows "already exists" with hint to use the update command
- `_handle_error`: removed `typer.echo` from both 404 and 409 handlers — API layer raises `ApiError` without printing; all user-facing messages now owned by command layer
- **dashboard**: added Host header validation (`_enforce_localhost_host`) — rejects requests with unexpected Host values to block DNS-rebinding attacks
- **dashboard**: changed password/key reveal endpoints from GET to POST with `Cache-Control: no-store` — secrets no longer cached to disk or retained in browser history
  - Updated JS `fetch()` calls in `entry_detail.html` and `api_key_detail.html` to use `{method: 'POST'}`

### Typed errors (#38)

- API layer now raises typed exceptions (`NotFoundError`, `SessionExpiredError`, `NetworkError`, `ValidationError`, `ConflictError`) — no origin-side printing; command layer owns all user-facing messages (single print site)
- `ak-get` / `ak-update` / `ak-add` / vault / notes: a dead or expired session is **no longer misreported as "key not found"** — shows `✗ Your session has expired → Run psamvault login`; network failures show `✗ Could not reach the psamvault server → check your connection`
- `browser open` / `browser daemon`: typed errors distinguish missing entry from session/network failure in both JSON and CLI output
- `whoami`: prints the actual reason (session expired / server unreachable) instead of exiting silently
- `search`: session/network failures are surfaced with a clean ✗ + hint instead of being silently swallowed
- Unreachable server / timeout anywhere now yields a clean connectivity message instead of a raw `httpx` traceback (including during token refresh)
- New global `--verbose` flag shows underlying error type/detail
- signup / migrate / auto-login-after-migration error paths no longer print raw exception text
- `update_check`: fixed Windows crash (`NotADirectoryError`) when the git repo path is invalid — update notice path degrades gracefully
