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
