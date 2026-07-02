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
- `get`: suppress traceback when fetching a non-existent entry — shows clean "No entry found" message instead of `ApiError` traceback
- `update`: same fix — `ApiError` caught on non-existent entries, clean error instead of traceback
- `delete`: same fix — `ApiError` caught on non-existent entries, clean error instead of traceback
- `add`: improved site name validation error — now includes valid name examples (e.g. `github.com`, `my-site_1`, `email@gmail.com`)
