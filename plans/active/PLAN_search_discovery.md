# PLAN — `search` is a discovery command (never prints values)

**Status:** 🟡 Decisions locked, build starting (2026-10-12)

**Proposed by:** psam, 2026-10-12 («It displays the exact keys. It's not supposed to show. Else it undermines the P.V. get command.»)

## Summary

`search` is the only discovery command that prints secrets. `list`, `ak-list` and `note-list`
show what exists and never decrypt a value; `search` decrypts every match and prints the
password, the key and the note content. The reveal gate built in 0.7.2 withheld those values
from **agent** callers only, which left a human-shaped hole in the guardrail and left a
recorded decision half-implemented: the module docstring of `tests/test_search_reveal_policy.py`
already says search "stays usable as a *discovery* command — names, projects, services, note
titles — and the value itself needs the reveal path (`get`/`ak-get`/`note-get`, or an approval)".

After this change `search` never prints a value or a free-text field, for any caller, under any
policy mode: each match names the command that reveals it. The value then leaves the vault
through exactly one audited path per entry.

## Key Points (current state)

- Emitting lines in `command/vault_commands.py::search`: `Password:` (site), `Notes:` (site),
  `Key:` (API key), `Notes:` (API key), `Content:` (note). Values are gated by
  `reveal_gate.DiscoveryReveal`; **`Notes:` for sites and API keys is printed with no gate at
  all** — measured: an agent caller gets the break-glass code stored in a note verbatim while
  the password beside it is withheld.
- `DiscoveryReveal` decides once per invocation at caller level (`policy.decide(policy, verdict,
  None)`), writes one audit row (`deny` when it withheld, else `allow`), never consults an
  approval token, and its footer hint offers `psamvault approve <entry> --for-agent` — advice
  that **cannot work**: a search covers many entries and `DiscoveryReveal` never reads approvals.
- `Policy.reveal` modes (`human-only` / `strict` / `open`) change search's output for `open`.
- Pinned behaviour (tests): `test_a_human_still_gets_the_values_and_an_allow_row`,
  `test_search_still_prints_the_key_value`, `test_the_invocation_writes_exactly_one_deny_row`.
- Documented behaviour: `docs/reference/commands.md` (search + guardrail sections),
  `docs/features.md`, `docs/guides/agent-reveal-guardrail.md`.

## Decisions Made

| # | Decision | Rationale |
|---|---|---|
| 1 | **`search` never prints a value, for any caller** (chosen **A**; `--reveal` opt-in (C) deferred) | The value leaves the vault through one audited path per entry; search keeps doing what only it can — finding the entry. Decided by psam, 2026-10-12. |
| 2 | **The withheld line is actionable**: `hidden — run  psamvault <get\|ak-get\|note-get> "<name>"` | A marker with no next step is a dead end; the hint names the exact command and argument. |
| 3 | **Free-text fields obey the same rule**: site/API-key `Notes:` as well as `Content:` | Measured leak: notes are free text the query matches, and they print ungated today. Fixing only the "value" fields would leave the hole open. |
| 4 | **No policy mode restores the old output** — not even `open` | One rule to document and test. The deliberate bulk path stays `export --plaintext`, which policy *does* govern. |
| 5 | **The hint quotes a name only when it contains whitespace** | Names may contain spaces (the forbidden-character set does not include one), and an unquoted argument would then split. |
| 6 | **One audit row per invocation, `decision="discovery"`** (new constant) | Search reveals nothing, so `allow` would read as "an agent was allowed to reveal" and `deny` would claim a refusal that never happened. The caller/signals are still recorded. |

## Build Order

1. `tests/` first (RED): flip the human test, add notes-gating for both callers, assert the hint
   names a runnable command, assert one `discovery` row per invocation.
2. `reveal_gate.py`: `DiscoveryReveal` → `Discovery` (classifies once, always withholds, renders
   the hint, writes the row); `audit.py`: `DECISION_DISCOVERY`.
3. `command/vault_commands.py::search`: route every emitting line through `Discovery`.
4. Docs: `docs/reference/commands.md`, `docs/features.md`,
   `docs/guides/agent-reveal-guardrail.md`, `SECURITY.md` (decision vocabulary).
5. Changelog entry — separate PR (`feat/changelog-pr-<N>`), based on `main`.

## Files Likely to Change

`command/vault_commands.py` (search), `reveal_gate.py`, `audit.py`,
`tests/test_search_reveal_policy.py`, `tests/test_search_api_key_display.py`,
`tests/test_reveal_gate.py`, `docs/reference/commands.md`, `docs/features.md`,
`docs/guides/agent-reveal-guardrail.md`, `SECURITY.md`, `CHANGELOG.unreleased.md`.

## Acceptance Criteria

- [ ] No matched value or free-text field appears in `search` output for **any** caller
      (human / uncertain / agent) under **any** policy mode — proven by test, not by reading.
- [ ] Every match still shows its identity: site + username, API-key name/project/source/service,
      note title/category, login URL.
- [ ] Every withheld line names a copy-pasteable command: `get <site>`, `ak-get "<name>"`,
      `note-get "<title>"` — quoted only when the name needs it.
- [ ] Exactly one audit row per invocation, `decision="discovery"`, with caller and signals.
- [ ] No approval token is spent by a search (unchanged).
- [ ] Docs updated in the same PR; `scripts/check-docs-surface.py` green.
- [ ] Full suite green locally **and** as CI runs it (`USERPROFILE`/`HOME` pointed at an empty
      dir), plus the CI matrix.

## Risks & Mitigations

- **Ergonomics**: a value that used to be one command away now needs `get`. Mitigation: the hint
  carries the exact command; the deferred `--reveal` flag is the answer if the audit trail shows
  the extra step is painful.
- **Breaking output change for other users of a public CLI**: ship it as a `Changed` changelog
  entry with the reason (the CLI is pre-1.0); docs updated in the same PR.
- **A future discovery command re-introduces the hole**: the rule lives at one chokepoint
  (`reveal_gate.Discovery`) that any discovery command must call to print a value line.

## Rejected Alternatives

- **B — keep printing for humans**: contradicts the recorded decision, and leaves the notes field
  ungated; rejected by psam.
- **C — `--reveal` opt-in flag**: deferred, not rejected. Re-open if the audit trail shows values
  being pulled from `search` more than rarely, or if a script of psam's greps search output.
- **Gate `Notes:` but keep values**: fixes the measured leak and keeps the odd one out; rejected
  as incoherent.
- **Per-entry decisions for search (allowlist / approval tokens)**: a search covers many entries,
  so a per-entry token would have to be minted per match; that is `get` with extra steps.

## Open Questions

- [ ] Does anything besides psam's own muscle memory depend on `search` printing values?
      (Nothing in this repo does: no test outside the two named files, no doc.)
