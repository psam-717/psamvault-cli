# Agent-Safe Vault — reveal guardrails and credential-blind writes

**Status:** 🟢 WAVE 1 MERGED — steps 1-5 shipped in v0.6.0 (PR #54, merged 2026-09-23):
classifier, ancestry, policy, audit, gate, `approve` command, `--agent` flag, all four reveal paths
gated, 97 new tests. Landing verified — the merge commit is an ancestor of `main`.

**🟡 WAVE 2 DECISIONS LOCKED (2026-09-24, psam) — credential-blind ingress, not started.**
Coverage (all three secret families), the handoff mechanism (`ak-pending` + opt-in `--wait`),
`--from-file` semantics and the wave boundary are decided below. Wave 3 (loopback claim form, use-side
per-entry policy, the MCP half) is deferred **with its decisions recorded**, so reopening starts from
them instead of from scratch. Step 11 (backend `/vault/proxy` → `410 Gone`) is independent of
wave 2 and can land any time.

**Proposed by:** User (psam)
**Date:** 2026-09-18

---

## Summary

Two halves of one problem: today an agent can (a) read a secret out of psamvault that was never meant
for it, and (b) cannot put a secret into psamvault without having seen it first.

Part 1 adds a **reveal guardrail**: a single chokepoint that classifies the caller, refuses to print
a secret from an agent context, and — when a human genuinely needs to hand one over — requires a
human-issued, single-use, TTL-bound approval token minted from a real terminal. Part 2 adds
**credential-blind ingress**: an agent can create a vault entry and hand the human a claim code, the
human supplies the secret in their own terminal or in a loopback web form, and the plaintext never
enters the agent's context, argv, or shell history. Part 2 also hardens the use side (per-entry
policy, wider redaction — leases park for later) so a stored secret stays usable without ever being
revealed.

## Threat model — read this before the design

**This is a guardrail, not a security boundary.** An agent that already has a shell *and* the user's
keychain can reach any secret: read Windows Credential Manager, `import crypto` and decrypt directly,
or install a pristine copy of the CLI. What this work buys is:

- well-behaved agents (Hermes, Claude Code, Codex, Goose, OpenCode) get a hard *structural* stop,
  not a prompt-level suggestion;
- accidents and prompt-injection-driven reveals become loud and auditable;
- the correct alternative (a capability, not a value) is always one message away;
- a real human approval leaves a trail.

A true boundary needs the agent to run as a **different OS user** with no access to the user's
keychain and no read on `~/.psamvault`. That is option D under Decision 1, documented in `SECURITY.md`
and priced, but deliberately not built now: Hermes and the desktop app currently run as the user.

## Key Points

1. The MCP server is already capability-shaped: 13 tools, **no tool returns plaintext**, and
   `run_with_credential` / `use_credential` inject a credential into a subprocess or HTTP request and
   redact it from captured output (`mcp_server/cmd_runner.py:155-160`). That design is the model to
   extend, not replace.
2. The CLI is the hole: `psamvault get <site>` prints the password to stdout
   (`command/vault_commands.py:221-222`), `psamvault ak-get <name>` does the same
   (`command/api_key_commands.py:229-240`), both support `--copy` (clipboard — an agent can read it),
   and `export --plaintext` writes everything readable to disk. `command/auth_commands.py` and
   `command/note_commands.py` have similar surfaces.
3. `psamvault-mcp/AGENTS.md` already tells agents *"do not improvise with … bare `psamvault get`"* —
   that is documentation only, with nothing enforcing it.
4. Nothing today distinguishes "a human at a terminal" from "a subprocess". There is no agent marker,
   no TTY check, no policy file, and no audit log anywhere in either repo (verified by grep).
5. `psamvault ak-add <name> --key <value>` puts the secret in **argv** — visible in process listings,
   shell history, and any wrapper that logs the command line. This is the current documented way to
   store a key non-interactively.
6. `mcp_server/tools.py` `run_with_credential` and `use_credential` redact the credential value, but
   only the raw value: not its base64 form, not URL-encoded, not the first-8-character prefix that
   `_redact` uses as a fallback hint in the other direction.
7. **Backend finding — `POST /vault/proxy` ships the plaintext to the server.** The MCP must put the
   credential in `body["_credential_password"]` (`app/controller/proxy_crud.py`); the schema docstring
   above it still describes the abandoned design ("the backend fetches, decrypts, injects") even
   though the backend holds no key and cannot decrypt. Pre-deletion checks run 2026-09-18:
   - **No caller in either repo.** The MCP's own proxy client was deleted on purpose in `086f32f`
     (2026-06-16, "remove proxy_request and add HTTPS URL validation"); `tests/test_api_client.py`
     keeps an empty `TestProxyRequest` class documenting the removal.
   - **Nothing outside the repos calls it** (grep of `D:\Projects\py-projects`, the Hermes skills tree,
     `config.yaml` and `scripts/` — only docs mention it: backend `README.md`, this plan, the
     `psamvault-cli-development` skill).
   - **Live in production**, confirmed from the deployed `/openapi.json` (HTTP 200, 25 paths, both
     `/vault/proxy` and `/vault/proxy/check/{site_name}` present), so removal needs a Render deploy.
   - **Legacy-client tail:** MCP releases ≤ `v0.3.0` (May 2026) still call it from `use_credential`
     (`v0.4.0`, 2026-06-18 onward do not; `run_with_credential` never did). The published CLI never
     had a proxy command.
   - The committed backend `openapi.json` is stale — it omits both proxy paths; regenerate it in the
     same PR so the removal is visible in the spec.

8. **Caller signals measured live (2026-09-18)** — this replaces the guesswork for the Hermes half of
   build step 1. In this desktop session the agent's own shell carries `AI_AGENT=hermes-agent`,
   `HERMES_AGENT=true`, `_HERMES_GATEWAY=1`, `HERMES_DESKTOP=1`; file descriptors 0/1/2 are **not**
   TTYs and stdin is `/dev/null`; `TERM=xterm-256color` is set *without* a terminal, so `TERM` is not a
   usable signal on its own. Consequences: **no new marker has to be injected into Hermes** (it already
   self-identifies), the guardrail blocks an agent's own runs as soon as `AI_AGENT` / `HERMES_AGENT` are
   in the frozen list, and `--agent` stays the escape hatch for hosts that set no marker at all.
   **Measured (2026-09-18)** — psam ran the probe in the app's own terminal pane and the result was
   read back from the pane: it is **PowerShell, a real TTY, with no agent markers** (`AI_AGENT` and
   `HERMES_AGENT` both empty). So a marker-based rule blocks the agent's runs while leaving the user's
   in-app terminal fully usable — **no path is lost**.
   **Known limit, demonstrated rather than assumed:** an agent can strip its own markers
   (`env -u AI_AGENT -u HERMES_AGENT …` — verified working) and can allocate its own pseudo-terminal
   (`winpty` is present at `/usr/bin/winpty` — verified), so a marker-only rule is defeatable by an
   agent that reads this source. Signal strength is therefore its own open question below; the real
   boundary remains the OS-user split.

9. **Wave 2 has no claim surface in the code today.** `grep` for `claim`, `pending`, `from_file` and
   `allow_hosts` across the CLI returns nothing but the JWT `exp` claim in `session.py` — steps 6-8
   are 0% built. One consequence to keep honest: a shell-driven agent (Hermes runs the CLI directly)
   can use the claim flow the moment wave 2 ships, but an agent whose only surface is the MCP server
   cannot create a claim until `create_entry_blind` lands there (wave 3) — the MCP has no
   create-entry tool at all today.

## Key Decisions Needed

All resolved — see **Decisions Made**. Rejected alternatives at the end.

## Decisions Made

| Decision | Choice | Rationale |
|---|---|---|
| Guardrail default strictness | **Deny in agent context + TTY-only single-use approval token** | Stops the real case (an agent's shell) without making a human's own terminal annoying; scripts on the same machine keep working via the `uncertain` path below |
| Classification of a bare non-TTY caller | `uncertain` by default → **allowed with an audit note**; `strict` policy mode denies it instead | A blanket "no TTY ⇒ deny" would break every existing pipe and **every existing CliRunner test** (`CliRunner` has no TTY). Blocking must key on *positive agent signals*, with strictness available opt-in |
| Agent signals | Explicit `PSAMVAULT_AGENT=1` / `--agent` first, then a frozen marker list probed in step 1, then the parent-process ancestry. **Amended 2026-09-23:** `CI=true` is recorded in the audit row (`env:CI`) but is no longer graded as an agent — unattended is not driven, and grading it as one would refuse secrets in every CI pipeline while catching no agent the markers or ancestry would not already catch | Deterministic and testable; no fragile heuristics like "parent process looks like python" in the default path |
| MCP children | `run_with_credential` exports `PSAMVAULT_AGENT=1` into the subprocess env | Any CLI the agent runs through the vault is classified correctly with no guessing |
| Approval token | Minted only in a real interactive TTY, single-use, TTL (default 120s), stored in the OS keychain, consumed on first successful reveal | Reuses the keychain as the tamper-resistant store; a token that survives one reveal cannot be replayed |
| Policy file | `~/.psamvault/policy.json`, `0600`, absent = safe defaults | One readable file, JSON like the rest of the tooling; no new format to learn |
| Audit log | `~/.psamvault/audit.jsonl`, `0600`, size-rotated, never contains a secret | JSONL is greppable and append-only in practice; needed for provenance claims |
| Blind ingress | **Claim code (human's own terminal) + optional loopback web form**; the code is the primitive, the form is a front-end | Works over SSH and relayed instructions when no browser is available, best UX when one is |
| Where pending claims live | Local `~/.psamvault/pending/<code>.json`, `0600`, TTL 15 min, holding only `{name, service, notes, created_at}` | The filler process is on the same machine and same OS user, so no backend table is needed; nothing secret is stored and nothing new is exposed server-side. Cross-machine claims are explicitly out of scope |
| Claim code shape | 8 characters, Crockford base32, single-use, `PV-XXXX-XXXX` | ~40 bits is ample for a local, TTL'd, single-use handoff and is readable over a phone/Telegram |
| `--key <value>` | Kept for interactive TTY with a warning; **blocked** in agent context | Removes the argv leak without breaking humans who script from their own shell |
| `--from-file` / `--from-env` | Added, with `--delete-source` opt-in | Lets an agent migrate a key it must not read (pairs with the existing `scan_and_protect` tool) |
| Use-side controls | Per-entry policy (`allow_hosts`, `allow_commands`, `allow_inject`) **now**; `lease` **deferred** | Policy stops the dangerous case (exfiltration to a disallowed host) at zero workflow cost. A lease only restrains *timing* while adding a state machine and mid-task failures — and it cannot serve unattended cron agents at all, because minting needs a TTY (reopen trigger recorded in Open Questions) |
| Backend proxy credential path | **Delete it (option A), shipped as `410 Gone`** with an "upgrade psamvault-mcp ≥ 0.4.0" hint; keep `GET /vault/proxy/check/{site_name}` | Decided 2026-09-18 after the pre-deletion checks (see Key Points 7): no live caller, no cross-repo consumer, nothing to break except pinned MCP ≤0.3.0 installs, which get a legible error instead of a silent failure. The zero-knowledge claim stays literally true and the hosted-agent case (option B) is not a user psamvault currently serves |
| Hermes' own self-identification | **Counts as an agent** — `AI_AGENT=hermes-agent` / `HERMES_AGENT=true` go into the frozen marker list | Decided 2026-09-18 after measuring both sides: the agent's shell carries them, the user's in-app terminal pane (PowerShell, real TTY) does not — so blocking the agent costs the user nothing |
| Signal strength | **Marker list + parent-process ancestry** | Decided 2026-09-18. Marker-only was *verified* bypassable (`env -u AI_AGENT …` scrub + self-allocated `winpty` PTY); ancestry is evaluated independently of the environment, so it holds against the env-stripping dodge. **Amended 2026-09-23 after live measurement:** ancestry survives an in-shell `unset` but goes blind across an MSYS `env.exe` hop (Cygwin fork stub). So the Hermes terminal markers (`TERMINAL_CWD`, `TERMINAL_ENV`) were added to the frozen list, and the pair — not either alone — is the design. The OS-user split remains documented as the only actual boundary |
| Blind ingress coverage (wave 2) | **All three secret families share one pending-store primitive** — API keys (`ak-add`), site credentials (`add`), secure notes (`note-add`) | The entry a human most often hands over is a password they want the agent to scaffold, not an API key. The pending record is type-agnostic (`{family, name, service, notes}`), so the extra coverage is two more `--claim` paths, not a second mechanism |
| Handoff discovery (wave 2) | **`psamvault ak-pending [--code]` check command + opt-in `--wait`/`--timeout`** on the creating command | The check works in every host with no blocking; `--wait` collapses the happy path to one call. A host that caps a tool call (the ~300 s cap observed with twine) cuts a wait short but cannot lose the claim — it lives in the pending store until its TTL, and the timeout message says so |
| `--from-file` semantics (wave 2) | **Both modes, chosen by `--from-key NAME`** — with it, parse a `.env`-style file and take that one value; without it, the whole file is the secret. `--delete-source` is valid only with `--from-key` | Both cases are real and different: a key inside a `.env` on disk vs a service-account JSON or `.pem` that *is* the secret. Deleting a whole file is not a migration, and `--delete-source` must never be able to destroy one |
| Wave boundary (2026-09-24) | **Wave 2 = blind ingress only** (claim codes for all three families, `ak-pending`, `--wait`, `--from-file`/`--from-env`, `--key` still refused in agent context). **Wave 3 = loopback claim form + use-side per-entry policy/redaction + the MCP half** | Step 10 lands mostly in `psamvault-mcp` and needs its own release, skill updates and compat bump, so bundling it makes the CLI PR unreviewable; the loopback form adds a local HTTP server (and a DNS-rebind surface to harden) for a case `--claim` in a terminal already covers |
| Use-side policy default for an undeclared entry (decided 2026-09-24, builds in wave 3) | **Fail-open** — a declared policy restricts; an entry with no policy stays usable in agent context, is audited, and `psamvault policy allow` declares one. `security status` names entries with no policy | Fail-closed would refuse every automated flow on the machine (release uploads through `run_with_credential`, the daily compat cron) on the day it ships, and a guardrail that walls off the pipeline gets switched off. The reveal side is already strict where it matters (`human-only`); the use side guards keys the user actually relies on, so restriction must be declarable rather than assumed |

## Design

### Part 1 — Reveal guardrail

| Layer | Module | Behaviour |
|---|---|---|
| L1 Reveal gate | `reveal_gate.py` (new) | One function `require_reveal(action, entry)` that every secret-emitting path calls before printing or copying |
| L2 Caller classification | `caller.py` (new) | Returns `human`, `uncertain`, or `agent`; one patchable entry point so tests control it exactly. Ladder: (1) explicit `--agent` / `PSAMVAULT_AGENT`, (2) known host markers incl. `AI_AGENT=hermes-agent`, (3) **parent-process ancestry** — consulted only when 1–2 are silent *and* a reveal is pending. `CI=true` is recorded as unattended (`env:CI` in the audit row), never graded as an agent |
| L3 Policy | `policy.py` (new) + `~/.psamvault/policy.json` | `{"reveal": "human-only" \| "strict" \| "open", "allow_entries": [...], "approval_ttl_seconds": 120, "audit": true}` |
| L4 Approval token | `session.py` (+`approval.<id>` keychain rows) | `psamvault approve <entry> --for-agent [--ttl N]`, TTY + interactive confirm required |
| L5 Refusal | `error_ui.py` `print_error` | Refusal always names the capability alternatives (`use_credential`, `run_with_credential`, `browser_login`, `approve`) |
| L6 Audit | `audit.py` (new) | JSONL rows: `ts, command, entry, caller, signals, tty, pid, ppid, decision, token_id` |
| L7 Parity | MCP side | A test asserts no MCP tool can emit a plaintext secret; `PSAMVAULT_AGENT=1` set for subprocesses |

Gated commands: `get`, `ak-get`, `note-get`, `export --plaintext`, plus `--copy` on any of them.
Read-only, non-revealing commands (`list`, `site-list`, `ak-list`, `note-list`, `whoami`,
`check_credential_exists`) are never gated — an agent must be able to discover *what* exists.

Blocked output:

```
✗ psamvault get is blocked in this context (agent terminal detected)
→ Ask the human to run it, or use a capability instead:
    psamvault approve github.com --for-agent --ttl 120   (human terminal only)
```

Approval flow: the human runs `approve` in their terminal → CLI confirms the entry exists, prints the
TTL, writes a token under `approval.<uuid>` in the keychain → the agent's `get` finds a live token,
consumes it (deletes the row), logs the reveal, and prints the secret. Expired or absent → blocked.

### Signal ladder and the ancestry check

Signals 1–3 are environment variables: cheap, but an agent can strip them (verified). Signal 4 is
**process ancestry**, which does not depend on the environment at all — the CLI walks its own parent
chain and asks whether any ancestor is an agent runtime.

- **Windows:** `CreateToolhelp32Snapshot` + `Process32First/Next` (pure `ctypes`, no WMI, no `psutil`)
  to build the pid → ppid map, then `QueryFullProcessImageName` for the image path.
- **POSIX:** `/proc/<pid>/stat` for ppid, `/proc/<pid>/exe` for the path.
- **Match on the ancestor's executable *path*, not its name** — Hermes runs as `python.exe`, so a name
  match is worthless; `...\hermes-agent\venv\Scripts\python.exe` and the desktop app's
  `...\hermes-agent\apps\desktop\...` are not.
- **Cost placement:** the walk runs **only** when signals 1–3 are silent *and* a reveal is pending, so
  no ordinary command pays for it. A miss downgrades to `uncertain` (never blocks a human wrongly).
- **Caveats to document:** PID reuse, a detached/re-parented process, and a runtime installed under a
  non-obviously-named path all defeat it. It raises the bar; it is not the boundary.

### Part 2 — Credential-blind ingress (wave 2, decisions locked 2026-09-24)

```bash
# agent side — no secret anywhere near the agent
psamvault ak-add github-prod --service GitHub
  →  Pending: github-prod (service: GitHub)              family: api_key
     Claim code: PV-4F2K-91QX        expires in 15m
     Human: run  psamvault ak-add --claim PV-4F2K-91QX
     (the loopback form is wave 3 — `--claim` in a terminal is the wave-2 path)
     The agent is told the code and nothing else, ever.

# human side — their own terminal, hidden input, no --key accepted on this path
psamvault ak-add --claim PV-4F2K-91QX
  API key for github-prod: ********        ← hidden
  →  ✓ stored github-prod (service: GitHub)

# the same primitive and the same code, for the other two families
psamvault add --claim PV-4F2K-91QX           # site credential: username + password
psamvault note-add --claim PV-4F2K-91QX      # secure note body

# how the agent finds out the human filled it
psamvault ak-pending                         # pending / filled / expired, with age
psamvault ak-pending --code PV-4F2K-91QX
psamvault ak-add github-prod --service GitHub --wait --timeout 15m
  →  returns the moment the human fills it; on timeout exit 3, the code still valid

# or migrate a file without reading it
psamvault ak-add stripe-test --service Stripe --from-file ./.env --from-key STRIPE_TEST_KEY --delete-source
psamvault ak-add sa-prod --service Google --from-file ./service-account.json   # the whole file is the secret
psamvault ak-add gh-token --service GitHub --from-env GITHUB_TOKEN
```

- **Loopback form — wave 3, deferred 2026-09-24, not built here.** `127.0.0.1` only, single-use token, write-only (no GET ever returns the secret),
  closes on success/TTL, serves a minimal page the CLI already has a precedent for in
  `browser_commands.py`, plus the dashboard's Host-allowlist/DNS-rebind check
  (`dashboard/__init__.py`) for the bind.
- The agent-visible response is `{"status": "pending", "claim_code": "PV-4F2K-91QX",
  "expires_in": 900, "family": "api_key"}` — and nothing else, ever.
- Pending entries are invisible to `ak-list` / `site-list` / `note-list` / `list` until filled — a
  half-created entry must not read as an entry.
- `psamvault ak-pending` lists, inspects and cancels outstanding claims (cancelling from an agent
  shell is allowed too: it reveals nothing).
- **Claims are local to the machine that created them.** An agent on the droplet cannot hand a claim to
  a human on the laptop; the message and the docs must say so rather than letting it look like a bug.

### Part 2b — Use-side hardening (wave 3 — decisions recorded, not built)

| Item | Change |
|---|---|
| Policy per entry | an `entries` block beside the existing reveal fields, e.g. `{"entries": {"github.com": {"allow_hosts": [...], "allow_commands": [...], "allow_inject": ["bearer_token" \| "api_key_header" \| "basic_auth" \| "env"]}}}` (shape proposed here, to confirm when wave 3 is built), enforced in `use_credential` and `run_with_credential`. **Undeclared = unrestricted + audited** (decided 2026-09-24, fail-open); `psamvault policy allow <entry> ...` declares, `security status` names the gap |
| Leases | **Deferred — not built in this wave** (decided 2026-09-18; see Open Questions for the reopen trigger and the headless-mint blocker) |
| Redaction | Extend `cmd_runner._redact`: raw value, base64, URL-encoded, first-8 prefix, and the username under `basic_auth` |
| Secrets on disk | `export_key_to_env_file` / `export_key_to_mcp_config` (`psamvault-mcp`) write plaintext secrets to disk: gate behind a confirm + audit row + `0600` verification |
| Proxy | Remove `_credential_username` / `_credential_password` from `ProxyRequest`; delete the credential path in `proxy_crud.py`, keep `GET /vault/proxy/check/{site_name}` |

## CLI changes

| File | Change |
|---|---|
| `caller.py`, `policy.py`, `reveal_gate.py`, `audit.py` | **new** — classification, policy load/validate, gate, audit writer |
| `command/approve_command.py` | **new** — approval token mint |
| `command/api_key_commands.py` | **wave 1:** gate `ak-get`. **wave 2:** `--claim`, `--wait`/`--timeout`, `--from-file`/`--from-key`/`--from-env`/`--delete-source`; when `--claim` is given, `--key` is not accepted and the claim path runs |
| `command/vault_commands.py` | **wave 1:** gate `get` (including `--copy`). **wave 2:** `add --claim` |
| `command/note_commands.py` | **wave 1:** gate `note-get`. **wave 2:** `note-add --claim` |
| `command/export_command.py` | gate `--plaintext` |
| `command/claim_server.py` | **new — wave 3** — loopback write-only claim form |
| `command/pending_store.py` | **new — wave 2** — `~/.psamvault/pending/*.json` read/write/prune, code re-roll on collision |
| `command/claim_commands.py` | **new — wave 2** — `ak-pending` list / inspect / cancel |
| `main.py` | register `approve` (wave 1), `ak-pending` (wave 2), `policy` / `security status` (wave 3); document `--agent` (no `lease` — deferred) |
| `session.py` | approval-token rows alongside the existing session keys |
| `tests/` | **wave 1:** `test_caller.py`, `test_policy.py`, `test_ancestry.py`, `test_audit.py`, `test_reveal_gate.py`, `test_approve.py`, `test_gated_commands.py`. **wave 2:** `test_pending_store.py`, `test_blind_ingress.py`, `test_from_file.py`. **wave 3:** `test_redaction.py`, `test_policy_entries.py`. Existing command tests get the gate patched or a permissive policy fixture |

## MCP changes (`psamvault-mcp`) — wave 3

| Item | Change |
|---|---|
| `mcp_server/cmd_runner.py` | Export `PSAMVAULT_AGENT=1` (wave 1's 🟡 half); wider redaction (wave 3) |
| `mcp_server/tools.py` | **wave 3:** enforce entry policy in `use_credential` / `run_with_credential`; add `create_entry_blind(family, name, service, notes)` returning the claim code; audit rows |
| `AGENTS.md` / `SKILL.md` / `agent_guide.py` | Replace "do not run bare `psamvault get`" with the enforced rule + the claim-code workflow |
| `tests/test_tools.py` | Assert no tool returns a secret value; assert the claim workflow never places the secret in a tool result |

## Backend changes (step 11 — independent)

| Item | Change |
|---|---|
| `app/schemas/proxy_schema.py` | Drop `_credential_*` from `ProxyRequest` (or deprecate the whole endpoint) |
| `app/controller/proxy_crud.py` | Remove the credential-decrypt/inject path; keep `check_site_exists` |
| `openapi.json` | Regenerate |

## Build Order

| Step | Work | Depends on | Status |
|---|---|---|---|
| 1 | **Marker probe — DONE 2026-09-23.** Measured live: Hermes agent shell `AI_AGENT=hermes-agent` + `HERMES_AGENT=true` + the terminal tool's `TERMINAL_CWD`/`TERMINAL_ENV`; Claude Code (launched with the Hermes markers stripped, so the measurement is clean) `AI_AGENT=claude-code_2-1-278_agent` + `CLAUDECODE=1` + `CLAUDE_CODE_ENTRYPOINT=sdk-cli`, and its CLI is `~/.local/bin/claude.exe`. Both shells: stdin on a TTY, **stdout piped** — so TTY presence is not a human signal either. Codex / Goose / OpenCode / aider are not installed on this machine: they rely on `PSAMVAULT_AGENT`/`--agent` plus the frozen basename list, and stay 🟡 until measured. Probe JSONs: `probe_hermes.json`, `probe_claude.json` (hermes cache scratch) | — | 🟢 |
| 2 | `caller.py` + `policy.py` + tests | 1 | 🟢 |
| 2b | `ancestry.py` — Toolhelp32 walk on Windows, `/proc` on POSIX, path + distinct-basename matching, injected probe so tests drive a fake chain. **Measured limit:** an MSYS `env.exe` hop re-parents the child to a Cygwin fork stub, which ends the Windows chain — that is why the marker list had to grow (`TERMINAL_*`), see Implementation Notes | 2 | 🟢 |
| 3 | `reveal_gate.py`, `audit.py`, gate the four reveal paths (`get`, `ak-get`, `note-get`, `export --plaintext`) + `--copy`; gate sits at the emit point so a failed fetch never burns a token; existing suite green | 2 | 🟢 |
| 4 | `approve` command + token lifecycle (`--for-agent` required, TTY required, single use, TTL clamp, expiry pruned, dropped on logout) | 3 | 🟢 |
| 5 | `--agent` flag + `PSAMVAULT_AGENT` handling + ladder verified live. **MCP env export is a separate repo** (`psamvault-mcp` `cmd_runner.py`) — follow-up PR | 4 | 🟢 CLI / 🟡 MCP |
| 6 | **WAVE 2 — blind ingress core.** `command/pending_store.py` (new: `~/.psamvault/pending/<code>.json`, 0600, 15-min TTL, code re-roll on collision, prune) + `command/claim_commands.py` (new: `ak-pending` list/inspect/cancel, `--wait`/`--timeout`). `ak-add`, `add`, `note-add` create a claim when the caller is an agent; `--claim CODE` completes it from a human terminal (hidden input, no `--key` on that path). `--service` becomes optional when `--claim` is given — the value is not known yet and the pending record supplies it. The claim path never echoes the value | 5 | 🔴 |
| 7 | **WAVE 2 — migrate without reading.** `--from-file` both modes (`--from-key NAME` parses `.env`; no flag = whole file is the secret), `--from-env VAR`, `--delete-source` (only with `--from-key`; the line is removed, a `.bak` kept) | 6 | 🔴 |
| 8 | **WAVE 2 — docs in the SAME PR, not a follow-up.** `docs/reference/commands.md` with a WHEN per new command (create-by-claim vs create-by-key vs fill-a-claim vs cancel vs migrate-a-file, and what each is NOT for), `docs/features.md`, `docs/guides/agent-reveal-guardrail.md`, and `SECURITY.md`'s claim-code limits (local-file scope, cross-machine gap, TTL). Then the changelog PR, then the code PR. The surface gate cannot see an undocumented NEW command — walk the diff by hand | 6-7 | 🔴 |
| 9 | WAVE 3 — loopback claim form (`command/claim_server.py`), deferred 2026-09-24 | 6 | ⏸ |
| 10 | WAVE 3 — use-side per-entry policy (`entries` block, fail-open default) + wider `cmd_runner._redact` + guards on `export_key_to_env_file`/`export_key_to_mcp_config`; CLI policy schema + MCP enforcement; MCP `create_entry_blind` and the `PSAMVAULT_AGENT=1` export (wave 1's 🟡 MCP half). Own release + compat/skill bump | 7 | ⏸ |
| 11 | Backend `POST /vault/proxy` → `410 Gone` + regenerate the committed `openapi.json` — independent of wave 2, no live caller | — | 🔴 |

Wave 1 (steps 1-5) shipped in v0.6.0. Wave 2 (steps 6-8) is one CLI PR and is independent of both
wave 3 and step 11; step 11 can go at any time.

**Concurrent work — read before branching.** A second agent works this repo's web dashboard
(`dashboard/`, the `pv dashboard` command) and lands on `main` while wave 2 is built. Branch from
current `main`, `git fetch` before every push and again immediately before opening the PR, rebase
onto `origin/main`, then re-run the full suite **and** `scripts/check-docs-surface.py`. The files
that actually collide are `CHANGELOG.unreleased.md` (keep both sides), `docs/reference/commands.md`
and `main.py`. `dashboard/*` is not touched by this wave — it is read-only precedent for the
wave-3 loopback form.

## Acceptance Criteria

**Wave 1 (steps 1-5) — status 2026-09-23.** Proven items carry the evidence; the
wave-2 items are untouched by this work and stay open.

- [x] Under Hermes (real session, not a simulation), `psamvault get postgresql` through the agent's
      terminal tool is refused with the guidance message, exit code 1, and one audit row naming the
      matched signal. **Proven live:** row `get postgresql | caller=agent |
      signals=[marker:AI_AGENT=hermes-agent, marker:HERMES_AGENT] | deny`. The same call site covers
      `ak-get`, `note-get`, `--copy`, and `export --plaintext` (covered by tests, plus a live
      `ak-get pypi` refusal).
- [x] In the same session, `site-list` still works and returns entries — discovery is never blocked.
      **Proven live** (5 entries listed in the agent's own shell) and pinned by a test.
- [x] **REVISED — the original criterion was not achievable as written.** `env -u AI_AGENT -u
      HERMES_AGENT …` + a self-allocated PTY is refused, but *by the marker layer, not by ancestry*:
      MSYS `env.exe` re-parents its child to a Cygwin fork stub, so the ppid walk ends at that hop.
      What is proven instead, both live: (a) an in-shell scrub (`unset AI_AGENT HERMES_AGENT …`)
      is refused with `ancestry:hermes-agent\\venv` named as the matched signal; (b) the `env -u`
      scrub that leaves `TERMINAL_*` set is refused with `marker:TERMINAL_CWD` named. The residual
      defeat — `env -i` *through* a re-parenting stub — is documented in `SECURITY.md` as work for
      the OS-user split, not papered over.
- [x] Ancestry adds no measurable cost to ordinary commands: a test patches the ancestry probe and
      asserts it is called only when signals 1-3 are silent and a reveal is pending.
- [~] `psamvault approve <entry> --for-agent` mints a one-time token from a real terminal, the
      agent's next `get` succeeds **once**, a second is blocked, an expired token is blocked — all
      covered by tests. The mint itself cannot be demonstrated from this (agent) shell **by design**:
      live run refuses with "approve needs a real terminal", which is the property being asserted.
      A human-terminal mint needs psam's own terminal (see Open Questions).
- [x] A bare pipe from the user's own shell (`psamvault get x | cat`) still works under the default
      policy and is logged as `uncertain` (live audit row: `uncertain | signals=[] | allow`);
      `"reveal": "strict"` refuses it (test).
- [x] The full existing CLI suite passes unchanged with the default policy — 331 passed (234
      pre-existing + 97 new); no test relies on a TTY.
- [x] `SECURITY.md` states plainly what the guardrail does and does not stop (keychain access,
      reinstalling the CLI, a permissive `policy.json`, a truncated audit trail, the re-parenting
      stub), and documents the OS-user separation as the actual boundary.

**Wave 2 (steps 6-8) — decisions locked 2026-09-24, not built.**

- [ ] In agent context (real Hermes session, not a simulation), `psamvault ak-add github-prod
      --service GitHub` prints a claim code, the family, the TTL and the human's next step — and
      nothing else. Same for `psamvault add <site>` and `psamvault note-add <title>`. One audit row
      per decision.
- [ ] The claim completes from a second (human) terminal for **each** of the three families: the
      entry exists afterwards, decrypts with the value the human typed, and the pending record is gone.
- [ ] The claim path cannot echo: no `--key` accepted, hidden prompt, value absent from stdout,
      stderr, argv and the audit rows — asserted by grepping every produced artifact for the typed
      value and requiring zero matches.
- [ ] `psamvault ak-pending` and `ak-pending --code CODE` report pending / filled / expired with age;
      cancel removes the record and the code stops working.
- [ ] `--wait --timeout` returns the moment the human fills the claim; on timeout it exits non-zero
      saying the code is still valid, and a fill that lands afterwards still completes.
- [ ] A claim older than 15 minutes is refused with a clear message and pruned on next access.
- [ ] `--from-file X --from-key NAME` stores that one value; `--from-file X` stores the whole file;
      `--delete-source` removes only that line, keeps a `.bak`, and is refused without `--from-key`.
      In no case does the agent-facing output contain the value.
- [ ] Pending claims are invisible to `ak-list` / `site-list` / `note-list` / `list`.
- [ ] `--key <value>` is still refused in agent context (wave 1 unchanged) and the full suite is green
      with no test relying on a TTY.
- [ ] Every new command and flag is in `docs/reference/commands.md` with its WHEN, the `docs` CI job is
      green, and the reference contrasts create-by-claim / create-by-key / fill / cancel / migrate.
- [ ] Live proof: the agent's own shell creating the claim plus a completion in psam's terminal,
      reported as audit rows (create / fill / refuse) — never the revealed value.
- [ ] Wave 3 items (loopback form, use-side policy, MCP `create_entry_blind`) stay open in this file.
- [ ] `POST /vault/proxy` returns `410 Gone` — **step 11, independent, not built.**

## Implementation Notes (wave 1 — shipped in v0.6.0)

Files: `caller.py`, `ancestry.py`, `policy.py`, `audit.py`, `reveal_gate.py` (new);
`command/approve_command.py` (new); `errors.py` (+`RevealBlockedError`), `session.py`
(approval tokens), `main.py` (`approve`, `--agent`), `command/{vault,api_key,note,export}_commands.py`
(gated). Tests: `test_caller`, `test_ancestry`, `test_policy`, `test_audit`, `test_reveal_gate`,
`test_approve`, `test_gated_commands` + an autouse conftest fixture that keeps the suite's own
environment (which is an agent shell) from turning every reveal test red for the wrong reason.

Live evidence, in the agent's own shell against the real vault:

| Run | Result |
|---|---|
| `get postgresql` (markers present) | refused, exit 1, `marker:AI_AGENT=hermes-agent, marker:HERMES_AGENT` |
| `unset AI_AGENT HERMES_AGENT …; ak-get pypi` | refused, `ancestry:hermes-agent\\venv` |
| `env -u AI_AGENT … get postgresql` | refused, `marker:TERMINAL_CWD, marker:TERMINAL_ENV` (before the marker was added: **allowed** — the gap this evidence closed) |
| `site-list`, `list` | work normally, exit 0 |
| `approve postgresql --for-agent` | refused: "approve needs a real terminal" |

## Risks & Mitigations

| Risk | Mitigation |
|---|---|
| Gate breaks the existing ~170 CLI tests (no TTY under `CliRunner`) | Design blocking around positive agent signals, not TTY absence; permissive-policy fixture for command tests; strictness is opt-in |
| Ancestry is platform code and imperfect — a renamed runtime path, PID reuse, or a detached process can defeat it | Match the ancestor's executable **path**, keep the signal additive (a miss only downgrades to `uncertain`), run it only on reveal paths, and state the limits in `SECURITY.md`; the OS-user split is the boundary |
| Marker probe is incomplete, so a real agent slips through as `uncertain` | Explicit `PSAMVAULT_AGENT=1` from the MCP and documented for hosts; `--agent` for anything else; strict mode for users who want non-TTY denial; audit of `uncertain` decisions so gaps are visible |
| An agent runs `psamvault approve` itself | `approve` requires a real TTY plus an interactive confirm and is never reachable with redirected stdin; documented as tamper-resistance, not a boundary |
| Claim code leaked in a transcript before the human uses it | TTL 15 min, single use, and the human's completion replaces the agent's pending entry — a stolen code lets an attacker fill *their own* secret into a name the user would notice, which is why `ak-list` and `create`'s output name the entry explicitly |
| Loopback form is read by something local | Write-only by construction: no route returns the submitted secret, no logs of the body, `127.0.0.1` bind only, single-use token |
| A permissive `policy.json` silently disables everything | `backup status`-style `psamvault security status` prints the effective policy; audit rows record the policy file hash at decision time |
| `--key` deprecation breaks existing scripts | Kept for interactive TTY with a warning; only agent context blocks it; changelog calls the change out |
| Windows vs macOS/Linux TTY/env differences | Step 1 probes both; `caller.py` is platform-branching with tests per platform; all docs give PowerShell **and** bash forms (psam: never Windows-only) |
| A claim code leaks in a transcript before the human uses it (wave 2) | TTL 15 min, single-use, and the human's fill replaces the agent's pending entry — a stolen code lets an attacker fill *their own* secret into a name that `create`'s output names explicitly, which is exactly what a user notices. Cancelling is allowed from any shell because it reveals nothing |
| The pending file is readable by anything running as the user, the agent included (wave 2) | It holds no secret by construction (`{family, name, service, notes}`) and is 0600. What it leaks is *which* entries are being created, at the moment the human is already being told the name — accepted and stated, not audited away |
| An agent on another machine cannot complete a claim created here (wave 2) | Say it in the message and in the docs: claims are local to the machine that created them. Cross-machine handoff is out of scope, not a bug |
| `--wait` parks an agent turn in a host that caps tool calls (wave 2) | The claim survives the truncation in the pending store; the timeout message names the code and the remaining TTL, so the agent's next call is `ak-pending --code`, not a fresh claim |
| Two claims land on the same code (wave 2) | Codes come from `secrets`, not the clock — this repo has already been bitten by ~15 ms timestamp granularity in `upgrade_utils` snapshots — and the store re-rolls when the file exists instead of overwriting it |
| A `--delete-source` typo destroys the wrong file (wave 2) | Deleting is allowed only for one line inside a `--from-key` source, a `.bak` is kept, and whole-file mode refuses `--delete-source` outright |

## Rejected Alternatives

| Rejected | Why |
|---|---|
| Warn-only reveal guard (log and still print) | Fails the actual requirement — an agent that reads the warning has already read the secret |
| Always require interactive confirmation, even in a human terminal | Punishes the primary user for the agent's risk; the approval token already covers the handoff case |
| Blanket "no TTY ⇒ deny" | Breaks pipes, CI, and the whole existing test suite for a signal that is not evidence of an agent. **Applied to `CI=true` itself on 2026-09-23:** it is recorded, not graded as an agent — this table's argument, turned on a signal that had been graded as one |
| Parent-process fingerprinting as the default mechanism | Brittle across platforms and shells; kept out of the default path |
| Build the OS-user split now | Correct boundary, large cost, and it conflicts with how Hermes currently runs as the user; documented as the escalation path |
| Server-side pending-claim table | The filler is the same OS user on the same machine; a local file avoids a migration and keeps the claim off the server |
| Loopback form only (no claim code) | Useless over SSH or when the human is being told what to do in chat rather than sitting at the machine |
| Keep `--key <value>` as the documented non-interactive path | Argv is observable (process listings, history, wrapper logs) |
| Keep the backend proxy credential path | Requires the plaintext to leave the machine to make a request the client already makes itself |
| Building `lease` in this wave | Deferred by decision (2026-09-18): per-entry policy already blocks the dangerous case (exfiltration to a disallowed host) at zero workflow cost, while a TTY-minted lease breaks unattended cron agents and adds a state machine for a timing-only gain |
| Loopback claim form in wave 2 | Deferred 2026-09-24: it adds a local HTTP server (and a DNS-rebind surface to harden) for the same-machine case `--claim` in a terminal already covers |
| API-keys-only blind ingress | The entry a human most often needs to hand over is a site password they want the agent to scaffold; the pending record is type-agnostic, so covering all three families is two more `--claim` paths, not a second mechanism |
| Fail-closed use-side policy (no policy ⇒ refuse) | It refuses every automated flow on the machine on the day it ships — release uploads through `run_with_credential`, the daily compat cron — and gets switched off. Declare-based fail-open with an audit trail and a `security status` gap report is the version that survives |
| Relay-only handoff (no `ak-pending`, no `--wait`) | Leaves an unattended agent unable to tell whether the human filled the claim, and pushes it to guess from `ak-list` |
| `--delete-source` on a whole-file migration | Moving a service-account JSON into the vault is a copy, not a move; deleting the source is a destructive default nobody asked for |

## Open Questions

- [x] **`TERMINAL_CWD` / `TERMINAL_ENV` in the human's own terminal pane — RESOLVED 2026-09-23, no pane check needed.** Sourced two ways instead of by running the one-liner: (1) the desktop app bundle sets `TERMINAL_CWD` in exactly ONE place — the *backend* spawn env (`TERMINAL_CWD: hermesCwd`, commented "Pin the gateway's tool/terminal cwd to the same directory we chose for the child process") — and never for a pane; (2) the live process tree shows the pane is an **ancestor** of that backend, not a descendant (`pwsh(19692) <- herdr <- herdr <- pwsh(16604) <- WindowsTerminal <- svchost`, while the agent chain is `bash <- python <- python <- hermes.exe(23596) <- pwsh(19692)`), and a process cannot inherit what the app hands to a child below it. A `get` in the pane therefore carries no `TERMINAL_*` and no agent ancestor in its chain -> classified `human`. Markers stay. Residual case: a pane spawned *from inside* the agent lineage would inherit them and be blocked — the correct outcome, since the agent is still driving.

- [x] ~~Which host actually sets `PSAMVAULT_AGENT` for us?~~ → **answered 2026-09-18 by measurement:**
      Hermes already exports `AI_AGENT=hermes-agent` / `HERMES_AGENT=true` on its agent shells, so no
      marker has to be injected and no `--agent` flag is needed for our own tooling. `PSAMVAULT_AGENT`
      stays for integration with hosts that set nothing, and `--agent` remains the manual escape hatch.
- [x] ~~Should `approve` also cover `export --plaintext` and `note-get`?~~ → **per-entry only**
      (decided 2026-09-18, no objection raised): `approve <entry>` authorises `get` / `ak-get` /
      `note-get` for that one entry. `export --plaintext` gets its own confirmation in a real terminal
      naming how many secrets it will expose — an entry token that unlocked a whole-vault dump would be
      a master key and would make the guardrail decorative.
- [x] ~~**Signal strength**: marker-only vs marker + ancestry vs OS-user split?~~ → **MARKER +
      ANCESTRY** (decided 2026-09-18). Design in *Signal ladder and the ancestry check* above; build step
      2b; the OS-user split stays the documented boundary. Independent of the choice, the audit log
      records every decision, including a bypass that succeeds.
- [x] ~~Does `psamvault lease` earn its keep, or is static per-entry policy enough for now?~~ →
      **DEFERRED — per-entry policy ships now, no lease in this wave** (decided 2026-09-18). Reopen
      only if unrestricted *timing* turns out to matter in practice. Two blockers to record before
      anyone reopens it: (a) a TTY-only mint makes a lease unusable for *unattended* agents — the cron
      jobs that would benefit most have no human to mint one, so a future design needs a headless
      grant model (scheduled/long-lived grant file), a fork of its own; (b) a lease is not a boundary
      either (an agent with shell access can read the keychain), so it buys friction on the
      well-behaved path only.
- [x] ~~Deprecate `POST /vault/proxy` entirely, or keep it for hosted agents that cannot make outbound
      calls themselves?~~ → **DELETE (option A)**, decided 2026-09-18. The hosted-agent case (keep it for
      an MCP server whose only permitted egress is our backend) is recorded as a rejected alternative,
      not a fork — nobody runs psamvault that way today, and the price is a permanently qualified
      zero-knowledge claim. Path C (scoped tokens so the server can decrypt) stays rejected.
- [x] ~~Wave 2 scope: blind ingress alone, or blind ingress plus use-side policy and the loopback
      form?~~ → **BLIND INGRESS ALONE** (decided 2026-09-24). Step 10 lands mostly in
      `psamvault-mcp` and needs its own release, skill updates and compat bump, so bundling it makes
      the CLI PR unreviewable; the loopback form can follow on its own.
- [x] ~~How does the agent learn a claim was filled?~~ → **`ak-pending` check command + opt-in
      `--wait`** (decided 2026-09-24). The check works everywhere without blocking; `--wait` collapses
      the happy path to one call and degrades safely when a host caps the tool call.
- [x] ~~Only API keys, or every secret family?~~ → **all three** (decided 2026-09-24) — one
      pending-store primitive behind `ak-add`, `add` and `note-add`.
- [x] ~~`--from-file`: one `.env` key, or the whole file?~~ → **both, chosen by `--from-key`**
      (decided 2026-09-24); `--delete-source` only with `--from-key`.
- [x] ~~Undeclared-entry default under use-side policy?~~ → **FAIL-OPEN + a declare helper**
      (decided 2026-09-24, builds in wave 3; see Decisions Made).
- [ ] **An MCP-only agent (no shell) cannot create a claim until `create_entry_blind` lands** — the
      MCP has no create-entry tool at all today. To settle when wave 3 is planned: does that tool ship
      with the policy work (one MCP release), or earlier as its own small PR? Not blocking wave 2 —
      Hermes runs the CLI directly.
- [ ] Does `PSAMVAULT_AGENT=1` in `cmd_runner.py` (wave 1's 🟡 MCP half) ride with the small
      step-11 PR, with wave 3, or on its own? It is three lines plus a test, and it makes every CLI
      call the MCP spawns classify correctly.
