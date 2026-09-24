# Agent-Safe Vault — reveal guardrails and credential-blind writes

**Status:** 🟢 WAVE 1 BUILT (2026-09-23) — steps 1-5 implemented on
`feat/agent-safe-vault-guardrail` (PR open): classifier, ancestry, policy, audit, gate,
`approve` command, `--agent` flag, all four reveal paths gated, 97 new tests.
Steps 6-9 (blind ingress, loopback form, use-side hardening, proxy removal) not started.

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

- well-behaved agents (Hermes, Claude Code, Codex, Goose, OpenCode, CI) get a hard *structural* stop,
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

## Key Decisions Needed

All resolved — see **Decisions Made**. Rejected alternatives at the end.

## Decisions Made

| Decision | Choice | Rationale |
|---|---|---|
| Guardrail default strictness | **Deny in agent context + TTY-only single-use approval token** | Stops the real case (an agent's shell) without making a human's own terminal annoying; scripts on the same machine keep working via the `uncertain` path below |
| Classification of a bare non-TTY caller | `uncertain` by default → **allowed with an audit note**; `strict` policy mode denies it instead | A blanket "no TTY ⇒ deny" would break every existing pipe and **every existing CliRunner test** (`CliRunner` has no TTY). Blocking must key on *positive agent signals*, with strictness available opt-in |
| Agent signals | Explicit `PSAMVAULT_AGENT=1` / `--agent` first, then a frozen marker list probed in step 1, then `CI=true` | Deterministic and testable; no fragile heuristics like "parent process looks like python" in the default path |
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

## Design

### Part 1 — Reveal guardrail

| Layer | Module | Behaviour |
|---|---|---|
| L1 Reveal gate | `reveal_gate.py` (new) | One function `require_reveal(action, entry)` that every secret-emitting path calls before printing or copying |
| L2 Caller classification | `caller.py` (new) | Returns `human`, `uncertain`, or `agent`; one patchable entry point so tests control it exactly. Ladder: (1) explicit `--agent` / `PSAMVAULT_AGENT`, (2) known host markers incl. `AI_AGENT=hermes-agent`, (3) `CI=true`, (4) **parent-process ancestry** — consulted only when 1–3 are silent *and* a reveal is pending |
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

### Part 2 — Credential-blind ingress

```bash
# agent side — no secret anywhere near the agent
psamvault ak-add github-prod --service GitHub
  →  Pending: github-prod (service: GitHub)
     Claim code: PV-4F2K-91QX        expires in 15m
     Human: run  psamvault ak-add --claim PV-4F2K-91QX
        or open  http://127.0.0.1:8765/claim/PV-4F2K-91QX

# human side — their own terminal, hidden input
psamvault ak-add --claim PV-4F2K-91QX
  API key for github-prod: ********
  →  ✓ stored github-prod (service: GitHub)

# or migrate a file without reading it
psamvault ak-add stripe-test --service Stripe --from-file ./.env --from-key STRIPE_TEST_KEY --delete-source
```

- Loopback form: `127.0.0.1` only, single-use token, write-only (no GET ever returns the secret),
  closes on success/TTL, serves a minimal page the CLI already has a precedent for in
  `browser_commands.py`.
- The agent-visible response is `{"status": "pending", "claim_code": "PV-4F2K-91QX",
  "expires_in": 900}` — and nothing else, ever.
- Pending entries are invisible to `ak-list` / `list` until filled.
- `psamvault ak-pending` lets a human list and cancel outstanding claims.

### Part 2b — Use-side hardening

| Item | Change |
|---|---|
| Policy per entry | `{"allow_hosts": [...], "allow_commands": [...], "allow_inject": ["bearer_token"]}` in `policy.json`, enforced in `use_credential` and `run_with_credential` |
| Leases | **Deferred — not built in this wave** (decided 2026-09-18; see Open Questions for the reopen trigger and the headless-mint blocker) |
| Redaction | Extend `cmd_runner._redact`: raw value, base64, URL-encoded, first-8 prefix, and the username under `basic_auth` |
| Secrets on disk | `export_key_to_env_file` / `export_key_to_mcp_config` (`psamvault-mcp`) write plaintext secrets to disk: gate behind a confirm + audit row + `0600` verification |
| Proxy | Remove `_credential_username` / `_credential_password` from `ProxyRequest`; delete the credential path in `proxy_crud.py`, keep `GET /vault/proxy/check/{site_name}` |

## CLI changes

| File | Change |
|---|---|
| `caller.py`, `policy.py`, `reveal_gate.py`, `audit.py` | **new** — classification, policy load/validate, gate, audit writer |
| `command/approve_command.py` | **new** — approval token mint |
| `command/api_key_commands.py` | claim/create/`--from-file`/`--from-env`/`--delete-source`; gate `ak-get` |
| `command/vault_commands.py` | gate `get` (including `--copy`) |
| `command/note_commands.py` | gate `note-get` |
| `command/export_command.py` | gate `--plaintext` |
| `command/claim_server.py` | **new** — loopback write-only claim form |
| `command/pending_store.py` | **new** — `~/.psamvault/pending/*.json` read/write/prune |
| `main.py` | register `approve`, `ak-pending`; document `--agent` (no `lease` — deferred) |
| `session.py` | approval-token rows alongside the existing session keys |
| `tests/` | `test_caller.py`, `test_policy.py`, `test_reveal_gate.py`, `test_approve.py`, `test_blind_ingress.py`, `test_redaction.py`; existing command tests get the gate patched or a permissive policy fixture |

## MCP changes (`psamvault-mcp`)

| Item | Change |
|---|---|
| `mcp_server/cmd_runner.py` | Export `PSAMVAULT_AGENT=1`; wider redaction |
| `mcp_server/tools.py` | Enforce entry policy in `use_credential` / `run_with_credential`; add `create_entry_blind(name, service, notes)` returning the claim code; audit rows |
| `AGENTS.md` / `SKILL.md` / `agent_guide.py` | Replace "do not run bare `psamvault get`" with the enforced rule + the claim-code workflow |
| `tests/test_tools.py` | Assert no tool returns a secret value; assert the claim workflow never places the secret in a tool result |

## Backend changes

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
| 6 | Blind ingress: pending store, claim code, `--claim`, `--from-file`/`--from-env`, block `--key` in agent context | 5 | 🔴 |
| 7 | Loopback claim form | 6 | 🔴 |
| 8 | Use-side per-entry policy + wider redaction (CLI + MCP) — **no lease** (deferred) | 6 | 🔴 |
| 9 | Backend proxy credential-path removal | — | 🔴 |
| 10 | Docs (`SECURITY.md` threat-model section, README agent section in both repos), changelog PR, live proof | 1-9 | 🔴 |

Steps 1-5 (guardrail) and 6-8 (blind ingress) are independently shippable; 9 can go at any time.

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
- [ ] `psamvault ak-add github-prod --service GitHub` in agent context prints only a claim code —
      **wave 2, not built.**
- [ ] The claim code completes from a second terminal, in the loopback web form, and via
      `--from-file` — **wave 2, not built.**
- [ ] Pending claims expire after 15 minutes — **wave 2, not built.**
- [ ] `run_with_credential` output redacts raw/base64/URL-encoded/first-8/username — **wave 2.**
- [ ] An entry outside `allow_hosts` is refused by `use_credential` — **wave 2.**
- [ ] Per-entry policy enforced in both use paths, no lease — **wave 2.**
- [ ] `POST /vault/proxy` returns `410 Gone` — **step 9, not built.**
- [x] `SECURITY.md` states plainly what the guardrail does and does not stop (keychain access,
      reinstalling the CLI, a permissive `policy.json`, a truncated audit trail, the re-parenting
      stub), and documents the OS-user separation as the actual boundary.

## Implementation Notes (wave 1, 2026-09-23)

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

## Rejected Alternatives

| Rejected | Why |
|---|---|
| Warn-only reveal guard (log and still print) | Fails the actual requirement — an agent that reads the warning has already read the secret |
| Always require interactive confirmation, even in a human terminal | Punishes the primary user for the agent's risk; the approval token already covers the handoff case |
| Blanket "no TTY ⇒ deny" | Breaks pipes, CI, and the whole existing test suite for a signal that is not evidence of an agent |
| Parent-process fingerprinting as the default mechanism | Brittle across platforms and shells; kept out of the default path |
| Build the OS-user split now | Correct boundary, large cost, and it conflicts with how Hermes currently runs as the user; documented as the escalation path |
| Server-side pending-claim table | The filler is the same OS user on the same machine; a local file avoids a migration and keeps the claim off the server |
| Loopback form only (no claim code) | Useless over SSH or when the human is being told what to do in chat rather than sitting at the machine |
| Keep `--key <value>` as the documented non-interactive path | Argv is observable (process listings, history, wrapper logs) |
| Keep the backend proxy credential path | Requires the plaintext to leave the machine to make a request the client already makes itself |
| Building `lease` in this wave | Deferred by decision (2026-09-18): per-entry policy already blocks the dangerous case (exfiltration to a disallowed host) at zero workflow cost, while a TTY-minted lease breaks unattended cron agents and adds a state machine for a timing-only gain |

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
