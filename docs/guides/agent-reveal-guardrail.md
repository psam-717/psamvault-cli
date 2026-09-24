---
title: The agent reveal guardrail
description: Who may print a secret — the three policy modes, one-shot agent approvals, and the measured limits of the guardrail.
order: 50
---

# Agents and the reveal guardrail

An agent with a shell can run `psamvault get` and read your password — a rule in
a document does not stop it. So the four commands that print a secret now ask
*who is calling* first, and refuse when the caller is a program.

| Situation | What happens |
|---|---|
| You run `psamvault get github.com` in your own terminal | Prints the password. Nothing changes. |
| Hermes, Claude Code, Codex, Goose or OpenCode runs it | Refused, exit code 1, with the capability alternatives printed. One audit row records it. |
| A script of yours pipes it (`psamvault get x \| cat`) | Allowed, with an audit note — a plain pipe is not evidence of an agent. Set `"reveal": "strict"` to refuse these too. |
| A CI job runs it (`CI=true`, e.g. GitHub Actions) | Allowed and audited — `env:CI` is recorded, but an unattended job is not an agent. An *agent* running inside CI is still refused, by its own markers or its ancestry. Use `"reveal": "strict"` to refuse CI too. |
| The agent needs the secret to finish a job | Use the MCP capabilities: `use_credential`, `run_with_credential` or `browser_login` — they inject the secret without ever revealing it. |
| The agent genuinely needs the value printed once | You run `psamvault approve` in your own terminal (below). |
| You were blocked but you *are* a human | Read `~/.psamvault/audit.jsonl` — the deny row names the exact signal that matched. |
| You want the guardrail out of the way on this machine | `~/.psamvault/policy.json` with `"reveal": "open"`. |

Gated: `get`, `ak-get`, `note-get`, `export --plaintext`, and `--copy` on any of
them (the clipboard is just as readable). Never gated: `list`, `site-list`,
`ak-list`, `note-list`, `whoami`, `check_credential_exists` — an agent must
always be able to see *what* exists.

## Hand an agent one secret, once

```bash
# you, in your own terminal — names the entry, the window, and asks once
psamvault approve github.com --for-agent
psamvault approve openai-prod --for-agent --ttl 60

# the agent's next reveal of that ONE entry
psamvault get github.com
```

The next reveal of that entry succeeds **once**; a second attempt is refused. The
approval covers nothing else — not another entry, and never a whole-vault dump.
`approve` requires a real terminal (both stdin and stdout), so an agent cannot
approve itself out of a refusal, and `--for-agent` is required so the intent to
hand a secret to a *program* is typed rather than assumed. `psamvault logout`
drops every pending approval.

Details of the command itself, including `--ttl`: [`psamvault approve`](../reference/commands.md#psamvault-approve) and [`--agent`](../reference/commands.md#global-options).

## Policy: three modes

`~/.psamvault/policy.json` — absent means the safe default, so a fresh machine is
protected with nothing to configure. The same file works on Windows, macOS and
Linux; the permission warning (`chmod 600`) is POSIX-only, since Windows reports
one mode for every file and uses your user ACL instead.

| `"reveal"` | An agent (markers, ancestry) | A bare pipe, script or CI job | |
|---|---|---|---|
| `"human-only"` *(default)* | refused | allowed + audited | stops the real case without breaking your pipes or CI |
| `"strict"` | refused | refused | "no terminal, no secret" — you opt in |
| `"open"` | allowed + audited | allowed + audited | everything works; the trail still records it |

```json
{ "reveal": "human-only", "allow_entries": ["github.com"], "approval_ttl_seconds": 120, "audit": true }
```

`allow_entries` is a per-entry allowlist for agents — useful when a long-running
job needs one specific secret. A malformed policy file falls back to the safe
defaults with a warning rather than crashing the CLI. The full schema is in the [Configuration reference](../reference/configuration.md#policyjson).

## How the caller is classified

The design is deliberately layered, because each layer was measured to fail on its own:

- **Explicit** — `PSAMVAULT_AGENT=1` (also what `psamvault --agent` sets), or the MCP server
  exporting it into a subprocess. Deterministic, and the only layer an integration controls.
- **Host markers** — the identity a known runtime leaves in the environment: Hermes
  (`AI_AGENT`, `HERMES_AGENT`, and its terminal's `TERMINAL_CWD`/`TERMINAL_ENV`) and Claude Code
  (`CLAUDECODE`, `CLAUDE_CODE_ENTRYPOINT`). Measured on a real agent shell, not assumed.
- **CI** — `CI=true` means no human is watching.
- **Ancestry** — the parent-process chain (Toolhelp32 on Windows, `/proc` on POSIX). Consulted
  only when the first three are silent and a reveal is pending, so ordinary commands pay nothing.
  It matches the ancestor's executable *path* (`...\hermes-agent\venv\...`) or a distinctly-named
  agent binary (`claude.exe`), never a bare `python.exe`/`node.exe` — and it deliberately does not
  match the desktop app's own install prefix, which would block the user's own terminal pane.

## What it stops

A well-behaved agent — Hermes, Claude Code, Codex, Goose, OpenCode, a CI job —
running `psamvault get` gets exit code 1 and a message naming the capability alternatives
(`use_credential`, `run_with_credential`, `browser_login`) and the one-shot human approval
(`psamvault approve <entry> --for-agent`). Every decision, allow or deny, appends a row to
`~/.psamvault/audit.jsonl` naming the caller, the matched signal and the outcome. An agent cannot
approve itself: `approve` requires a real terminal (both stdin and stdout on a TTY), and an
approval covers exactly one entry for exactly one reveal.

## What it does not stop

This is a guardrail, not a boundary. An agent that already has your shell *and*
your keychain can read the credential straight out of Windows Credential Manager,
decrypt the vault itself, or install a pristine copy of the CLI. What it buys is
a hard structural stop for well-behaved agents, a loud audit trail for accidents,
and a capability always one message away. The actual boundary is running the
agent as a different OS user with no access to your keychain — see
[`SECURITY.md`](../../SECURITY.md).

**What it does not stop, and why that is acceptable.** This is a guardrail, not a security
boundary. Concretely, measured on Windows 2026-09-23:

- An agent that strips its markers *and* routes the invocation through a re-parenting stub
  (`env -i … psamvault get x` over MSYS `env.exe`) defeats both the marker list and the ancestry
  walk: Cygwin's fork points the child's Windows parent at a stub that exits immediately, so the
  chain ends there. The same scrub performed in-shell (`unset AI_AGENT …`) is still refused via
  ancestry, and a scrub that leaves `TERMINAL_*` in place is refused by the markers.
- An agent with the user's credentials can read the OS keychain and decrypt the vault directly,
  install a pristine copy of the CLI, edit or delete `policy.json` (a permissive `"reveal": "open"`
  disables the guardrail), or truncate the audit trail. The trail is evidence about well-behaved
  callers, not tamper-proof logging.
- Writing a policy file it owns makes the *policy* layer cooperative, not enforced.

The actual boundary is running the agent as a **different OS user** with no access to the user's
keychain and no read on `~/.psamvault`. That is the recommended hardening for anyone who needs a
real boundary; it costs the ability to share a session between the human and the agent.

The approval token is stored in the OS keychain, which anything running as the user (including an
agent) can read and write. It buys a hard structural stop for well-behaved callers, plus a real
trail of who authorised what — tamper-*resistance*, not a boundary.

## Related pages

- [Configuration](../reference/configuration.md#policyjson) — the `policy.json` schema, the audit row fields and the `PSAMVAULT_*` variables.
- [Commands](../reference/commands.md#agent-guardrail-commands) — `psamvault approve` and the global `--agent` flag.
- [SECURITY.md](../../SECURITY.md) — the threat model this guardrail sits inside.
