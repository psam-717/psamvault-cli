# Security Policy

## Reporting a Vulnerability

**Please do not open public GitHub issues for security vulnerabilities.**

If you discover a security issue in psamvault, please report it privately via
[GitHub Security Advisories](https://github.com/psam-717/psamvault-cli/security/advisories/new).

You should receive a response within 48 hours. If you don't, please follow up
by mentioning @psam-717 in the advisory thread.

## What to include

- A clear description of the vulnerability
- Steps to reproduce (proof of concept is ideal)
- Affected versions
- Any potential mitigations you've identified

## What to expect

- I will acknowledge receipt within 48 hours
- I will aim to release a fix within 7 days for critical issues
- I will credit you in the release notes (unless you prefer to remain anonymous)

## Scope

This security policy covers the **psamvault CLI** repository. The backend API
(psam-vault-backend) is a separate service with its own security boundaries.

## Key material and recovery

The sensitive half of psamvault lives on your device, not on the server:

| Material | Where it lives | What the server sees |
|---|---|---|
| Login password | nowhere — typed each time | only an Argon2id hash of the pepper-derived value |
| Pepper | OS keychain (Windows Credential Manager, macOS Keychain, Linux Secret Service) | never |
| Vault Encryption Key (VEK) | unwrapped into the keychain/memory during a session | only as an AES-256-GCM ciphertext |
| Entry plaintext | never persisted | never — ciphertext only |
| Backup passphrase | nowhere | never — only an Argon2id hash, used to verify a restore attempt |
| Recovery kit file | the path you chose (Desktop by default), mode `0600` | never |

The key chain is:

```
login password --HMAC-SHA256(pepper)--> master --PBKDF2-HMAC-SHA256(600k, kdf_salt)--> login key
login key --AES-256-GCM--> unwrap the encrypted VEK --> VEK --AES-256-GCM--> every entry
```

**Why the pepper makes a backup necessary.** The pepper is generated per device and never sent
to the server, so the same login password derives a different key on a different machine. That is
what makes a lost machine unloginable — and it is exactly why `psamvault backup create` +
`psamvault restore` exist. A restore re-derives a **fresh** pepper on the new machine, re-wraps
the same VEK under it, and stores that wrap; entries are never re-encrypted.

### What a backup contains

`psamvault backup create` wraps the VEK under a passphrase you choose, using
PBKDF2-HMAC-SHA256 (600,000 iterations, random salt) + AES-256-GCM, and places the wrap in two
independent places: a server-side slot, and a portable kit file (`0600`). The kit holds key
material only — no entry plaintext, no ciphertext, no pepper, no passphrase. The server stores
the wrapped VEK alongside an Argon2id hash of the passphrase, which exists solely to verify a
restore attempt.

### Why the restore endpoints are not an unauthenticated password reset

The server cannot unwrap the VEK — it holds no key — so it can never verify possession of the key
itself. A restore is therefore authenticated on the one thing the server *can* verify: an Argon2id
hash of the backup passphrase. Without that, a public endpoint that rewrites an account's login
wrap would be a lockout/DoS vector by construction. The passphrase-verifying endpoints are also
rate-limited (5 attempts per hour), and a successful restore revokes every live refresh token so
an old session cannot outlive the rotation.

### Threat model, stated honestly

- Whoever holds the kit file **and** the passphrase holds your vault. The passphrase is the only
  thing between a found kit and your entries — use a long one (12 characters is the floor, not a
  target) and store it apart from the kit.
- A backup protects against *losing* a machine, not against a *compromised* one. Code running as
  you can read the OS keychain, the session state, and anything the CLI prints.
- `psamvault export --plaintext`, `psamvault get`, `ak-get` and `note-get` print secrets in
  cleartext. Treat shell history, process listings and terminal scrollback as untrusted. These
  are the commands the reveal guardrail below refuses in an agent context.

### The reveal guardrail — who may print a secret

Four commands emit secrets: `get`, `ak-get`, `note-get` and `export --plaintext` (plus `--copy`
on any of them). Each one now classifies its caller first and refuses when the caller is a
program. The design is deliberately layered, because each layer was measured to fail on its own:

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

**What it stops.** A well-behaved agent — Hermes, Claude Code, Codex, Goose, OpenCode, a CI job —
running `psamvault get` gets exit code 1 and a message naming the capability alternatives
(`use_credential`, `run_with_credential`, `browser_login`) and the one-shot human approval
(`psamvault approve <entry> --for-agent`). Every decision, allow or deny, appends a row to
`~/.psamvault/audit.jsonl` naming the caller, the matched signal and the outcome. An agent cannot
approve itself: `approve` requires a real terminal (both stdin and stdout on a TTY), and an
approval covers exactly one entry for exactly one reveal.

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

## Known limitations

- **Rotating a backup passphrase does not invalidate a kit file that was already copied.** The VEK
  never changes, so a copy taken before a rotation still carries usable key material. Rotation
  revokes the *server* slot, and the CLI refuses a revoked slot while online; destroying the copies
  you no longer trust is on you. (`psamvault backup rotate` is the right command when it is the
  passphrase that leaked; nothing today disarms a kit file that was copied before it.) Real
  revocation requires rotating the VEK and re-encrypting every entry, which is not implemented.
- A kit file is not a data backup. If the server's data were lost, the kit would restore access to
  nothing — keep a `psamvault export` dump as well.

## Safe Harbor

Any security research conducted in good faith on the latest stable release of
psamvault is authorised. I will not take legal action against researchers who
report issues through the advisory process.
