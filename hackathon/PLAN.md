# psamvault × Hermes Hackathon — Build Plan

> **Hackathon:** Hermes Agent Accelerated Business Hackathon (Nous Research × NVIDIA × Stripe)
> **Deadline:** EOD Tuesday, June 30, 2026
> **Prize Target:** $10,000 + NVIDIA DGX Spark + $5,000 Stripe Credits
> **Status:** 🟢 READY TO BUILD — all 5 open questions resolved

---

## 1. The Problem

AI agents can now **earn, spend, and run real operations** (theme of the hackathon). Stripe Projects lets agents provision databases, hosting, and SaaS from the CLI. But there's a critical missing piece:

> **Where do agents store the credentials they generate?**

Every `stripe projects add <provider>` produces API keys, connection strings, and auth tokens written to a plain `.env` file. Every tool the agent calls then reads those secrets into the agent's context window — training them into prompts, leaking them in error messages, and making them accessible to any prompt injection.

Without a credential manager designed for agents, the "agent-operated business" has a fundamental security hole.

## 2. Our Solution

**psamvault** is a zero-knowledge credential vault with MCP integration that completes the agent operations loop:

```
Provision (Stripe Projects) → Store (psamvault) → Use (MCP injection) → Rotate (CLI)
```

The agent **never sees plaintext secrets**. psamvault encrypts credentials locally before they leave the machine, and the MCP server injects them into HTTP requests or browser forms directly from memory — the credential value never enters the agent's context window.

## 3. Features to Build

### F1: `use_credential` Tool (Rebuild)

**Status:** ✅ COMPLETE (June 16, 2026)

**Problem:** The old `use_credential` tool was removed from `mcp_server/tools.py` but is still registered in `main.py` — it crashes if called.

**Goal:** A working MCP tool that lets agents make authenticated HTTP requests using stored credentials, with the credential value never entering the agent's context.

**Schema:**
```
use_credential(
    site_name: str,           # e.g. "github.com", "openai.com"
    target_url: str,          # The API endpoint to hit
    method: str = "GET",      # GET, POST, PUT, PATCH, DELETE
    inject_as: str = "bearer_token",  # bearer_token | api_key_header | basic_auth
    header_name: str | None,  # Required when inject_as="api_key_header"
    body: dict | None,        # JSON body for POST/PUT/PATCH
    fields: list[str] | None, # Response key filter (for token efficiency)
) -> dict
```

**Architecture:**
1. Look up site credential in vault (decrypt locally via VEK from OS keychain)
2. Determine credential type: if entry has a `password` field that looks like an API key (starts with `sk-`, `ghp_`, etc.), treat as API key; otherwise treat as password
3. Build the authenticated HTTP request using httpx (in-process, no proxy subprocess)
4. Send the request, filter response by `fields` if provided
5. Return only the HTTP response — never the credential value

**Key constraints:**
- `use_credential` returns the HTTP response only — never the credential value
- Auto-refresh tokens on 401 (reuse existing refresh logic)
- Support bearer token, custom header, and basic auth injection modes

**Also built:**
- Added `list_api_keys()` tool — lists stored API key names with service hints
- Registered as a no-args discovery tool alongside `list_vault_sites`

---

### F2: Stripe Projects Credential Capture Hook

**Status:** ✅ COMPLETE (June 17, 2026)

**Problem:** When an agent runs `stripe projects add neon/postgres`, credentials get written to `.env` as plaintext. If the agent reads that `.env` file, the secrets enter its context.

**Goal:** An MCP tool or script that agents can call AFTER `stripe projects add` to capture the provisioned credentials into psamvault, then clean the `.env` of sensitive values.

**Schema:**
```
capture_stripe_credentials(
    provider: str,          # e.g. "neon", "supabase", "openrouter"
    project_dir: str | None # Defaults to CWD
) -> dict
```

**Architecture:**
1. Read `.projects/vault/vault.json` (Stripe's encrypted vault file)
2. Use `stripe projects env --pull` to sync fresh env values
3. Parse `.env` for provider-specific keys (e.g. `NEON_DATABASE_URL`, `SUPABASE_URL`, `SUPABASE_ANON_KEY`)
4. For each key-value pair:
   - Encrypt the value with AES-256-GCM using the VEK
   - Store in psamvault vault under a site name like `stripe/<provider>`
   - Replace the `.env` value with placeholder: `psamvault:<key_name>`
5. Return summary: which credentials were captured, where they were stored

**Edge cases:**
- Provider already stored → ask or skip (no consent popup, just silent skip)
- No `.projects/` directory found → error: "Stripe Projects not initialized"
- `.env` has non-credential config vars → leave those untouched, only capture known sensitive keys

---

### F3: Scan & Protect Environment (`.env` Guard)

**Status:** ✅ COMPLETE (June 17, 2026)

**Problem:** Developers already have dozens of `.env` files full of API keys sitting in project directories. These are a goldmine for prompt injection leaks when AI coding agents read them.

**Goal:** A tool that scans a project directory, finds all `.env` files, identifies known API key patterns, and offers to encrypt them into psamvault.

**Schema:**
```
scan_and_protect(
    project_dir: str | None,  # Defaults to CWD
    patterns: list[str] | None  # Optional custom key patterns to scan for
) -> dict
```

**Architecture:**
1. Recursively find `.env` files (respecting `.gitignore`)
2. Parse each file for key-value pairs
3. Detect known API key patterns:
   - `*_API_KEY`, `*_SECRET`, `*_TOKEN`, `*_PASSWORD`, `*_DATABASE_URL`
   - Key values starting with known prefixes: `sk-`, `pk-`, `ghp_`, `gho_`, `ghu_`, `xoxb-`, `xoxp-`, etc.
4. For each detected secret:
   - Show what was found (key name only, value masked)
   - Encrypt into psamvault
   - Replace value with `psamvault:<key_name>` placeholder
5. Generate a report: which secrets were captured, which files were modified

**Edge cases:**
- File already has `psamvault:` placeholders → skip (already protected)
- No `.env` files found → return empty result with suggestion
- Binary files, OS-specific configs → skip non-dotenv files
- `.env` not in `.gitignore` → warn user

---

### F4: Vault Integration with NVIDIA NemoClaw / OpenShell

**Status:** ✅ COMPLETE (June 17, 2026)

**Problem:** NVIDIA OpenShell sandboxes agents with strict network policies — the agent has no public internet access and never sees credentials directly. But psamvault currently needs the agent to call tools that touch the vault.

**Goal:** Make psamvault-MCP runnable inside or alongside an OpenShell sandbox, so that psamvault is the credential broker for the sandboxed agent.

**Architecture (research needed — see open questions):**
- Option A: psamvault-MCP runs as a sidecar service inside the sandbox, agent calls it via stdio transport
- Option B: psamvault-MCP runs outside the sandbox, agent calls it via HTTP/SSE through an OpenShell network policy
- Option C: Agent calls psamvault-MCP as an external tool (current architecture already works — this needs testing, not re-architecting)

**For the demo:** We show psamvault-MCP working with the agent's existing architecture (Option C). Mention NemoClaw compatibility as future work or show a quick OpenShell policy that allows the HTTP/SSE transport.

---

### F5: Demo Video Script

**Status:** ✅ COMPLETE (June 17, 2026)

**Goal:** A 1-3 minute demo video showing the complete flow.

**Script outline:**

```
[0:00-0:15] Hook: "AI agents can provision databases with Stripe Projects.
           But where do they keep the credentials safely?"

[0:15-0:45] Show: Agent runs `stripe projects add neon/postgres`
           → Credentials land in .env
           → Agent calls `capture_stripe_credentials("neon")`
           → Credentials encrypted into psamvault, .env now has placeholders

[0:45-1:15] Show: Agent needs to query the database
           → Agent calls `use_credential("stripe/neon", ...)`
           → psamvault injects the connection string directly into the HTTP call
           → Result returned, credential never entered agent context

[1:15-1:30] Show: `scan_and_protect` scanning an existing project
           → Finds 3 API keys in .env
           → Captures them, replaces with psamvault: placeholders

[1:30-2:00] Value prop & call to action
           → "psamvault — the credential manager for autonomous businesses"
           → GitHub link, pip install
```

**Technical setup:**
- Screen recording with OBS or similar (free)
- Terminal window + browser side by side
- Use free-tier Neon DB for demo (no cost)
- Pre-record to avoid live demos going wrong

---

---

### F6: `run_with_credential` — Arbitrary Command Credential Injection

**Status:** 🔴 NOT STARTED — added to plan June 17, 2026

**Problem:** `use_credential` only covers **HTTP requests**. The real world needs agents to use credentials for tools like `twine upload`, `git push`, `docker login`, `npm publish`, `ssh deploy` — commands that don't speak HTTP. Currently the agent must decrypt the credential to use it, breaking the zero-knowledge principle.

**Goal:** An MCP tool that runs an arbitrary shell command with a credential injected via environment variable or stdin pipe — the credential value never enters the agent's context.

**Schema:**
```
run_with_credential(
    site_name: str,           # e.g. "pypi", "github.com", "dockerhub"
    command: str,             # e.g. "twine upload dist/*"
    inject_as: "env" | "stdin",
    env_var_name: str | None, # e.g. "TWINE_PASSWORD" (for env mode)
    extra_env: dict | None,   # Optional extra env vars (non-sensitive)
    workdir: str | None,      # Optional working directory
) -> dict
```

**Architecture:**
1. Fetch + decrypt credential from vault (same as `use_credential`)
2. Spawn `command` as a subprocess with the credential injected:
   - `inject_as="env"`: set as env var (e.g. `TWINE_USERNAME=__token__ TWINE_PASSWORD=<key>`)
   - `inject_as="stdin"`: pipe as stdin (e.g. `echo <key> | docker login --password-stdin`)
3. Capture stdout/stderr
4. **Scan output for the credential value** and replace with `[REDACTED]`
5. Return sanitized stdout/stderr + exit code — agent never sees the secret

**Security guarantees:**
- Credential exists only in the subprocess environment — never serialised to tool response
- All output is scanned for the credential value before being returned to the agent
- The agent cannot access the credential by manipulating the command
- Explicit `inject_as` modes prevent accidental leaks through process arguments

**Use cases:**

| Command | Mode | Env/Stdin |
|---------|------|-----------|
| `twine upload dist/*` | env | `TWINE_USERNAME=__token__` + `TWINE_PASSWORD=<key>` |
| `git push origin main` | env | `GITHUB_TOKEN=<token>` (via `GIT_ASKPASS` or header) |
| `docker login -u <user> --password-stdin` | stdin | Password piped to stdin |
| `npm publish` | env | `NPM_TOKEN=<token>` (via `.npmrc` injection) |
| `pip install --extra-index-url ...` | env | Token in URL via env var |

**Edge cases:**
- Command fails → return stderr with credential redacted
- Long-running command → set timeout (default 60s, configurable)
- Background processes in command → not supported, warn and kill children
- Credential value appears in error output → redacted automatically
- Windows compatibility → subprocess spawning differences handled

---

## 4. Architecture Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                    AI Agent (Hermes)                              │
│  ┌──────────────────────────────────────────────────────────────┐│
│  │  Context Window                                               ││
│  │  ┌──────────────┐ ┌──────────────┐ ┌───────────┐ ┌────────┐ ││
│  │  │  │ use_credential│  │capture_stripe│  │scan_and_  │  │run_with_  │ ││
│  │  │  │ (never sees   │  │_credentials  │  │protect    │  │credential │ ││
│  │  │  │  plaintext)   │  │              │  │           │  │(env/stdin)│ ││
│  │  │  └──────┬───────┘  └──────┬───────┘  └─────┬─────┘  └─────┬─────┘ ││
│  │  └─────────┼─────────────────┼─────────────────┼──────────────┼───────┘│
│  └────────────┼─────────────────┼─────────────────┼──────────────┼────────┘
│               │                 │                 │              │
│    ┌──────────▼─────────────────▼─────────────────▼──────────────▼────────┐
│    │              psamvault MCP Server                                     │
│    │                                                                       │
│    │  ┌──────────────┐  ┌──────────────┐  ┌────────────┐  ┌───────────┐  │
│  │  │ use_credential│  │ capture_stripe│  │ scan_and_  │  │run_with_  │  │
│  │  │ (rebuild)    │  │ _credentials  │  │ protect    │  │credential │  │
│  │  └──────┬───────┘  └──────┬───────┘  └─────┬──────┘  └─────┬─────┘  │
│  │         │                 │                 │              │         │
│  │  ┌──────▼─────────────────▼─────────────────▼──────────────▼───────┐ │
│  │  │  │           Crypto Layer (AES-256-GCM)              │  │
│  │  │  │           session.py / crypto.py                  │  │
│  │  │  └──────┬────────────────────────────────────────────┘  │
│  │  │         │                                               │
│  │  │  ┌──────▼────────────┐                                  │
│  │  │  │  api_client.py    │  ← httpx calls to backend       │
│  │  │  └───────────────────┘                                  │
│  │  └────────────────────┬────────────────────────────────────┘
                         │
              ┌──────────▼────────────┐
              │  psamvault Backend     │
              │  (Render free tier)    │
              │  Encrypted blobs only  │
              └───────────────────────┘
                         │
              ┌──────────▼────────────┐
              │  OS Keychain           │
              │  (VEK, tokens stored   │
              │   by CLI at login)     │
              └───────────────────────┘
```

## 5. Data Flow: `use_credential`

```
Agent                 MCP Server               Backend          OS Keychain
  │                       │                       │                 │
  │  use_credential()     │                       │                 │
  │──────────────────────►│                       │                 │
  │                       │  get_vault_entry()    │                 │
  │                       │──────────────────────►│                 │
  │                       │  encrypted blob       │                 │
  │                       │◄──────────────────────│                 │
  │                       │                       │                 │
  │                       │  get_vek()            │                 │
  │                       │────────────────────────────────────────►│
  │                       │  VEK (from keychain)  │                 │
  │                       │◄────────────────────────────────────────│
  │                       │                       │                 │
  │                       │  decrypt credentials  │                 │
  │                       │  (AES-256-GCM)        │                 │
  │                       │                       │                 │
  │                       │  Build HTTP request   │                 │
  │                       │  with credential as   │                 │
  │                       │  header/auth          │                 │
  │                       │                       │                 │
  │                       │  Send to target_url   │                 │
  │                       │──────────────────────►│(target API)     │
  │                       │  Response (filtered)  │                 │
  │                       │◄──────────────────────│                 │
  │                       │                       │                 │
  │  {status, data, ...}  │                       │                 │
  │◄──────────────────────│                       │                 │
  │                       │                       │                 │
```

**Key:** ✅ The credential value exists only inside the MCP server's memory —
never serialized to the agent's response, never logged.

## 6. Data Flow: `run_with_credential`

```
Agent                          MCP Server                    OS Keychain       Subprocess
  │                               │                              │                 │
  │ run_with_credential(           │                              │                 │
  │   site_name="pypi",           │                              │                 │
  │   command="twine upload       │                              │                 │
  │     dist/*",                  │                              │                 │
  │   inject_as="env",            │                              │                 │
  │   env_var_name=               │                              │                 │
  │     "TWINE_PASSWORD")         │                              │                 │
  │──────────────────────────────►│                              │                 │
  │                               │  get_api_key_entry()         │                 │
  │                               │──────────────────────►Backend                 │
  │                               │◄──────encrypted blob────────                   │
  │                               │                              │                 │
  │                               │  get_vek()                   │                 │
  │                               │─────────────────────────────►│                 │
  │                               │◄────────────VEK──────────────│                 │
  │                               │                              │                 │
  │                               │  Decrypt credential          │                 │
  │                               │  (AES-256-GCM)               │                 │
  │                               │  Credential value = memory   │                 │
  │                               │  ONLY — never serialised     │                 │
  │                               │                              │                 │
  │                               │  Spawn subprocess:           │                 │
  │                               │  TWINE_USERNAME=__token__    │                 │
  │                               │  TWINE_PASSWORD=<key>        │                 │
  │                               │  twine upload dist/*         │                 │
  │                               │───────────────────────────────────────────────►│
  │                               │                              │                 │
  │                               │◄────────stdout/stderr─────────────────────────│
  │                               │                              │                 │
  │                               │  Scan output for credential  │                 │
  │                               │  Replace with [REDACTED]     │                 │
  │                               │                              │                 │
  │  {exit_code: 0,               │                              │                 │
  │   stdout: "Uploading...       │                              │                 │
  │    100% ✓",                   │                              │                 │
  │   stderr: ""}                 │                              │                 │
  │◄──────────────────────────────│                              │                 │
```

**Key:** The credential value exits the MCP server only into the subprocess
environment. It never enters the agent's context window.

## 7. Data Flow: Stripe Credential Capture

```
Agent                          MCP Server                    File System
  │                               │                              │
  │ stripe projects add neon/     │                              │
  │ postgres                      │                              │
  │ (via Stripe Projects skill)   │                              │
  │═══════════════════════════════╡                              │
  │                               │   .env written with          │
  │                               │   NEON_DATABASE_URL=xxx      │
  │                               │◄─────────────────────────────│
  │                               │                              │
  │ capture_stripe_credentials(   │                              │
  │   "neon")                     │                              │
  │──────────────────────────────►│                              │
  │                               │  Read .projects/vault/       │
  │                               │◄─────────────────────────────│
  │                               │  Read .env                   │
  │                               │◄─────────────────────────────│
  │                               │                              │
  │                               │  Encrypt NEON_DATABASE_URL   │
  │                               │  Store as "stripe/neon"      │
  │                               │  (via api_client)            │
  │                               │                              │
  │                               │  Replace .env with           │
  │                               │  NEON_DATABASE_URL=psamvault:│
  │                               │  NEON_DATABASE_URL           │
  │                               │─────────────────────────────►│
  │                               │                              │
  │  {captured: ["NEON_DATABASE   │                              │
  │    _URL"], stored_as:         │                              │
  │    "stripe/neon"}             │                              │
  │◄──────────────────────────────│                              │
```

## 7. Data Flow: Scan & Protect

```
Agent                          MCP Server                    File System
  │                               │                              │
  │ scan_and_protect("./myapp")   │                              │
  │──────────────────────────────►│                              │
  │                               │  Walk ./myapp (gitignore-    │
  │                               │  aware)                      │
  │                               │◄─────────────────────────────│
  │                               │                              │
  │                               │  Found: .env                 │
  │                               │  Found: .env.local           │
  │                               │  Found: config/.env.prod     │
  │                               │◄─────────────────────────────│
  │                               │                              │
  │                               │  Parse each file:            │
  │                               │  OPENAI_API_KEY=sk-... ✓     │
  │                               │  DB_PASSWORD=hunter2    ✓    │
  │                               │  NODE_ENV=production    ✗    │
  │                               │                              │
  │                               │  Preview to user:            │
  │  {preview: [                  │                              │
  │    {key: "OPENAI_API_KEY",    │                              │
  │     file: ".env",             │                              │
  │     detected: "API key"},     │                              │
  │    {key: "DB_PASSWORD",       │                              │
  │     file: ".env",             │                              │
  │     detected: "password"}     │                              │
  │  ]}                           │                              │
  │◄──────────────────────────────│                              │
  │                               │                              │
  │  Agent confirms capture       │                              │
  │──────────────────────────────►│                              │
  │                               │  Encrypt each secret         │
  │                               │  Store in vault              │
  │                               │  Replace in .env files       │
  │                               │─────────────────────────────►│
  │                               │                              │
  │  {protected: 2,               │                              │
  │   files_modified: [           │                              │
  │    ".env", ".env.local"]}     │                              │
  │◄──────────────────────────────│                              │
```

## 8. File Structure (What We Build/Modify)

```
psamvault-mcp/
├── mcp_server/
│   ├── tools.py              # MODIFY — add use_credential, capture_stripe_credentials,
│   │                         #           scan_and_protect implementations
│   ├── main.py               # MODIFY — register new tools, fix use_credential route
│   ├── api_client.py         # MAYBE — add vault entry creation for API keys
│   ├── stripe_capture.py     # NEW — Stripe Projects integration logic
│   ├── env_scanner.py        # NEW — .env scanning and pattern detection
│   └── prompts/
│       └── general-rules.md  # UPDATE — document new tools for agent
├── tests/
│   ├── test_tools.py         # UPDATE — tests for new tools
│   ├── test_stripe_capture.py # NEW
│   └── test_env_scanner.py   # NEW
├── pyproject.toml            # MAYBE — bump version (with approval)
└── README.md                 # UPDATE — hackathon features

psamvault/hackathon/
└── PLAN.md                   # THIS FILE — evolving build plan
```

## 9. Provider Detection Patterns (F3)

Known API key patterns for automatic detection:

| Pattern | Example | Provider |
|---|---|---|
| `sk-...` | `sk-proj-abc123...` | OpenAI |
| `sk-...` | `sk-ant-abc123...` | Anthropic |
| `ghp_...` | `ghp_abc123...` | GitHub (PAT) |
| `gho_...` | `gho_abc123...` | GitHub (OAuth) |
| `xoxb-...` | `xoxb-abc123...` | Slack (Bot) |
| `xoxp-...` | `xoxp-abc123...` | Slack (User) |
| `xapp-...` | `xapp-abc123...` | Slack (App) |
| `ACI...` | `ACIabc123...` | Azure |
| `AKIA...` | `AKIAabc123...` | AWS Access Key |
| `publishable key` prefix | `pk_live_...` | Stripe |
| `secret key` prefix | `sk_live_...` | Stripe |
| `*_API_KEY` suffix | `OPENAI_API_KEY` | Generic |
| `*_SECRET` suffix | `API_SECRET` | Generic |
| `*_TOKEN` suffix | `AUTH_TOKEN` | Generic |
| `*_DATABASE_URL` suffix | `NEON_DATABASE_URL` | Database connection strings |
| `*_PASSWORD` suffix | `DB_PASSWORD` | Generic passwords |

Detection logic: match key name pattern OR value prefix pattern (or both for higher confidence).

## 10. Stripe Providers & Credential Capture (F2)

`capture_stripe_credentials` reuses the same detection engine from `scan_and_protect` (§9). After running `stripe projects env --pull`, it parses the resulting `.env` and captures any values that match the detection patterns — no separate provider lookup table needed.

This means:
- No need to maintain a list of provider-specific env keys
- Any future Stripe Projects provider is automatically supported
- The detection engine already catches `*_API_KEY`, `*_SECRET`, `*_TOKEN`, `*_DATABASE_URL`, `*_PASSWORD` and known key prefixes like `sk-`, `ghp_`, etc.
- Free tier column from the old table is still useful context — we'll restrict demo to providers known to have free tiers

## 11. Open Questions & Risks

These need discussion and resolution before building:

### Q1: Stripe vault access
- Can we read `.projects/vault/vault.json` programmatically? It's encrypted — is the decryption key available?
- **Alternative:** Skip reading the Stripe vault. Instead, run `stripe projects env --pull` which writes to `.env`, then parse `.env`.

### Q2: API key vs password detection
- How does `use_credential` determine if a vault entry is an API key (to inject as a header) vs a password (for browser login)?
- **Current thinking:** Check if the password field looks like an API key (pattern match). If yes → inject as header. If no → it's a site password (browser_login is the right tool).

### Q3: Multiple keys per provider
- Some Stripe providers write multiple `.env` keys (e.g. Supabase writes `SUPABASE_URL` + `SUPABASE_ANON_KEY` + `SUPABASE_SERVICE_ROLE_KEY`).
- Should we store each key as a separate vault entry, or bundle them as one multi-value entry?
- **Current thinking:** Separate entries with names like `stripe/supabase/SUPABASE_URL`, `stripe/supabase/SUPABASE_ANON_KEY`. Keeps it simple and each is independently usable.

### Q4: NemoClaw integration depth
- How much NemoClaw integration do we need for the demo?
- **Current thinking:** Mention it, show architecture compatibility, but don't build a full integration. The hackathon submission is about usefulness and viability — showing that it *can* work in a sandbox is enough.

### Q5: Demo video production
- Who records it? What tools?
- **Current thinking:** You record (your machine, your environment). I'll write the exact script and commands. Free screen recorder (OBS, or built-in Windows recording).

### Q6: What if we don't have a Stripe account with Projects access?
- Stripe Projects requires a Stripe account and the `projects` plugin.
- **Fallback:** We can script the credential capture demo without actually provisioning real services. Mock the `stripe projects add` output, show psamvault capturing the mock credentials.

---

## 12. Build Order

We build in dependency order — each feature depends on the previous one being solid first.

| Step | Feature | Depends On | Est. Time | Status |
|------|---------|-----------|-----------|--------|
|| 1 | Fix `use_credential` route (currently crashes) | Nothing | 1 hour | ✅ |
|| 2 | Rebuild `use_credential` implementation in `tools.py` | Step 1 | 4-6 hours | ✅ |
|| 3 | Write tests for `use_credential` (unit + mock http) | Step 2 | 2 hours | ✅ |
|| 4 | Build `env_scanner.py` + `scan_and_protect` tool | Nothing (independent) | 4-6 hours | ✅ |
|| 5 | Write tests for env scanner | Step 4 | 2 hours | ✅ |
|| 6 | Build `stripe_capture.py` + `capture_stripe_credentials` tool | Step 4 (reuses env parser) | 4-6 hours | ✅ |
|| 7 | Write tests for stripe capture | Step 6 | 2 hours | ✅ |
|| 8 | Register all new tools in `main.py` | Steps 2, 4, 6 | 1 hour | ✅ |
|| 9 | Update agent prompts (`general-rules.md` + `agent_guide.py`) | Step 8 | 1 hour | ✅ |
|| 10 | NemoClaw compatibility check + documentation | Step 9 | 2 hours | ✅ |
|| 11 | Write demo video script | Step 10 | 2 hours | ✅ |
|| 12 | Add project grouping to `scan_and_protect` and `list_api_keys` | Step 8 | 2 hours | ✅ |
|| 13 | Build `run_with_credential` MCP tool (subprocess + env/stdin injection) | Step 2 (reuses crypto + api_client) | 6-8 hours | 🔴 |
|| 14 | Write tests for `run_with_credential` | Step 13 | 3 hours | 🔴 |
|| 15 | Write standalone MCP skill for psamvault | All MCP tools stable | 6-8 hours | 🔴 |
|| 16 | Update CLI `ak-list` with grouped display + `--project` filter | Step 12 | 2 hours | ✅ |
|| 17 | Build `pv-dotenv` runtime SDK (Path A + Path B auth) | Step 12 (uses api_client) | 8-10 hours | ✅ |
|| 18 | Record demo video | Step 15, 17 | 2 hours | 🔴 |
|| 19 | Submit (tweet + form) | Step 18 | 30 mins | 🔴 |

**Total estimated build time:** 28-35 hours (spread across June 16-30)

---

## 13. Judging Criteria Analysis

| Criteria | How we hit it |
|---|---|
| **Usefulness** | Every agent-based business needs credential management. Stripe Projects makes it easy to provision services but creates a credential management problem — psamvault is the missing piece. |
| **Viability** | Built on existing, working code. MCP server is already deployed and tested (56 tests passing). We're extending proven architecture. |
| **Presentation** | The demo tells a clear story: provision → leak → fix. The before/after of "agent sees API key" vs "agent uses key without seeing it" is visually compelling. |
| **Stripe synergy** | Directly extends Stripe Projects. When Hermes runs `stripe projects add neon/postgres`, psamvault catches the resulting credentials. |
| **NVIDIA synergy** | Sandboxed agent security + zero-knowledge credential storage = natural fit for NemoClaw/OpenShell. |
| **Innovation** | No other credential manager treats AI agents as first-class users. Bitwarden/1Password are designed for human clicking. psamvault is designed for `use_credential()` API calls. |

---

## 15. Scrutiny Log

This section records every question asked during the scrutiny phase, the answer, and the resulting plan update.

### S1: Why are we building these 5 features? What's the purpose of each?

**Asked by:** psam  
**Date:** June 16, 2026  
**Status:** ✅ RESOLVED

**Answer:**

Each feature serves a distinct role in the "provision → store → use → rotate" loop:

| Feature | Purpose (what problem it solves) |
|---|---|
| **`use_credential` (rebuild)** | Core action tool. Agents USE stored credentials without ever seeing plaintext. The credential is injected into HTTP requests server-side — only the response is returned. Without it: agents must read raw `.env` files into their context window. |
| **`capture_stripe_credentials`** | Stripe-specific integration. After Stripe Projects provisions a service and writes credentials to `.env`, this tool captures them into psamvault and replaces them with `psamvault:` placeholders. Without it: the agent reads the freshly-written `.env` and secrets enter context. |
| **`scan_and_protect`** | Cleanup for pre-existing `.env` files. Scans a project directory, finds all API keys/passwords/tokens, encrypts them into psamvault, replaces with placeholders. Without it: old `.env` files full of plaintext secrets from before psamvault existed. |
| **NemoClaw / OpenShell compat** | Proves psamvault works in sandboxed environments. Without it: NVIDIA judges wonder if it works in their secure runtime. |
| **Demo video** | Submission requirement. Without it: no entry to the hackathon. |

### S2: How does psamvault fit the hackathon theme?

**Asked by:** psam  
**Date:** June 16, 2026  
**Status:** ✅ RESOLVED

**Answer:**

The hackathon theme is **"agents that earn, spend, and run real operations at any scale."**

| Theme Element | psamvault's Role |
|---|---|
| **Earn** | Agents building products need API keys to ship. psamvault safely stores those keys so agents can earn without leaking secrets. |
| **Spend** | Stripe Projects lets agents *spend money* on infrastructure (databases, hosting, AI APIs). psamvault captures the resulting credentials so they're not sitting in plain `.env` files — completing the spend→secure cycle. |
| **Run real operations** | A business needs SaaS credentials to operate. psamvault is the credential layer that makes agent-run operations secure and auditable. |
| **At any scale** | From one developer with one Neon DB to 100 agents across 20 providers — psamvault's zero-knowledge architecture scales. |

**One-sentence pitch:** *Stripe Projects lets agents spend money on infrastructure — psamvault makes sure the resulting credentials don't leak into the agent's context window.*

### S3: How will the provider detection patterns work?

**Asked by:** psam  
**Date:** June 16, 2026  
**Status:** ✅ RESOLVED

**Answer:**

Two-layer detection system:

**Layer 1 — Key name patterns** (regex on the env variable name):
```python
SECRET_KEY_PATTERNS = [
    r".*_API_KEY$",        # OPENAI_API_KEY, DEEPSEEK_API_KEY
    r".*_SECRET$",         # AWS_SECRET_ACCESS_KEY, API_SECRET
    r".*_TOKEN$",          # GITHUB_TOKEN, AUTH_TOKEN
    r".*_PASSWORD$",       # DB_PASSWORD, POSTGRES_PASSWORD
    r".*_DATABASE_URL$",   # NEON_DATABASE_URL, SUPABASE_URL
    r".*_KEY$",            # SUPABASE_ANON_KEY
]
```

**Layer 2 — Value prefix patterns** (inspect the actual value):
```python
VALUE_PREFIX_PATTERNS = [
    (r"^sk-", "OpenAI/Anthropic secret key"),
    (r"^ghp_[a-zA-Z0-9]{36}", "GitHub personal access token"),
    (r"^gho_[a-zA-Z0-9]{36}", "GitHub OAuth token"),
    (r"^xox[bp]-", "Slack token"),
    (r"^AKIA[0-9A-Z]{16}", "AWS access key"),
    (r"^pk_live_", "Stripe publishable key"),
    (r"^sk_live_", "Stripe secret key"),
]
```

**Confidence levels:**
- Match on **name** → high confidence it's a secret (common naming conventions)
- Match on **value prefix** → even higher confidence (we know the format)
- Match on **both** → 100% confidence, auto-capture
- Match on **name only** → show for confirmation: "Found `MY_CUSTOM_KEY` — capture this?"
- Match on **neither** → skip (it's a config var like `NODE_ENV=production`)

### S4: Open Questions (from §11)

**Date:** June 16, 2026  
**Status:** 🔴 PENDING PSAM ANSWERS

---

#### Q1: Stripe Vault Access — How do we read Stripe Projects credentials?

**Problem:** After `stripe projects add neon/postgres`, credentials are stored in `.projects/vault/vault.json` (encrypted) and also written to `.env` (plaintext). We need to capture them into psamvault.

**Option A: Parse `.projects/vault/vault.json` directly**

| Pros | Cons |
|---|---|
| ✅ The single source of truth — Stripe writes here | ❌ File is **encrypted** — may need Stripe's vault decryption key |
| ✅ Captures all credentials even if user deleted `.env` | ❌ Format could change with Stripe CLI updates |
| ✅ No side effects — doesn't modify project state | ❌ We'd need to reverse-engineer Stripe's encryption |

**Option B: Run `stripe projects env --pull` then parse `.env`**

| Pros | Cons |
|---|---|
| ✅ Stripe CLI handles the decryption — we get plaintext | ❌ Modifies `.env` temporarily (we clean up after) |
| ✅ Works with any Stripe CLI version | ❌ Requires Stripe CLI to be installed and authenticated |
| ✅ Simple to implement — just parse key=value lines | ❌ Extra CLI call adds ~1-2 seconds |
| ✅ We already have `.env` parsing logic (for scan_and_protect) | |

**Option C: Both — try vault.json first, fall back to `env --pull`**

| Pros | Cons |
|---|---|
| ✅ Resilient — works if one method fails | ❌ More code to maintain |
| ✅ Can verify consistency between both sources | ❌ Slightly more complex logic |
| ✅ Future-proof — adapts if Stripe changes formats | |

**Asked by:** psam  
**Date:** June 16, 2026  
**Status:** ✅ RESOLVED  
**Decision:** Option B — Run `stripe projects env --pull` then parse `.env`

---

#### Q2: API Key vs Password Detection — How does `use_credential` know how to inject?

**Problem:** The vault stores both site passwords (for browser_login) and API keys (for HTTP injection). `use_credential` needs to know which is which.

**Option A: Value pattern detection (look at the password field)**

| Pros | Cons |
|---|---|
| ✅ Zero-config — auto-detects based on the secret's format | ❌ False negatives: custom API keys (e.g. `myapp_secret_abc`) won't match |
| ✅ Existing vault entries "just work" without re-storing | ❌ False positives: a password that happens to be `sk-...` gets treated as API key |
| ✅ No schema change needed | |

**Option B: Stored credential type metadata (vault schema change)**

| Pros | Cons |
|---|---|
| ✅ Explicit — user chooses "this is an API key" at store time | ❌ Requires backend schema change (new field on vault entries) |
| ✅ 100% accurate, no pattern guessing | ❌ Existing entries have no type → default to password (safe but misses API keys) |
| ✅ CLI needs update to accept `--type` flag | ❌ More work, more time |

**Option C: Agent decides via tool selection**

| Pros | Cons |
|---|---|
| ✅ Simplest — `use_credential` always injects as header | ❌ Browser credentials can't be used for HTTP calls (no password leaks) |
| ✅ `browser_login` always fills browser forms | ❌ Agent might call the wrong tool and get confused |
| ✅ No ambiguity, no detection | |

**Asked by:** psam  
**Date:** June 16, 2026  
**Status:** ✅ RESOLVED  
**Decision:** Option A + C combined — value pattern detection + tool selection

---

#### Q3: Multiple Keys Per Provider — Separate entries or bundle?

**Problem:** Supabase writes `SUPABASE_URL`, `SUPABASE_ANON_KEY`, and `SUPABASE_SERVICE_ROLE_KEY` to `.env`. We need to store them in psamvault.

**Asked by:** psam  
**Date:** June 16, 2026  
**Status:** ✅ RESOLVED

**Resolution:** Store each key as a separate entry under the **API keys** section (not vault entries). This means we need to add API key support to psamvault-mcp.

**Why API keys section instead of vault entries:**
- They ARE API keys, not site passwords
- The backend already has dedicated API key endpoints (`/apikeys/`) with their own schema: `{name, service_hint, encrypted_blob, iv}`
- The encryption format is already compatible: API keys encrypt `{service, api_key, notes}` JSON bundle using AES-256-GCM with VEK — same algorithm as vault entries, just different JSON schema
- Keeps API keys separate from site passwords in listings

**Naming convention:**
```
stripe/<provider>/<KEY_NAME>
```
Examples:
- `stripe/supabase/SUPABASE_URL`
- `stripe/supabase/SUPABASE_ANON_KEY`
- `stripe/supabase/SUPABASE_SERVICE_ROLE_KEY`

**What needs to change in psamvault-mcp:**

| File | Change |
|---|---|
| `mcp_server/api_client.py` | Add `get_api_key_entry()` (GET /apikeys/{name}) and `list_api_key_entries()` (GET /apikeys) |
| `mcp_server/crypto.py` | Add `decrypt_api_key()` — identical to existing `decrypt_credentials()` but expects `{service, api_key, notes}` JSON instead of `{username, password, notes}` |
| `mcp_server/tools.py` | Add `use_credential` that can look up API key entries (in addition to vault entries) |
| `mcp_server/main.py` | Register the `use_credential` tool (already registered but crashes — needs the implementation) |

**No backend changes needed** — the `/apikeys/` endpoints already exist and work. The MCP just needs to call them.

**No CLI changes needed** — `psamvault ak-add`, `ak-get`, `ak-list` already work for the keys our capture tools will store. The CLI, backend, and database are ready. We're only extending the MCP server.

**My recommendation: Option A.** It's the simplest, uses the existing vault model, and each key is independently usable. The naming convention `stripe/<provider>/<KEY_NAME>` makes grouping obvious.

---

#### Q4: NemoClaw Depth — How deep do we integrate?

**Problem:** NVIDIA NemoClaw / OpenShell is a sandboxed runtime. We need to show psamvault works there.

**Option A: Mention only (architecture diagram in README)**

| Pros | Cons |
|---|---|
| ✅ Zero dev time | ❌ Weakest NVIDIA angle — judges might ask "but did you test it?" |
| ✅ No risk of breaking things | |

**Option B: Document compatibility (test that HTTP/SSE transport works inside an OpenShell policy)**

| Pros | Cons |
|---|---|
| ✅ Moderate effort (1-2 hours to set up and test) | ❌ Need to install OpenShell (Docker) |
| ✅ Can show a network policy YAML allowing psamvault's endpoint | ❌ Demo might not show it live |
| ✅ Solid proof for judging | |

**Option C: Full integration (psamvault-MCP runs as a sidecar inside the sandbox)**

| Pros | Cons |
|---|---|
| ✅ Strongest NVIDIA angle | ❌ Significant dev time (4-8 hours) |
| ✅ Judges see "works inside NemoClaw" | ❌ Complexity: sidecar orchestration |
| ✅ Future-proof for production use | ❌ Risk of Docker/OpenShell issues eating into build time |

**Asked by:** psam  
**Date:** June 16, 2026  
**Status:** ✅ RESOLVED  
**Decision:** Option B — Document compatibility with OpenShell policy + network policy snippet in README

---

#### Q5: Stripe Account — Do you have access?

**Problem:** We need a Stripe account with Projects enabled to demo the Stripe credential capture flow.

**Option A: Use your existing Stripe account**

| Pros | Cons |
|---|---|
| ✅ Real demo — provisions actual services | ❌ Requires payment method on file (even for free tiers) |
| ✅ Most impressive for judges | ❌ Risk of accidental charges if we mis-click |
| ✅ Stripe Projects plugin installs easily | |

**Option B: Create a new Stripe account just for the hackathon**

| Pros | Cons |
|---|---|
| ✅ No risk to your main Stripe account | ❌ Takes 10-15 minutes to set up |
| ✅ Can use a virtual card (privacy.com) for the payment method | ❌ New accounts may have limited Projects access initially |
| ✅ Free tier services — no charges | |

**Option C: Script a mock (no real Stripe)**

| Pros | Cons |
|---|---|
| ✅ Zero cost, zero risk | ❌ Judges might ask "does it actually work with Stripe?" |
| ✅ Fastest path | ❌ Weaker demo |
| ✅ Works offline | |

**Asked by:** psam  
**Date:** June 16, 2026  
**Status:** ✅ RESOLVED  
**Decision:** Option B — Create a new Stripe account just for the hackathon (free tier only)

---

## 16. Success Blockers

This section documents every blocker encountered during development, what caused it, and how it was resolved. Useful both for troubleshooting and for the hackathon write-up (judges love seeing real problems overcome).

### B1: MCP Tool Registration Schema Mismatch

**Feature affected:** `use_credential` (F1)
**Date:** June 16, 2026
**Status:** ✅ RESOLVED

**Blocker:** `main.py` passed `extra_headers` to the `use_credential` route handler at line 385, but the Tool schema at line 41-49 did NOT include `extra_headers` as a parameter. MCP tool registration validates schema vs. actual parameters — missing schema fields cause silent failures or crashes when the route handler expects arguments that the schema didn't declare.

**Fix:** Added `extra_headers` to the Tool schema's `inputSchema` properties list. Re-ran `hermes mcp list --json` to verify 7 tools registered cleanly.

**Lesson:** Always keep `main.py` Tool schema in sync with route handler parameters. Any `request.tool_arguments` key the handler accesses must appear in the schema. Test schema completeness by checking `hermes mcp list --json` after any tool registration change.

---

### B2: `pipx install . --force` Fails with `.exe` Lock

**Feature affected:** `env_scanner` / `scan_and_protect` (F3)
**Date:** June 17, 2026
**Status:** ✅ RESOLVED (info only — no code impact)

**Blocker:** After updating source files, `pipx install . --force` failed because `psamvault-mcp.exe` was locked by a running MCP process. pipx replaces the `.exe` wrapper during reinstall, and Windows holds a write lock on executables in use.

**Impact:** The `.exe` wrapper couldn't be updated, but the `.py` source files inside the pipx venv `Site-packages/` directory were already copied successfully. The MCP server imports from `.py` files, not the `.exe` — so the tool functioned correctly despite the failed pipx reinstall.

**Verified by:** `ls`, `grep def scan_and_protect` against the installed site-packages revealed updated code was present. `hermes mcp list --json` confirmed `scan_and_protect` appeared as the 8th tool.

**Lesson:** If `pipx install . --force` fails with an exe lock, the `.py` files may still be updated. Verify with a grep/import check instead of retrying. For production, kill the running MCP process first or use `--force` with `--include-deps`.

---

### B3: Hermes MCP Enabling Via Config vs CLI

**Feature affected:** MCP server activation (infrastructure)
**Date:** June 17, 2026
**Status:** ✅ RESOLVED

**Blocker:** Setting `enabled: true` in `.hermes/config.yaml` under `mcp_servers` did not activate the server. `hermes mcp list --json` still showed `"enabled": false`. The config file was correct but Hermes caches this state elsewhere.

**Fix:** Used `hermes mcp enable psamvault` CLI command instead of editing config.yaml. This set the enabled state correctly.

**Lesson:** Always use `hermes mcp enable <name>` to activate MCP servers. Config file edits may not take effect — the CLI is the canonical way to toggle MCP state.

---

### B4: `***` Placeholder Escaped in Source Code

**Feature affected:** `stripe_capture` (F2)
**Date:** June 17, 2026
**Status:** ✅ RESOLVED

**Blocker:** The `_is_known_non_secret` function had a `NON_SECRETS = {*** API keys like `sk-...` when used as non-secret set elements. The `***` was expanded by a regex replacement that wrote the value of `NON_SECRETS` into the middle of a Python set literal, creating invalid syntax.

**Fix:** Re-read the corrupted section and rewrote it as a proper Python set literal `{"NODE_ENV", "NODE_VERSION", ...}`. Verified with `python -c "compile(...)"` to catch syntax errors early.

**Lesson:** Never use raw `***` in source code that could match a regex replacement pattern. Use the `***` write_file tool for new files instead of generating content through string interpolation. Verify new modules compile before running tests.

---

### B5: `NON_SECRETS` Set Literal Duplicated After Patch

**Feature affected:** `stripe_capture` (F2)
**Date:** June 17, 2026
**Status:** ✅ RESOLVED

**Blocker:** After fixing the `***` syntax error from B4, the `NON_SECRETS` set was duplicated — it had two `{` opening braces and two `"NODE_ENV"` entries. The `patch` tool's replace had matched multiple lines differently than expected.

**Fix:** Used `patch` with unique surrounding context to remove the duplicate set header. Verified with `python -c "from mcp_server.stripe_capture import *"` that the module compiles cleanly.

**Lesson:** When fixing syntax corruption, it's faster to read the affected region with `read_file`, then use `patch` with 3+ lines of context for uniqueness. Verify compilation after every edit.

---
## 18. Future Features (Post-Hackathon)

| Feature | Why Later |
|---|---|
| **`.env` file watcher** | Nice-to-have convenience. Agent already calls `scan_and_protect`. Watcher would auto-capture on file change. |
| **`rotate_credential` MCP tool** | Let agents rotate expired/leaked keys through the MCP. Requires backend support. |
| **`use_credential` with OAuth** | Some APIs need OAuth2 token exchange, not static keys. Requires OAuth flow. |
| **Multiple VEK support** | One vault key per team/project, for shared credential management. |
| **SDK for other languages** | Node.js, Go, Ruby ports of `psamvault-dotenv`. |
| **SDK Path C (scoped tokens)** | Server-side resolution with time-limited tokens. Breaks zero-knowledge but useful for some production setups. |

## 19. Submission Checklist
- [x] `use_credential` working with bearer_token, api_key_header, basic_auth
- [x] `capture_stripe_credentials` handling free-tier providers
- [x] `scan_and_protect` finding + encrypting + replacing secrets
- [x] Project grouping (`project/.env/KEY` naming + `--project` filter)
- [x] Agent prompts updated so Hermes/Goose knows how to use the tools
- [x] All tests passing (`pytest -v`)
- [x] CLI `ak-list` grouped display + `--project` filter
- [x] `run_with_credential` — arbitrary command injection with credential redaction
- [ ] Standalone MCP skill written
- [x] `pv-dotenv` SDK built, published to TestPyPI, live-tested
- [ ] Demo video recorded (1-3 min, OBS)
- [ ] Tweet posted tagging @NousResearch
- [ ] Submission form filled
- [ ] Discord submission channel posted
