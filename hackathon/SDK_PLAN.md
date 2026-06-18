# psamvault Runtime SDK — Build Plan

> **Goal:** A Python SDK (`pv-dotenv`) that applications use at runtime to resolve `psamvault:` placeholders into real values. This allows `.env` files to stay as placeholders safely — the AI agent sees nothing sensitive, and the running app gets the real secrets transparently.
>
> **Core idea:** Drop-in replacement for `python-dotenv`. Same API, one import change. When the app loads `.env`, the SDK detects `psamvault:` values and resolves them from the vault.
>
> **Status:** 🟢 BRAINSTORMING — Q5 (Python version) still open
>
> **Hackathon relevance:** Strong. Completes the "provision → store → use" loop. Stripe Projects provisions → `scan_and_protect` captures → app reads via SDK. Agent never touches real values.

---

## Table of Contents

1. [The Problem](#1-the-problem)
2. [Architecture Overview](#2-architecture-overview)
3. [Auth: Path A + Path B](#3-auth-path-a--path-b)
4. [SDK Surface](#4-sdk-surface)
5. [How Resolution Works](#5-how-resolution-works)
6. [Security Model](#6-security-model)
7. [Open Questions](#7-open-questions)
8. [How It Fits the Product Line](#8-how-it-fits-the-product-line)
9. [Build Order](#9-build-order)
10. [Change Log](#10-change-log)

---

## 1. The Problem

### Current Flow (Broken)

```
.env (plaintext)
DATABASE_URL=postgresql://user:***@neon.tech/db
         │
         ├──► Application reads .env → works ✅
         │
         └──► AI agent reads .env → secrets leak ❌
```

If `scan_and_protect` replaces with placeholders:

```
.env (placeholders)
DATABASE_URL=psamvault:DATABASE_URL
         │
         ├──► Application reads .env → crashes ❌
         │
         └──► AI agent reads .env → sees nothing ✅
```

### Desired Flow

```
.env (placeholders)
DATABASE_URL=psamvault:DATABASE_URL
         │
         ├──► Application calls load_dotenv()
         │    → SDK resolves psamvault: values from vault
         │    → os.environ['DATABASE_URL'] = real_postgresql_url
         │    → Application works ✅
         │
         └──► AI agent reads .env → sees "psamvault:DATABASE_URL"
              → nothing leaked ✅
```

---

## 2. Architecture Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                       Application Process                          │
│                                                                    │
│  ┌──────────────┐     ┌─────────────────────┐     ┌────────────┐ │
│  │  .env file    │────►│ pv-dotenv           │────►│ os.environ │ │
│  │  DATABASE_URL │     │                     │     │ is now     │ │
│  │  =psamvault:..│     │  Detects psamvault: │     │ populated  │ │
│  │  JWT_SECRET   │     │  placeholders       │     │ with real  │ │
│  │  =psamvault:..│     │  ↓                  │     │ values     │ │
│  └──────────────┘     │  Decrypts each via   │     └────────────┘ │
│                       │  VEK from keychain   │                    │
│                       │  or PSAMVAULT_VEK    │                    │
│                       │  ↓                   │                    │
│                       │  Injects into        │                    │
│                       │  os.environ          │                    │
│                       └──────────┬───────────┘                    │
│                                  │                                │
└──────────────────────────────────┼────────────────────────────────┘
                                   │
                                   │  Calls psamvault backend
                                   ▼
                    ┌─────────────────────────────┐
                    │     psamvault Backend         │
                    │  (stores encrypted blobs)    │
                    └─────────────────────────────┘
```

### Key Design Decisions ✅ Resolved

| Decision | Chosen | Why |
|---|---|---|
| **Package name** | **`pv-dotenv`** | Short, consistent with `pv` CLI alias |
| **API** | Drop-in `load_dotenv()` replacement | `from pv_dotenv import load_dotenv` replaces `from dotenv import load_dotenv` |
| **Auth** | Path A (keychain) + Path B (env vars) | Zero config on dev machine, works in Docker/CI |
| **Caching** | In-memory only (os.environ) | Decrypt once per process lifetime |
| **Scope** | Only `psamvault:` prefixed values | Non-prefixed values pass through unchanged |
| **Missing VEK?** | Crash with clear error + key name | Loud and clear — no silent fallback |
| **Deleted vault entry?** | Crash with clear error + key name | App will crash anyway — better to know why |
| **Install location** | In project's venv (like any dependency) | `pip install pv-dotenv` per project |
| **Project name** | Explicit `project_name` parameter | No auto-detection. Developer must pass it. |

---

## 3. Auth: Path A + Path B

### Path A — OS Keychain (Dev Machine)

```
1. Developer runs: psamvault login
2. CLI stores VEK + access token in OS keychain
3. pv-dotenv calls keyring.get_password() to retrieve them
4. VEK used to decrypt locally, token used for API calls
5. Zero config — works automatically after login
```

**VEK flow:**
```python
def _get_vek() -> bytes:
    # Path A: OS keychain
    hex_vek = keyring.get_password("psamvault", "session.vek")
    if hex_vek:
        return bytes.fromhex(hex_vek)
    # Path B: env var
    hex_vek = os.environ.get("PSAMVAULT_VEK")
    if hex_vek:
        return bytes.fromhex(hex_vek)
    raise RuntimeError(
        "No VEK found. Run 'psamvault login' or set PSAMVAULT_VEK env var."
    )
```

**Token flow (same pattern):**
```python
def _get_access_token() -> str:
    token = keyring.get_password("psamvault", "session.access_token")
    if token:
        return token
    token = os.environ.get("PSAMVAULT_TOKEN")
    if token:
        return token
    raise RuntimeError(
        "No access token found. Run 'psamvault login' or set PSAMVAULT_TOKEN env var."
    )
```

### Path B — Environment Variables (Docker / CI)

```bash
# Export from logged-in session
psamvault vek export         # prints PSAMVAULT_VEK=hex...
psamvault token export       # prints PSAMVAULT_TOKEN=jwt...

# Or from existing session info:
export PSAMVAULT_VEK=<hex>
export PSAMVAULT_TOKEN=<jwt>
```

**Docker Compose example:**
```yaml
services:
  app:
    build: .
    env_file:
      - .env  # psamvault: placeholders
    environment:
      PSAMVAULT_VEK: ${PSAMVAULT_VEK}  # from host env or .env file
      PSAMVAULT_TOKEN: ${PSAMVAULT_TOKEN}
```

---

## 4. SDK Surface

### Basic Usage

```python
# Instead of:
from dotenv import load_dotenv
load_dotenv()

# Do:
from pv_dotenv import load_dotenv
load_dotenv()  # Same signature — drop-in replacement
```

### Advanced Usage

```python
# Custom .env path
load_dotenv("/path/to/.env")

# Project-scoped lookup (for project/.env/KEY pattern)
load_dotenv(project_name="twitter-bot")

# Override resolution: prefer env var if already set
load_dotenv(override=False)  # default: don't override existing env vars

# Get resolved values without modifying os.environ
values = resolve_dotenv("/path/to/.env")
# returns {"DATABASE_URL": "postgresql://...", "JWT_SECRET": "..."}
```

### Return Value

```python
result = load_dotenv()
# {
#   "resolved": ["DATABASE_URL", "JWT_SECRET"],  # keys that had psamvault: values
#   "passthrough": ["NODE_ENV"],                  # keys with raw values
#   "errors": [],                                 # keys that failed to resolve
# }
```

### What happens inside `load_dotenv()`

1. Read `.env` file (or specified path)
2. Parse all key-value pairs
3. For each value starting with `psamvault:`:
   a. Extract the vault entry name after `psamvault:` — e.g. `psamvault:DATABASE_URL` → looks up `DATABASE_URL`
   b. Call `GET /apikeys/{name}` on the backend (or `GET /apikeys/project/.env/{name}` if `project_name` provided)
   c. If 404, try vault entries `GET /vault/{name}` (fallback for site passwords)
   d. Decrypt the returned `encrypted_blob` using VEK from keychain/env
   e. Set `os.environ[key] = real_value`
4. For non-`psamvault:` values, set `os.environ[key] = value` directly (passthrough)
5. Return the resolution report

---

## 5. How Resolution Works (Detailed)

### Step-by-step for a `.env` line

```
DATABASE_URL=psamvault:DATABASE_URL
```

1. SDK parses the line → key=`DATABASE_URL`, value=`psamvault:DATABASE_URL`
2. Detects `psamvault:` prefix → extracts entry name = `DATABASE_URL`
3. Calls `GET /apikeys/DATABASE_URL` on the backend
   - If found → returns encrypted blob
   - If 404 and `project_name` provided → tries `GET /apikeys/{project}/.env/DATABASE_URL`
   - If still 404 → tries `GET /vault/DATABASE_URL` (vault fallback)
   - If all 404 → **crash with error**: `"DATABASE_URL: not found in vault or API keys"`
4. Decrypts the returned `encrypted_blob` using VEK
5. Extracts the `api_key` (or `password`) field
6. Sets `os.environ["DATABASE_URL"] = "postgresql://user:***@neon.tech/db"`
7. Agent sees only `psamvault:DATABASE_URL` in the `.env` file — never the real value

### Resolution Priority

| Order | Lookup | Example Name |
|---|---|---|
| 1 | Direct API key match | `DATABASE_URL` |
| 2 | Project-scoped API key | `my-project/.env/DATABASE_URL` (only if `project_name` provided) |
| 3 | Vault entry (site password) | `DATABASE_URL` (in vault, not API keys) |

---

## 6. Security Model

| Property | How It's Guaranteed |
|---|---|
| **VEK stays on machine** | Path A: OS keychain → process memory. Path B: env var → process memory. Never serialized to disk. Never sent over network. |
| **Backend never sees plaintext** | Encrypted blobs stored on backend. SDK fetches blob + decrypts locally. Backend cannot read the values. |
| **No agent read** | `.env` only contains `psamvault:` placeholders — no real values at rest |
| **In-memory only** | Decrypted values live in `os.environ` dictionary. No disk writes. |
| **HTTPS only** | SDK communicates with backend over HTTPS. Non-HTTPS URLs are rejected. |
| **Audit trail** | Backend logs which API keys were accessed and when |

### What the SDK Does NOT Do

- ❌ Store plaintext credentials on disk
- ❌ Send the VEK over the network
- ❌ Log or print resolved credential values
- ❌ Expose credentials to subprocesses (they inherit `os.environ` — same as normal `dotenv` behaviour)
- ❌ Cache decrypted values to disk

---

## 7. Open Questions

### ✅ All Questions Resolved

| # | Question | Decision |
|---|---|---|
| Q1 | Package name | **`pv-dotenv`** (`pip install pv-dotenv`) |
| Q2 | What if VEK is wrong / decryption fails? | **Crash with clear error + key name** |
| Q3 | Install location? | **In project's venv** (like any dependency) |
| Q4 | Project name auto-detection? | **Explicit `project_name` parameter required** |
| Q5 | What if user has no session? | **Crash with instructions** — "Run `psamvault login` or set PSAMVAULT_VEK + PSAMVAULT_TOKEN" |
| Q6 | Non-`psamvault:` values? | Passthrough — unchanged |
| Q7 | Disk cache? | No — in-memory only |
| Q8 | Offline support? | No for v1 |
| Q9 | `os.environ` already set? | Don't override by default (`override=False`) |
| Q10 | How to get backend URL? | Read `PSAMVAULT_API_URL` from env, default to `https://psam-vault-backend.onrender.com` |
| Q11 | `export` prefix in `.env`? | Supported — stripped before setting `os.environ` |
| Q12 | Deleted vault entry? | **Crash with error + key name** |
| Q13 | Access token source? | Same two-path: keychain or `PSAMVAULT_TOKEN` env var |

---

| Version | Pros | Cons | Who'll Be Left Out |
|---|---|---|---|
| **3.8** | Widest compatibility (still in Ubuntu 20.04, Debian 11, AWS Lambda) | No `match` statements, no `importlib.metadata` (need backport), no `|` union type syntax | Nobody — still in mainstream use |
| **3.9** | Better than 3.8 (dict merge `|`, `str.removeprefix()`, `zoneinfo`) | Same cons as 3.8 essentially — 3.8 is just as compatible | 3.8 users can still install most packages |
| **3.10** | `match` statements, parenthesized context managers, more ergonomic | Drops Ubuntu 20.04 LTS, Debian 11, some old CI runners | Users on older LTS releases (Ubuntu 20.04 was April 2020) |
| **3.11** | Fastest Python version, better error messages, `tomllib` in stdlib | Drops Python 3.8-3.10 users who can't upgrade | Any team stuck on older Python for dependency reasons |
| **3.12** | Latest stable, best perf, `f-string` improvements | Drops even more users | Similar to 3.11 |
| **3.13** | Cutting edge | Hardly any package ecosystem ready | Most users won't have this yet |

**My analysis and recommendation:**

The SDK only uses basic Python — HTTP calls, JSON parsing, string manipulation, cryptography. It doesn't need `match` statements, `tomllib`, or any 3.10+ feature. The heavy dependency is **`keyring`** (OS keychain access) plus **`cryptography`** (AES decryption) — both support Python 3.8+.

**I recommend 3.10 as the minimum for v1.** Reasons:
- 3.8 and 3.9 are technically supported but the QoL improvements in 3.10+ make development smoother
- Most modern CI runners and Docker images have 3.10 available
- If someone is still on 3.8 in 2026, they have bigger problems than a dotenv library

**Decision: ✅ Python 3.10 minimum.**

---

## 8. How It Fits the Product Line

```
        Provision                     Store                    Use (Runtime)
┌──────────────────┐     ┌──────────────────┐     ┌─────────────────────────┐
│  Developer adds   │     │  psamvault MCP   │     │  pv-dotenv SDK          │
│  secrets to .env  │────►│  scan_and_protect│────►│  load_dotenv()          │
│                   │     │  replaces with   │     │  resolves psamvault:    │
│                   │     │  psamvault:      │     │  sets os.environ        │
└──────────────────┘     └──────────────────┘     └─────────────────────────┘
         │                       │                           │
         │                       ▼                           │
         │               ┌───────────────┐                   │
         │               │  AI Agent      │                   │
         │               │  reads .env    │                   │
         │               │  → sees "psam. │                   │
         │               │  → uses MCP    │                   │
         │               │  tools instead │                   │
         │               └───────────────┘                   │
         │                                                   │
         └───────────────────────────────────────────────────┘
                   Application reads os.environ normally
                   Never knows the SDK is doing anything
```

**Zero code changes to the application.** The only change is the import statement.

---

## 9. Build Order

| Step | Feature | Est. Time | Status |
|---|---|---|---|
| 1 | Create `pv-dotenv` package structure (pyproject.toml, pv_dotenv/, README) | 30 min | ✅ |
| 2 | Implement `_get_vek()` + `_get_access_token()` — Path A (keychain) + Path B (env var) | 1 hour | ✅ |
| 3 | Implement `resolve_value()` — fetch single encrypted blob + decrypt locally | 2 hours | ✅ |
| 4 | Implement `load_dotenv()` — parse `.env`, resolve all placeholders, set os.environ | 2 hours | ✅ |
| 5 | Add `project_name` support + multi-lookup fallback (name → project/name → vault) | 1 hour | ✅ |
| 6 | Add `resolve_dotenv()` — return dict without modifying os.environ | 30 min | ✅ |
| 7 | Handle edge cases: missing VEK, 404, malformed values, `export` prefix, `#` comments | 1 hour | ✅ |
| 8 | Write unit tests (mocked backend + keychain) | 2 hours | ✅ |
| 9 | Live integration test against real backend | 1 hour | ✅ |
| 10 | Update `PLAN.md`, `SKILL_PLAN.md`, and `SDK_PLAN.md` | 30 min | 🔴 |
| 11 | Publish to PyPI as `pv-dotenv` | 30 min | 🔴 |

---

## 10. Change Log

| Date | Change |
|---|---|
| 2026-06-17 | Initial plan created |
| 2026-06-17 | Added Path A + Path B auth model, resolved Q11 (access token) |
|| 2026-06-17 | Resolved Q1-Q4, Q5 (Python 3.10), Q6-Q12. Package named `pv-dotenv`. All questions closed. |
| | 2026-06-17 | All 9 build steps complete. 28/28 unit tests + live integration test passing. |
