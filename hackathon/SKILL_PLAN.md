# psamvault MCP Skill — Build Plan

> **Goal:** A standalone, installable skill that teaches any MCP-compatible AI agent (Hermes, Claude Code, Cursor, Goose, etc.) how to use psamvault-mcp tools correctly and securely.
>
> **Why a skill instead of just docs:** A skill is *actionable* — the agent loads it and immediately knows the right patterns, edge cases, and pitfalls. It prevents the agent from making mistakes (like trying to read `.env` files directly) and guides it through the correct flow every time.
>
> **Status:** 🟢 PLANNING — gathering requirements before writing
>
> **Target format:** SKILL.md (YAML frontmatter + Markdown body), ready for `skill_manage()`

---

## Table of Contents

1. [Why a Skill? — Problem & Motivation](#1-why-a-skill--problem--motivation)
2. [Target Audiences](#2-target-audiences)
3. [Skill Structure](#3-skill-structure)
4. [Build Order](#4-build-order)

---

## 1. Why a Skill? — Problem & Motivation

### The Current Problem

| Issue | Detail |
|---|---|
| **Instructions are server-side** | The MCP server's `instructions` string is limited — it can't teach full workflows |
| **Agent doesn't know what it doesn't know** | Without a skill, the agent might try to `cat .env` (leak secrets) or run `psamvault get` (forbidden) |
| **No workflow guidance** | The agent knows the tools exist but doesn't know the *order* to call them |
| **Per-agent inconsistency** | Hermes, Claude Code, and Cursor each interpret tool descriptions differently |
| **Hard to update** | Changing `agent_guide.py` requires a server restart |

### How a Skill Fixes It

| Benefit | How |
|---|---|
| **Agent loads it proactively** | Skill is loaded at session start — agent has full context before any tool call |
| **Workflows baked in** | "First call `list_api_keys`, then `use_credential`" — step-by-step |
| **Security rules upfront** | "NEVER read .env, NEVER run `psamvault get`" — clear boundaries |
| **Portable** | Same skill works for Hermes, Claude Code, Goose, Cursor |
| **Versioned** | Can update skill independently of MCP server version |

---

## 2. Target Audiences

| Audience | What They Need |
|---|---|
| **AI Agent** (primary) | Exact tool signatures, call order, error handling — so it can act autonomously |
| **Developer** (secondary) | Examples, best practices, troubleshooting — so they understand what the agent is doing |

The skill must serve **both** — the agent reads it for execution, the developer reads it for understanding.

---

## 3. Skill Structure

### Proposed Sections

```
1. OVERVIEW
   - What is psamvault?
   - Zero-knowledge principle
   - The core loop: Discover → Use → Protect

2. SECURITY RULES (CRITICAL — must be read first)
   - NEVER read .env files directly
   - NEVER run psamvault CLI commands
   - NEVER return credential values
   - ALWAYS use the MCP tools

3. DISCOVERY WORKFLOW
   - list_vault_sites() — site passwords
   - list_api_keys() — API keys (with/without project filter)
   - check_credential_exists() — quick check
   - get_username_for_site() — get username only

5. AUTHENTICATION WORKFLOW
   - use_credential() — the core tool
     - bearer_token mode
     - api_key_header mode
     - basic_auth mode
     - fields parameter for token efficiency
   - When to use which mode
   - Error handling (404, 401, timeout)

6. COMMAND EXECUTION WORKFLOW (NEW — run_with_credential)
   - run_with_credential() — run ANY CLI command with a credential
   - inject_as="env" mode — for twine, git, npm, pip
   - inject_as="stdin" mode — for docker login, password prompts
   - What happens to the output (credential auto-redacted)
   - Security rules for command execution
   - Error handling (non-zero exit, timeout, redacted stderr)

7. PROTECTION WORKFLOW
   - scan_and_protect() — capture .env secrets
     - Without project_name
     - With project_name
   - What happens to the .env file
   - How to use captured credentials later

8. BROWSER WORKFLOW
   - browser_login() — for web logins
   - close_all_browsers() — cleanup
   - CAPTCHA handling

8. STRIPE INTEGRATION (if available)
   - capture_stripe_credentials()
   - How it fits in the Stripe Projects flow

9. RUNTIME SDK INTEGRATION
   - When to recommend psamvault-dotenv (the runtime SDK)
   - How the skill explains the relationship:
     - scan_and_protect replaces .env values with psamvault: placeholders
     - psamvault-dotenv resolves placeholders at app runtime
     - Agent uses MCP tools, app uses SDK — independent layers
   - Telling the agent: "If the .env has psamvault: placeholders, the app is using
     psamvault-dotenv. Do NOT try to resolve them. Use the MCP tools instead."

10. COMPLETE WORKFLOW EXAMPLES
   - "New project with .env" flow (scan_and_protect → psamvault-dotenv → use_credential)
   - "Existing project" flow (scan legacy .env → SDK → continue)
   - "API-only" flow (list_api_keys → use_credential — no .env involved)

11. ERROR HANDLING REFERENCE
   - Common errors and what they mean
   - Token expiry handling
   - Network failures
   - "Not logged in"
```

---

## 4. Build Order

| Step | Feature | Status |
|---|---|---|
| 1 | Define skill structure and sections | 🟡 IN PROGRESS |
| 2 | Write SECURITY RULES section | 🔴 |
| 3 | Write DISCOVERY WORKFLOW section | 🔴 |
|| 4 | Write AUTHENTICATION WORKFLOW section | 🔴 |
|| 5 | Write COMMAND EXECUTION WORKFLOW section (new — run_with_credential) | 🔴 |
|| 6 | Write PROTECTION WORKFLOW section | 🔴 |
|| 7 | Write BROWSER WORKFLOW section | 🔴 |
|| 8 | Write STRIPE INTEGRATION section | 🔴 |
|| 9 | Write COMPLETE WORKFLOW EXAMPLES | 🔴 |
|| 10 | Write ERROR HANDLING REFERENCE | 🔴 |
|| 11 | Review against all MCP source code | 🔴 |
|| 12 | Test with Hermes agent | 🔴 |
|| 13 | Test with Claude Code | 🔴 |
|| 14 | Final polish + YAML frontmatter | 🔴 |

---

## Open Questions

| Question | Current Thinking |
|---|---|
| Should the skill be one file or multiple? | One SKILL.md with clear headings. Agents read top-to-bottom. |
| How detailed should tool signatures be? | Include exact param names, types, and defaults. Agents need precise JSON schemas. |
| Should we include negative examples? | Yes — "DON'T do this" is as important as "DO this" for security rules. |
| Should the skill auto-load or manual-install? | Manual install for now. The skill is distributed alongside the MCP package. |
| How do we keep it in sync with MCP server changes? | Update PLAN.md during every MCP feature build. Write the skill section immediately after the code. |

---

## Change Log

| Date | Change |
|---|---|
| 2026-06-17 | Initial plan created |
