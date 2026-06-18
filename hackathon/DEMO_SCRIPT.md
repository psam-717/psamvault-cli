# Demo Video Script

> **Target:** 2 minutes (judge attention span)
> **Style:** Screencast with voiceover OR text overlays
> **Tool:** OBS Studio (free) — terminal + browser side-by-side
> **Deadline:** June 30, 2026
> **Status:** 🔴 DRAFT

---

## Scene 1: The Hook (0:00–0:20)

### Visual
Split screen: Terminal (left) + simple title card (right)

### Audio / Text
> *"AI agents can now provision databases, APIs, and hosting from the command line. But there's a problem — where do those credentials go?"*

### Screen action
- Show a project directory with a `.env` file
- `cat .env` showing plaintext secrets:
  ```env
  OPENAI_API_KEY=sk-...
  GITHUB_TOKEN=ghp_...
  DB_PASSWORD=hunter2
  ```
- Highlight: every time the AI agent reads this file, the secrets enter its context

### Overlay text
> ⚠️ **Plaintext credentials = leak into agent context**

---

## Scene 2: The Problem (0:20–0:35)

### Visual
Same split. Right side shows a mock agent "thinking" bubble.

### Audio / Text
> *"Every time the agent reads that .env file, the secrets enter its context window. Prompt injection? Logged errors? Shared transcripts? The credentials leak."*

### Screen action
- Show: Agent reads .env → credentials appear in context
- Highlight the credential values in red
- Fade to: `"What if the agent never saw them at all?"`

### Overlay text
> 🚫 **Credentials in context = leak waiting to happen**

---

## Scene 3: Scan & Protect (0:35–0:55)

### Visual
Terminal fills the screen.

### Audio / Text
> *"psamvault finds those exposed secrets, encrypts them, and replaces them with safe placeholders — in one call."*

### Screen action
- Type: `scan_and_protect(project_name="my-app")`
- Show result:
  ```
  files_scanned: [".env"]
  secrets_found: 3
  captured: [
    { key: "OPENAI_API_KEY", stored_as: "my-app/.env/OPENAI_API_KEY" },
    { key: "GITHUB_TOKEN", stored_as: "my-app/.env/GITHUB_TOKEN" },
    { key: "DB_PASSWORD", stored_as: "my-app/.env/DB_PASSWORD" }
  ]
  ```
- Then `cat .env` again:
  ```env
  OPENAI_API_KEY=psamvault:OPENAI_API_KEY
  GITHUB_TOKEN=psamvault:GITHUB_TOKEN
  DB_PASSWORD=psamvault:DB_PASSWORD
  ```
- **New:** Highlight that these are now safe placeholders — but the app still needs real values to run

### Overlay text
> ✅ **Secrets encrypted. Plaintext replaced with placeholders.**

---

## Scene 4: The Runtime Problem (0:55–1:05)

### Visual
Split screen: Terminal (left) shows the app crashing.

### Audio / Text
> *"But wait — the application needs those real values to run. If we just leave placeholders, the app crashes."*

### Screen action
- Show `python app.py` failing with a connection error or import error
- Show the `.env` with `psamvault:` values
- Caption: "Placeholders = broken app"

### Overlay text
> ⚠️ **App can't read psamvault: values. It crashes.**

---

## Scene 5: The Fix — psamvault-dotenv (1:05–1:20)

### Visual
Side-by-side code comparison.

### Audio / Text
> *"The psamvault-dotenv SDK solves this. One import change — the app resolves placeholders at runtime without the agent ever seeing the real values."*

### Screen action
- Before:
  ```python
  from dotenv import load_dotenv
  load_dotenv()
  ```
- After:
  ```python
  from psamvault_dotenv import load_dotenv
  load_dotenv()
  ```
- Show `python app.py` running successfully now
- Show output confirming the database connects

### Overlay text
> 🔄 **Drop-in replacement. Same API. Same behaviour.**

---

## Scene 6: Discover + Use (1:20-1:40)

### Visual
Terminal showing MCP tool calls.

### Audio / Text
> *"Meanwhile, the AI agent calls list_api_keys and use_credential — it never sees the real values. And with run_with_credential, the agent can even publish packages, push code, or deploy containers — all without seeing the secret key."*

### Screen action
- Quick cuts showing:
  ```
  list_api_keys()
  -> 3 project keys for my-app

  use_credential("github-api", "https://api.github.com/user")
  -> { login: "psam-717", repos: 47 }
  ```
- **New:** Show run_with_credential:
  ```
  run_with_credential(
    site_name="pypi",
    command="twine upload dist/*",
    inject_as="env",
    env_var_name="TWINE_PASSWORD"
  )
  -> Published! (credential never seen)
  ```
- Side-by-side: App running + Agent using MCP

### Overlay text
> App runs with real values. Agent never sees them.

---

## Scene 7: The Pitch (1:40-2:00)

### Visual
Single clean frame — product name, tagline, CTA buttons.

### Audio / Text
> *"psamvault is the credential manager for autonomous businesses. The CLI stores secrets. The MCP tools let agents use them safely. The SDK lets applications read them at runtime. One ecosystem, three layers, zero leakage."*

### On-screen
```
╔══════════════════════════════════════════╗
║                                          ║
║              psamvault                   ║
║    Credential manager for agents         ║
║                                          ║
║    Three layers, one goal:               ║
║    🔒 psamvault-mcp  — MCP tools / command exec   ║
║    🔒 psamvault-dotenv — Runtime SDK     ║
║    🔒 psamvault CLI  — Management        ║
║                                          ║
║    pip install psamvault-dotenv          ║
║    pipx install psamvault-mcp            ║
║    github.com/psam-717/psamvault         ║
║                                          ║
║    Built with Hermes Agent               ║
║    Zero-knowledge encryption             ║
║                                          ║
╚══════════════════════════════════════════╝
```

### Overlay text
> 🏁 **psamvault — because agents shouldn't see your secrets, but your app still needs them.**

---

## Technical Setup

### Recording
| Item | Detail |
|---|---|
| **Tool** | OBS Studio (free, [obsproject.com](https://obsproject.com)) |
| **Resolution** | 1920×1080, 30fps |
| **Layout** | Terminal on left (70% width), browser/overlay on right (30%) |
| **Audio** | Screen-only with text overlays if no mic — judges read the slides |
| **Duration** | 1:45–2:00 (strictly under 2 minutes) |

### Pre-written commands for the demo script
```python
# SCENE 3: Scan existing project for exposed secrets
scan_and_protect(project_name="my-app")

# SCENE 5: App resolves placeholders at runtime
# (In app.py)
from psamvault_dotenv import load_dotenv
load_dotenv(project_name="my-app")

# SCENE 6: List project keys
list_api_keys(project_name="my-app")

# SCENE 6: Use credential via MCP
use_credential("github-api", "https://api.github.com/user",
               fields=["login", "public_repos", "followers"])
```

### Pre-recording checklist
- [ ] Hermes running with psamvault MCP enabled
- [ ] Logged in: `psamvault login`
- [ ] `psamvault-dotenv` installed: `pip install psamvault-dotenv`
- [ ] Test project dir with fake .env files ready (for scan_and_protect scene)
- [ ] Sample `app.py` that calls load_dotenv() and prints a success message
- [ ] OBS configured with terminal capture source
- [ ] Record a practice run first

---

## Judging Rubric Mapping

| Criteria | How the demo hits it |
|---|---|
| **Usefulness** | Shows the exact problem every agent operator faces (credential leakage) and solves it — both for the agent AND the application |
| **Viability** | All tools are working code — **4 APIs live-tested** (GitHub, Hugging Face, OpenRouter, DeepSeek). SDK planned as `psamvault-dotenv` |
| **Presentation** | Clear before/after: plaintext → psamvault placeholders → app resolves at runtime via SDK |
| **Stripe synergy** | Stripe Projects integration built and documented (not demoed due to regional availability) |
| **NVIDIA synergy** | NemoClaw compatibility documented (MCP bridge pattern + network policy preset) |
| **Innovation** | No other credential manager treats AI agents as first-class users — zero-knowledge, agent-native, with a runtime SDK for application compatibility |

## After Recording

1. Upload to YouTube as unlisted
2. Include link in the hackathon submission form
3. Tweet tagging @NousResearch, @NVIDIAAI, @Stripe
4. Post in the Hermes Accelerated Business Hackathon Discord channel
