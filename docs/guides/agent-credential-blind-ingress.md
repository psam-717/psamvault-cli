---
title: Credential-blind ingress
description: Let an agent create a vault entry without ever holding the secret — pending claim codes and hidden-input fills in your own terminal.
order: 55
---

# Credential-blind ingress

[The reveal guardrail](agent-reveal-guardrail.md) answers *who may print a secret*. This is the other
direction: an agent has to **create** an entry — a token for the project it is working on, a credential
for a site — and must never hold the value itself.

So the agent does not ask for the secret. It creates a **claim**, prints a code, and you fill that code
in your own terminal. The value goes from your keyboard into the encrypted entry; it never passes
through the agent's process, its output, or its command line.

```
  agent shell                        your terminal
  ───────────                        ─────────────
  psamvault ak-add github-prod --service GitHub
    │
    ├─ no value, agent detected
    │
    └─ Claim code: PV-4F2K-91QX ──────────────► psamvault ak-add --claim PV-4F2K-91QX
       expires in 15 minutes                       │  API key for github-prod: ********
       Run this in your own terminal:              │  ✓ stored github-prod (GitHub)
           psamvault ak-add --claim PV-4F2K-91QX   │
                                                   └─ the claim file is DELETED (single use)
```

| Situation | What happens |
|---|---|
| You run `psamvault ak-add xai-prod --service XAI` in your own terminal | Prompts for the key (hidden input). Nothing changes. |
| Hermes, Claude Code, Codex, Goose or OpenCode runs the same command | No prompt. It prints a claim code `PV-XXXX-XXXX`, valid for 15 minutes. |
| You run the printed `psamvault ak-add --claim PV-XXXX-XXXX` | Prompts for the value and stores the entry. The code is spent. |
| An agent runs that fill command | Refused — a fill needs your terminal. The claim stays valid. |
| An agent runs `psamvault ak-add x --service X --key sk-...` | Refused: a value in argv is visible to process listings, shell history and any wrapper that logs a command line. The refusal names the claim flow instead. |

The same flow covers all three kinds of entry — `add` (site credentials), `ak-add` (API keys) and
`note-add` (secure notes). Nothing new is stored on the server for a claim: an entry exists only after
*you* fill it.

## The claim lifecycle

1. **An agent asks for an entry without a value.** The CLI notices it is talking to a program, writes a
   pending claim to `~/.psamvault/pending/<code>.json`, and prints the code and the exact command for you.
2. **You fill it in your own terminal.** `psamvault ak-add --claim PV-4F2K-91QX` shows the entry's name
   and service, prompts for the value with hidden input, encrypts it with your vault key and stores it.
   Only then is the code spent — and spending it **deletes** the file, so a code cannot be replayed and
   no filled-claim record is left behind.
3. **Either side can check.** `psamvault pending` lists what is still waiting with the time left; an
   agent that asked for an entry checks the same command on its next turn.

A claim holds **metadata only** — the name, the service or category, the notes, never a value. If the
store fails — the name already exists, you are logged out, the network drops — the claim survives, so a
typo does not cost you the code.

## Which command, when

| You want to | Run |
|---|---|
| Store an entry yourself, value in hand | `psamvault ak-add ... --key` / `psamvault add ... --pass` / `psamvault note-add ... --content` |
| Store an entry yourself without the value on the command line | same command, omit the value — it prompts with hidden input |
| Create the entry an agent asked for, without the agent seeing it | the agent runs the command with no value; you run the `--claim` command it prints |
| See what is waiting | `psamvault pending` |
| Stop a claim you no longer want | `psamvault pending --cancel PV-4F2K-91QX` |
| Give an agent a secret it needs *printed* | not this page — that is [`psamvault approve`](agent-reveal-guardrail.md#hand-an-agent-one-secret-once) |

> #### `pending` vs `approve` — two opposite handoffs
>
> | | `psamvault pending` (this page) | `psamvault approve` (the guardrail) |
> |---|---|---|
> | Direction | a secret the **agent** needs stored, you supply | a secret the **agent** needs printed, you permit |
> | Value crosses the agent | never | yes, once |
> | Who can run it | anyone — it shows metadata only | you, at a real terminal |
> | Lifetime | 15-minute claim, single-use, deleted on fill | one reveal, window 15–3600s |

## Limits — stated, not implied

- **Claims are local to the machine that created them.** A claim lives in `~/.psamvault/pending/` on
  the machine that ran the command, so an agent on a server cannot hand one to you on your laptop.
  Cross-machine handoff is not covered.
- **A code is not a secret, but it is not harmless.** Anyone who reads it can fill that entry — with
  *their* value, into a name you can see. If you did not ask for a claim, `psamvault pending` shows it
  and `--cancel` ends it. Filling a claim you did not ask for is the case this design cannot prevent,
  which is why the code names the entry explicitly.
- **The claim file is as readable as anything else owned by your user**, so an agent that goes looking
  will find it. It holds names and timestamps, and by construction no value.
- **It does not stop an agent that can read a file.** The guarantee is about the value never entering
  the agent's transcript, its arguments or a shell history — not that a process with `cat` cannot read
  a file you left it.
- **It needs you to be present.** An agent cannot fill its own claim, and no approval token changes
  that. Nothing about this replaces the guardrail either — it keeps a secret out of an *agent's* hands,
  not out of a chat.

## What this does not cover yet

Two neighbouring pieces are planned and deliberately not in this release:

- **Blocking waits.** An agent cannot currently ask the CLI to wait for you to fill a claim; it checks
  `psamvault pending` on its next turn. `--wait` / `--timeout` are deferred.
- **Migrating a secret that is already on the machine** without printing it — a key inside a `.env`,
  a whole service-account JSON. The `--from-file` / `--from-key` / `--from-env` path is deferred too.

Both are recorded in [`plans/active/PLAN_agent_safe_vault.md`](../../plans/active/PLAN_agent_safe_vault.md)
with their decisions, so reopening them starts from them rather than from scratch.

## See also

- [The agent reveal guardrail](agent-reveal-guardrail.md) — who may print a secret, and the one-shot approval.
- [Commands](../reference/commands.md#psamvault-pending) — `pending` and the claim flag on `add`, `ak-add` and `note-add`.
- [Configuration](../reference/configuration.md#pending-claims) — the pending claim file, its permissions and its lifetime.
