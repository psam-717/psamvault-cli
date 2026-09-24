---
title: Credential-blind ingress
description: Let an agent create a vault entry without ever holding the secret — pending claim codes, hidden-input fills, and migrating a value that is already on the machine.
order: 55
---

# Credential-blind ingress

[The reveal guardrail](agent-reveal-guardrail.md) answers *who may print a secret*. This is the other direction: an agent has to **create** an entry — a token for the project it is working on, a credential for a site — and must never hold the value itself.

So the agent does not ask for the secret. It creates a **claim**, prints a code, and you fill that code in your own terminal. The value goes from your keyboard into the encrypted entry; it never passes through the agent's process, its output, or its command line.

| Situation | What happens |
|---|---|
| You run `psamvault ak-add xai-prod --service XAI` in your own terminal | Prompts for the key (hidden input). Nothing changes. |
| Hermes, Claude Code, Codex, Goose or OpenCode runs the same command | No prompt. It prints a claim code `PV-XXXX-XXXX`, valid for 15 minutes. |
| You run the printed `psamvault ak-add --claim PV-XXXX-XXXX` | Prompts for the value and stores the entry. The code is spent. |
| An agent runs that fill command | Refused — a fill needs your terminal. The claim stays valid. |
| An agent runs `psamvault ak-add x --service X --key sk-...` | Refused: a value in argv is visible to process listings, shell history and any wrapper that logs a command line. |
| The secret is already in a file on this machine | `--from-file` reads it without printing it; `--from-key` takes one `NAME=` line out of a `.env`; `--delete-source` removes that line afterwards and keeps a backup. |
| The agent needs to know whether you have filled it | `psamvault pending` (or add `--wait` to the command that asked). |

The same flow covers all three kinds of entry — `add` (site credentials), `ak-add` (API keys) and `note-add` (secure notes). Nothing new is stored on the server for a claim: an entry exists only after *you* fill it.

## The claim lifecycle

1. **An agent asks for an entry without a value.** The CLI notices it is talking to a program, writes a pending claim to `~/.psamvault/pending/<code>.json`, and prints the code and the exact command for you.
2. **You fill it in your own terminal.** `psamvault ak-add --claim PV-4F2K-91QX` shows the entry's name and service, prompts for the value with hidden input, encrypts it with your vault key and stores it. Only then is the code marked used.
3. **Either side can check.** `psamvault pending` lists outstanding claims with their remaining time, and shows `filled 3m ago` once you have filled one. `--wait` blocks in the agent's shell until it happens.

A claim holds **metadata only** — the name, the service or category, the notes, never a value. A code is single-use, expires after 15 minutes, and is refused after a failed store is retried (a failed store leaves the claim fillable, so a typo does not cost you the code).

## Which command, when

| You want to | Run |
|---|---|
| Store an entry yourself, value in hand | `psamvault ak-add ... --key` / `psamvault add ... --pass` / `psamvault note-add ... --content` |
| Store an entry yourself without the value on the command line | same command, omit the value — it prompts with hidden input |
| Create the entry an agent asked for, without the agent seeing it | the agent runs the command with no value; you run the `--claim` command it prints |
| Scaffold the entry up front and fill it later | `--wait` on the agent's side, or fill it whenever `psamvault pending` reminds you |
| See what is waiting, or whether it was filled | `psamvault pending` |
| Show one claim in full | `psamvault pending --code PV-4F2K-91QX` |
| Stop a claim you no longer want | `psamvault pending --cancel PV-4F2K-91QX` |
| Move a secret that is already on this machine into the vault | `--from-file` / `--from-key` / `--from-env` |
| Give an agent a secret it needs *printed* | not this page — that is [`psamvault approve`](agent-reveal-guardrail.md#hand-an-agent-one-secret-once) |

> #### `pending` vs `approve` — two opposite handoffs
>
> | | `psamvault pending` (this page) | `psamvault approve` (the guardrail) |
> |---|---|---|
> | Direction | a secret the **agent** needs stored, you supply | a secret the **agent** needs printed, you permit |
> | Value crosses the agent | never | yes, once |
> | Who can run it | anyone — it shows metadata only | you, at a real terminal |
> | Lifetime | 15-minute claim, single-use | one reveal, window 15–3600s |

## `--wait`: for an agent that wants to continue

```bash
psamvault ak-add gh-token --service GitHub --wait --timeout 15m
```

The command prints the claim as usual, then waits until you fill it. On success it says so and exits `0`. On timeout it exits `3` — not a failure: the claim is **still valid**, and you can fill it later. Exit `3` is there so an agent can tell "the human has not answered yet" apart from "something is broken", since many agent hosts cap how long a single tool call may run.

`--timeout` takes `30s`, `15m` or `1h`; without it, `--wait` waits for the claim's own 15-minute lifetime.

## Migrating a value that is already on the machine

When the secret already exists as a file — a `.env`, a `service-account.json`, a `.pem` — the agent does not need to read it out. It hands the whole problem to the CLI, which reads the value and encrypts it without ever printing it.

```bash
# one NAME= line out of a .env, then delete that line and keep a .env.bak
psamvault ak-add stripe-test --service Stripe --from-file ./.env --from-key STRIPE_TEST_KEY --delete-source

# the whole file is the secret (service-account JSON, PEM, private key)
psamvault ak-add sa-prod --service Google --from-file ./service-account.json

# the value is in the environment already
psamvault ak-add gh-token --service GitHub --from-env GITHUB_TOKEN
```

| Flag | What it does |
|---|---|
| `--from-file <path>` | Read the value out of that file. Without `--from-key`, the whole file is the secret |
| `--from-key <NAME>` | Take one `NAME=value` line out of the `--from-file` file (quotes and a leading `export` are handled) |
| `--from-env <VAR>` | Read the value out of an environment variable |
| `--delete-source` | Remove the one line that was read. Valid only with `--from-file --from-key`; the original is kept at `<file>.bak` |

`--from-file` is the one path an **agent** may run, because the value never touches its argv, its output or your shell history — and the agent already had whatever read access the file needed. A whole-file source is never deleted: that file *is* the secret.

## What this does not do

- **It does not stop an agent that can read the file.** The guarantee is that the value never enters the agent's transcript, its arguments or a shell history — not that a process with `cat` cannot read a file you left it. If the file must stay unreadable to the agent, fill a claim by hand instead.
- **It does not hide the entry's name.** An agent that asks for `gh-token --service GitHub` gets the claim, so it knows the name, the service and the notes it supplied. Metadata is not secret.
- **A code is not a secret, but it is a capability** for its lifetime: whoever fills it decides the value. Codes are stored owner-only (`0600`), single-use, and local to the machine that created them.
- **It needs you to be present.** An agent cannot fill its own claim, and no approval token changes that.

## See also

- [The agent reveal guardrail](agent-reveal-guardrail.md) — who may print a secret, and the one-shot approval.
- [Commands](../reference/commands.md#psamvault-pending) — `pending` and the claim flags on `add`, `ak-add` and `note-add`.
- [Configuration](../reference/configuration.md#pending-claims) — the pending claim file, its permissions and its lifetime.
