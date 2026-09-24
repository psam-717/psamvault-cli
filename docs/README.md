---
title: psamvault documentation
description: Index of the psamvault documentation — introduction, guides and reference.
order: 0
---

# psamvault documentation

psamvault is a secure command-line password vault for the terminal — **with a web dashboard**. Your credentials are **encrypted locally** before being sent to the server — the server never sees your plaintext passwords or your encryption key.

These pages are the full documentation. The [project README](../README.md) is the landing page, and [SECURITY.md](../SECURITY.md) documents the key material and the threat model.

## Introduction

- [Overview](overview.md) — what psamvault is, the problem it solves, how the client-side encryption model works, and what it is not for.
- [Installation](installation.md) — install psamvault on Windows, macOS or Linux, and get from a fresh machine to a working vault.
- [Features](features.md) — the feature map: what each capability is, when you reach for it, and where its full documentation lives.

## Guides

- [Backup and recovery](guides/backup-and-recovery.md) — the runbook for a new machine or a wiped laptop: back up the vault key, verify it, restore access, and know the failure modes.
- [The agent reveal guardrail](guides/agent-reveal-guardrail.md) — who may print a secret, the three policy modes, one-shot agent approvals, and the measured limits of the guardrail.
- [Upgrading](guides/upgrading.md) — the pipx and source upgrade paths, pre-update state snapshots, stashing, rollback hints, and the data-vs-key distinction.
- [Web dashboard](guides/web-dashboard.md) — the dashboard: how to start it, the login flow, and how it interacts with the OS keychain.

## Reference

- [Commands](reference/commands.md) — every command and subcommand with its flags, examples and when to run it.
- [Configuration](reference/configuration.md) — every file, path and environment variable: the `~/.psamvault` layout, the OS keychain, `PSAMVAULT_*` variables, `policy.json` and the audit trail.

## See also

- [README](../README.md) — the project landing page and quick start.
- [SECURITY.md](../SECURITY.md) — key material, the backup threat model, and the known limits of rotation.
- [CONTRIBUTING.md](../CONTRIBUTING.md) — local setup and how to submit changes.
- [LICENSE](../LICENSE) — MIT.
