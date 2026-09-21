# Secure Notes — Feature Plan

**Status:** 🟡 IN PLAN — design decisions resolved, ready to build

**Proposed by:** Psam
**Date:** 2026-07-01

---

## Summary

Add a new "Secure Notes" entry type to psamvault that lets users store arbitrary encrypted text — SSH keys, Wi-Fi passwords, recovery codes, software licenses, API docs, etc. — alongside existing site credentials and API keys.

---

## Decisions Made

| # | Decision | Choice | Rationale |
|---|---|---|---|
| 1 | Server endpoint | **New `/notes/` endpoint** | Clean separation, mirrors `/apikeys/` pattern |
| 2 | CLI commands | **Top-level short commands** — `psamvault note-add`, `note-list`, `note-get`, `note-delete`, `note-update` | Consistent with existing `ak-add` / `ak-list` pattern |
| 3 | Note fields | **Title + Content + (optional) Category** | Rich metadata, searchable by category |
| 4 | Encryption | **Title decrypted (stored as server field), content encrypted in blob** | Fast listing/search without decrypting every entry |

---

## Build Order

| Step | What | Depends On | Status |
|---|---|---|---|
| 1 | Server — Add notes model + CRUD endpoints (`/notes/`) | Nothing | ✅ |
| 2 | Client — Add `encrypt_note` / `decrypt_note` helpers in `crypto.py` | Nothing | 🔴 |
| 3 | Client — Add `note_commands.py` with note-add, note-get, note-list, note-delete, note-update | Step 1, 2 | 🔴 |
| 4 | Client — Add API client functions in `api_client.py` | Step 1 | 🔴 |
| 5 | Wire commands into `main.py` | Step 3 | 🔴 |
| 6 | Update `list` command to include notes in combined view | Step 3, 4 | 🔴 |
| 7 | Update `search` to include notes | Step 2 | 🔴 |
| 8 | Update export/import to handle notes | Step 2 | 🔴 |
| 9 | Tests | All above | 🔴 |

---

## Files Likely to Change

### Server (psam-vault-backend)
- `models.py` — Add Note model (title, category, encrypted_blob, iv, user_id FK)
- `schemas.py` — Add NoteCreate, NoteResponse, NoteList schemas
- `routes/` — Add new notes router
- `main.py` — Register notes router

### Client (psamvault-cli)
- `crypto.py` — Add `encrypt_note(content)`, `decrypt_note(blob, iv)`
- `api_client.py` — Add `add_note_entry`, `get_note_entry`, `list_note_entries`, `update_note_entry`, `delete_note_entry`
- `command/note_commands.py` — New file: note-add, note-get, note-list, note-delete, note-update
- `main.py` — Wire in note commands + short aliases
- `command/vault_commands.py` — Update `list_entries()` to show notes; update `_search_credentials()` to include notes
- `command/export_command.py` — Include notes in export
- `command/import_command.py` — Include notes in import

---

## Acceptance Criteria

- [ ] `psamvault note-add my-ssh-key --content "..." --category ssh` stores and encrypts
- [ ] `psamvault note-list` shows all notes (title + category, no content)
- [ ] `psamvault note-get my-ssh-key` decrypts and shows content
- [ ] `psamvault note-delete my-ssh-key` removes it
- [ ] `psamvault note-update my-ssh-key --content "..."` updates content
- [ ] `psamvault list` includes notes alongside sites and API keys
- [ ] `psamvault search` finds notes by title, category, and content
- [ ] Export/import includes notes
- [ ] All commands handle auth expiry same as existing commands
- [ ] Forbidden chars validated on note titles (same as site names / API key names)

---

## Risks & Mitigations

- **Backend changes require deploying to Render** — coordinate with existing hackathon work, make note endpoints match the same patterns
- **Note content can be large** (SSH keys, config blocks) — ensure encrypted blob field has sufficient size on the backend; add a reasonable content limit (e.g. 10KB)
- **Listing notes without decrypting** means the server stores title in plaintext — acceptable since titles aren't secrets (mirrors how `site_name` and `name` are already stored plaintext for sites and API keys)
