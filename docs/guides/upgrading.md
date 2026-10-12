---
title: Upgrading
description: The registry (pipx / uv tool) and source upgrade paths, pre-update state snapshots, stashing, rollback hints, and the data-vs-key distinction.
order: 60
---

# Upgrading

## Check for and install the latest version

Check for and install the latest version from PyPI.

```bash
psamvault upgrade
```

Upgrades in place through the tool that owns the install — pipx, or `uv tool`. If the owning tool is not on your PATH, instructions are printed instead.

`psamvault upgrade` detects your install type automatically: the registry track (pipx or `uv tool`), or the source track.

## The registry track (pipx or `uv tool`)

This is the path for a `pipx install psamvault` or a `uv tool install psamvault` install.
`psamvault upgrade` asks pipx first, then `uv tool`, which of them owns the install.

1. It reads the installed version and asks PyPI for the latest one. If PyPI cannot be reached, it says so and stops.
2. If the installed version is already current, it says `psamvault is already up to date (v…).` and stops.
3. Otherwise it names the move (`Update available: v<installed> → v<latest>`), asks `Proceed with upgrade?`, and upgrades **in place** through the tool that owns the install:

   | Owner | Command it runs |
   |---|---|
   | pipx | `pipx upgrade psamvault` |
   | `uv tool` | `uv tool upgrade psamvault` |

4. It reads the version back from that same tool and only reports success when the install really moved. If it did not — the recorded source is not the PyPI registry (a URL or a TestPyPI index, say) — it names what it found and offers the reinstall below.
5. If neither pipx nor `uv tool` owns the install, it says so and stops, naming `pip install --upgrade psamvault` for an install made by plain pip. It never installs a second copy with a different tool: two installs of the same command shadow each other on `PATH`.
6. If the owning tool is missing from your PATH, the manual equivalent is printed instead of failing silently:

   ```bash
   pip install --upgrade pipx
   pipx install --force psamvault==<latest>
   ```

### Why in place — and why the rebuild is not run from here

`pipx install --force psamvault==<latest>` and `uv tool install --force psamvault==<latest>`
both **rebuild the environment**, and `psamvault upgrade` is itself running from that
environment. On Windows a running executable's image is locked, so the rebuild cannot
replace the interpreter it is trying to replace:

- **pipx** dies copying it, and leaves the previous install in place:

  ```
  error: Failed to create virtual environment
    cause: failed to copy file from ...\venvlauncher.exe to ...\venvs\psamvault\Scripts\python.exe:
           The process cannot access the file because it is being used by another process. (os error 32)
  ```

- **uv** removes the environment directory first and then fails, which leaves `psamvault` unimportable until it is reinstalled:

  ```
  error: failed to remove directory `...\tools\psamvault\Scripts`: Access is denied. (os error 5)
  ```

`pipx upgrade` and `uv tool upgrade` install into the **existing** environment instead, so
nothing has to replace the running interpreter and both work from inside it.

The rebuilding reinstall is still reached in two situations:

| Situation | What happens |
|---|---|
| Something **outside** that environment runs the upgrade (a source checkout upgrading a pipx install) | The reinstall runs automatically — the rebuild is safe there |
| The upgrade is running **from** that environment and the in-place route failed, or the version did not move | It explains what happened and prints the tool's own command to run **after this process exits** |

```bash
pipx install --force psamvault==<latest>      # for a pipx install
uv tool install --force psamvault==<latest>   # for a uv tool install
```

**Editable/source-linked installs are refused on this track.** If pipx reports psamvault as an editable install, `pipx upgrade` would break that link or fail, so the command stops and tells you:

```
  This psamvault install is editable/source-linked — pipx upgrade
  would break that link or fail.
  If you installed from a local checkout, run  psamvault upgrade  inside
  that checkout (source track), or reinstall from PyPI first:
    pipx reinstall psamvault
```

## The source track (git checkout)

This is the path for a source install — a clone you installed with `pipx install -e .` or `pip install -e .`. It is deliberately conservative, because a checkout can hold work that is not on the remote.

1. **Fetch.** It runs `git fetch origin`. If the remote cannot be reached, it stops.
2. **Refuse to lose your commits.** If you have local commits not on `origin/main`, it says so and stops, suggesting `git pull --rebase origin main`. Upgrade keeps them but cannot fast-forward past them.
3. **Already current?** With nothing to pull, it reports `psamvault is already up to date` and stops.
4. **Confirm.** Otherwise it names how many commits behind you are and asks `Proceed with upgrade?`.
5. **Snapshot.** Before touching anything, it copies your psamvault state into `~/.psamvault/backups/backup-<UTC stamp>/`. At most the **5** most recent snapshots are kept; older ones are pruned.
6. **Stash, pull, restore.** Local changes (including untracked files) are stashed under a `psamvault-upgrade-autostash-<stamp>` label, `git pull --ff-only origin main` runs, and the stash is popped on success.
7. **Reinstall and smoke-test.** It runs `pip install -e .` in the checkout, then imports the updated code to prove it loads.
8. **Report.** On success: `psamvault upgraded successfully.` followed by `Done. Run psamvault changelog to see what's new.`

### What the snapshot contains — and what it is not

The snapshot exists so an upgrade cannot lose your *state*, not so it can replace a backup:

| Snapshotted | Not snapshotted (and not needed) |
|---|---|
| `session.json` — the empty presence marker | The pepper, tokens and VEK — they live in the OS keychain |
| `last_seen_version` — the version the changelog notice has already shown | Your vault entries — they live encrypted on the server |
| | Your vault **key** — that is what `psamvault backup` escrows, see [Backup and recovery](backup-and-recovery.md) |

Because the sensitive material lives in the keychain rather than in `~/.psamvault`, an upgrade that goes wrong costs you a session at worst: log in again. It does not cost you your key or your entries — and a pre-update snapshot is **not** a substitute for a verified `psamvault backup` or a `psamvault export`.

### Stashing, conflicts and rollback

- **Local changes, happy path:** `Local changes stashed and restored.`
- **The pull fails:** your local changes are restored from the stash before the command returns, and the error is reported. Nothing is clobbered.
- **The stash will not reapply:** the upgrade itself succeeded, but the stash is **left parked** so nothing is lost, with the instructions to resolve it yourself:

  ```bash
  git stash list
  git stash pop   # after resolving any conflicts
  ```

- **The updated code will not import:** it stops and prints the rollback:

  ```bash
  git reset --hard origin/main  &&  pip install -e .
  ```

- **The dependency install fails:** the code was pulled but the package may be inconsistent; re-run `psamvault upgrade` to retry.
- **pipx track rollback:** `pipx reinstall psamvault`, or pin a known-good version with `pipx install --force psamvault==<version>`. Both rebuild the venv, so run them from a plain shell — not from a `psamvault` process that is using it.

## After an upgrade

After every `pipx upgrade psamvault`, the changelog for any new versions is shown automatically on the next command you run — you never need to remember to check.

```bash
psamvault changelog              # latest version only
psamvault changelog latest       # same as above
psamvault changelog all          # full version history
psamvault changelog show 0.3.0   # specific version
```

If you created your account before the master-password scheme was introduced, run the one-time migration after updating:

```bash
psamvault migrate
```

Your vault data is preserved. After migrating, regenerate your recovery codes with `psamvault generate-codes`.

## Related pages

- [Backup and recovery](backup-and-recovery.md) — the key escrow that an upgrade does not replace.
- [Maintenance and upgrade commands](../reference/commands.md#maintenance-and-upgrade-commands) — `changelog`, `upgrade` and `uninstall` in full.
- [Configuration](../reference/configuration.md) — the `~/.psamvault` layout, including `backups/`.
