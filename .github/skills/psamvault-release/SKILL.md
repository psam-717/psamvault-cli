---
name: psamvault-release
description: >
  Full release workflow for psamvault CLI. Use this skill when the user asks
  to release, publish, ship, bump the version, or cut a new version of psamvault.
  Guides through: version bump → changelog entry → build → TestPyPI → user
  verification → PyPI → GitHub release.
allowed-tools: shell
---

# psamvault Release Workflow

You are helping the developer release a new version of the **psamvault** CLI package.
The repo root is `D:\Projects\pythonSideQuests\psamVault\cli`.
The venv is at `.\cli_venv\Scripts\`.

Follow these steps **in order**, pausing at each checkpoint for the user's confirmation.

---

## Step 1 — Determine the new version

Ask the user what the new version should be (current version is in `pyproject.toml`).
Classify it as:
- **patch** (x.y.Z) — bug fixes only
- **minor** (x.Y.0) — new features, backwards compatible
- **major** (X.0.0) — breaking changes

Show the current version and suggest the appropriate bump based on what changed.

---

## Step 2 — Update `pyproject.toml`

Edit the `version` field in `pyproject.toml`:

```toml
version = "<new_version>"
```

Confirm the change by reading the file back and showing the updated line.

---

## Step 3 — Add changelog entry to `changelog.py`

Open `changelog.py` and add a new key at the top of the `CHANGELOG` dict for the
new version. The entries should:
- Start with `"New:   "` for new features
- Start with `"Fixed: "` for bug fixes
- Start with `"Changed: "` for changes to existing behaviour
- Start with `"Removed: "` for removed features
- Use a second line starting with spaces for continuation/detail lines

Ask the user to describe what changed if not already known from the conversation.
Show the proposed entry and wait for approval before writing.

---

## Step 4 — Build the package

Run from the repo root:

```powershell
.\cli_venv\Scripts\python -m build
```

Confirm that both `psamvault-<version>-py3-none-any.whl` and
`psamvault-<version>.tar.gz` were created in `dist/`.

---

## Step 5 — Upload to TestPyPI

```powershell
.\cli_venv\Scripts\python -m twine upload --repository testpypi dist\psamvault-<version>*
```

After upload succeeds, show the user the TestPyPI URL:
`https://test.pypi.org/project/psamvault/<version>/`

And show the pipx install command for testing:
```
pipx install --index-url https://test.pypi.org/simple/ --pip-args="--extra-index-url https://pypi.org/simple/" psamvault==<version>
```

---

## Step 6 — Wait for user verification ✋

**STOP HERE.** Tell the user to:
1. Install from TestPyPI using the command above
2. Run `psamvault --version` to confirm the version
3. Run `psamvault changelog` to confirm the changelog entry appears correctly
4. Test any new features introduced in this release

Ask: "Have you verified the TestPyPI release and are ready to publish to production PyPI?"
Do NOT proceed until the user explicitly confirms.

---

## Step 7 — Upload to production PyPI

```powershell
.\cli_venv\Scripts\python -m twine upload dist\psamvault-<version>*
```

After upload, show the PyPI URL:
`https://pypi.org/project/psamvault/<version>/`

---

## Step 8 — Create GitHub Release

```powershell
.\cli_venv\Scripts\python scripts\release.py
```

The script will show a preview and prompt for `y/N` confirmation — send `y`.

After success, show the GitHub release URL:
`https://github.com/psam-717/psamvault-cli/releases/tag/v<version>`

---

## Step 9 — Summary

Print a clean summary:

```
✓ psamvault v<version> released!

  PyPI:    https://pypi.org/project/psamvault/<version>/
  GitHub:  https://github.com/psam-717/psamvault-cli/releases/tag/v<version>

  Users can upgrade with:
    pipx upgrade psamvault
    pip install --upgrade psamvault
```

---

## Important rules

- Never skip the TestPyPI step — it is mandatory before production PyPI.
- Never upload to PyPI before the user has explicitly verified TestPyPI.
- If any step fails, stop and report the full error before continuing.
- The `dist/` folder may contain artifacts from previous releases — only upload
  files matching the exact new version (e.g. `psamvault-0.2.4*`).
- If `twine` or `build` is not installed in the venv, install them first:
  `.\cli_venv\Scripts\pip install build twine --quiet`
