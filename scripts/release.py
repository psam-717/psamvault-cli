#!/usr/bin/env python3
"""
release.py — psamvault release helper
======================================
Reads the current version from pyproject.toml, pulls the matching entry
from changelog.py, and creates a GitHub release with formatted notes and
the built wheel + sdist attached.

Usage
-----
    # From the repo root:
    python scripts/release.py            # full release
    python scripts/release.py --dry-run  # preview only, no GitHub call

Requirements
------------
    - gh  (GitHub CLI, authenticated)
    - Python 3.11+  (tomllib is stdlib)
    - dist/ must already contain the built artifacts
      (run  python -m build  first if needed)

Workflow
--------
    1. Bump version in pyproject.toml
    2. Add the new version entry to changelog.py
    3. Build:     python -m build
    4. Upload:    python -m twine upload dist/psamvault-<ver>*
    5. Release:   python scripts/release.py
"""

import subprocess
import sys
import tomllib
from pathlib import Path

# ── Resolve paths ─────────────────────────────────────────────────────────────
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))   # so we can import changelog.py

from changelog import CHANGELOG, format_changelog, _version_tuple  # noqa: E402


# ── Read version from pyproject.toml ─────────────────────────────────────────
def get_version() -> str:
    pyproject = REPO_ROOT / "pyproject.toml"
    with open(pyproject, "rb") as f:
        data = tomllib.load(f)
    return data["project"]["version"]


# ── Format release notes as Markdown ─────────────────────────────────────────
def build_release_notes(version: str) -> str:
    entries = CHANGELOG.get(version)
    if not entries:
        print(f"  ⚠  No changelog entries found for v{version}.")
        print("     Add them to changelog.py before releasing.")
        sys.exit(1)

    lines = [f"## What's new in v{version}\n"]
    for entry in entries:
        # Turn the plain-text entries into GitHub Markdown bullets.
        # Strip leading spaces (continuation lines) before formatting.
        stripped = entry.strip()
        if stripped.startswith(("Fixed:", "New:", "Changed:", "Removed:")):
            lines.append(f"- {stripped}")
        else:
            # Continuation line — indent under the previous bullet.
            lines.append(f"  {stripped}")

    lines.append("")
    lines.append(
        "---\n"
        f"Full changelog: https://github.com/psam-717/psamvault-cli/blob/main/changelog.py"
    )
    return "\n".join(lines)


# ── Find dist artifacts ───────────────────────────────────────────────────────
def find_artifacts(version: str) -> list[Path]:
    dist_dir = REPO_ROOT / "dist"
    artifacts = sorted(dist_dir.glob(f"psamvault-{version}*"))
    return artifacts


# ── Main ──────────────────────────────────────────────────────────────────────
def main() -> None:
    dry_run = "--dry-run" in sys.argv

    version = get_version()
    tag = f"v{version}"
    title = f"psamvault {tag}"
    notes = build_release_notes(version)
    artifacts = find_artifacts(version)

    print(f"\n  Release:    {title}")
    print(f"  Tag:        {tag}")
    print(f"  Artifacts:  {[a.name for a in artifacts] or 'none found in dist/'}")
    print(f"\n  ── Release notes ──────────────────────────────────────────────")
    for line in notes.splitlines():
        print(f"  {line}")
    print()

    if not artifacts:
        print("  ✗  No dist artifacts found. Run  python -m build  first.")
        sys.exit(1)

    if dry_run:
        print("  [dry-run] Skipping GitHub release creation.\n")
        return

    # Confirm before pushing
    confirm = input("  Create this GitHub release? [y/N] ").strip().lower()
    if confirm != "y":
        print("  Cancelled.\n")
        sys.exit(0)

    cmd = [
        "gh", "release", "create", tag,
        "--title", title,
        "--notes", notes,
        *[str(a) for a in artifacts],
    ]

    print(f"\n  Running: {' '.join(cmd[:5])} ...\n")
    result = subprocess.run(cmd, cwd=REPO_ROOT)

    if result.returncode == 0:
        print(f"\n  ✓  GitHub release {tag} created successfully.")
        print(f"     https://github.com/psam-717/psamvault-cli/releases/tag/{tag}\n")
    else:
        print(f"\n  ✗  gh release create failed (exit {result.returncode}).\n")
        sys.exit(result.returncode)


if __name__ == "__main__":
    main()
