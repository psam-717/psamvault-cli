"""Parse and resolve API key names, including project/.env/KEY rows.

scan_and_protect stores a project key as ``project/.env/KEY`` and an unscoped
key as ``env/<file>/KEY``. The leaf (``KEY``) is not unique: the same key can
sit in ``.env`` and in a backup file, or in two projects. Callers that only
have the leaf ask ``resolve_api_key_name`` which row they mean.
"""

from __future__ import annotations

from errors import NotFoundError

# Characters refused in a single label. ``/`` separates the namespaced form;
# it is not allowed inside a segment.
FORBIDDEN_NAME_CHARS = set('\\/"\' <>|?*&#%')

# Suffixes that mean "a person copied .env before editing", not a live file
# such as .env.local or .env.production.
_BACKUP_SUFFIXES = ("bak", "old", "save", "backup", "orig", "copy", "tmp", "swp")


class AmbiguousApiKeyName(Exception):
    """A leaf name matches more than one live row."""

    def __init__(self, requested: str, matches: list[str]):
        super().__init__(requested)
        self.requested = requested
        self.matches = list(matches)


def is_stale_env_source(source: str | None) -> bool:
    """True for backup copies of an env file, false for live env files."""
    if not source:
        return False
    name = source.lower()
    if not name.startswith(".env") or name == ".env":
        return False
    if name.endswith("~"):
        return True
    rest = name[4:]
    suffix = rest[1:] if rest.startswith(".") else rest
    if suffix.startswith(_BACKUP_SUFFIXES):
        return True
    return suffix.isdigit()


def parse_api_key_name(name: str) -> dict:
    """Split a stored name into project, source file, and key.

    A namespaced name has the env file as the second-to-last segment
    (``atlas/.env/KEY``, ``env/.env.bak-20260926/KEY``). Anything else is a
    standalone label and is returned unchanged.
    """
    parts = name.split("/")
    namespaced = (
        len(parts) >= 3
        and all(parts)
        and parts[-2].startswith(".env")
    )
    if not namespaced:
        return {
            "name": name,
            "namespaced": False,
            "project": None,
            "display_project": None,
            "source": None,
            "key_name": name,
            "stale": False,
        }
    project = "/".join(parts[:-2])
    source = parts[-2]
    return {
        "name": name,
        "namespaced": True,
        "project": project,
        "display_project": _display_project(project),
        "source": source,
        "key_name": parts[-1],
        "stale": is_stale_env_source(source),
    }


def _display_project(project: str) -> str:
    """The unscoped bucket is stored under the literal project ``env``."""
    if project == "env":
        return "(unscoped)"
    if project.startswith("env/"):
        return "(unscoped)/" + project[4:]
    return project


def entry_name_error(name: str) -> str | None:
    """None when the name can be stored. A sentence otherwise."""
    if not name.strip():
        return "Entry name cannot be blank."
    parsed = parse_api_key_name(name)
    if parsed["namespaced"]:
        segments = name.split("/")
        source_at = len(segments) - 2
        for index, segment in enumerate(segments):
            if index == source_at:
                error = _source_error(segment)
            else:
                error = _label_error(segment)
            if error:
                return error
        return None
    return _label_error(name)


def _label_error(segment: str) -> str | None:
    found = [char for char in segment if char in FORBIDDEN_NAME_CHARS]
    if not found:
        return None
    unique = "".join(dict.fromkeys(found))
    shown = " ".join(repr(char) for char in unique)
    return (
        f"Entry name contains invalid character(s): {shown}\n"
        "  Forbidden characters: \\ / \" ' < > | ? * & # %"
    )


def _source_error(segment: str) -> str | None:
    if not segment.startswith(".env"):
        return _label_error(segment)
    return _label_error(segment)


def resolve_api_key_name(requested: str, entries: list[dict]) -> str:
    """Return the stored name for a full name or a leaf.

    An exact match wins. A leaf that hits one row uses that row. A leaf that
    hits one live ``.env`` row and any number of backup copies uses the live
    row. Two live rows is an error: the caller has to pass the full name.
    """
    names = [entry["name"] for entry in entries if isinstance(entry, dict) and entry.get("name")]
    folded = requested.strip().lower()
    exact = [name for name in names if name.lower() == folded]
    if len(exact) == 1:
        return exact[0]
    if len(exact) > 1:
        raise AmbiguousApiKeyName(requested, exact)

    leaves = [
        name for name in names
        if parse_api_key_name(name)["key_name"].lower() == folded
    ]
    if len(leaves) == 1:
        return leaves[0]
    live = [name for name in leaves if not parse_api_key_name(name)["stale"]]
    if len(live) == 1:
        return live[0]
    if leaves:
        raise AmbiguousApiKeyName(requested, leaves)
    raise NotFoundError(f"No API key entry found for '{requested}'.")


def _project_matches(item: dict, project_name: str) -> bool:
    wanted = project_name.strip().lower()
    for candidate in (item.get("project"), item.get("display_project")):
        if candidate and candidate.lower() == wanted:
            return True
    return False


def prepare_list_items(entries: list[dict], project_name: str | None = None) -> dict:
    """Group namespaced keys and fold backup copies onto the live row.

    ``stored`` counts rows that matched the filter. ``shown`` counts rows
    after backup copies of a live key are folded in. A key that exists only
    as a backup stays visible and is marked stale, so it can still be deleted.
    """
    parsed: list[dict] = []
    for entry in entries:
        item = parse_api_key_name(entry.get("name") or "")
        item["service_hint"] = entry.get("service_hint") or "-"
        item["notes"] = entry.get("notes") or None
        item["updated"] = (entry.get("updated_at") or "?")[:10]
        if project_name and not _project_matches(item, project_name):
            continue
        parsed.append(item)

    groups: dict[tuple, list[dict]] = {}
    order: list[tuple] = []
    standalone: list[dict] = []
    for item in parsed:
        if not item["namespaced"]:
            standalone.append(item)
            continue
        key = (item["display_project"], item["key_name"].lower())
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(item)

    folded: list[dict] = []
    for key in order:
        group = groups[key]
        live = [row for row in group if not row["stale"]]
        stale = [row for row in group if row["stale"]]
        if live:
            live.sort(key=lambda row: (row["source"] != ".env", row["source"] or ""))
            for index, row in enumerate(live):
                folded.append({
                    **row,
                    "stale_count": len(stale) if index == 0 else 0,
                    "stale_only": False,
                })
        else:
            stale.sort(key=lambda row: row["updated"], reverse=True)
            folded.append({
                **stale[0],
                "stale_count": len(stale) - 1,
                "stale_only": True,
            })

    projects: dict[str, list[dict]] = {}
    for row in folded:
        projects.setdefault(row["display_project"], []).append(row)
    for rows in projects.values():
        rows.sort(key=lambda row: row["key_name"].lower())
    standalone.sort(key=lambda row: row["key_name"].lower())

    shown = sum(len(rows) for rows in projects.values()) + len(standalone)
    return {
        "projects": dict(sorted(projects.items())),
        "standalone": standalone,
        "stored": len(parsed),
        "shown": shown,
    }
