"""One renderer for API key listings, shared by `ak-list` and `list`.

Both commands show the same rows, so a second renderer would drift: a fix to the
grouping, to the folded backup copies or to the summary line would land in one
command and not the other. `print_api_key_groups` owns the whole block - project
sections, the standalone table, the summary - and both commands call it.

Column widths follow the data, with the historical widths as the floor, so a long
key or a backup-only source label (`.env.bak-20260926t091411z (stale)`) widens the
table instead of pushing the date out of line.
"""

from __future__ import annotations

import typer

KEY_MIN = 28
SOURCE_MIN = 28
NAME_MIN = 28
SERVICE_MIN = 22
NOTES_MIN = 30


def _source_label(item: dict) -> str:
    """The source file, with folded backup copies named in the same cell."""
    source = item.get("source") or "-"
    if item.get("stale_only"):
        extra = item.get("stale_count") or 0
        suffix = f" +{extra} more" if extra else ""
        return f"{source} (stale){suffix}"
    extra = item.get("stale_count") or 0
    if extra:
        return f"{source} (+{extra} stale)"
    return source


def _notes_label(item: dict) -> str:
    notes = item.get("notes") or ""
    return notes[:27] + "..." if len(notes) > 30 else notes


def project_widths(rows: list[dict]) -> tuple[int, int]:
    """The KEY and SOURCE column widths that fit every row of the project tables."""
    key_width = max([KEY_MIN] + [len(str(row["key_name"])) for row in rows])
    source_width = max([SOURCE_MIN] + [len(_source_label(row)) for row in rows])
    return key_width, source_width


def standalone_widths(rows: list[dict]) -> tuple[int, int, int]:
    """The NAME, SERVICE and NOTES column widths that fit every standalone row."""
    name_width = max([NAME_MIN] + [len(str(row["key_name"])) for row in rows])
    service_width = max([SERVICE_MIN] + [len(str(row["service_hint"])) for row in rows])
    notes_width = max([NOTES_MIN] + [len(_notes_label(row)) for row in rows])
    return name_width, service_width, notes_width


def print_project_keys(
    project: str,
    rows: list[dict],
    key_width: int = KEY_MIN,
    source_width: int = SOURCE_MIN,
) -> None:
    typer.echo(f"  Project: {project}")
    typer.echo(f"    {'KEY':<{key_width}} {'SOURCE':<{source_width}} {'UPDATED'}")
    typer.echo(f"    {'-'*key_width} {'-'*source_width} {'-'*20}")
    for item in rows:
        label = _source_label(item)
        typer.echo(
            f"    {item['key_name']:<{key_width}} {label:<{source_width}} {item['updated']}"
        )
    typer.echo()


def print_standalone_keys(
    rows: list[dict],
    name_width: int = NAME_MIN,
    service_width: int = SERVICE_MIN,
    notes_width: int = NOTES_MIN,
) -> None:
    typer.echo("  Standalone Keys")
    typer.echo(
        f"    {'NAME':<{name_width}} {'SERVICE':<{service_width}} "
        f"{'NOTES':<{notes_width}} {'UPDATED'}"
    )
    typer.echo(
        f"    {'-'*name_width} {'-'*service_width} {'-'*notes_width} {'-'*20}"
    )
    for item in rows:
        typer.echo(
            f"    {item['key_name']:<{name_width}} {item['service_hint']:<{service_width}} "
            f"{_notes_label(item):<{notes_width}} {item['updated']}"
        )
    typer.echo()


def print_summary(prepared: dict, project_name: str | None = None) -> None:
    stored = prepared["stored"]
    shown = prepared["shown"]
    if project_name:
        typer.echo(f"  {shown} entr{'y' if shown == 1 else 'ies'} in project '{project_name}'.\n")
        return
    if shown != stored:
        typer.echo(f"  {stored} stored, {shown} shown (stale copies folded).\n")
        return
    typer.echo(f"  {shown} entr{'y' if shown == 1 else 'ies'} found.\n")


def print_api_key_groups(prepared: dict, project_name: str | None = None) -> None:
    """The shared body: project sections, standalone keys, then the summary."""
    project_rows = [row for rows in prepared["projects"].values() for row in rows]
    key_width, source_width = project_widths(project_rows)
    for proj_name, proj_items in prepared["projects"].items():
        print_project_keys(proj_name, proj_items, key_width, source_width)

    standalone = prepared["standalone"]
    if standalone:
        name_width, service_width, notes_width = standalone_widths(standalone)
        print_standalone_keys(standalone, name_width, service_width, notes_width)

    print_summary(prepared, project_name)
