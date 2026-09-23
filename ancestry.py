"""Parent-process ancestry — signal 4 of the caller ladder.

Signals 1-3 (``caller.py``) are environment variables: cheap, but an agent can
strip them (verified). Ancestry does not depend on the environment at all — the
CLI walks its own parent chain and asks whether any ancestor is an agent
runtime. A marker-scrubbed invocation that allocates its own PTY is still
refused.

Matching rules, and why they are narrow:

* Match the ancestor's executable **path**, not its name — Hermes runs as
  ``python.exe``, so a name match is worthless.
* The hints name the *agent runtime* (``...\\hermes-agent\\venv\\...``,
  ``hermes_cli``), never a bare ``hermes-agent`` prefix: the desktop app's own
  terminal pane descends from the same install, so a prefix match would block
  the human's terminal — the one thing this ladder must never do.
* POSIX also reads ``/proc/<pid>/cmdline``, which is where a ``node``-hosted
  agent (Claude Code, Codex, OpenCode) shows up. On Windows only the image path
  is available without WMI, so those hosts are covered by their markers
  instead.

Honest limits (documented in ``SECURITY.md``): PID reuse, a detached or
re-parented process, and a runtime installed under a non-obviously-named path
all defeat this. A miss downgrades the verdict to ``uncertain`` — it never
blocks a human wrongly. The OS-user split remains the actual boundary.

**Measured limit (2026-09-23), and why markers still matter.** Cygwin/MSYS
``fork`` sets a child's Windows parent to a *stub* that exits immediately: an
invocation routed through ``env.exe`` (``env -u AI_AGENT … psamvault get x``)
ends the ppid chain right there, and this walk cannot see past it. The same
scrub done in-shell (``unset AI_AGENT …``) is caught normally. So ancestry is a
real second signal, not a replacement for the marker list — and ``env -i``
through a fork stub is the residue that only the OS-user split closes.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field

# How far up the chain to walk before giving up. Deep enough for
# shell → agent runtime → terminal emulator → explorer.
MAX_DEPTH = 12

# Path (and, on POSIX, command-line) fragments that identify an AGENT RUNTIME.
# Kept narrow on purpose — see the module docstring.
AGENT_RUNTIME_HINTS = (
    "hermes-agent\\venv",
    "hermes-agent/venv",
    "hermes_cli",
    "claude-code",
    "codex-cli",
    "opencode-ai",
    "goose-cli",
)

# Command-line fragments to look for on POSIX, where /proc exposes argv.
AGENT_CMDLINE_HINTS = AGENT_RUNTIME_HINTS + (
    "@anthropic-ai/claude",
    "claude_code",
    "codex",
    "opencode",
)

# Distinctly-named agent binaries. A basename match is only safe because none of
# these names is shared by anything a human runs — unlike ``python.exe`` or
# ``node.exe``, which is why the general rule is path fragments. Measured
# 2026-09-23: Claude Code's CLI is ``~/.local/bin/claude.exe``, whose PATH
# contains no distinctive directory, so path fragments alone miss it.
AGENT_EXE_NAMES = (
    "claude",
    "claude.exe",
    "codex",
    "codex.exe",
    "opencode",
    "opencode.exe",
    "goose",
    "goose.exe",
    "aider",
    "aider.exe",
)


@dataclass
class ProcessInfo:
    """One process in the walk: its pid, its parent, and what it looks like."""

    pid: int
    ppid: int = 0
    path: str = ""
    cmdline: str = ""
    matched: str = ""


@dataclass
class AncestryResult:
    """Outcome of a walk — kept as data so tests and the audit log share it."""

    is_agent: bool
    matched_hint: str | None = None
    matched_path: str = ""
    depth: int = 0
    chain: list[ProcessInfo] = field(default_factory=list)

    def summary(self) -> str:
        """Short human-readable form for the audit row's ``signals`` field."""
        if not self.is_agent:
            return f"ancestry:none(depth={self.depth})"
        return f"ancestry:{self.matched_hint}"


def _normalise(value: str) -> str:
    return value.replace("/", "\\").lower()


def _hint_in(text: str, hints: tuple[str, ...]) -> str | None:
    """Return the first hint found in ``text``, or None."""
    if not text:
        return None
    folded = _normalise(text)
    for hint in hints:
        if _normalise(hint) in folded:
            return hint
    return None


def agent_in_chain(entries: list[ProcessInfo]) -> AncestryResult:
    """Classify a materialised process chain (pure — no OS calls).

    This is the function the tests drive with fake chains; the platform
    walkers only exist to fill ``entries`` in.
    """
    for entry in entries:
        # `path` is the primary signal and the only one Windows can offer;
        # `cmdline` is only populated on POSIX (empty on Windows, so the check
        # is unconditional rather than platform-branched).
        hint = _hint_in(entry.path, AGENT_RUNTIME_HINTS)
        where = entry.path
        if hint is None:
            name = entry.path.replace("\\", "/").rsplit("/", 1)[-1].strip().lower()
            if name in AGENT_EXE_NAMES:
                hint = f"exe:{name}"
        if hint is None:
            hint = _hint_in(entry.cmdline, AGENT_CMDLINE_HINTS)
            where = entry.cmdline
        if hint is not None:
            return AncestryResult(
                is_agent=True,
                matched_hint=hint,
                matched_path=where,
                depth=len(entries),
                chain=entries,
            )
    return AncestryResult(is_agent=False, depth=len(entries), chain=entries)


# ── Windows: Toolhelp32 snapshot + QueryFullProcessImageName ──────────────


_TH32CS_SNAPPROCESS = 0x00000002
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000


def _windows_ppid_map() -> dict[int, int]:
    """pid -> parent pid for every live process (one snapshot)."""
    import ctypes
    from ctypes import wintypes

    class PROCESSENTRY32(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.POINTER(wintypes.ULONG)),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", wintypes.CHAR * 260),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    snapshot = kernel32.CreateToolhelp32Snapshot(_TH32CS_SNAPPROCESS, 0)
    if snapshot == -1:
        return {}

    mapping: dict[int, int] = {}
    try:
        entry = PROCESSENTRY32()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
        if not kernel32.Process32First(snapshot, ctypes.byref(entry)):
            return {}
        while True:
            mapping[int(entry.th32ProcessID)] = int(entry.th32ParentProcessID)
            if not kernel32.Process32Next(snapshot, ctypes.byref(entry)):
                break
    finally:
        kernel32.CloseHandle(snapshot)
    return mapping


def _windows_image_path(pid: int) -> str:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    handle = kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return ""
    try:
        size = wintypes.DWORD(32768)
        buffer = ctypes.create_unicode_buffer(size.value)
        ok = kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size))
        return buffer.value if ok else ""
    finally:
        kernel32.CloseHandle(handle)


def _walk_windows(start_pid: int | None, max_depth: int) -> list[ProcessInfo]:
    parents = _windows_ppid_map()
    entries: list[ProcessInfo] = []
    seen: set[int] = set()
    pid = os.getpid() if start_pid is None else start_pid
    for _ in range(max_depth):
        if pid in (0, None) or pid in seen:
            break
        seen.add(pid)
        ppid = parents.get(pid, 0)
        entries.append(ProcessInfo(pid=pid, ppid=ppid, path=_windows_image_path(pid)))
        pid = ppid
    return entries


# ── POSIX: /proc ──────────────────────────────────────────────────────────


def _posix_ppid(pid: int) -> int:
    try:
        with open(f"/proc/{pid}/stat", "r", encoding="utf-8", errors="replace") as handle:
            data = handle.read()
    except OSError:
        return 0
    # "pid (comm) state ppid ..." — comm may contain spaces/parens, so split
    # after the LAST ')'.
    try:
        rest = data[data.rindex(")") + 1:].split()
        return int(rest[1])
    except (ValueError, IndexError):
        return 0


def _posix_path(pid: int) -> str:
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except OSError:
        return ""


def _posix_cmdline(pid: int) -> str:
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as handle:
            return handle.read().replace(b"\x00", b" ").decode("utf-8", "replace").strip()
    except OSError:
        return ""


def _walk_posix(start_pid: int | None, max_depth: int) -> list[ProcessInfo]:
    entries: list[ProcessInfo] = []
    seen: set[int] = set()
    pid = os.getpid() if start_pid is None else start_pid
    for _ in range(max_depth):
        if not pid or pid in seen:
            break
        seen.add(pid)
        ppid = _posix_ppid(pid)
        entries.append(
            ProcessInfo(
                pid=pid,
                ppid=ppid,
                path=_posix_path(pid),
                cmdline=_posix_cmdline(pid),
            )
        )
        pid = ppid
    return entries


# ── Public API ────────────────────────────────────────────────────────────


def walk(start_pid: int | None = None, max_depth: int = MAX_DEPTH) -> list[ProcessInfo]:
    """Materialise the ancestor chain, starting at ``start_pid`` (self by default)."""
    if sys.platform == "win32":
        return _walk_windows(start_pid, max_depth)
    return _walk_posix(start_pid, max_depth)


def inspect(start_pid: int | None = None, max_depth: int = MAX_DEPTH) -> AncestryResult:
    """Walk the chain and classify it. Never raises — a failure is ``no match``."""
    try:
        return agent_in_chain(walk(start_pid, max_depth))
    except Exception:
        # Ancestry is an additive signal: any platform hiccup means "no match",
        # never a blocked human.
        return AncestryResult(is_agent=False)
