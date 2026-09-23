"""Who is calling? ``human``, ``uncertain``, or ``agent``.

One patchable entry point (:func:`classify`) so tests control classification
exactly, and so a single rule governs every secret-emitting path.

The ladder (signals 1-4, cheapest first):

1. **explicit** — ``PSAMVAULT_AGENT`` set (also what ``--agent`` sets), or the
   MCP exporting it into a subprocess it started.
2. **host markers** — the self-identification a known agent runtime leaves in
   the environment. Hermes exports ``AI_AGENT=hermes-agent`` /
   ``HERMES_AGENT=true`` and its terminal tool exports ``TERMINAL_CWD`` /
   ``TERMINAL_ENV``; Claude Code exports ``CLAUDECODE`` /
   ``CLAUDE_CODE_ENTRYPOINT``. All measured on this machine, not assumed.
3. **unattended** — ``CI=true`` is *recorded* (``env:CI`` lands in the audit row)
   but does not by itself make the caller an agent. Unattended is not the same
   as driven: a pipeline the human wrote is not an agent, and an agent running
   *inside* CI still carries its own markers or shows up in the ancestry chain —
   neither of which ``CI`` suppresses. Calling CI an agent would break real
   pipelines on upgrade and protect nothing, so the caller stays ``uncertain``:
   allowed and audited under ``human-only``, refused under ``strict``.
4. **ancestry** — the parent-process chain (:mod:`ancestry`). Consulted
   *only* when 1-2 are silent, so an ordinary command never pays for it.

Why both 2 and 4, when they overlap: measured 2026-09-23, ancestry holds when
the chain is intact (an agent that runs ``unset AI_AGENT HERMES_AGENT`` in its
own shell is still refused, ``ancestry:hermes-agent\\venv``) but goes blind when
an invocation crosses an MSYS ``env.exe`` boundary — Cygwin's fork re-parents the
child to a stub that exits immediately, so the Windows ppid chain ends there. A
marker-only rule is strippable; an ancestry-only rule is breakable. Together
they cover the realistic scrubs, and the honest residue (``env -i`` through a
fork stub) is documented in ``SECURITY.md`` as work for the OS-user split.

Two rules keep this honest:

* **Only markers verified absent in the human's own terminal may block.**
  Measured 2026-09-18 in the desktop app's terminal pane: PowerShell, a real
  TTY, no agent markers. ``AI_AGENT``, ``HERMES_AGENT`` and the Claude Code
  markers were checked directly. The two ``TERMINAL_*`` entries were added from
  measured agent-side evidence (they are present in the agent's shell, next to
  ``AI_AGENT``) and were cleared for the pane without a manual check: the
  desktop app sets ``TERMINAL_CWD`` in exactly one place, the backend spawn env
  (never a pane), and the live process tree shows the pane is an *ancestor* of
  that backend — so it cannot inherit what the app hands to a child below it.
  Hermes' other
  internals (``_HERMES_GATEWAY``, ``HERMES_DESKTOP``) are deliberately NOT in
  the list: a false block of the human's own terminal is the one failure this
  design must not have.
* **Never gate on TTY absence.** ``typer.testing.CliRunner`` has no TTY, so a
  "no TTY ⇒ deny" rule would fail every command test in the suite and turn a
  security feature into a test rewrite. A bare non-TTY caller is ``uncertain``
  (allowed, audited); blocking keys on POSITIVE signals.

Measured on this host (see the plan's step 1): the Hermes agent shell has
``stdin`` on a TTY but ``stdout`` piped — so TTY presence is not a reliable
"human" signal either. ``human`` requires BOTH ends to be terminals.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field

import ancestry

VERDICT_HUMAN = "human"
VERDICT_UNCERTAIN = "uncertain"
VERDICT_AGENT = "agent"

# Set by the global `--agent` flag, or by a host/MCP that talks to the CLI.
EXPLICIT_ENV = "PSAMVAULT_AGENT"

_TRUTHY = {"1", "true", "yes", "on"}

# (name, kind) — kind None means "any non-empty value counts".
HOST_MARKERS: tuple[tuple[str, str | None], ...] = (
    ("AI_AGENT", None),
    ("HERMES_AGENT", "truthy"),
    ("CLAUDECODE", "truthy"),
    ("CLAUDE_CODE_ENTRYPOINT", None),
    # Hermes' terminal tool exports its own environment into the shell it hands
    # the agent. Adding it closes the measured gap where a scrub crosses an MSYS
    # `env.exe` boundary: that re-parents the child to a fork stub, which breaks
    # the Windows parent chain and blinds the ancestry signal (see ancestry.py).
    ("TERMINAL_CWD", None),
    ("TERMINAL_ENV", None),
)

CI_MARKER = "CI"


def _is_truthy(value: str | None) -> bool:
    return bool(value) and value.strip().lower() in _TRUTHY


@dataclass
class CallerVerdict:
    """The classification, plus the evidence behind it (for the audit row)."""

    verdict: str
    signals: list[str] = field(default_factory=list)
    tty: bool = False

    @property
    def is_agent(self) -> bool:
        return self.verdict == VERDICT_AGENT

    def describe(self) -> str:
        return ", ".join(self.signals) if self.signals else f"no signals (tty={self.tty})"


def _default_ancestry_probe() -> ancestry.AncestryResult:
    return ancestry.inspect()


# Indirection so tests (and the conftest safety fixture) can pin the probe
# without patching the ancestry module itself.
_probe_ancestry = _default_ancestry_probe


def tty_present() -> bool:
    """True when a human could actually be looking at this process.

    Both ends must be terminals: the agent's own shell has stdin on a TTY and
    stdout piped, so a stdout-only or stdin-only check would call an agent a
    human.
    """
    try:
        return bool(sys.stdin.isatty() and sys.stdout.isatty())
    except Exception:
        return False


def classify(
    env: dict | None = None,
    *,
    with_ancestry: bool = False,
    ancestry_probe=None,
) -> CallerVerdict:
    """Classify the caller.

    ``with_ancestry`` is set by the reveal gate (a reveal is pending); every
    other caller leaves it off so ordinary commands never walk the process
    chain.
    """
    environ = os.environ if env is None else env
    signals: list[str] = []
    notes: list[str] = []

    if _is_truthy(environ.get(EXPLICIT_ENV)):
        signals.append(f"explicit:{EXPLICIT_ENV}")
    else:
        for name, kind in HOST_MARKERS:
            value = environ.get(name)
            if not value:
                continue
            if kind == "truthy" and not _is_truthy(value):
                continue
            signals.append(f"marker:{name}" + (f"={value}" if kind is None else ""))
        # Recorded for the audit trail, never evidence of an agent: see the
        # ladder's signal 3. An agent in CI is caught by its markers or ancestry.
        if _is_truthy(environ.get(CI_MARKER)):
            notes.append(f"env:{CI_MARKER}")

    tty = tty_present()
    if signals:
        return CallerVerdict(VERDICT_AGENT, signals + notes, tty)

    if with_ancestry:
        probe = ancestry_probe or _probe_ancestry
        try:
            result = probe()
        except Exception:
            result = ancestry.AncestryResult(is_agent=False)
        if getattr(result, "is_agent", False):
            return CallerVerdict(
                VERDICT_AGENT, [result.summary()] + notes, tty
            )

    return CallerVerdict(VERDICT_HUMAN if tty else VERDICT_UNCERTAIN, notes, tty)
