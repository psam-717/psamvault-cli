"""The reveal gate — one chokepoint every secret-emitting path calls first.

``require_reveal`` is the only place that decides whether a secret may be
printed or copied. Every gated command calls it immediately before it emits
(not before it fetches): a token is therefore consumed only by a reveal that
actually happens, so a token is never burned by a failed fetch.

    from reveal_gate import require_reveal

    try:
        require_reveal(action="get", entry=site)
    except RevealBlockedError as exc:
        exit_error(exc)

Gated actions: ``get``, ``ak-get``, ``note-get``, ``export --plaintext``, plus
``--copy`` on any of them (the same call site covers both — the clipboard is a
reveal). Discovery is never gated: ``list``, ``site-list``, ``ak-list``,
``note-list``, ``whoami`` and ``check_credential_exists`` stay open, because an
agent must be able to see *what* exists.

What this is and is not: a guardrail, not a boundary. An agent that already has
a shell *and* the user's keychain can read Windows Credential Manager, import
``crypto`` and decrypt directly, or install a pristine CLI. What it buys is a
hard structural stop for well-behaved agents, a loud audited trail for
accidents, and an always-available capability alternative. ``SECURITY.md``
states the limits; the OS-user split is the actual boundary.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import audit
import caller
import policy as policy_module
import session
from errors import RevealBlockedError

# Named alternatives, in the order a caller should consider them. The point of
# the refusal is to leave the agent a way to finish the job without the value.
_CAPABILITIES = (
    "psamvault MCP use_credential — call an API with the secret injected, never revealed",
    "psamvault MCP run_with_credential — run a command with the secret in its environment",
    "psamvault MCP browser_login — type the secret into a site without printing it",
)

APPROVE_HINT = "Ask the human to run it, or use a capability instead"


@dataclass
class RevealDecision:
    """Why a reveal was allowed — recorded in the audit trail either way."""

    allowed: bool
    verdict: str
    signals: list[str] = field(default_factory=list)
    reason: str = ""
    token_id: str | None = None


def _reason_phrase(verdict: str, policy: policy_module.Policy) -> str:
    if verdict == caller.VERDICT_AGENT:
        return "agent terminal detected"
    return f"no terminal, and the policy mode is {policy.reveal}"


def _refusal_details(action: str, entry: str | None, whole_vault: bool, policy, verdict) -> list[str]:
    details: list[str] = []
    if whole_vault:
        details.append(
            "a whole-vault dump cannot be approved for an agent — run it in your own terminal"
        )
    elif entry:
        details.append(
            f"psamvault approve {entry} --for-agent --ttl {policy.approval_ttl_seconds}"
            "   (human terminal only)"
        )
    details.extend(_CAPABILITIES)
    return details


def require_reveal(
    action: str,
    entry: str | None = None,
    *,
    whole_vault: bool = False,
    policy: policy_module.Policy | None = None,
    verdict: caller.CallerVerdict | None = None,
    with_ancestry: bool = True,
) -> RevealDecision:
    """Allow or refuse a reveal. Refusal raises :class:`RevealBlockedError`.

    ``entry`` is the vault name being revealed (site, API-key name, note title);
    ``whole_vault=True`` marks a bulk dump, which no approval token can cover —
    an entry token that unlocked everything would make the guardrail decorative.
    ``verdict``/``policy`` are injectable so tests drive the gate exactly.
    """
    active_policy = policy if policy is not None else policy_module.load()
    verdict = verdict if verdict is not None else caller.classify(with_ancestry=with_ancestry)

    decision = policy_module.decide(active_policy, verdict.verdict, entry)

    if decision == policy_module.DENY and entry and not whole_vault:
        approval = session.live_approval_for(entry)
        if approval is not None:
            session.consume_approval(approval["token_id"])
            audit.record(
                command=action,
                decision=audit.DECISION_APPROVED,
                caller=verdict.verdict,
                entry=entry,
                signals=list(verdict.signals),
                tty=verdict.tty,
                token_id=approval["token_id"],
                policy_mode=active_policy.reveal,
            )
            return RevealDecision(
                allowed=True,
                verdict=verdict.verdict,
                signals=list(verdict.signals),
                reason="approved",
                token_id=approval["token_id"],
            )

    if decision == policy_module.DENY:
        audit.record(
            command=action,
            decision=audit.DECISION_DENY,
            caller=verdict.verdict,
            entry=entry,
            signals=list(verdict.signals),
            tty=verdict.tty,
            policy_mode=active_policy.reveal,
        )
        message = f"psamvault {action} is blocked in this context ({_reason_phrase(verdict.verdict, active_policy)})"
        details = _refusal_details(action, entry, whole_vault, active_policy, verdict.verdict)
        raise RevealBlockedError(message, details=details, hint=APPROVE_HINT)

    audit.record(
        command=action,
        decision=audit.DECISION_ALLOW,
        caller=verdict.verdict,
        entry=entry,
        signals=list(verdict.signals),
        tty=verdict.tty,
        policy_mode=active_policy.reveal,
    )
    return RevealDecision(
        allowed=True,
        verdict=verdict.verdict,
        signals=list(verdict.signals),
        reason="policy",
    )
