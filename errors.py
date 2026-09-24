"""
Typed error hierarchy for psamvault.

Every user-facing failure is a ``PsamVaultError`` subclass carrying a clean
``message`` and an optional actionable ``hint``. Commands render errors as:

    ✗ <message>
    → <hint>

Why typed exceptions (instead of one generic ``ApiError``): a single catch-all
type caused misattribution — e.g. ``ak-get`` reported session expiry and
network failures as "API key 'x' was not found in your vault", because every
API error landed in one ``except ApiError`` clause.

The CLI prints at the command layer only. ``api_client`` raises typed errors
without echoing, so the same exception can serve non-CLI consumers (dashboard,
TUI, MCP) without duplicate terminal output.
"""


class PsamVaultError(Exception):
    """Base class for all user-facing psamvault errors.

    Attributes:
        message: Human-readable description shown to the user.
        hint:    Optional single actionable hint line (rendered after message).
    """

    def __init__(self, message: str, hint: str | None = None):
        super().__init__(message)
        self.message = message
        self.hint = hint


class ApiError(PsamVaultError):
    """Base class for API-origin failures (non-2xx responses, session expiry).

    Kept as the common ancestor so pre-existing ``except ApiError`` handlers
    keep working during migration.
    """


class NotFoundError(ApiError):
    """The requested resource does not exist on the server (HTTP 404)."""


class SessionExpiredError(ApiError):
    """The session could not be refreshed (HTTP 401 + failed token refresh).

    The user must log in again — no command can heal a dead refresh token.
    """


class NetworkError(ApiError):
    """The server could not be reached (connect/timeout/DNS errors)."""


class ValidationError(ApiError):
    """The request failed server-side validation (HTTP 422).

    Attributes:
        details: Optional bullet list of per-field messages from FastAPI.
    """

    def __init__(self, message: str, details: list[str] | None = None, hint: str | None = None):
        super().__init__(message, hint=hint)
        self.details = list(details or [])


class ConflictError(ApiError):
    """The request conflicts with existing state (HTTP 409)."""


class RateLimitedError(ApiError):
    """Too many attempts in the server's rate-limit window (HTTP 429).

    Recovery and backup-passphrase verification are deliberately capped (a wrong
    passphrase is a brute-force target), so this is an expected outcome rather than
    a server fault — the hint must say "wait", not "try again in a moment".
    """


class DecryptionError(PsamVaultError):
    """Local decryption failed (wrong key, corrupt blob, unexpected format)."""


class RevealBlockedError(PsamVaultError):
    """A secret-emitting command was refused in this context.

    Raised by the reveal gate (``reveal_gate.py``) when the caller is an agent,
    or when a strict policy refuses a non-terminal caller. The refusal is not a
    failure of the command — it is the guardrail working — so the message names
    the capability alternatives:

        ✗ psamvault get is blocked in this context (agent terminal detected)
           • psamvault approve github.com --for-agent --ttl 120  (human terminal only)
           • use_credential — inject the secret without revealing it
        → Ask the human to run it, or use a capability instead

    Attributes:
        details: Bullet lines rendered under the message (capability choices).
    """

    def __init__(self, message: str, details: list[str] | None = None, hint: str | None = None):
        super().__init__(message, hint=hint)
        self.details = list(details or [])


class IngressBlockedError(PsamVaultError):
    """A secret was about to *enter* through a context that keeps copies.

    The mirror image of :class:`RevealBlockedError`: the reveal gate stops a
    secret leaving the vault, this stops one arriving by command line — where
    process listings, shell history and any wrapper that logs a command line all
    keep a copy. Raised when an agent asks for ``--key``/``--pass``, or tries to
    fill a claim itself instead of handing the code to the human.

        ✗ psamvault --key is blocked in this context (agent terminal detected)
           • a value in argv is visible to process listings, shell history …
           • psamvault ak-add github-prod --service GitHub   (prints a claim code …)
        → Ask the human for the value via the claim flow, or use --from-file

    Attributes:
        details: Bullet lines rendered under the message.
    """

    def __init__(self, message: str, details: list[str] | None = None, hint: str | None = None):
        super().__init__(message, hint=hint)
        self.details = list(details or [])
