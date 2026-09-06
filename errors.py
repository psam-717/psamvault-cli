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
    """The request failed server-side validation (HTTP 422)."""


class ConflictError(ApiError):
    """The request conflicts with existing state (HTTP 409)."""


class DecryptionError(PsamVaultError):
    """Local decryption failed (wrong key, corrupt blob, unexpected format)."""
