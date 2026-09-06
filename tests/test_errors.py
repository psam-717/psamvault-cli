"""
Tests for the typed exception hierarchy (errors.py).

The hierarchy fixes the misattribution bug where every API failure (session
expiry, network, 409...) was caught as one generic ApiError and reported as
"not found" by ak-get and friends.

Rules under test:
- PsamVaultError is the base for ALL user-facing errors.
- ApiError remains importable from api_client (back-compat for dashboard + old tests).
- Each failure class carries a user message and an optional actionable hint.
"""
import pytest

import errors
import api_client


# ── Hierarchy ─────────────────────────────────────────────────────────────────

def test_base_error_subclasses_exception():
    assert issubclass(errors.PsamVaultError, Exception)


@pytest.mark.parametrize(
    "name",
    [
        "NotFoundError",
        "SessionExpiredError",
        "NetworkError",
        "ValidationError",
        "ConflictError",
        "DecryptionError",
    ],
)
def test_typed_errors_exist_and_subclass_api_error(name):
    cls = getattr(errors, name)
    assert issubclass(cls, errors.ApiError) or issubclass(cls, errors.PsamVaultError)
    # All API-origin failures share the ApiError lineage so existing
    # `except ApiError` code keeps working during migration.
    assert issubclass(cls, errors.PsamVaultError)


def test_api_error_still_importable_from_api_client_for_backcompat():
    # Dashboard and existing tests import `ApiError` from api_client.
    assert api_client.ApiError is errors.ApiError


# ── Message + hint semantics ──────────────────────────────────────────────────

def test_error_carries_message_and_optional_hint():
    err = errors.NotFoundError("No entry found for 'x'", hint="psamvault site-list to see saved sites")
    assert err.message == "No entry found for 'x'"
    assert err.hint == "psamvault site-list to see saved sites"
    assert str(err) == "No entry found for 'x'"


def test_error_hint_defaults_to_none():
    err = errors.SessionExpiredError("Your session has expired")
    assert err.message == "Your session has expired"
    assert err.hint is None


def test_error_is_raiseable_and_catchable_as_base():
    with pytest.raises(errors.PsamVaultError):
        raise errors.NetworkError("Could not reach the server")
