import os

# Set env vars before any CLI module is imported during test collection.
# load_config() only overwrites env vars that aren't already set, so these
# take precedence over anything in config.env or the OS keychain.
os.environ.setdefault("PSAMVAULT_PEPPER", "a" * 64)
os.environ.setdefault("PSAMVAULT_API_URL", "https://test.example.com")

import pytest

import ancestry
import audit
import caller
import pending_store
import policy
import session

# ── Shared constants ──────────────────────────────────────────────────────────

TEST_VEK = bytes(range(32))  # deterministic 32-byte key for crypto tests
TEST_ACCESS_TOKEN = "test_access_token"
TEST_REFRESH_TOKEN = "test_refresh_token"


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _guardrail_safe_environment(monkeypatch, tmp_path):
    """Keep the reveal guardrail out of every test's way — and out of the real home.

    Two hazards, both silent if left alone:

    * this suite is often run FROM an agent shell (``AI_AGENT``/``HERMES_AGENT``
      set, and an ancestor under ``...\\hermes-agent\\venv``), which the real
      classifier correctly calls an agent — every reveal test would then be
      refused and every command test would go red for the wrong reason;
    * the policy file and the audit trail live under the user's real
      ``~/.psamvault``, so tests would append to the live audit log.

    Tests that exercise the guardrail itself opt back in explicitly — with
    ``PSAMVAULT_AGENT=1`` or an injected ancestry probe — so the real classifier,
    policy loader and gate all stay under test, just never by accident.
    """
    for name in (
        "PSAMVAULT_AGENT",
        "AI_AGENT",
        "HERMES_AGENT",
        "CLAUDECODE",
        "CLAUDE_CODE_ENTRYPOINT",
        "CI",
        "_HERMES_GATEWAY",
        "HERMES_DESKTOP",
        "TERMINAL_CWD",
        "TERMINAL_ENV",
    ):
        monkeypatch.delenv(name, raising=False)

    monkeypatch.setattr(
        caller, "_probe_ancestry", lambda: ancestry.AncestryResult(is_agent=False)
    )
    monkeypatch.setattr(policy, "POLICY_FILE", tmp_path / "policy.json")
    monkeypatch.setattr(audit, "AUDIT_FILE", tmp_path / "audit.jsonl")
    # Pending claims are created by the ingress tests, so the directory has to
    # point somewhere disposable too — otherwise a "creates a claim" test writes
    # a real claim into the user's own ~/.psamvault/pending.
    monkeypatch.setattr(pending_store, "PENDING_DIR", tmp_path / "pending")


@pytest.fixture
def fake_keychain(monkeypatch):
    """In-memory keychain, so token tests never touch the user's real one."""

    class _Errors:
        class PasswordDeleteError(Exception):
            pass

    class _Keychain:
        errors = _Errors

        def __init__(self):
            self.store: dict[tuple[str, str], str] = {}

        def get_password(self, service, key):
            return self.store.get((service, key))

        def set_password(self, service, key, value):
            self.store[(service, key)] = value

        def delete_password(self, service, key):
            if (service, key) not in self.store:
                raise self.errors.PasswordDeleteError(f"{key} not found")
            del self.store[(service, key)]

    keychain = _Keychain()
    monkeypatch.setattr(session, "keyring", keychain)
    return keychain


@pytest.fixture
def vek():
    """Deterministic 32-byte Vault Encryption Key for use in crypto tests."""
    return TEST_VEK


@pytest.fixture
def sample_creds():
    return {"username": "alice@example.com", "password": "s3cr3t", "notes": ""}


@pytest.fixture
def mock_session():
    """Fake session dict that mirrors what load_session() returns."""
    return {
        "access_token": TEST_ACCESS_TOKEN,
        "refresh_token": TEST_REFRESH_TOKEN,
        "kdf_salt": "aa" * 32,
        "vek": TEST_VEK.hex(),
        "encrypted_vek": "bb" * 44,
        "vek_iv": "cc" * 12,
    }
