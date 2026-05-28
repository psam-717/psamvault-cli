import os

# Set env vars before any CLI module is imported during test collection.
# load_config() only overwrites env vars that aren't already set, so these
# take precedence over anything in config.env or the OS keychain.
os.environ.setdefault("PSAMVAULT_PEPPER", "a" * 64)
os.environ.setdefault("PSAMVAULT_API_URL", "https://test.example.com")

import pytest

# ── Shared constants ──────────────────────────────────────────────────────────

TEST_VEK = bytes(range(32))  # deterministic 32-byte key for crypto tests
TEST_ACCESS_TOKEN = "test_access_token"
TEST_REFRESH_TOKEN = "test_refresh_token"


# ── Fixtures ──────────────────────────────────────────────────────────────────

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
