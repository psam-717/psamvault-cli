"""
Layer 1: Pure function tests for crypto.py.
No mocking, no network, no keychain — just deterministic math.
"""
import re
import pytest
from cryptography.exceptions import InvalidTag

from crypto import (
    derive_master_password,
    derive_key,
    encrypt_credentials,
    decrypt_credentials,
    encrypt_api_key,
    decrypt_api_key,
    encrypt_vek,
    decrypt_vek,
    wipe,
    generate_vek,
    generate_recovery_codes,
    encrypt_master_with_code,
    decrypt_master_with_code,
    hash_recovery_code,
)

_PEPPER = "deadbeef" * 8  # 64-char hex pepper for deterministic tests
_SALT = "aa" * 32          # 32-byte hex kdf_salt


# ── derive_master_password ────────────────────────────────────────────────────

def test_derive_master_password_is_deterministic(monkeypatch):
    monkeypatch.setenv("PSAMVAULT_PEPPER", _PEPPER)
    assert derive_master_password("mypassword") == derive_master_password("mypassword")


def test_derive_master_password_returns_64_hex_chars(monkeypatch):
    monkeypatch.setenv("PSAMVAULT_PEPPER", _PEPPER)
    result = derive_master_password("mypassword")
    assert len(result) == 64
    assert re.fullmatch(r"[0-9a-f]{64}", result)


def test_derive_master_password_changes_with_different_pepper(monkeypatch):
    monkeypatch.setenv("PSAMVAULT_PEPPER", "pepper1" * 8)
    r1 = derive_master_password("samepassword")
    monkeypatch.setenv("PSAMVAULT_PEPPER", "pepper2" * 8)
    r2 = derive_master_password("samepassword")
    assert r1 != r2


def test_derive_master_password_changes_with_different_password(monkeypatch):
    monkeypatch.setenv("PSAMVAULT_PEPPER", _PEPPER)
    assert derive_master_password("password1") != derive_master_password("password2")


# ── derive_key ────────────────────────────────────────────────────────────────

def test_derive_key_returns_32_bytes():
    key = derive_key("master_password", _SALT)
    assert len(key) == 32


def test_derive_key_is_deterministic():
    k1 = derive_key("master", _SALT)
    k2 = derive_key("master", _SALT)
    assert bytes(k1) == bytes(k2)


def test_derive_key_changes_with_different_salt():
    k1 = derive_key("master", "aa" * 32)
    k2 = derive_key("master", "bb" * 32)
    assert bytes(k1) != bytes(k2)


def test_derive_key_changes_with_different_password():
    assert bytes(derive_key("pass1", _SALT)) != bytes(derive_key("pass2", _SALT))


# ── encrypt_credentials / decrypt_credentials ─────────────────────────────────

def test_encrypt_decrypt_credentials_roundtrip(vek):
    blob, iv = encrypt_credentials(vek, "alice@example.com", "s3cr3t", "some notes")
    result = decrypt_credentials(vek, blob, iv)
    assert result["username"] == "alice@example.com"
    assert result["password"] == "s3cr3t"
    assert result["notes"] == "some notes"


def test_decrypt_credentials_empty_notes_roundtrip(vek):
    blob, iv = encrypt_credentials(vek, "user", "pass")
    result = decrypt_credentials(vek, blob, iv)
    assert result["notes"] == ""


def test_decrypt_credentials_raises_on_tampered_blob(vek):
    blob, iv = encrypt_credentials(vek, "user", "pass")
    # Flip the last two hex chars
    tampered = blob[:-2] + ("00" if blob[-2:] != "00" else "ff")
    with pytest.raises(InvalidTag):
        decrypt_credentials(vek, tampered, iv)


def test_decrypt_credentials_raises_on_wrong_key(vek):
    blob, iv = encrypt_credentials(vek, "user", "pass")
    with pytest.raises(InvalidTag):
        decrypt_credentials(bytes(32), blob, iv)


def test_encrypt_credentials_produces_unique_ivs(vek):
    _, iv1 = encrypt_credentials(vek, "user", "pass")
    _, iv2 = encrypt_credentials(vek, "user", "pass")
    assert iv1 != iv2


def test_encrypt_credentials_iv_is_24_hex_chars(vek):
    # IV is 12 bytes → 24 hex chars
    _, iv = encrypt_credentials(vek, "user", "pass")
    assert len(iv) == 24
    assert re.fullmatch(r"[0-9a-f]{24}", iv)


# ── encrypt_api_key / decrypt_api_key ────────────────────────────────────────

def test_encrypt_decrypt_api_key_roundtrip(vek):
    blob, iv = encrypt_api_key(vek, "OpenAI", "sk-abc123", "read-only")
    result = decrypt_api_key(vek, blob, iv)
    assert result["service"] == "OpenAI"
    assert result["api_key"] == "sk-abc123"
    assert result["notes"] == "read-only"


def test_decrypt_api_key_raises_on_wrong_key(vek):
    blob, iv = encrypt_api_key(vek, "OpenAI", "sk-abc123")
    with pytest.raises(InvalidTag):
        decrypt_api_key(bytes(32), blob, iv)


def test_encrypt_api_key_unique_ivs(vek):
    _, iv1 = encrypt_api_key(vek, "OpenAI", "key1")
    _, iv2 = encrypt_api_key(vek, "OpenAI", "key1")
    assert iv1 != iv2


# ── encrypt_vek / decrypt_vek ─────────────────────────────────────────────────

def test_encrypt_decrypt_vek_roundtrip(vek):
    login_key = bytes(range(32))
    blob, iv = encrypt_vek(login_key, vek)
    recovered = decrypt_vek(login_key, blob, iv)
    assert bytes(recovered) == vek


def test_decrypt_vek_raises_on_wrong_key(vek):
    login_key = bytes(range(32))
    blob, iv = encrypt_vek(login_key, vek)
    with pytest.raises(InvalidTag):
        decrypt_vek(bytes(32), blob, iv)


# ── wipe ──────────────────────────────────────────────────────────────────────

def test_wipe_zeros_all_bytes():
    buf = bytearray(b"supersecretdata1234")
    wipe(buf)
    assert all(b == 0 for b in buf)


def test_wipe_empty_bytearray_is_safe():
    wipe(bytearray())  # must not raise


# ── generate_vek ──────────────────────────────────────────────────────────────

def test_generate_vek_returns_32_bytes():
    assert len(generate_vek()) == 32


def test_generate_vek_is_random():
    # Two consecutive calls must differ (astronomically unlikely to collide)
    assert generate_vek() != generate_vek()


# ── generate_recovery_codes ───────────────────────────────────────────────────

_CODE_RE = re.compile(r"^[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}$")


def test_generate_recovery_codes_default_count():
    assert len(generate_recovery_codes()) == 8


def test_generate_recovery_codes_custom_count():
    assert len(generate_recovery_codes(count=4)) == 4


def test_generate_recovery_codes_format():
    for code in generate_recovery_codes():
        assert _CODE_RE.match(code), f"Bad format: {code!r}"


def test_generate_recovery_codes_are_unique():
    codes = generate_recovery_codes()
    assert len(set(codes)) == len(codes)


# ── encrypt_master_with_code / decrypt_master_with_code ──────────────────────

def test_encrypt_decrypt_master_with_code_roundtrip():
    code = "A1B2-C3D4-E5F6"
    master = "a" * 64
    enc, iv, salt = encrypt_master_with_code(code, master)
    assert decrypt_master_with_code(code, enc, iv, salt) == master


def test_decrypt_master_with_wrong_code_raises():
    enc, iv, salt = encrypt_master_with_code("GOOD-C0DE-ABCD", "a" * 64)
    with pytest.raises(InvalidTag):
        decrypt_master_with_code("BADC-0DE0-0000", enc, iv, salt)


def test_encrypt_master_produces_unique_salts():
    code = "A1B2-C3D4-E5F6"
    _, _, salt1 = encrypt_master_with_code(code, "master")
    _, _, salt2 = encrypt_master_with_code(code, "master")
    assert salt1 != salt2


# ── hash_recovery_code ────────────────────────────────────────────────────────

def test_hash_recovery_code_returns_argon2_phc_string():
    hashed = hash_recovery_code("A1B2-C3D4-E5F6")
    assert hashed.startswith("$argon2")


def test_hash_recovery_code_two_hashes_differ():
    # Argon2 embeds a random salt, so the same input hashes differently each time
    h1 = hash_recovery_code("A1B2-C3D4-E5F6")
    h2 = hash_recovery_code("A1B2-C3D4-E5F6")
    assert h1 != h2
