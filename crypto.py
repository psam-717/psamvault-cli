import ctypes
import hashlib
import json
import hmac
import os

from argon2 import PasswordHasher
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_ph = PasswordHasher(
    time_cost=2,
    memory_cost=65536,
    parallelism=2,
    hash_len=32,
    salt_len=16
)


def wipe(buf: bytearray) -> None:
    """
    Overwrite a bytearray's contents with zeros in-place.

    This is best-effort — Python may have already copied the data internally,
    and string/bytes objects cannot be wiped. Use for bytearrays holding
    key material after they are no longer needed.
    """
    if buf:
        ctypes.memset(ctypes.addressof(ctypes.c_char.from_buffer(buf)), 0, len(buf))

def derive_master_password(login_password: str) -> str:
    """
    Derive a strong master password from the user's login password.
 
    Uses HMAC-SHA256 keyed with a per-device pepper so the result is:
      - Always 64 hex characters (256 bits) regardless of login password strength
      - Completely different from the login password itself
      - Not guessable even if an attacker knows the derivation scheme,
        because they would also need the pepper value
 
    This frees the user from remembering two passwords. They only ever
    type their login password — the master password is derived automatically
    and never shown or stored in plaintext anywhere.
 
    Args:
        login_password: The raw login password typed by the user.
 
    Returns:
        A 64-character hex string used as the master password for key
        derivation. Never transmitted to the server.
 
    Example:
        login_password  -> "mphil7177214"
        master_password -> "a3f8c2d1e9b47f6c..." (64 hex chars, always)
    """
    return hmac.new(
        key=os.getenv("PSAMVAULT_PEPPER", "").encode("utf-8"),
        msg=login_password.encode("utf-8"),
        digestmod=hashlib.sha256
    ).hexdigest()
    


def derive_key(master_password: str, kdf_salt: str) -> bytearray:
    """
    Derive a 256-bit AES encryption key from the master password and kdf_salt.

    Uses PBKDF2-HMAC-SHA256 with 600,000 iterations (NIST recommended minimum).
    The kdf_salt is fetched from the server at login and stored locally —
    it ensures two users with the same master password get different keys.

    Args:
        master_password: The raw master password string typed by the user.
        kdf_salt:        Hex-encoded salt string from the server (stored in session).

    Returns:
        A 32-byte bytearray — the AES-256 encryption key. Call wipe() after use.
        Never store or transmit this.
    """
    return bytearray(hashlib.pbkdf2_hmac(
        hash_name="sha256",
        password=master_password.encode("utf-8"),
        salt=bytes.fromhex(kdf_salt),
        iterations=600_000,
        dklen=32
    ))


def encrypt_credentials(
    key: bytes,
    username: str,
    password: str,
    notes: str = ""
) -> tuple[str, str]:
    """
    Encrypt a credential bundle using AES-256-GCM.
 
    Bundles username, password, and optional notes into a single JSON payload
    before encrypting so the entire object is protected as one unit.
 
    A fresh random IV is generated on every call — never reuse an IV with
    the same key, as this breaks AES-GCM's security guarantees.
 
    Args:
        key:      32-byte encryption key from derive_key().
        username: Plaintext username or email for the site.
        password: Plaintext password for the site.
        notes:    Optional plaintext notes (default empty string).
 
    Returns:
        A tuple of (encrypted_blob_hex, iv_hex) — both hex-encoded strings
        ready to be sent as JSON to the API.
    """
    payload = json.dumps({
        "username": username,
        "password": password,
        "notes": notes,
    }).encode("utf-8")
    
    iv = os.urandom(12)
    
    aesgcm = AESGCM(key)
    encrypted_blob = aesgcm.encrypt(iv, payload, None)
    
    return encrypted_blob.hex(), iv.hex()


def decrypt_credentials(
    key: bytes,
    encrypted_blob: str,
    iv: str,
) -> dict:
    """
    Decrypt a credential bundle using AES-256-GCM.
 
    AES-GCM is authenticated encryption — if the ciphertext or IV has been
    tampered with, decryption raises an InvalidTag exception rather than
    returning corrupt data silently.
 
    Args:
        key:            32-byte encryption key from derive_key().
        encrypted_blob: Hex-encoded ciphertext string from the API response.
        iv:             Hex-encoded IV string from the API response.
 
    Returns:
        A dict with keys: username, password, notes.
 
    Raises:
        cryptography.exceptions.InvalidTag: If decryption fails due to a
        wrong key or tampered ciphertext.
    """
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(
        bytes.fromhex(iv),
        bytes.fromhex(encrypted_blob),
        None
    )
    return json.loads(plaintext.decode("utf-8"))

# recovery code helpers

def generate_recovery_codes(count: int = 8) -> list[str]:
    """
    Generate a set of cryptographically secure recovery codes.
 
    Each code is formatted as XXXX-XXXX-XXXX (groups of 4 uppercase hex
    characters) — easy to read and write down, hard to guess.
 
    Args:
        count: Number of codes to generate (default 8).
 
    Returns:
        A list of raw code strings shown to the user once and never stored.
    """
    codes = []
    for _ in range(count):
        raw = os.urandom(6).hex().upper()
        formatted = f"{raw[0:4]}-{raw[4:8]}-{raw[8:12]}"
        codes.append(formatted)
    return codes


def encrypt_master_with_code(
    recovery_code: str,
    master_password: str
) -> tuple[str, str, str]:
    """
    Encrypt the master password using a recovery code as the AES key.

    A fresh random 16-byte salt is generated per call so that two codes with
    the same value produce different AES keys, preventing cross-code attacks.

    Args:
        recovery_code:   Raw recovery code string (e.g. "A1B2-C3D4-E5F6").
        master_password: The user's master password hex string to protect.

    Returns:
        A tuple of (encrypted_master_hex, iv_hex, salt_hex).
    """
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac(
        hash_name="sha256",
        password=recovery_code.encode("utf-8"),
        salt=salt,
        iterations=100_000,
        dklen=32
    )

    iv = os.urandom(12)
    aesgcm = AESGCM(key)
    encrypted = aesgcm.encrypt(iv, master_password.encode("utf-8"), None)

    return encrypted.hex(), iv.hex(), salt.hex()


def decrypt_master_with_code(
    recovery_code: str,
    encrypted_master: str,
    iv: str,
    salt: str
) -> str:
    """
    Decrypt the master password using a recovery code.

    Args:
        recovery_code:    Raw recovery code typed by the user.
        encrypted_master: Hex-encoded ciphertext from the server.
        iv:               Hex-encoded IV from the server.
        salt:             Hex-encoded per-code PBKDF2 salt from the server.

    Returns:
        The plaintext master password string.

    Raises:
        cryptography.exceptions.InvalidTag: If the recovery code is wrong.
    """
    key = hashlib.pbkdf2_hmac(
        hash_name="sha256",
        password=recovery_code.encode("utf-8"),
        salt=bytes.fromhex(salt),
        iterations=100_000,
        dklen=32
    )

    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(
        bytes.fromhex(iv),
        bytes.fromhex(encrypted_master),
        None
    )
    return plaintext.decode("utf-8")

def hash_recovery_code(raw_code: str) -> str:
    """
    Hash a recovery code with Argon2id for secure server-side storage.

    Using Argon2id (memory-hard) instead of SHA-256 makes brute-forcing
    stolen hashes computationally infeasible. The PHC string returned
    includes the salt and parameters, so no separate salt column is needed.

    Args:
        raw_code: The raw recovery code string (e.g. "A1B2-C3D4-E5F6").

    Returns:
        An Argon2id PHC string (~97 chars) safe to store in the DB.
    """
    return _ph.hash(raw_code)


def generate_vek() -> bytes:
    """Generate a cryptographically random 32-byte Vault Encryption Key."""
    return os.urandom(32)


def encrypt_vek(login_key: bytes, vek: bytes) -> tuple[str, str]:
    """
    Encrypt the VEK with the login-derived key using AES-256-GCM.

    Called at signup and again after a password reset to wrap the VEK
    with the new login key. The encrypted result is stored on the server.

    Args:
        login_key: 32-byte key from derive_key(derive_master_password(pw), kdf_salt).
        vek:       32-byte raw Vault Encryption Key.

    Returns:
        (encrypted_vek_hex, vek_iv_hex) — hex strings safe to send as JSON.
    """
    iv = os.urandom(12)
    aesgcm = AESGCM(login_key)
    encrypted = aesgcm.encrypt(iv, vek, None)
    return encrypted.hex(), iv.hex()


def decrypt_vek(login_key: bytes, encrypted_vek: str, vek_iv: str) -> bytearray:
    """
    Decrypt the VEK using the login-derived key.

    Called at login to recover the raw VEK from the server's encrypted copy.

    Args:
        login_key:     32-byte key from derive_key(derive_master_password(pw), kdf_salt).
        encrypted_vek: Hex-encoded ciphertext from the server.
        vek_iv:        Hex-encoded IV from the server.

    Returns:
        A 32-byte bytearray — the Vault Encryption Key. Call wipe() after use.

    Raises:
        cryptography.exceptions.InvalidTag: If the login key is wrong.
    """
    aesgcm = AESGCM(login_key)
    return bytearray(aesgcm.decrypt(
        bytes.fromhex(vek_iv),
        bytes.fromhex(encrypted_vek),
        None
    ))
    
    
    
def encrypt_api_key(
    key: bytes,
    service: str,
    api_key: str,
    notes: str = ""
) -> tuple[str, str]:
    """
    Encrypt an API key bundle using AES-256-GCM.
 
    Bundles service name, the raw API key, and optional notes into a single
    JSON payload before encrypting — same pattern as encrypt_credentials().
 
    Args:
        key:     32-byte VEK from the session.
        service: Human-readable service name, e.g. "OpenAI".
        api_key: The plaintext API key string.
        notes:   Optional notes, e.g. "read-only, expires 2025-12".
 
    Returns:
        (encrypted_blob_hex, iv_hex)
    """
    payload = json.dumps({
        "service": service,
        "api_key": api_key,
        "notes": notes
    }).encode("utf-8")
    
    iv= os.urandom(12)
    aesgcm = AESGCM(key)
    encrypted_blob = aesgcm.encrypt(iv, payload, None)
    
    return encrypted_blob.hex(), iv.hex()


def decrypt_api_key(
    key: bytes,
    encrypted_blob: str,
    iv: str
) -> dict:
    """
     Decrypt an API key bundle using AES-256-GCM.
 
    Args:
        key:            32-byte VEK from the session.
        encrypted_blob: Hex-encoded ciphertext from the API response.
        iv:             Hex-encoded IV from the API response.
 
    Returns:
        A dict with keys: service, api_key, notes.
 
    Raises:
        cryptography.exceptions.InvalidTag: If decryption fails
    """
    aesgcm= AESGCM(key)
    plaintext= aesgcm.decrypt(
        bytes.fromhex(iv),
        bytes.fromhex(encrypted_blob),
        None
    )
    return json.loads(plaintext.decode("utf-8"))