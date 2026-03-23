import hashlib
import json
import hmac
import os
from dotenv import load_dotenv

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
load_dotenv()

_PEPPER =  os.getenv("PSAMVAULT_PEPPER")

def derive_master_password(login_password: str) -> str:
    """
    Derive a strong master password from the user's login password.
 
    Uses HMAC-SHA256 keyed with a server-side pepper so the result is:
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
        key=_PEPPER.encode("utf-8"),
        msg=login_password.encode("utf-8"),
        digestmod=hashlib.sha256
    ).hexdigest()
    


def derive_key(master_password: str, kdf_salt: str) -> bytes:
    """
    Derive a 256-bit AES encryption key from the master password and kdf_salt.
 
    Uses PBKDF2-HMAC-SHA256 with 600,000 iterations (NIST recommended minimum).
    The kdf_salt is fetched from the server at login and stored locally —
    it ensures two users with the same master password get different keys.
 
    Args:
        master_password: The raw master password string typed by the user.
        kdf_salt:        Hex-encoded salt string from the server (stored in session).
 
    Returns:
        32 raw bytes — the AES-256 encryption key. Never store or transmit this.
    """
    return hashlib.pbkdf2_hmac(
        hash_name="sha256",
        password=master_password.encode("utf-8"),
        salt=bytes.fromhex(kdf_salt),
        iterations=600_000,
        dklen=32
    )


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
) -> tuple[str, str]:
    """
    Encrypt the master password using a recovery code as the AES key.
 
    The recovery code is hashed with PBKDF2 to produce a proper 256-bit key
    before encryption — raw recovery codes are too short to use directly.
 
    Args:
        recovery_code:   Raw recovery code string (e.g. "A1B2-C3D4-E5F6").
        master_password: The user's master password hex string to protect.
 
    Returns:
        A tuple of (encrypted_master_hex, iv_hex).
    """
    key = hashlib.pbkdf2_hmac(
        hash_name= "sha256",
        password= recovery_code.encode("utf-8"),
        salt= b"psamvault-recovery-salt",
        iterations=100_000,
        dklen=32
    )
    
    iv = os.urandom(12)
    aesgcm = AESGCM(key)
    encrypted = aesgcm.encrypt(iv, master_password.encode("utf-8"), None)
    
    return encrypted.hex(), iv.hex()


def decrypt_master_with_code(
    recovery_code: str,
    encrypted_master: str,
    iv: str
) -> str:
    """
    Decrypt the master password using a recovery code.
 
    Args:
        recovery_code:    Raw recovery code typed by the user.
        encrypted_master: Hex-encoded ciphertext from the server.
        iv:               Hex-encoded IV from the server.
 
    Returns:
        The plaintext master password string.
 
    Raises:
        cryptography.exceptions.InvalidTag: If the recovery code is wrong.
    """
    key = hashlib.pbkdf2_hmac(
        hash_name="sha256",
        password=recovery_code.encode("utf-8"),
        salt=b"psamvault-recovery-salt",
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
    return hashlib.sha256(raw_code.encode()).hexdigest()
    
    
    