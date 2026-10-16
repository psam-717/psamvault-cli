import os
import secrets
from pathlib import Path

import keyring

import keychain

_SERVICE = "psamvault"
_PEPPER_KEY = "config.pepper"

CONFIG_DIR = Path.home() / ".psamvault"
CONFIG_FILE = CONFIG_DIR / "config.env"

REQUIRED_KEYS = ["PSAMVAULT_API_URL", "PSAMVAULT_PEPPER"]

DEFAULT_API_URL = "https://psam-vault-backend.onrender.com"


def generate_pepper() -> str:
    """
    Generate a cryptographically secure 64-character hex pepper.

    The pepper is unique per user/device. It is combined with the login
    password via HMAC-SHA256 to produce the master password, ensuring
    that even if two users share the same login password their vault
    encryption keys are completely different.

    Returns:
        A 64-character hex string — 32 random bytes encoded as hex.
    """
    return secrets.token_hex(32)


def _config_entries() -> list[tuple[str, str]]:
    """Non-comment ``KEY=value`` rows from config.env. Empty when the file is absent."""
    if not CONFIG_FILE.exists():
        return []
    entries: list[tuple[str, str]] = []
    for line in CONFIG_FILE.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if key:
            entries.append((key, value))
    return entries


def _legacy_pepper() -> str | None:
    """Pepper left in config.env by an install from before the keychain migration."""
    for key, value in _config_entries():
        if key == "PSAMVAULT_PEPPER" and value:
            return value
    return None


def _notice_pepper_disagrees() -> None:
    """The file pepper and the keychain pepper are both real, and they differ.

    The file line stays. The notice does not include either value.
    """
    import typer

    typer.echo(
        "\n⚠ The OS keychain already holds a different pepper from the "
        "PSAMVAULT_PEPPER line in config.env — the keychain pepper is the one "
        "in use, and the file line was left in place. Remove that line only "
        "after you have confirmed which pepper this machine should keep.\n",
        err=True,
    )


def _remove_pepper_from_config_file() -> None:
    """Rewrite config.env without the PSAMVAULT_PEPPER line (migration helper)."""
    lines = CONFIG_FILE.read_text().splitlines()
    filtered = [line for line in lines if not line.strip().startswith("PSAMVAULT_PEPPER")]
    CONFIG_FILE.write_text("\n".join(filtered) + "\n")
    os.chmod(CONFIG_FILE, 0o600)


def load_public_config() -> None:
    """
    Load non-secret config.env values into os.environ.

    Never reads or writes the OS keychain. ``--version`` and ``--help`` call
    this at startup; they must not touch the keychain, because a missing
    Secret Service raises and a locked one can block on a GUI prompt.

    A legacy ``PSAMVAULT_PEPPER`` line is left in the file. It is moved to
    the keychain later, by :func:`load_pepper`, and only after the keychain
    has confirmed it stored the value. It is not loaded into the environment
    from disk.
    """
    for key, value in _config_entries():
        if key == "PSAMVAULT_PEPPER":
            continue
        # A real environment variable always wins over the config file.
        if value and key not in os.environ:
            os.environ[key] = value


def load_pepper() -> None:
    """
    Load the pepper from the OS keychain into os.environ.

    Migrates a legacy config.env pepper first: the keychain write has to
    read back the same value before the line is removed from the file. If
    the keychain cannot keep it, the line stays and the command stops.
    If the keychain already holds a different pepper, the file line stays
    and a notice is printed — that line is not discarded. The pepper is
    never copied to a new file.

    A ``PSAMVAULT_PEPPER`` already in the environment wins over the keychain
    once any legacy file line has been migrated. The environment variable
    does not replace the keychain for session tokens.
    """
    legacy = _legacy_pepper()
    if legacy is not None:
        existing = keychain.call(keyring.get_password, _SERVICE, _PEPPER_KEY)
        if not existing:
            keychain.call(keyring.set_password, _SERVICE, _PEPPER_KEY, legacy)
            existing = keychain.call(keyring.get_password, _SERVICE, _PEPPER_KEY)
            if existing != legacy:
                # Nothing was stored. Leave the file line so the only copy is not deleted.
                keychain.abort(keychain.NOT_KEPT)
            _remove_pepper_from_config_file()
            if not os.environ.get("PSAMVAULT_PEPPER"):
                os.environ["PSAMVAULT_PEPPER"] = existing
            return
        if existing != legacy:
            # The keychain pepper is the one this install has been using.
            # Deleting the file line would throw away the only other copy.
            _notice_pepper_disagrees()
            if not os.environ.get("PSAMVAULT_PEPPER"):
                os.environ["PSAMVAULT_PEPPER"] = existing
            return
        _remove_pepper_from_config_file()
        if not os.environ.get("PSAMVAULT_PEPPER"):
            os.environ["PSAMVAULT_PEPPER"] = existing
        return

    if os.environ.get("PSAMVAULT_PEPPER"):
        return

    pepper = keychain.call(keyring.get_password, _SERVICE, _PEPPER_KEY)
    if pepper and "PSAMVAULT_PEPPER" not in os.environ:
        os.environ["PSAMVAULT_PEPPER"] = pepper


def load_config() -> None:
    """
    Load config into os.environ so that api_client.py and crypto.py pick
    them up via os.getenv().

    PSAMVAULT_API_URL is read from config.env (non-sensitive).
    PSAMVAULT_PEPPER is read from the OS keychain (sensitive).

    Migrates automatically from the old all-in-config.env format when a
    command needs the pepper: if config.env contains PSAMVAULT_PEPPER, it is
    moved to the keychain and removed from the file only after the keychain
    read-back matches.

    Not called at import. main.py calls :func:`load_public_config` so that
    ``--version`` and ``--help`` never touch the keychain. Commands that
    need the pepper call this via :func:`is_configured` or :func:`get_config`.
    """
    load_public_config()
    load_pepper()


def save_config(api_url: str, pepper: str) -> None:
    """
    Write PSAMVAULT_API_URL to config.env (non-sensitive) and store
    PSAMVAULT_PEPPER in the OS keychain.

    The file is written only after the keychain read-back matches. A null
    backend and a missing keychain both fail here, and neither leaves the
    pepper on disk.

    Args:
        api_url: The base URL of the psamvault backend API.
        pepper:  The HMAC pepper used to derive the master password.
    """
    keychain.call(keyring.set_password, _SERVICE, _PEPPER_KEY, pepper)
    stored = keychain.call(keyring.get_password, _SERVICE, _PEPPER_KEY)
    if stored != pepper:
        keychain.abort(keychain.NOT_KEPT)

    CONFIG_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)

    content = (
        "# psamvault configuration\n"
        "# Generated by  psamvault configure\n"
        "\n"
        f"PSAMVAULT_API_URL={api_url}\n"
    )

    CONFIG_FILE.write_text(content)
    os.chmod(CONFIG_FILE, 0o600)


def is_configured() -> bool:
    """
    Return True if both required config values are available —
    either from the config file/keychain or from real environment variables.
    """
    load_config()
    return all(os.getenv(k) for k in REQUIRED_KEYS)


def get_config() -> dict:
    """
    Return the current config values as a dict.
    Loads the config file first so values are always fresh.
    """
    load_config()
    return {k: os.getenv(k, "") for k in REQUIRED_KEYS}
