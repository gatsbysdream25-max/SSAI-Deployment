"""Optional storage of API keys in the operating system's key vault (consensus plan section 9.6).

Windows Credential Manager, macOS Keychain or the Linux Secret Service, through the `keyring` package. A provider entry may name a
vault item with "key_ref": "ssai/moonshot"; the key is then read from the vault when the environment variable named by "key_env" is
not set. Keys never go in the config file, in logs, in SQLite or in git; the environment variable still wins, so every existing
.env file keeps working unchanged.

This module only READS and manages vault items on request. Nothing is migrated automatically: moving a key is the operator's act.
If `keyring` is not installed (or no vault is available, as on a headless server) every call quietly returns "no key".
"""
from __future__ import annotations

import logging

log = logging.getLogger("keyvault")
SERVICE = "ssai"


def _keyring():
    try:
        import keyring
        return keyring
    except Exception:                                            # noqa: BLE001 -- not installed, or no usable backend
        return None


def available() -> bool:
    kr = _keyring()
    if kr is None:
        return False
    try:
        return "fail" not in type(kr.get_keyring()).__module__.lower()
    except Exception:                                            # noqa: BLE001
        return False


def get(ref: str) -> str:
    """The stored key for `ref`, or '' (not stored, no vault, vault locked). Never raises and never logs the value."""
    kr = _keyring()
    if kr is None or not ref:
        return ""
    try:
        return (kr.get_password(SERVICE, ref) or "").strip()
    except Exception as exc:                                     # noqa: BLE001
        log.warning(f"key vault could not be read for {ref}: {type(exc).__name__}")
        return ""


def put(ref: str, value: str) -> bool:
    """Store a secret in the operating system's key store under this name. Returns True if it was saved, False if it
    could not be."""
    kr = _keyring()
    if kr is None or not ref or not value:
        return False
    try:
        kr.set_password(SERVICE, ref, value)
        return True
    except Exception as exc:                                     # noqa: BLE001
        log.warning(f"key vault could not store {ref}: {type(exc).__name__}")
        return False


def remove(ref: str) -> bool:
    """Delete a stored secret from the operating system's key store. Returns True if it was deleted, False if it was not
    there or could not be."""
    kr = _keyring()
    if kr is None or not ref:
        return False
    try:
        kr.delete_password(SERVICE, ref)
        return True
    except Exception:                                            # noqa: BLE001 -- nothing stored is also fine
        return False


def last4(value: str) -> str:
    """How a key is ever shown on screen: the last four characters only."""
    return ("..." + value[-4:]) if value and len(value) >= 8 else ("set" if value else "")
