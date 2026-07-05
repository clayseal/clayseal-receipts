"""Encrypt Biscuit root private keys at rest."""

from __future__ import annotations

from .secret_encryption import (
    decrypt_secret,
    encrypt_secret,
    encryption_enabled,
    is_encrypted_value,
)

BISCUIT_CONTEXT = "biscuit_root_ed25519_v1"


def is_encrypted_private_hex(stored: str) -> bool:
    return is_encrypted_value(stored)


def is_plaintext_private_hex(stored: str) -> bool:
    if is_encrypted_private_hex(stored):
        return False
    try:
        raw = bytes.fromhex(stored)
    except ValueError:
        return False
    return len(raw) == 32


def encrypt_private_hex(plaintext_hex: str) -> str:
    return encrypt_secret(plaintext_hex, context=BISCUIT_CONTEXT)


def decrypt_private_hex(stored: str) -> str:
    if is_plaintext_private_hex(stored):
        if encryption_enabled():
            raise ValueError(
                "refusing to load plaintext Biscuit root key while secret encryption is enabled"
            )
        return stored
    return decrypt_secret(stored, context=BISCUIT_CONTEXT)


def maybe_reencrypt_biscuit_root_key(db, root_key) -> None:
    if not encryption_enabled() or is_encrypted_private_hex(root_key.private_hex):
        return
    root_key.private_hex = encrypt_private_hex(root_key.private_hex)
    db.add(root_key)
    db.commit()
    db.refresh(root_key)
