"""Encrypt JWT signing private keys at rest."""

from __future__ import annotations

from .secret_encryption import (
    decrypt_secret,
    encrypt_secret,
    encryption_enabled,
    is_encrypted_value,
)

SIGNING_CONTEXT = "signing_ed25519_pem_v1"


def is_encrypted_private_pem(stored: str) -> bool:
    return is_encrypted_value(stored)


def is_plaintext_private_pem(stored: str) -> bool:
    return "BEGIN" in stored and not is_encrypted_private_pem(stored)


def encrypt_private_pem(plaintext: str) -> str:
    return encrypt_secret(plaintext, context=SIGNING_CONTEXT)


def decrypt_private_pem(stored: str) -> str:
    if is_plaintext_private_pem(stored):
        if encryption_enabled():
            raise ValueError(
                "refusing to load plaintext signing key while secret encryption is enabled"
            )
        return stored
    return decrypt_secret(stored, context=SIGNING_CONTEXT)


def maybe_reencrypt_signing_key(db, signing_key) -> None:
    if not encryption_enabled() or is_encrypted_private_pem(signing_key.private_pem):
        return
    signing_key.private_pem = encrypt_private_pem(signing_key.private_pem)
    db.add(signing_key)
    db.commit()
    db.refresh(signing_key)
