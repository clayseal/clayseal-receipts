"""Tests for Biscuit root key encryption."""

from __future__ import annotations

import pytest

from agentauth.backend import capabilities as cap_service
from agentauth.backend.biscuit_keys import (
    decrypt_private_hex,
    encrypt_private_hex,
    is_encrypted_private_hex,
    maybe_reencrypt_biscuit_root_key,
)
from agentauth.backend.db import SessionLocal
from agentauth.backend.models import BiscuitRootKey, Customer


def test_create_root_key_stores_encrypted_private_hex(customer):
    with SessionLocal() as db:
        key = cap_service.create_root_key(db, customer["customer_id"])
        assert is_encrypted_private_hex(key.private_hex)
        plain = decrypt_private_hex(key.private_hex)
        assert len(bytes.fromhex(plain)) == 32


def test_maybe_reencrypt_biscuit_root_key_upgrades_legacy_plaintext(customer):
    with SessionLocal() as db:
        cust = db.get(Customer, customer["customer_id"])
        legacy = BiscuitRootKey(
            kid="legacy-biscuit",
            customer_id=cust.id,
            private_hex="11" * 32,
            public_hex="22" * 32,
            algorithm="ed25519",
            status="active",
        )
        db.add(legacy)
        db.commit()
        db.refresh(legacy)
        maybe_reencrypt_biscuit_root_key(db, legacy)
        db.refresh(legacy)
        assert is_encrypted_private_hex(legacy.private_hex)
        assert decrypt_private_hex(legacy.private_hex) == "11" * 32


def test_encrypt_decrypt_roundtrip():
    plain = "aa" * 32
    stored = encrypt_private_hex(plain)
    assert decrypt_private_hex(stored) == plain


def test_decrypt_private_hex_refuses_plaintext_when_encryption_enabled():
    with pytest.raises(ValueError, match="refusing to load plaintext Biscuit root key"):
        decrypt_private_hex("aa" * 32)
