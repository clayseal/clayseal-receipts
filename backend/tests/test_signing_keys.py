"""Tests for at-rest signing key encryption."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from agentauth.backend.db import SessionLocal
from agentauth.backend.identity import create_signing_key, get_active_key
from agentauth.backend.models import Customer, SigningKey
from agentauth.backend.signing_keys import (
    decrypt_private_pem,
    encrypt_private_pem,
    is_encrypted_private_pem,
    maybe_reencrypt_signing_key,
)


def test_create_signing_key_stores_encrypted_private_pem(customer):
    with SessionLocal() as db:
        key = create_signing_key(db, customer["customer_id"])
        assert is_encrypted_private_pem(key.private_pem)
        assert "BEGIN" not in key.private_pem
        pem = decrypt_private_pem(key.private_pem)
        assert "BEGIN PRIVATE KEY" in pem
        assert key.algorithm == "EdDSA"
        public_key = serialization.load_pem_public_key(key.public_pem.encode())
        assert isinstance(public_key, ed25519.Ed25519PublicKey)


def test_maybe_reencrypt_signing_key_upgrades_legacy_plaintext(customer):
    with SessionLocal() as db:
        cust = db.get(Customer, customer["customer_id"])
        legacy = SigningKey(
            kid="legacy-kid",
            customer_id=cust.id,
            private_pem="-----BEGIN PRIVATE KEY-----\nlegacy\n-----END PRIVATE KEY-----\n",
            public_pem="-----BEGIN PUBLIC KEY-----\nlegacy\n-----END PUBLIC KEY-----\n",
            algorithm="EdDSA",
            status="active",
        )
        db.add(legacy)
        db.commit()
        db.refresh(legacy)
        maybe_reencrypt_signing_key(db, legacy)
        db.refresh(legacy)
        assert is_encrypted_private_pem(legacy.private_pem)
        assert decrypt_private_pem(legacy.private_pem).startswith("-----BEGIN PRIVATE KEY-----")


def test_get_active_key_replaces_legacy_rsa_signing_key(customer):
    with SessionLocal() as db:
        cust = db.get(Customer, customer["customer_id"])
        current = get_active_key(db, cust.id)
        current.status = "retired"
        db.add(current)
        db.commit()
        legacy = SigningKey(
            kid="legacy-rsa-kid",
            customer_id=cust.id,
            private_pem="-----BEGIN PRIVATE KEY-----\nlegacy\n-----END PRIVATE KEY-----\n",
            public_pem="-----BEGIN PUBLIC KEY-----\nlegacy\n-----END PUBLIC KEY-----\n",
            algorithm="RS256",
            status="active",
        )
        db.add(legacy)
        db.commit()

        key = get_active_key(db, cust.id)
        db.refresh(legacy)

        assert legacy.status == "retired"
        assert key.kid != legacy.kid
        assert key.algorithm == "EdDSA"


def test_encrypt_decrypt_roundtrip():
    pem = "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n"
    stored = encrypt_private_pem(pem)
    assert decrypt_private_pem(stored) == pem


def test_decrypt_private_pem_refuses_plaintext_when_encryption_enabled():
    pem = "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n"
    with pytest.raises(ValueError, match="refusing to load plaintext signing key"):
        decrypt_private_pem(pem)
