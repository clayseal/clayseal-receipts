"""RFC 9180 HPKE base mode — DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM.

Used for **confidential receipts** (SOTA-11): seal a sensitive receipt payload to a
recipient's public key so the transparency log and witnesses see only ciphertext, while
the signed statement + COSE Receipt still prove it was logged. This is the HPKE-seal
pattern of the "Notarized Agents" comparable (SOTA-16) and complements the in-circuit
confidential proofs (SOTA-9).

Implemented from primitives (no HPKE library available) and **validated against the RFC
9180 §A.1 test vector** in ``test_hpke.py`` — so this is interoperable, not just
self-consistent.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

# Ciphersuite identifiers (RFC 9180 §7).
KEM_ID = 0x0020  # DHKEM(X25519, HKDF-SHA256)
KDF_ID = 0x0001  # HKDF-SHA256
AEAD_ID = 0x0001  # AES-128-GCM
_NSECRET = 32
_NK = 16  # AES-128 key
_NN = 12  # GCM nonce
_HASH = 32  # SHA-256 output


def _i2osp(n: int, length: int) -> bytes:
    return n.to_bytes(length, "big")


def _suite_id(kem_only: bool) -> bytes:
    if kem_only:
        return b"KEM" + _i2osp(KEM_ID, 2)
    return b"HPKE" + _i2osp(KEM_ID, 2) + _i2osp(KDF_ID, 2) + _i2osp(AEAD_ID, 2)


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract = HMAC(salt, ikm); empty salt is zeros of the hash length."""
    h = hmac.HMAC(salt or (b"\x00" * _HASH), hashes.SHA256())
    h.update(ikm)
    return h.finalize()


def _labeled_extract(salt: bytes, label: bytes, ikm: bytes, *, kem: bool) -> bytes:
    labeled_ikm = b"HPKE-v1" + _suite_id(kem) + label + ikm
    return _hkdf_extract(salt, labeled_ikm)


def _labeled_expand(
    prk: bytes, label: bytes, info: bytes, length: int, *, kem: bool
) -> bytes:
    labeled_info = _i2osp(length, 2) + b"HPKE-v1" + _suite_id(kem) + label + info
    return HKDFExpand(SHA256(), length, info=labeled_info).derive(prk)


def _extract_and_expand(dh: bytes, kem_context: bytes) -> bytes:
    eae_prk = _labeled_extract(b"", b"eae_prk", dh, kem=True)
    return _labeled_expand(eae_prk, b"shared_secret", kem_context, _NSECRET, kem=True)


def _encap(pk_r: bytes, *, eph_private: X25519PrivateKey | None = None) -> tuple[bytes, bytes]:
    sk_e = eph_private or X25519PrivateKey.generate()
    pk_e = sk_e.public_key().public_bytes_raw()
    dh = sk_e.exchange(X25519PublicKey.from_public_bytes(pk_r))
    shared_secret = _extract_and_expand(dh, pk_e + pk_r)
    return shared_secret, pk_e


def _decap(enc: bytes, sk_r: X25519PrivateKey) -> bytes:
    dh = sk_r.exchange(X25519PublicKey.from_public_bytes(enc))
    pk_r = sk_r.public_key().public_bytes_raw()
    return _extract_and_expand(dh, enc + pk_r)


def _key_schedule_base(shared_secret: bytes, info: bytes) -> tuple[bytes, bytes]:
    psk_id_hash = _labeled_extract(b"", b"psk_id_hash", b"", kem=False)
    info_hash = _labeled_extract(b"", b"info_hash", info, kem=False)
    ks_context = b"\x00" + psk_id_hash + info_hash  # mode_base = 0x00
    secret = _labeled_extract(shared_secret, b"secret", b"", kem=False)
    key = _labeled_expand(secret, b"key", ks_context, _NK, kem=False)
    base_nonce = _labeled_expand(secret, b"base_nonce", ks_context, _NN, kem=False)
    return key, base_nonce


def seal_base(
    pk_r: bytes,
    plaintext: bytes,
    *,
    info: bytes = b"",
    aad: bytes = b"",
    eph_private: X25519PrivateKey | None = None,
) -> tuple[bytes, bytes]:
    """Single-shot HPKE SealBase. Returns ``(enc, ciphertext)``.

    ``eph_private`` injects the ephemeral key for test-vector reproduction; production
    callers omit it for a fresh ephemeral key per message.
    """
    shared_secret, enc = _encap(pk_r, eph_private=eph_private)
    key, base_nonce = _key_schedule_base(shared_secret, info)
    ciphertext = AESGCM(key).encrypt(base_nonce, plaintext, aad)
    return enc, ciphertext


def open_base(
    enc: bytes,
    sk_r: X25519PrivateKey,
    ciphertext: bytes,
    *,
    info: bytes = b"",
    aad: bytes = b"",
) -> bytes:
    """Single-shot HPKE OpenBase. Returns the plaintext (raises on auth failure)."""
    shared_secret = _decap(enc, sk_r)
    key, base_nonce = _key_schedule_base(shared_secret, info)
    return AESGCM(key).decrypt(base_nonce, ciphertext, aad)
