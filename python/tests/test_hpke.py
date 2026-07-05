"""HPKE base mode validated against the RFC 9180 §A.1 test vector (SOTA-11)."""

from __future__ import annotations

from agentauth.receipts import hpke
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

# RFC 9180 Appendix A.1: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, base mode.
INFO = bytes.fromhex("4f6465206f6e2061204772656369616e2055726e")
SK_EM = bytes.fromhex("52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736")
ENC = bytes.fromhex("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431")
SK_RM = bytes.fromhex("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8")
PK_RM = bytes.fromhex("3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d")
AAD0 = bytes.fromhex("436f756e742d30")
PT0 = bytes.fromhex("4265617574792069732074727574682c20747275746820626561757479")
CT0 = bytes.fromhex(
    "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a"
)


def test_seal_matches_rfc9180_vector():
    eph = X25519PrivateKey.from_private_bytes(SK_EM)
    enc, ct = hpke.seal_base(PK_RM, PT0, info=INFO, aad=AAD0, eph_private=eph)
    assert enc == ENC  # ephemeral public matches the RFC
    assert ct == CT0  # full key schedule + AEAD match the RFC


def test_open_matches_rfc9180_vector():
    sk_r = X25519PrivateKey.from_private_bytes(SK_RM)
    pt = hpke.open_base(ENC, sk_r, CT0, info=INFO, aad=AAD0)
    assert pt == PT0


def test_random_roundtrip():
    sk_r = X25519PrivateKey.generate()
    pk_r = sk_r.public_key().public_bytes_raw()
    msg = b"confidential receipt payload"
    enc, ct = hpke.seal_base(pk_r, msg, info=b"agent-receipt", aad=b"hdr")
    assert hpke.open_base(enc, sk_r, ct, info=b"agent-receipt", aad=b"hdr") == msg


def test_open_fails_on_wrong_key_or_tamper():
    import pytest

    sk_r = X25519PrivateKey.generate()
    pk_r = sk_r.public_key().public_bytes_raw()
    enc, ct = hpke.seal_base(pk_r, b"secret", info=b"i", aad=b"a")
    # wrong recipient
    with pytest.raises(Exception):  # noqa: B017,PT011 - InvalidTag
        hpke.open_base(enc, X25519PrivateKey.generate(), ct, info=b"i", aad=b"a")
    # tampered ciphertext
    with pytest.raises(Exception):  # noqa: B017,PT011
        hpke.open_base(enc, sk_r, ct[:-1] + bytes([ct[-1] ^ 1]), info=b"i", aad=b"a")
    # wrong aad
    with pytest.raises(Exception):  # noqa: B017,PT011
        hpke.open_base(enc, sk_r, ct, info=b"i", aad=b"different")
