"""Ed25519 workload proof-of-possession helpers.

The workload key is the sender-constraining key for AgentAuth credentials and
Biscuit grants. New bindings use the DPoP-compatible ``cnf.jkt`` shape: a
base64url SHA-256 JWK thumbprint. PoP signatures are request-bound and Ed25519
only; RSA remains only for the prototype's separate node-attestation JWT path.
"""
from __future__ import annotations

import base64
import hashlib
import json
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def load_workload_public_key(pubkey_pem: str) -> ed25519.Ed25519PublicKey:
    """Parse and require an Ed25519 workload public key."""
    public_key = serialization.load_pem_public_key(pubkey_pem.encode())
    if not isinstance(public_key, ed25519.Ed25519PublicKey):
        raise ValueError("workload public key must be Ed25519")
    return public_key


def canonical_public_pem(pubkey_pem: str) -> str:
    """Return a normalized SPKI PEM for a workload public key."""
    public_key = load_workload_public_key(pubkey_pem)
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def public_key_jwk(public_key: ed25519.Ed25519PublicKey) -> dict[str, str]:
    """Return the public JWK members used in an RFC 7638 thumbprint."""
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return {"crv": "Ed25519", "kty": "OKP", "x": _b64u(raw)}


def jwk_thumbprint_for_pem(pubkey_pem: str) -> str:
    """Return the RFC 7638-style JWK SHA-256 thumbprint for a PEM public key."""
    public_key = load_workload_public_key(pubkey_pem)
    jwk = public_key_jwk(public_key)
    canonical = json.dumps(jwk, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return _b64u(hashlib.sha256(canonical).digest())


def keyhash_for_pem(pubkey_pem: str) -> str:
    """Stable workload key id used for new bindings: ``cnf.jkt`` thumbprint."""
    return jwk_thumbprint_for_pem(pubkey_pem)


def token_hash(token: str) -> str:
    """DPoP/WPT-style SHA-256 token hash (base64url, no padding)."""
    return _b64u(hashlib.sha256(token.encode("utf-8")).digest())


def request_pop_message(
    keyhash: str,
    challenge: str,
    *,
    htm: str,
    htu: str,
    ath: str,
    iat: int,
    jti: str,
    operation: tuple[str, str] | None = None,
) -> bytes:
    """Canonical request-shaped PoP bytes.

    This is intentionally close to DPoP/WPT: method, target, token hash, issued
    time, unique proof id, and server nonce. ``operation`` keeps the existing
    resource/action authorization semantics bound into the signed payload.
    """
    payload: dict[str, object] = {
        "ath": ath,
        "cnf": keyhash,
        "htm": htm.upper(),
        "htu": htu,
        "iat": int(iat),
        "jti": jti,
        "nonce": challenge,
        "typ": "agentauth-pop+jwt",
    }
    if operation is not None:
        payload["operation"] = {"resource": operation[0], "action": operation[1]}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sign_message(privkey_pem: str, message: bytes) -> str:
    private_key = serialization.load_pem_private_key(privkey_pem.encode(), password=None)
    if not isinstance(private_key, ed25519.Ed25519PrivateKey):
        raise ValueError("Unsupported workload private key type.")
    signature = private_key.sign(message)
    return base64.b64encode(signature).decode("ascii")


def sign_request_pop(
    privkey_pem: str,
    keyhash: str,
    challenge: str,
    *,
    htm: str,
    htu: str,
    ath: str,
    iat: int,
    jti: str,
    operation: tuple[str, str] | None = None,
) -> str:
    """Create a request-shaped PoP signature."""
    message = request_pop_message(
        keyhash,
        challenge,
        htm=htm,
        htu=htu,
        ath=ath,
        iat=iat,
        jti=jti,
        operation=operation,
    )
    return _sign_message(privkey_pem, message)


def _verify_with_public_key(public_key, signature: bytes, message: bytes) -> bool:
    try:
        public_key.verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False


def verify_request_pop(
    pubkey_pem: str,
    keyhash: str,
    challenge: str,
    *,
    htm: str,
    htu: str,
    ath: str,
    iat: int,
    jti: str,
    signature_b64: str,
    operation: tuple[str, str] | None = None,
    expected_htm: str | None = None,
    expected_htu: str | None = None,
    expected_ath: str | None = None,
    max_age_seconds: int = 300,
    now: int | None = None,
) -> bool:
    """Verify a request-shaped PoP and its freshness envelope."""
    if not jti or not htm or not htu or not ath:
        return False
    if expected_htm is not None and htm.upper() != expected_htm.upper():
        return False
    if expected_htu is not None and htu != expected_htu:
        return False
    if expected_ath is not None and ath != expected_ath:
        return False
    try:
        iat_int = int(iat)
    except (TypeError, ValueError):
        return False
    now_int = int(time.time()) if now is None else int(now)
    if iat_int > now_int + 30:
        return False
    if now_int - iat_int > max_age_seconds:
        return False
    try:
        signature = base64.b64decode(signature_b64, validate=True)
        public_key = load_workload_public_key(pubkey_pem)
    except (ValueError, TypeError):
        return False
    if keyhash_for_pem(pubkey_pem) != keyhash:
        return False
    message = request_pop_message(
        keyhash,
        challenge,
        htm=htm,
        htu=htu,
        ath=ath,
        iat=iat_int,
        jti=jti,
        operation=operation,
    )
    return _verify_with_public_key(public_key, signature, message)
