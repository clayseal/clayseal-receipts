"""AttestationVerifier implementations (Phase 3 BYO audit)."""

from __future__ import annotations

import base64

import pytest

jwt = pytest.importorskip("jwt")

from agentauth.core import plugins  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402

from agentauth.receipts.attestation import (  # noqa: E402
    EatJwtAttestationVerifier,
    NitroAttestationVerifier,
)


@pytest.fixture(scope="module")
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _token(rsa_key, claims: dict, *, kid: str = "kid-1", alg: str = "RS256") -> str:
    return jwt.encode(claims, rsa_key, algorithm=alg, headers={"kid": kid})


def _jwks(rsa_key, *, kid: str = "kid-1") -> dict:
    import json

    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(rsa_key.public_key()))
    jwk["kid"] = kid
    return {"keys": [jwk]}


def test_nitro_verifier_rejects_garbage_evidence():
    verifier = NitroAttestationVerifier()
    with pytest.raises(ValueError, match="nitro attestation rejected"):
        verifier.verify(base64.standard_b64encode(b"not an attestation document").decode())


def test_nitro_verifier_rejects_unsupported_quote_dict():
    with pytest.raises(ValueError, match="rejected"):
        NitroAttestationVerifier().verify({"format": "unsupported", "quote_b64": ""})


def test_eat_jwt_verifies_with_inline_jwks(rsa_key):
    claims = {"iss": "https://verifier.example", "eat_profile": "tdx", "tee": "intel_tdx"}
    token = _token(rsa_key, claims)
    verifier = EatJwtAttestationVerifier(issuer="https://verifier.example")
    verified = verifier.verify(token, context={"jwks": _jwks(rsa_key)})
    assert verified["eat_profile"] == "tdx"
    assert verified["iss"] == "https://verifier.example"


def test_eat_jwt_verifies_with_pem_public_key(rsa_key):
    pem = rsa_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    token = _token(rsa_key, {"iss": "i"})
    verified = EatJwtAttestationVerifier().verify(token, context={"public_key": pem})
    assert verified["iss"] == "i"


def test_eat_jwt_enforces_issuer(rsa_key):
    token = _token(rsa_key, {"iss": "https://evil.example"})
    verifier = EatJwtAttestationVerifier(issuer="https://verifier.example")
    with pytest.raises(ValueError, match="rejected"):
        verifier.verify(token, context={"jwks": _jwks(rsa_key)})


def test_eat_jwt_enforces_audience(rsa_key):
    token = _token(rsa_key, {"iss": "i", "aud": "someone-else"})
    verifier = EatJwtAttestationVerifier(audience="us")
    with pytest.raises(ValueError, match="rejected"):
        verifier.verify(token, context={"jwks": _jwks(rsa_key)})


def test_eat_jwt_rejects_wrong_kid(rsa_key):
    token = _token(rsa_key, {"iss": "i"}, kid="unknown-kid")
    with pytest.raises(ValueError, match="no JWKS key matches"):
        EatJwtAttestationVerifier().verify(
            token, context={"jwks": _jwks(rsa_key, kid="kid-1")}
        )


def test_eat_jwt_requires_key_source(rsa_key, monkeypatch):
    monkeypatch.delenv("AGENTAUTH_ATTESTATION_JWKS_URL", raising=False)
    token = _token(rsa_key, {"iss": "i"})
    with pytest.raises(ValueError, match="no key source"):
        EatJwtAttestationVerifier().verify(token)


def test_verifiers_resolve_via_plugin_registry(rsa_key):
    verifier = plugins.get_plugin("attestation_verifiers", "eat_jwt")
    token = _token(rsa_key, {"iss": "i"})
    assert verifier.verify(token, context={"jwks": _jwks(rsa_key)})["iss"] == "i"