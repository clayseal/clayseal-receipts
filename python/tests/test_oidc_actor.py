"""Tests for OIDC actor verification (gate / CI binding)."""

from __future__ import annotations

import json
import time

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from agentauth.receipts.oidc_actor import (
    GITHUB_ACTIONS_ISSUER,
    resolve_verified_actor,
    verify_oidc_token,
)


def _rsa_jwks(*, kid: str = "test-kid") -> tuple[rsa.RSAPrivateKey, dict]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_numbers = private_key.public_key().public_numbers()
    jwk = {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": "RS256",
        "n": jwt.utils.base64url_encode(
            public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, "big")
        ).decode("ascii"),
        "e": jwt.utils.base64url_encode(
            public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, "big")
        ).decode("ascii"),
    }
    return private_key, {"keys": [jwk]}


def test_verify_oidc_token_and_resolve_actor():
    private_key, jwks = _rsa_jwks()
    token = jwt.encode(
        {
            "sub": "repo:org/repo:ref:refs/heads/main",
            "iss": GITHUB_ACTIONS_ISSUER,
            "actor": "devin-ai-integration[bot]",
            "repository": "org/repo",
            "exp": int(time.time()) + 300,
        },
        private_key,
        algorithm="RS256",
        headers={"kid": "test-kid"},
    )
    claims = verify_oidc_token(
        token,
        jwks=jwks,
        issuer=GITHUB_ACTIONS_ISSUER,
    )
    assert claims["actor"] == "devin-ai-integration[bot]"

    identity = resolve_verified_actor(token, jwks=jwks, issuer=GITHUB_ACTIONS_ISSUER)
    assert identity.oidc_subject.startswith("repo:")
    assert identity.github_actor == "devin-ai-integration[bot]"
    assert identity.repository == "org/repo"


def test_verify_oidc_token_rejects_missing_exp():
    private_key, jwks = _rsa_jwks()
    token = jwt.encode(  # no exp — OIDC requires it
        {"sub": "user:1", "iss": GITHUB_ACTIONS_ISSUER},
        private_key,
        algorithm="RS256",
        headers={"kid": "test-kid"},
    )
    try:
        verify_oidc_token(token, jwks=jwks, issuer=GITHUB_ACTIONS_ISSUER)
        assert False, "expected missing-exp rejection"
    except jwt.MissingRequiredClaimError:
        pass


def test_verify_oidc_token_rejects_wrong_issuer():
    private_key, jwks = _rsa_jwks(kid="other")
    token = jwt.encode(
        {"sub": "user:123", "iss": "https://evil.example", "exp": int(time.time()) + 300},
        private_key,
        algorithm="RS256",
        headers={"kid": "other"},
    )
    try:
        verify_oidc_token(token, jwks=jwks, issuer=GITHUB_ACTIONS_ISSUER)
        assert False, "expected issuer mismatch"
    except jwt.InvalidIssuerError:
        pass
