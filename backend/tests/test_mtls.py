"""Tests for mTLS client certificate extraction and token binding.

Uses proxy header mode (AGENTAUTH_MTLS_CLIENT_CERT_HEADER=X-Client-Cert) to
inject cert DER as base64 without a real TLS handshake, then verifies that the
binding check in verify_mtls_binding accepts matching certs and rejects mismatched
or absent ones.
"""
from __future__ import annotations

import base64
import datetime
import os
import time
import uuid

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from agentauth.backend import capabilities as cap_service
from agentauth.backend.config import get_settings
from tests.attest import (
    WORKLOAD_PRIVATE_PEM,
    WORKLOAD_PUBLIC_PEM,
    register_and_identify,
)

MTLS_HEADER = "X-Client-Cert"


def _make_cert(private_key) -> bytes:
    """Return DER bytes for a self-signed Ed25519 cert with a SPIFFE SAN."""
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-agent")])
    spiffe_san = x509.UniformResourceIdentifier(
        "spiffe://agentauth.io/customer/test/agent/researcher"
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([spiffe_san]), critical=False)
        .sign(private_key, None)  # Ed25519 uses None for the hash algorithm
    )
    return cert.public_bytes(serialization.Encoding.DER)


def _workload_private_key():
    """Load the module-level workload private key from its PEM."""
    return serialization.load_pem_private_key(WORKLOAD_PRIVATE_PEM.encode(), password=None)


@pytest.fixture(scope="module")
def matching_cert_der() -> bytes:
    """DER cert whose public key matches WORKLOAD_PUBLIC_PEM (= cnf.jkt on issued tokens)."""
    return _make_cert(_workload_private_key())


@pytest.fixture(scope="module")
def mismatched_cert_der() -> bytes:
    """DER cert whose public key does NOT match WORKLOAD_PUBLIC_PEM."""
    wrong_key = ed25519.Ed25519PrivateKey.generate()
    return _make_cert(wrong_key)


def _pop(client, headers, token):
    """Build a valid PoP proof for the validate endpoint."""
    challenge = client.post("/v1/challenge", headers=headers).json()["challenge"]
    keyhash = cap_service.keyhash_for_pem(WORKLOAD_PUBLIC_PEM)
    iat = int(time.time())
    jti = uuid.uuid4().hex
    return {
        "challenge": challenge,
        "signature": cap_service.sign_request_pop(
            WORKLOAD_PRIVATE_PEM,
            keyhash,
            challenge,
            htm="POST",
            htu="/v1/validate",
            ath=cap_service.token_hash(token),
            iat=iat,
            jti=jti,
            operation=("jwt", "validate"),
        ),
        "pubkey_pem": WORKLOAD_PUBLIC_PEM,
        "htm": "POST",
        "htu": "/v1/validate",
        "ath": cap_service.token_hash(token),
        "iat": iat,
        "jti": jti,
    }


def test_mtls_matching_cert_passes(client: TestClient, customer: dict, matching_cert_der: bytes, monkeypatch):
    """When the presented cert's public key matches cnf.jkt, validate returns 200."""
    id_resp = register_and_identify(client, customer["headers"])
    assert id_resp.status_code in (200, 201), id_resp.text
    token = id_resp.json()["token"]
    pop = _pop(client, customer["headers"], token)

    monkeypatch.setenv("AGENTAUTH_MTLS_ENABLED", "1")
    monkeypatch.setenv("AGENTAUTH_MTLS_CLIENT_CERT_HEADER", MTLS_HEADER)
    monkeypatch.setenv("AGENTAUTH_MTLS_STRICT", "1")
    get_settings.cache_clear()

    cert_b64 = base64.b64encode(matching_cert_der).decode()
    resp = client.post(
        "/v1/validate",
        json={"token": token, "pop": pop},
        headers={**customer["headers"], MTLS_HEADER: cert_b64},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["valid"] is True


def test_mtls_mismatched_cert_returns_401(
    client: TestClient, customer: dict, mismatched_cert_der: bytes, monkeypatch
):
    """When the cert's public key does not match cnf.jkt, validate returns 401."""
    id_resp = register_and_identify(client, customer["headers"])
    assert id_resp.status_code in (200, 201), id_resp.text
    token = id_resp.json()["token"]
    pop = _pop(client, customer["headers"], token)

    monkeypatch.setenv("AGENTAUTH_MTLS_ENABLED", "1")
    monkeypatch.setenv("AGENTAUTH_MTLS_CLIENT_CERT_HEADER", MTLS_HEADER)
    monkeypatch.setenv("AGENTAUTH_MTLS_STRICT", "1")
    get_settings.cache_clear()

    cert_b64 = base64.b64encode(mismatched_cert_der).decode()
    resp = client.post(
        "/v1/validate",
        json={"token": token, "pop": pop},
        headers={**customer["headers"], MTLS_HEADER: cert_b64},
    )
    assert resp.status_code == 401, resp.text


def test_mtls_strict_missing_cert_returns_401(client: TestClient, customer: dict, monkeypatch):
    """In strict mode, validate returns 401 when no client cert is presented."""
    id_resp = register_and_identify(client, customer["headers"])
    assert id_resp.status_code in (200, 201), id_resp.text
    token = id_resp.json()["token"]
    pop = _pop(client, customer["headers"], token)

    monkeypatch.setenv("AGENTAUTH_MTLS_ENABLED", "1")
    monkeypatch.setenv("AGENTAUTH_MTLS_CLIENT_CERT_HEADER", MTLS_HEADER)
    monkeypatch.setenv("AGENTAUTH_MTLS_STRICT", "1")
    get_settings.cache_clear()

    resp = client.post(
        "/v1/validate",
        json={"token": token, "pop": pop},
        headers=customer["headers"],  # no cert header
    )
    assert resp.status_code == 401, resp.text
    assert resp.json()["error"]["code"] == "invalid_token"


def test_mtls_disabled_no_cert_passes(client: TestClient, customer: dict, monkeypatch):
    """When mTLS is disabled, no cert is required and the existing PoP path works."""
    id_resp = register_and_identify(client, customer["headers"])
    assert id_resp.status_code in (200, 201), id_resp.text
    token = id_resp.json()["token"]
    pop = _pop(client, customer["headers"], token)

    monkeypatch.setenv("AGENTAUTH_MTLS_ENABLED", "0")
    get_settings.cache_clear()

    resp = client.post(
        "/v1/validate",
        json={"token": token, "pop": pop},
        headers=customer["headers"],
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["valid"] is True


def test_mtls_non_strict_missing_cert_passes(client: TestClient, customer: dict, monkeypatch):
    """In non-strict mode, a missing cert is allowed and falls back to PoP-only."""
    id_resp = register_and_identify(client, customer["headers"])
    assert id_resp.status_code in (200, 201), id_resp.text
    token = id_resp.json()["token"]
    pop = _pop(client, customer["headers"], token)

    monkeypatch.setenv("AGENTAUTH_MTLS_ENABLED", "1")
    monkeypatch.setenv("AGENTAUTH_MTLS_CLIENT_CERT_HEADER", MTLS_HEADER)
    monkeypatch.setenv("AGENTAUTH_MTLS_STRICT", "0")
    get_settings.cache_clear()

    resp = client.post(
        "/v1/validate",
        json={"token": token, "pop": pop},
        headers=customer["headers"],  # no cert header
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["valid"] is True


def test_spiffe_id_extraction(matching_cert_der: bytes):
    """spiffe_id_from_cert correctly extracts the SPIFFE SAN URI."""
    from agentauth.backend.mtls import spiffe_id_from_cert

    spiffe_id = spiffe_id_from_cert(matching_cert_der)
    assert spiffe_id == "spiffe://agentauth.io/customer/test/agent/researcher"


def test_cert_public_key_pem_roundtrip(matching_cert_der: bytes):
    """cert_public_key_pem extracts a PEM whose keyhash matches WORKLOAD_PUBLIC_PEM's keyhash."""
    from agentauth.backend.mtls import cert_public_key_pem
    from agentauth.workload_keys import keyhash_for_pem

    extracted_pem = cert_public_key_pem(matching_cert_der)
    assert keyhash_for_pem(extracted_pem) == keyhash_for_pem(WORKLOAD_PUBLIC_PEM)
