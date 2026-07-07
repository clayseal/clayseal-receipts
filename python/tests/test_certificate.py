"""Agent certificate issuer signature and trust policy tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentauth.receipts import AgentWrapper, Policy
from agentauth.receipts.certificate import (
    dev_certificate,
    load_managed_certificate_issuer_key,
    load_or_create_partner_certificate,
    sign_certificate,
    verify_certificate_issuer,
)
from agentauth.receipts.export import build_receipt_bundle, verify_receipt_bundle
from agentauth.core.signing import generate_keypair
from agentauth.receipts.verification import VerifyErrorCode

ROOT = Path(__file__).resolve().parents[2]


def test_sign_certificate_roundtrip():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())
    key = generate_keypair()
    signed = sign_certificate(cert, key)
    assert verify_certificate_issuer(signed) == []


def test_partner_certificate_uses_managed_issuer_key(monkeypatch, tmp_path):
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    issuer_path = tmp_path / "issuer.key"
    cert_path = tmp_path / "agent.cert.json"
    monkeypatch.setenv("AGENT_RECEIPTS_CERTIFICATE_ISSUER_KEY_PATH", str(issuer_path))

    cert = load_or_create_partner_certificate(
        cert_path,
        policy_commitment=policy.commitment(),
        model_hash="sha256:model-dev-v1",
        organization="acme",
        principal_id="agent-prod",
    )

    assert cert.issuer_signature is not None
    assert verify_certificate_issuer(cert) == []
    assert load_or_create_partner_certificate(
        cert_path,
        policy_commitment=policy.commitment(),
        model_hash="sha256:model-dev-v1",
        organization="acme",
        principal_id="agent-prod",
    ).issuer_signature == cert.issuer_signature


def test_managed_certificate_issuer_requires_encryption_when_configured(monkeypatch, tmp_path):
    issuer_path = tmp_path / "issuer.key"
    monkeypatch.setenv("AGENT_RECEIPTS_CERTIFICATE_ISSUER_KEY_PATH", str(issuer_path))
    monkeypatch.setenv("AGENT_RECEIPTS_REQUIRE_KEY_ENCRYPTION", "1")
    monkeypatch.delenv("AGENT_RECEIPTS_SIGNING_KEY_PASSWORD", raising=False)

    with pytest.raises(ValueError, match="refusing to create unencrypted signing key"):
        load_managed_certificate_issuer_key()


def test_unsigned_certificate_rejected_by_default(monkeypatch):
    monkeypatch.delenv("AGENT_RECEIPTS_ALLOW_UNSIGNED_CERTIFICATE", raising=False)
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())
    assert verify_certificate_issuer(cert) == ["certificate is unsigned"]


def test_verify_certificate_issuer_rejects_tampered_signature():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())
    key = generate_keypair()
    signed = sign_certificate(cert, key)
    signed.issuer_signature["signature"] = "00" * 64
    violations = verify_certificate_issuer(signed)
    assert any("invalid" in item for item in violations)


def test_verify_certificate_issuer_requires_trusted_key(monkeypatch):
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    issuer = generate_keypair()
    impostor = generate_keypair()
    signed = sign_certificate(dev_certificate(policy.commitment()), issuer)

    monkeypatch.setenv(
        "AGENT_RECEIPTS_TRUSTED_CERTIFICATE_ISSUER_PUBLIC_KEYS",
        impostor.public_key_hex,
    )
    violations = verify_certificate_issuer(signed)
    assert any("trusted key" in item for item in violations)

    monkeypatch.setenv(
        "AGENT_RECEIPTS_TRUSTED_CERTIFICATE_ISSUER_PUBLIC_KEYS",
        issuer.public_key_hex,
    )
    assert verify_certificate_issuer(signed) == []


def test_verify_receipt_bundle_enforces_trusted_certificate_issuer(monkeypatch):
    from agentauth.receipts.certificate import AgentCertificate, certificate_ref_hash

    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    issuer = generate_keypair()
    cert = sign_certificate(dev_certificate(policy.commitment()), issuer)
    monkeypatch.setenv(
        "AGENT_RECEIPTS_TRUSTED_CERTIFICATE_ISSUER_PUBLIC_KEYS",
        issuer.public_key_hex,
    )

    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.2},
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
    )
    result = agent.run({"transaction_id": "t1", "amount": 100.0})
    bundle = build_receipt_bundle(result, certificate=cert, policy=policy)
    check = verify_receipt_bundle(bundle)
    assert not any(
        issue["code"] == VerifyErrorCode.CERTIFICATE_MISMATCH.value and "issuer" in issue["message"]
        for issue in check["issues"]
    )

    unsigned_dict = dict(bundle["certificate"])
    unsigned_dict.pop("issuer_signature", None)
    unsigned_cert = AgentCertificate.from_dict(unsigned_dict)
    bundle["certificate"] = unsigned_dict
    bundle["execution_proof"]["certificate_ref"] = certificate_ref_hash(unsigned_cert)
    tampered = verify_receipt_bundle(bundle)
    assert any("unsigned" in reason for reason in tampered["reasons"])
