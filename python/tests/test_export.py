"""Receipt bundle export and verification."""

from __future__ import annotations

import os
import shutil
from datetime import timedelta, timezone
from pathlib import Path

import pytest

from agentauth.receipts import AgentWrapper, Policy
from agentauth.receipts.authority_binding import AuthorityBinding
from agentauth.receipts.certificate import dev_certificate, sign_certificate
from agentauth.receipts.export import (
    build_receipt_bundle,
    execution_proof_from_bundle,
    load_receipt_bundle,
    verify_receipt_bundle,
    write_receipt_bundle,
)
from agentauth.core.runtime import ActionDescriptor, SideEffectLevel
from agentauth.core.signing import generate_keypair, sign_bundle

ROOT = Path(__file__).resolve().parents[2]


def _trusted_certificate(monkeypatch: pytest.MonkeyPatch, policy: Policy):
    issuer = generate_keypair()
    cert = sign_certificate(dev_certificate(policy.commitment()), issuer)
    monkeypatch.setenv(
        "AGENT_RECEIPTS_TRUSTED_CERTIFICATE_ISSUER_PUBLIC_KEYS",
        issuer.public_key_hex,
    )
    return cert


def _sign_and_trust_bundle(monkeypatch: pytest.MonkeyPatch, bundle: dict):
    signer = generate_keypair()
    sign_bundle(bundle, signer, role="agent")
    monkeypatch.setenv(
        "AGENT_RECEIPTS_TRUSTED_SIGNER_PUBLIC_KEYS",
        signer.public_key_hex,
    )
    return bundle


def test_receipt_bundle_roundtrip_and_verify():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.2},
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
    )
    result = agent.run(
        {"transaction_id": "t1", "amount": 2000.0},
        session_id="sess-1",
        authority_version=3,
    )
    bundle = build_receipt_bundle(result, certificate=cert, policy=policy)
    proof = execution_proof_from_bundle(bundle)
    assert proof.proof_id == result.proof.proof_id
    assert bundle["decision"]["outcome"] == "allow"
    assert bundle["decision"]["session_id"] == "sess-1"
    assert bundle["decision"]["authority_version"] == 3

    check = verify_receipt_bundle(bundle)
    assert check["valid"] is False  # shadow mode
    assert any("shadow" in r for r in check["reasons"])
    assert check["decision"]["session_id"] == "sess-1"
    assert bundle["authority"]["authority_version"] == 3
    assert bundle["execution_context"]["authority"]["session_id"] == "sess-1"


def test_receipt_bundle_embeds_verifiable_audit_inclusion():
    from agentauth.receipts.audit import AuditChain

    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.2},
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
    )
    result = agent.run({"transaction_id": "t1", "amount": 2000.0})
    bundle = build_receipt_bundle(result, certificate=cert, policy=policy, audit_chain=agent.audit)
    inclusion = bundle["audit_inclusion"]
    assert AuditChain.verify_inclusion(
        result.audit_record.record_hash, inclusion["proof"], inclusion["checkpoint"]
    )


def test_receipt_bundle_decision_mismatch_detected():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.2},
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
    )
    result = agent.run({"transaction_id": "t1", "amount": 100.0}, session_id="sess-x")
    bundle = build_receipt_bundle(result, certificate=cert, policy=policy)
    bundle["decision"]["session_id"] = "sess-y"
    check = verify_receipt_bundle(bundle)
    assert any("session_id" in r for r in check["reasons"])


def test_receipt_bundle_output_tamper_detected():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.2},
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
    )
    result = agent.run({"transaction_id": "t1", "amount": 100.0})
    bundle = build_receipt_bundle(result, certificate=cert, policy=policy)
    bundle["output"] = {"decision": "deny", "fraud_score": 0.99}
    check = verify_receipt_bundle(bundle)
    assert any("output_hash" in r for r in check["reasons"])


def test_receipt_bundle_execution_context_tamper_detected():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.2},
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
    )
    result = agent.run({"transaction_id": "t1", "amount": 100.0}, session_id="sess-x")
    bundle = build_receipt_bundle(result, certificate=cert, policy=policy)
    bundle["execution_context"]["authority"]["session_id"] = "sess-y"
    check = verify_receipt_bundle(bundle)
    assert any("context_hash" in r for r in check["reasons"])


def test_receipt_bundle_certificate_tamper_detected():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.2},
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
    )
    result = agent.run({"transaction_id": "t1", "amount": 100.0})
    bundle = build_receipt_bundle(result, certificate=cert, policy=policy)
    bundle["certificate"]["principal"]["principal_id"] = "mallory"
    check = verify_receipt_bundle(bundle)
    assert any("certificate_ref" in r for r in check["reasons"])


def test_receipt_bundle_certificate_agent_id_mismatch_detected():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.2},
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
    )
    result = agent.run({"transaction_id": "t1", "amount": 100.0})
    bundle = build_receipt_bundle(result, certificate=cert, policy=policy)
    other_cert = dev_certificate(policy.commitment())
    bundle["certificate"]["agent_id"] = str(other_cert.agent_id)
    check = verify_receipt_bundle(bundle)
    assert any("agent_id" in r for r in check["reasons"])


def test_receipt_bundle_expired_certificate_detected():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.2},
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
    )
    result = agent.run({"transaction_id": "t1", "amount": 100.0})
    bundle = build_receipt_bundle(result, certificate=cert, policy=policy)
    created_at = result.proof.created_at.astimezone(timezone.utc)
    bundle["certificate"]["not_before"] = (created_at - timedelta(days=2)).isoformat()
    bundle["certificate"]["not_after"] = (created_at - timedelta(days=1)).isoformat()
    check = verify_receipt_bundle(bundle)
    assert any("not valid" in r for r in check["reasons"])


def test_receipt_bundle_not_yet_valid_certificate_detected():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.2},
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
    )
    result = agent.run({"transaction_id": "t1", "amount": 100.0})
    bundle = build_receipt_bundle(result, certificate=cert, policy=policy)
    created_at = result.proof.created_at.astimezone(timezone.utc)
    bundle["certificate"]["not_before"] = (created_at + timedelta(hours=1)).isoformat()
    bundle["certificate"]["not_after"] = (created_at + timedelta(days=1)).isoformat()
    check = verify_receipt_bundle(bundle)
    assert any("not valid" in r for r in check["reasons"])


def test_receipt_bundle_includes_structured_action_metadata():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.15},
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
    )
    result = agent.run(
        {"transaction_id": "t3", "amount": 10.0},
        action=ActionDescriptor(
            action_name="payments.refund",
            action_category="payments",
            resource_type="transaction",
            resource_ref="txn-1",
            side_effect_level=SideEffectLevel.BOUNDED_WRITE,
        ),
    )
    bundle = build_receipt_bundle(result, certificate=cert, policy=policy)
    assert bundle["action"]["action_name"] == "payments.refund"
    assert bundle["action"]["resource_ref"] == "txn-1"
    assert bundle["execution_context"]["action"]["side_effect_level"] == "bounded_write"


def test_receipt_bundle_surfaces_agentauth_authority_fields():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.15},
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
    )
    binding = AuthorityBinding.from_agentauth_credential(
        {
            "agent_id": "agent-123",
            "spiffe_id": "spiffe://agentauth.io/customer/acme/agent/researcher",
            "agent_type": "researcher",
            "owner": "alice@acme.ai",
            "scopes": ["db:read", "web:*"],
            "selectors": ["k8s:ns:customer-acme", "k8s:sa:researcher"],
            "expires_at": "2026-06-20T00:00:00Z",
            "capabilities": [
                {"resource": "db", "action": "read"},
                {"resource": "web", "action": "*"},
            ],
            "biscuit": "cap-token",
            "bound_keyhash": "bound-hash",
        }
    )
    result = agent.run(
        {"transaction_id": "t-auth", "amount": 10.0},
        action=ActionDescriptor(
            action_name="read",
            action_category="data",
            resource_type="db",
            side_effect_level=SideEffectLevel.READ_ONLY,
        ),
        session_id="sess-auth",
        authority_version=4,
        authority_binding=binding,
    )

    bundle = build_receipt_bundle(result, certificate=cert, policy=policy)

    assert bundle["authority"]["tenant_id"] == "acme"
    assert bundle["authority"]["owner_ref"] == "alice@acme.ai"
    assert (
        bundle["authority"]["workload_principal"]
        == "spiffe://agentauth.io/customer/acme/agent/researcher"
    )
    assert bundle["authority"]["scope_claims"] == ["db:read", "web:*"]
    assert bundle["authority"]["capability_rules"] == [
        {"resource": "db", "action": "read"},
        {"resource": "web", "action": "*"},
    ]
    assert bundle["authority"]["proof_of_possession"] is True
    assert bundle["authority"]["presenter_key_hash"] == "bound-hash"
    assert bundle["authority"]["has_capability_grant"] is True


@pytest.mark.skipif(
    not (ROOT / "target" / "release" / "agent-receipts").is_file(),
    reason="release CLI not built",
)
@pytest.mark.skipif(
    shutil.which("ezkl") is None and not os.environ.get("EZKL"),
    reason="ezkl not installed",
)
def test_receipt_bundle_prove_mode_verifies(tmp_path: Path, monkeypatch):
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = _trusted_certificate(monkeypatch, policy)
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.25},
        policy=policy,
        certificate=cert,
        mode="prove",
        prove_composed=False,
        prove_inference=True,
        audit_db=":memory:",
    )
    result = agent.run({"transaction_id": "t2", "amount": 2500.0})
    path = tmp_path / "receipt.json"
    bundle = build_receipt_bundle(result, certificate=cert, policy=policy)
    _sign_and_trust_bundle(monkeypatch, bundle)
    write_receipt_bundle(path, bundle)
    loaded = load_receipt_bundle(path)
    check = verify_receipt_bundle(loaded)
    assert check["valid"] is True


def test_verify_receipt_bundle_requires_envelope_signature_by_default(monkeypatch):
    from agentauth.receipts.verification import VerifyErrorCode

    monkeypatch.delenv("AGENT_RECEIPTS_REQUIRE_BUNDLE_SIGNATURES", raising=False)
    monkeypatch.setenv("AGENT_RECEIPTS_ALLOW_UNSIGNED_CERTIFICATE", "1")
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())
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

    codes = {item["code"] for item in check["issues"]}
    assert VerifyErrorCode.SIGNATURE_INVALID.value in codes
    assert check["signatures"]["signed"] is False


def test_receipt_bundle_policy_satisfied_mismatch_detected():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.2},
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
    )
    result = agent.run({"transaction_id": "t1", "amount": 100.0})
    bundle = build_receipt_bundle(result, certificate=cert, policy=policy)
    bundle["decision"]["policy_satisfied"] = not result.proof.policy_satisfied
    check = verify_receipt_bundle(bundle)
    assert any("policy_satisfied" in r for r in check["reasons"])


def test_receipt_bundle_policy_commitment_mismatch_detected():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.2},
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
    )
    result = agent.run({"transaction_id": "t1", "amount": 100.0})
    bundle = build_receipt_bundle(result, certificate=cert, policy=policy)
    bundle["policy"]["commitment"] = "sha256:wrong-policy"
    check = verify_receipt_bundle(bundle)
    assert any("policy.commitment" in r for r in check["reasons"])


def test_verify_receipt_bundle_validates_audit_inclusion():
    from agentauth.receipts.audit import AuditChain
    from agentauth.core.signing import generate_keypair
    from agentauth.receipts.verification import VerifyErrorCode

    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())
    signing_key = generate_keypair()
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.2},
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
    )
    agent.audit = AuditChain.in_memory(signing_key=signing_key)
    result = agent.run({"transaction_id": "t1", "amount": 100.0})
    bundle = build_receipt_bundle(result, certificate=cert, policy=policy, audit_chain=agent.audit)
    check = verify_receipt_bundle(bundle)
    assert not any(
        issue["code"] == VerifyErrorCode.AUDIT_INCLUSION_INVALID.value for issue in check["issues"]
    )

    bundle["audit_inclusion"]["checkpoint"] = dict(
        bundle["audit_inclusion"]["checkpoint"],
        merkle_root="deadbeef",
    )
    tampered = verify_receipt_bundle(bundle)
    codes = {item["code"] for item in tampered["issues"]}
    assert VerifyErrorCode.AUDIT_INCLUSION_INVALID.value in codes


def test_verify_receipt_bundle_validates_audit_record_signature():
    from agentauth.receipts.audit import AuditChain
    from agentauth.core.signing import generate_keypair
    from agentauth.receipts.verification import VerifyErrorCode

    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())
    signing_key = generate_keypair()
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.2},
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
    )
    agent.audit = AuditChain.in_memory(signing_key=signing_key)
    result = agent.run({"transaction_id": "t1", "amount": 100.0})
    bundle = build_receipt_bundle(
        result, certificate=cert, policy=policy, audit_chain=agent.audit
    )
    assert bundle["audit_inclusion"]["log_public_key"] == signing_key.public_key_hex
    check = verify_receipt_bundle(bundle)
    assert not any(
        issue["code"] == VerifyErrorCode.AUDIT_INCLUSION_INVALID.value
        and "signature" in issue["message"].lower()
        for issue in check["issues"]
    )

    bundle["audit_record"]["signature"]["signature"] = "00" * 64
    tampered = verify_receipt_bundle(bundle)
    codes = {item["code"] for item in tampered["issues"]}
    assert VerifyErrorCode.AUDIT_INCLUSION_INVALID.value in codes
    assert any("signature" in item["message"].lower() for item in tampered["issues"])


def test_verify_receipt_bundle_rejects_incomplete_session_proof():
    from agentauth.receipts.verification import VerifyErrorCode

    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.2},
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
    )
    result = agent.run({"transaction_id": "t1", "amount": 100.0}, session_id="sess-1")
    bundle = build_receipt_bundle(result, certificate=cert, policy=policy)
    bundle["session_proof"] = {"mode": "folded", "digest": "abc123"}

    check = verify_receipt_bundle(bundle)
    codes = {item["code"] for item in check["issues"]}
    assert VerifyErrorCode.SESSION_PROOF_INVALID.value in codes


def test_verify_receipt_bundle_validates_session_proof_bindings(monkeypatch):
    from agentauth.receipts.session import session_proof_bundle_section
    from agentauth.receipts.verification import VerifyErrorCode

    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.2},
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
    )
    result = agent.run({"transaction_id": "t1", "amount": 100.0}, session_id="sess-1")
    bundle = build_receipt_bundle(result, certificate=cert, policy=policy)
    proof = execution_proof_from_bundle(bundle)
    envelope = {
        "version": 1,
        "aggregation_mode": "halo2_batch_v1",
        "session_id": "sess-1",
        "policy_commitment": proof.policy_commitment,
        "action_count": 1,
        "actions": [
            {
                "output_hash": proof.output_hash,
                "policy_commitment": proof.policy_commitment,
                "score_scaled": "1",
                "min_scaled": "0",
                "max_plus_one": "2",
                "required_presence_mask": "0",
            }
        ],
        "session_digest": "abc123digest",
        "proof_hex": "deadbeef",
    }
    bundle["session_proof"] = session_proof_bundle_section(envelope)

    monkeypatch.setattr(
        "agentauth.receipts.session.verify_session",
        lambda _blob: {"valid": True, "mode": "halo2_batch_v1", "reasons": []},
    )
    check = verify_receipt_bundle(bundle)
    assert not any(
        issue["code"] == VerifyErrorCode.SESSION_PROOF_INVALID.value for issue in check["issues"]
    )

    bundle["session_proof"]["envelope"]["session_id"] = "sess-other"
    tampered = verify_receipt_bundle(bundle)
    codes = {item["code"] for item in tampered["issues"]}
    assert VerifyErrorCode.SESSION_PROOF_INVALID.value in codes


def test_verify_receipt_bundle_detects_certificate_agent_id_mismatch():
    from agentauth.receipts.verification import VerifyErrorCode

    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.2},
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
    )
    result = agent.run({"transaction_id": "t1", "amount": 100.0})
    bundle = build_receipt_bundle(result, certificate=cert, policy=policy)
    bundle["certificate"]["agent_id"] = str(__import__("uuid").uuid4())
    check = verify_receipt_bundle(bundle)
    codes = {item["code"] for item in check["issues"]}
    assert VerifyErrorCode.CERTIFICATE_MISMATCH.value in codes
    assert any("agent_id" in reason for reason in check["reasons"])


def test_verify_receipt_bundle_detects_certificate_ref_tampering():
    from agentauth.receipts.verification import VerifyErrorCode

    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.2},
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
    )
    result = agent.run({"transaction_id": "t1", "amount": 100.0})
    bundle = build_receipt_bundle(result, certificate=cert, policy=policy)
    bundle["certificate"]["principal"]["principal_id"] = "tampered-principal"
    check = verify_receipt_bundle(bundle)
    codes = {item["code"] for item in check["issues"]}
    assert VerifyErrorCode.CERTIFICATE_MISMATCH.value in codes
    assert any("certificate_ref" in reason for reason in check["reasons"])


def test_wrapper_rejects_model_provenance_mismatch():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment(), model_hash="sha256:cert-model")
    with pytest.raises(ValueError, match="model_provenance_hash"):
        AgentWrapper(
            model=lambda inp: {"decision": "approve", "fraud_score": 0.2},
            policy=policy,
            certificate=cert,
            model_provenance_hash="sha256:wrapper-model",
            mode="shadow",
            audit_db=":memory:",
        )


def test_verify_receipt_bundle_detects_output_tampering():
    from agentauth.receipts.verification import VerifyErrorCode

    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.2},
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
    )
    result = agent.run({"transaction_id": "t1", "amount": 100.0})
    bundle = build_receipt_bundle(result, certificate=cert, policy=policy)
    bundle["output"]["fraud_score"] = 0.99
    check = verify_receipt_bundle(bundle)
    codes = {item["code"] for item in check["issues"]}
    assert VerifyErrorCode.OUTPUT_MISMATCH.value in codes


def test_verify_receipt_bundle_detects_execution_context_tampering():
    from agentauth.receipts.verification import VerifyErrorCode

    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.2},
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
    )
    result = agent.run({"transaction_id": "t1", "amount": 100.0})
    bundle = build_receipt_bundle(result, certificate=cert, policy=policy)
    bundle["execution_context"]["input"]["amount"] = 999.0
    check = verify_receipt_bundle(bundle)
    codes = {item["code"] for item in check["issues"]}
    assert VerifyErrorCode.CONTEXT_MISMATCH.value in codes


def test_verify_receipt_bundle_detects_composed_context_hash_mismatch():
    import base64
    import json

    from agentauth.receipts.verification import VerifyErrorCode

    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.2},
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
    )
    result = agent.run({"transaction_id": "t1", "amount": 100.0})
    bundle = build_receipt_bundle(result, certificate=cert, policy=policy)
    proof = bundle["execution_proof"]
    composed = json.dumps(
        {
            "bindings": {
                "context_hash": "wrong-context",
                "model_provenance_hash": cert.model_provenance_hash,
            },
            "inference": {},
        }
    ).encode()
    proof.setdefault("bundle", {})
    proof["bundle"]["composed_proof_b64"] = base64.b64encode(composed).decode()
    check = verify_receipt_bundle(bundle)
    codes = {item["code"] for item in check["issues"]}
    assert VerifyErrorCode.CONTEXT_MISMATCH.value in codes


def test_verify_receipt_bundle_detects_model_provenance_mismatch():
    import base64
    import json

    from agentauth.receipts.verification import VerifyErrorCode

    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment(), model_hash="sha256:cert-model")
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.2},
        policy=policy,
        certificate=cert,
        model_provenance_hash="sha256:cert-model",
        mode="shadow",
        audit_db=":memory:",
    )
    result = agent.run({"transaction_id": "t1", "amount": 100.0})
    bundle = build_receipt_bundle(result, certificate=cert, policy=policy)
    proof = bundle["execution_proof"]
    composed = json.dumps(
        {
            "bindings": {
                "context_hash": proof["context_hash"],
                "model_provenance_hash": "sha256:wrong-model",
            },
            "inference": {"model_provenance_hash": "sha256:wrong-model"},
        }
    ).encode()
    proof.setdefault("bundle", {})
    proof["bundle"]["composed_proof_b64"] = base64.b64encode(composed).decode()
    check = verify_receipt_bundle(bundle)
    codes = {item["code"] for item in check["issues"]}
    assert VerifyErrorCode.CERTIFICATE_MISMATCH.value in codes
    assert any("model_provenance" in issue["message"] for issue in check["issues"])


def test_audit_export_jsonl(tmp_path: Path):

    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.1},
        policy=policy,
        mode="shadow",
        audit_db=tmp_path / "chain.sqlite",
    )
    agent.run({"transaction_id": "a"})
    agent.run({"transaction_id": "b"})
    out = tmp_path / "audit.jsonl"
    n = agent.audit.export_jsonl(out)
    assert n == 2
    lines = out.read_text().strip().splitlines()
    assert len(lines) == 2


@pytest.mark.skipif(
    not (ROOT / "target" / "release" / "agent-receipts").is_file(),
    reason="release CLI not built",
)
def test_verify_receipt_bundle_rejects_stub_proofs_without_opt_in(monkeypatch):
    from agentauth.receipts.verification import VerifyErrorCode

    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.25},
        policy=policy,
        certificate=cert,
        mode="prove",
        prove_composed=False,
        prove_inference=True,
        audit_db=":memory:",
    )
    monkeypatch.setenv("AGENT_RECEIPTS_ALLOW_STUB", "1")
    result = agent.run({"transaction_id": "t2", "amount": 2500.0})
    bundle = build_receipt_bundle(result, certificate=cert, policy=policy)

    monkeypatch.setenv("AGENT_RECEIPTS_ALLOW_STUB", "0")
    check = verify_receipt_bundle(bundle)
    codes = {item["code"] for item in check["issues"]}
    assert VerifyErrorCode.STUB_PROOF_NOT_ALLOWED.value in codes


def test_verify_receipt_bundle_enforces_audit_witness_quorum(monkeypatch):
    from agentauth.receipts.audit import AuditChain
    from agentauth.core.signing import generate_keypair
    from agentauth.receipts.verification import VerifyErrorCode
    from agentauth.receipts.witness import add_witness_cosignature

    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())
    log_key = generate_keypair()
    witness_key = generate_keypair()
    monkeypatch.setenv("AGENT_RECEIPTS_TRUSTED_AUDIT_LOG_PUBLIC_KEYS", log_key.public_key_hex)
    monkeypatch.setenv("AGENT_RECEIPTS_REQUIRED_AUDIT_WITNESSES", "2")
    monkeypatch.setenv(
        "AGENT_RECEIPTS_TRUSTED_AUDIT_WITNESS_KEYS",
        witness_key.public_key_hex,
    )

    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.2},
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
    )
    agent.audit = AuditChain.in_memory(signing_key=log_key)
    result = agent.run({"transaction_id": "t1", "amount": 100.0})
    bundle = build_receipt_bundle(result, certificate=cert, policy=policy, audit_chain=agent.audit)
    checkpoint = bundle["audit_inclusion"]["checkpoint"]
    add_witness_cosignature(checkpoint, witness_key, allow_unsafe=True)

    check = verify_receipt_bundle(bundle)
    codes = {item["code"] for item in check["issues"]}
    assert VerifyErrorCode.AUDIT_INCLUSION_INVALID.value in codes
    assert any("witness quorum" in reason for reason in check["reasons"])


def test_verify_receipt_bundle_validates_signed_delegation():
    from agentauth.capabilities.operations import mcp_tool_capability
    from agentauth.capabilities.delegation import issue_delegation, sign_delegation
    from agentauth.receipts.verification import VerifyErrorCode

    key = generate_keypair()
    token = issue_delegation(
        None,
        delegate_agent_id=__import__("uuid").uuid4(),
        capabilities=[mcp_tool_capability("score_transaction")],
    )
    envelope = sign_delegation(token, key)

    policy2 = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert2 = dev_certificate(policy2.commitment())
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.2},
        policy=policy2,
        certificate=cert2,
        mode="shadow",
        audit_db=":memory:",
    )
    result = agent.run({"transaction_id": "t1", "amount": 100.0})
    bundle = build_receipt_bundle(result, certificate=cert2, policy=policy2)
    from agentauth.core.hash_util import hash_canonical_json

    tool_input = {"transaction_id": "t1", "amount": 100.0}
    bundle["execution_context"]["authorization"] = {
        "protocol": "mcp",
        "delegation_id": str(token.delegation_id),
        "delegation_depth": token.depth,
        "tool_name": "score_transaction",
        "arguments_hash": hash_canonical_json(tool_input),
        "signed_delegation": envelope,
    }
    bundle["execution_context"]["input"] = tool_input

    check = verify_receipt_bundle(bundle)
    assert not any(
        issue["code"] == VerifyErrorCode.DELEGATION_INVALID.value for issue in check["issues"]
    )

    bundle["execution_context"]["authorization"]["signed_delegation"] = sign_delegation(
        issue_delegation(
            None,
            delegate_agent_id=__import__("uuid").uuid4(),
            capabilities=[mcp_tool_capability("transfer_funds")],
        ),
        key,
    )
    tampered = verify_receipt_bundle(bundle)
    codes = {item["code"] for item in tampered["issues"]}
    assert VerifyErrorCode.DELEGATION_INVALID.value in codes
