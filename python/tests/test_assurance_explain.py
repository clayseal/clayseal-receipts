"""Assurance levels, structured verification, and explain reports."""

from __future__ import annotations

from pathlib import Path

from agentauth.receipts import AgentWrapper, Policy
from agentauth.receipts.assurance import AssuranceLevel, assurance_from_proof
from agentauth.receipts.certificate import dev_certificate
from agentauth.receipts.explain import explain_receipt_bundle
from agentauth.receipts.export import (
    build_receipt_bundle,
    compact_receipt_bundle,
    verify_receipt_bundle,
)
from agentauth.receipts.proof import AttestationPath, DecisionOutcome, ExecutionProof, ProofBundle
from agentauth.receipts.verification import VerifyErrorCode

ROOT = Path(__file__).resolve().parents[2]


def test_assurance_shadow_level():
    proof = ExecutionProof.from_action(
        dev_certificate("pol"),
        {"input": {}},
        {"decision": "approve"},
        policy_satisfied=True,
        path=AttestationPath.SHADOW,
        decision_outcome=DecisionOutcome.ALLOW,
    )
    summary = assurance_from_proof(proof)
    assert summary.level == AssuranceLevel.SHADOW


def test_assurance_policy_proved_level():
    proof = ExecutionProof.from_action(
        dev_certificate("pol"),
        {"input": {}},
        {"decision": "approve"},
        policy_satisfied=True,
        path=AttestationPath.FULL_ZK,
        decision_outcome=DecisionOutcome.ALLOW,
    )
    proof.bundle = ProofBundle(policy_proof=b"{}", verification_key_id="policy_range_v3")
    summary = assurance_from_proof(proof)
    assert summary.level == AssuranceLevel.POLICY_PROVED


def test_verify_returns_structured_issues():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.2},
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
    )
    result = agent.run({"transaction_id": "t1", "amount": 100.0}, session_id="sess-a")
    bundle = build_receipt_bundle(result, certificate=cert, policy=policy)
    bundle["decision"]["session_id"] = "sess-b"
    check = verify_receipt_bundle(bundle)
    assert check["valid"] is False
    codes = {item["code"] for item in check["issues"]}
    assert VerifyErrorCode.SESSION_MISMATCH.value in codes
    assert check["assurance"]["level"] == "shadow"


def test_bundle_includes_assurance():
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
    assert bundle["schema"] == "agent-receipts.receipt-bundle.v2"
    assert bundle["evidence"]["assurance"]["level"] == "shadow"
    assert bundle["evidence"]["assurance"]["attestation_path"] == "shadow"


def test_explain_receipt_bundle():
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
    report = explain_receipt_bundle(bundle)
    assert report["proof_id"] == str(result.proof.proof_id)
    assert report["decision"]["outcome"] == "allow"
    assert "shadow" in report["summary"]
    assert report["assurance"]["level"] == "shadow"


def test_compact_receipt_bundle():
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
    bundle = build_receipt_bundle(result, certificate=cert, policy=policy, context={"input": {}})
    compact = compact_receipt_bundle(bundle)
    assert "output" in compact
    assert "context" not in compact
    assert compact["evidence"]["assurance"]["level"] == "shadow"
