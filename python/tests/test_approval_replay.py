"""Approval, replay re-eval, auditor summary, and signature verify tests."""

from __future__ import annotations

from pathlib import Path

from agentauth.receipts import AgentWrapper, Policy
from agentauth.receipts.approval import infer_approval_state
from agentauth.receipts.auditor import auditor_evidence_summary
from agentauth.receipts.certificate import dev_certificate
from agentauth.core.decision import ApprovalMetadata, ApprovalState
from agentauth.receipts.export import build_receipt_bundle, verify_receipt_bundle
from agentauth.receipts.proof import DecisionOutcome
from agentauth.receipts.replay import re_evaluate_policy_decision
from agentauth.core.runtime import ActorKind
from agentauth.core.signing import sign_bundle

ROOT = Path(__file__).resolve().parents[2]


def test_infer_approval_state_from_outcome():
    assert infer_approval_state(DecisionOutcome.PENDING_APPROVAL) == ApprovalState.PENDING
    assert infer_approval_state(DecisionOutcome.ALLOW) == ApprovalState.NOT_REQUIRED


def test_wrapper_records_approval_metadata():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.1},
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
    )
    result = agent.record(
        action="agent.run",
        context={
            "input": {"transaction_id": "t1"},
            "authority": {
                "authority_id": "auth-1",
                "authority_version": 2,
                "session_id": "sess-a",
                "actor_ref": {
                    "kind": ActorKind.TOP_LEVEL_AGENT.value,
                    "actor_id": "agent-1",
                },
            },
            "touched_resources": ["service:payments"],
        },
        output={"decision": "approve", "fraud_score": 0.1},
        decision_outcome=DecisionOutcome.PENDING_APPROVAL,
        approval_metadata=ApprovalMetadata(
            approval_id="appr-99",
            approver_ref="human:alice",
        ),
    )
    assert result.decision.approval_state == ApprovalState.PENDING
    assert result.decision.approval_metadata is not None
    assert result.execution_context.authority.actor_ref is not None
    assert result.execution_context.touched_resources == ["service:payments"]


def test_re_evaluate_policy_decision_matches():
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
    report = re_evaluate_policy_decision(bundle, policy)
    assert report["match"] is True


def test_re_evaluate_detects_tampered_output():
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
    bundle["output"]["fraud_score"] = 9.9
    report = re_evaluate_policy_decision(bundle, policy)
    assert report["match"] is False
    assert "violations" in report["mismatches"] or "policy_satisfied" in report["mismatches"]


def test_auditor_summary_omits_raw_io():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.1},
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
    )
    result = agent.run({"transaction_id": "secret-tx", "amount": 1.0})
    bundle = build_receipt_bundle(result, certificate=cert, policy=policy)
    summary = auditor_evidence_summary(bundle)
    assert "output" not in summary
    assert summary["decision"]["outcome"] == "allow"
    assert summary["proof_id"] == str(result.proof.proof_id)


def test_verify_bundle_checks_signatures(trusted_signer):
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.1},
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
    )
    result = agent.run({"transaction_id": "t1", "amount": 1.0})
    bundle = build_receipt_bundle(result, certificate=cert, policy=policy)
    sign_bundle(bundle, trusted_signer, role="agent")
    check = verify_receipt_bundle(bundle)
    assert check.get("signatures", {}).get("valid") is True

    bundle["output"]["decision"] = "deny"
    tampered = verify_receipt_bundle(bundle)
    assert tampered["valid"] is False
    assert any(i["code"] == "signature_invalid" for i in tampered["issues"])
