"""Attestation profile verification tests."""

from __future__ import annotations

from agentauth.receipts.certificate import dev_certificate
from agentauth.receipts.proof import AttestationPath, DecisionOutcome, ExecutionProof


def test_full_zk_requires_inference_or_composed_proof():
    cert = dev_certificate("policy-commit")
    proof = ExecutionProof.from_action(
        cert,
        {"input": {"x": 1}},
        {"decision": "approve", "fraud_score": 0.1},
        policy_satisfied=True,
        path=AttestationPath.FULL_ZK,
        decision_outcome=DecisionOutcome.ALLOW,
    )
    result = proof.verify()
    assert result["valid"] is False
    assert any("missing policy_proof" in reason for reason in result["reasons"])
    assert any(
        "missing inference_proof or composed_proof" in reason
        for reason in result["reasons"]
    )
