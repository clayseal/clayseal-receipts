"""Lineage, handoff, budget, replay, and TEE stub tests."""

from __future__ import annotations

from pathlib import Path

from agentauth.receipts import AgentWrapper, Policy
from agentauth.capabilities.budget import BudgetType, CapabilityBudget
from agentauth.receipts.certificate import dev_certificate
from agentauth.receipts.evidence_refs import EvidenceRefs
from agentauth.receipts.export import (
    build_receipt_bundle,
    export_bundle_for_audience,
    verify_receipt_bundle,
)
from agentauth.receipts.handoff import SessionHandoffArtifact
from agentauth.capabilities.lineage import AuthorityLineage, AuthorityTransitionType
from agentauth.receipts.proof import AttestationPath, DecisionOutcome, ExecutionProof
from agentauth.receipts.replay import compare_stored_decision, rebuild_context_from_bundle
from agentauth.receipts.tee import TeeQuote, TeeQuoteFormat, verify_tee_quote

ROOT = Path(__file__).resolve().parents[2]


def test_lineage_and_budgets_in_bundle():
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
    lineage = AuthorityLineage(
        authority_id=str(cert.agent_id),
        authority_version=1,
        transition_type=AuthorityTransitionType.INITIAL,
    )
    budgets = [
        CapabilityBudget(
            budget_id="usd-daily",
            budget_type=BudgetType.USD_LIMIT,
            unit="usd",
            limit=1000,
            remaining=900,
        )
    ]
    refs = EvidenceRefs(state_snapshot_id="snap-1", decision_context_hash="abc")
    bundle = build_receipt_bundle(
        result,
        certificate=cert,
        lineage=lineage,
        budgets=budgets,
        evidence_refs=refs,
    )
    assert bundle["lineage"]["transition_type"] == "initial"
    assert bundle["budget"]["items"][0]["budget_id"] == "usd-daily"
    assert bundle["evidence_refs"]["state_snapshot_id"] == "snap-1"
    check = verify_receipt_bundle(bundle)
    assert check["valid"] is False  # shadow crypto


def test_handoff_artifact_roundtrip():
    handoff = SessionHandoffArtifact.create(
        session_id="sess-1",
        from_authority_version=1,
        to_authority_version=2,
        reason="scope_narrowed",
        prior_receipt_refs=["proof-a"],
    )
    restored = SessionHandoffArtifact.from_dict(handoff.to_dict())
    assert restored.handoff_id == handoff.handoff_id
    assert restored.prior_receipt_refs == ["proof-a"]


def test_replay_helpers():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.1},
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
    )
    result = agent.run({"transaction_id": "t1", "amount": 1.0}, session_id="s1")
    bundle = build_receipt_bundle(result, certificate=cert)
    ctx = rebuild_context_from_bundle(bundle)
    assert ctx["decision"]["outcome"] == "allow"
    cmp = compare_stored_decision(bundle)
    assert cmp["match"] is True


def test_tee_quote_stub():
    quote = TeeQuote(format=TeeQuoteFormat.TDX_V1, quote_b64="deadbeef")
    result = verify_tee_quote(quote)
    assert result["valid"] is False
    assert result["stub"] is True


def test_tee_hybrid_proof_verify_stub():
    proof = ExecutionProof.from_action(
        dev_certificate("pol"),
        {"input": {}},
        {"decision": "approve"},
        policy_satisfied=True,
        path=AttestationPath.TEE_HYBRID,
        decision_outcome=DecisionOutcome.ALLOW,
    )
    proof.bundle.tee_quote = TeeQuote(
        format=TeeQuoteFormat.TDX_V1,
        quote_b64="abc",
    ).to_dict()
    check = proof.verify()
    assert check["valid"] is False
    assert any("tee_hybrid attestation rejected" in r for r in check["reasons"])


def test_export_bundle_for_audience_modes():
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
    bundle = build_receipt_bundle(result, certificate=cert, context={"input": {"x": 1}})
    compact = export_bundle_for_audience(bundle, mode="compact")
    assert "output" in compact
    redacted = export_bundle_for_audience(bundle, mode="redacted")
    assert redacted["certificate"]["principal"]["principal_id"] == "[REDACTED]"
