"""L3 foundation acceptance tests (L3-1, L3-3, L3-5, L3-9, X-5)."""

from __future__ import annotations

from pathlib import Path

from agentauth.receipts import AgentWrapper, Policy
from agentauth.receipts.certificate import dev_certificate
from agentauth.core.decision import (
    ApprovalMetadata,
    ApprovalState,
    DecisionResult,
    Obligation,
    is_standard_obligation_type,
)
from agentauth.receipts.export import build_receipt_bundle, verify_receipt_bundle
from agentauth.receipts.handoff import SessionHandoffArtifact
from agentauth.capabilities.lineage import AuthorityLineage, AuthorityTransitionType
from agentauth.receipts.mcp import ReceiptedMcpGateway
from agentauth.core.runtime import (
    ActionDescriptor,
    ActorKind,
    ActorRef,
    AuthorityContext,
    ExecutionContext,
    SideEffectLevel,
)
from agentauth.receipts.verification import VerifyErrorCode

ROOT = Path(__file__).resolve().parents[2]


def test_run_result_and_mcp_share_decision_result():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.1},
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
    )
    run = agent.run({"transaction_id": "t1", "amount": 1.0}, session_id="s1")
    assert isinstance(run.decision, DecisionResult)

    gw = ReceiptedMcpGateway(agent, server_name="fraud")
    gw.register_tool("score_fraud_model", lambda args: {"fraud_score": 0.2})
    tool = gw.call_tool("score_fraud_model", {"amount": 1.0})
    assert isinstance(tool.decision, DecisionResult)
    assert tool.decision.outcome == run.decision.outcome.__class__(tool.decision.outcome.value)


def test_record_accepts_execution_context_object():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())
    agent = AgentWrapper(
        model=lambda inp: inp,
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
    )
    ctx = ExecutionContext(
        action=ActionDescriptor(
            action_name="cloud.deploy",
            action_category="deployment",
            resource_type="service",
            resource_ref="service:payments-api",
            side_effect_level=SideEffectLevel.PRIVILEGED_MUTATION,
        ),
        input={"release_id": "rel-1"},
        authority=AuthorityContext(
            authority_id=str(cert.agent_id),
            authority_version=2,
            session_id="sess-ctx",
            actor_ref=ActorRef(kind=ActorKind.TOP_LEVEL_AGENT, actor_id="planner-1"),
            budget_refs=["deploy-budget"],
        ),
        touched_resources=["service:payments-api"],
    )
    result = agent.record(
        action=ctx.action,
        context=ctx,
        output={"decision": "approve", "fraud_score": 0.05},
        approval_metadata=ApprovalMetadata(approval_id="appr-1"),
        approval_state=ApprovalState.APPROVED,
    )
    bundle = build_receipt_bundle(result, certificate=cert, policy=policy)
    assert bundle["action"]["side_effect_level"] == "privileged_mutation"
    assert bundle["authority"]["session_id"] == "sess-ctx"
    assert bundle["decision"]["approval_state"] == "approved"
    assert bundle["execution_context"]["authority"]["budget_refs"] == ["deploy-budget"]
    restored = ExecutionContext.from_dict(bundle["execution_context"])
    assert restored.authority.session_id == "sess-ctx"


def test_obligations_on_receipt_and_evidence_block():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.1},
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
    )
    obligation = Obligation(
        type="create_case",
        details={"queue": "fraud-review"},
        required_after_effect=True,
    )
    assert is_standard_obligation_type("create_case")
    result = agent.record(
        action="agent.run",
        context={"input": {"transaction_id": "t1"}},
        output={"decision": "approve", "fraud_score": 0.1},
        obligations=[obligation],
    )
    bundle = build_receipt_bundle(result, certificate=cert, policy=policy)
    assert bundle["decision"]["obligations"][0]["type"] == "create_case"
    assert bundle["evidence"]["obligations"]["blocking"] == []
    assert len(bundle["evidence"]["obligations"]["after_effect"]) == 1
    check = verify_receipt_bundle(bundle)
    assert not any("obligation" in issue["message"] for issue in check["issues"])


def test_verifier_detects_tampered_obligation_summary():
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
        context={"input": {}},
        output={"decision": "approve", "fraud_score": 0.1},
        obligations=[Obligation(type="log_extra")],
    )
    bundle = build_receipt_bundle(result, certificate=cert, policy=policy)
    bundle["evidence"]["obligations"]["all"] = []
    check = verify_receipt_bundle(bundle)
    codes = {item["code"] for item in check["issues"]}
    assert VerifyErrorCode.DECISION_MISMATCH.value in codes


def test_action_classification_on_audit_and_receipt():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.1},
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
    )
    action = ActionDescriptor(
        action_name="payments.capture",
        action_category="payments",
        resource_type="transaction",
        resource_ref="transaction:txn-9",
        side_effect_level=SideEffectLevel.BOUNDED_WRITE,
    )
    result = agent.run({"amount": 1.0}, action=action, session_id="s9")
    assert result.audit_record.action == "payments.capture"
    bundle = build_receipt_bundle(result, certificate=cert)
    assert bundle["action"]["action_category"] == "payments"
    assert bundle["action"]["resource_ref"] == "transaction:txn-9"


def test_lineage_and_handoff_on_receipt():
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
        authority_version=2,
        transition_type=AuthorityTransitionType.DELEGATED,
    )
    handoff = SessionHandoffArtifact.create(
        session_id="sess-h",
        from_authority_version=1,
        to_authority_version=2,
        reason="delegation",
    )
    bundle = build_receipt_bundle(
        result,
        certificate=cert,
        lineage=lineage,
        handoff=handoff,
    )
    assert bundle["lineage"]["transition_type"] == "delegated"
    assert bundle["handoff"]["session_id"] == "sess-h"
