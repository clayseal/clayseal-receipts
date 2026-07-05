"""Backward compatibility shims (X-1) and decision outcomes (L3-2)."""

from __future__ import annotations

from pathlib import Path

from agentauth.receipts import AgentWrapper, Policy
from agentauth.receipts.certificate import dev_certificate
from agentauth.core.decision import STANDARD_OBLIGATION_TYPES, Obligation
from agentauth.receipts.export import build_receipt_bundle
from agentauth.receipts.mcp import ReceiptedMcpGateway
from agentauth.receipts.proof import DecisionOutcome

ROOT = Path(__file__).resolve().parents[2]


def test_run_result_legacy_dict_matches_shims():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.1},
        policy=policy,
        mode="shadow",
        audit_db=":memory:",
    )
    result = agent.run(
        {"transaction_id": "t1", "amount": 1.0},
        session_id="sess-1",
        authority_version=2,
    )
    legacy = result.to_legacy_dict()
    assert legacy["policy_violations"] == result.policy_violations
    assert legacy["decision_outcome"] == "allow"
    assert legacy["policy_satisfied"] is True
    assert legacy["session_id"] == "sess-1"
    assert legacy["authority_version"] == 2
    assert result.approval_state.value == "not_required"
    assert result.budget_effects == []


def test_decision_outcome_allow_deny_and_obligations():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.1},
        policy=policy,
        mode="shadow",
        audit_db=":memory:",
    )
    allow = agent.run({"transaction_id": "ok", "amount": 1.0})
    assert allow.decision_outcome == DecisionOutcome.ALLOW
    assert allow.proof.decision_outcome == DecisionOutcome.ALLOW

    deny = agent.record(
        action="agent.run",
        context={"input": {"transaction_id": "bad"}},
        output={"decision": "approve"},  # missing fraud_score
    )
    assert deny.decision_outcome == DecisionOutcome.DENY
    assert deny.policy_satisfied is False
    assert deny.proof.decision_outcome == DecisionOutcome.DENY

    with_ob = agent.record(
        action="agent.run",
        context={"input": {"transaction_id": "ob", "amount": 1.0}},
        output={"decision": "approve", "fraud_score": 0.1},
        obligations=[Obligation(type="create_case")],
    )
    assert with_ob.decision_outcome == DecisionOutcome.ALLOW_WITH_OBLIGATIONS
    bundle = build_receipt_bundle(with_ob, certificate=agent.certificate, policy=policy)
    assert bundle["decision"]["outcome"] == "allow_with_obligations"
    assert bundle["execution_proof"]["decision_outcome"] == "allow_with_obligations"


def test_mcp_blocked_tool_sets_deny_outcome():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())
    agent = AgentWrapper(
        model=lambda inp: inp,
        policy=policy,
        certificate=cert,
        mode="bounded_auto",
        audit_db=":memory:",
    )
    gw = ReceiptedMcpGateway(agent, server_name="test")
    gw.register_tool("score_fraud_model", lambda args: {"fraud_score": 0.1})
    blocked = gw.call_tool("not_allowed_tool", {})
    assert blocked.blocked is True
    assert blocked.decision_outcome == DecisionOutcome.DENY
    assert blocked.proof.decision_outcome == DecisionOutcome.DENY
    legacy = blocked.to_legacy_dict()
    assert legacy["decision_outcome"] == "deny"
    assert legacy["blocked"] is True


def test_supported_outcomes_cover_vocabulary():
    values = set(DecisionOutcome.supported_values())
    for expected in (
        "allow",
        "deny",
        "pending_approval",
        "pending_step_up",
        "allow_with_obligations",
        "budget_reservation_required",
    ):
        assert expected in values


def test_standard_obligation_types_are_documented():
    assert "persist_handoff" in STANDARD_OBLIGATION_TYPES
    assert "create_case" in STANDARD_OBLIGATION_TYPES
