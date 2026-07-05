"""Budget export, replay compare, bounded_auto execution gate, and v2 redaction."""

from __future__ import annotations

from pathlib import Path

from agentauth.receipts import AgentWrapper, Policy
from agentauth.capabilities.budget import BudgetType, CapabilityBudget
from agentauth.receipts.certificate import dev_certificate
from agentauth.core.decision import BudgetEffect, Obligation
from agentauth.receipts.explain import explain_receipt_bundle
from agentauth.receipts.export import build_receipt_bundle, verify_receipt_bundle
from agentauth.receipts.policy_engine import ReservationResult
from agentauth.receipts.proof import DecisionOutcome
from agentauth.receipts.redact import REDACTED, redact_receipt_bundle
from agentauth.receipts.replay import compare_budget_effects

ROOT = Path(__file__).resolve().parents[2]


def _reservation_with_effects(*_args, **_kwargs) -> ReservationResult:
    return ReservationResult(
        outcome=DecisionOutcome.ALLOW,
        budget_effects=[
            BudgetEffect(
                budget_id="usd-daily",
                effect_type="reserve",
                amount=50.0,
                status="planned",
            )
        ],
    )


def test_v2_budget_section_includes_summary():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.1},
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
        reservation_callback=_reservation_with_effects,
    )
    result = agent.run({"transaction_id": "t1", "amount": 10.0})
    budgets = [
        CapabilityBudget(
            budget_id="usd-daily",
            budget_type=BudgetType.USD_LIMIT,
            unit="usd",
            limit=1000,
            remaining=950,
        )
    ]
    bundle = build_receipt_bundle(result, certificate=cert, budgets=budgets)
    assert "summary" in bundle["budget"]
    assert bundle["budget"]["summary"]["usd-daily"]["reserved_amount"] == 50.0
    check = verify_receipt_bundle(bundle)
    assert check["valid"] is False  # shadow crypto
    assert not any(
        issue["message"].startswith("budget.")
        for issue in check["issues"]
    )


def test_compare_budget_effects_detects_mismatch():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.1},
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
        reservation_callback=_reservation_with_effects,
    )
    result = agent.run({"transaction_id": "t1", "amount": 10.0})
    bundle = build_receipt_bundle(result, certificate=cert)
    assert compare_budget_effects(bundle)["match"] is True
    bundle["budget"]["effects"][0]["amount"] = 999.0
    report = compare_budget_effects(bundle)
    assert report["match"] is False
    assert "effects" in report["mismatches"]


def test_explain_includes_execution_gate_and_budget():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.1},
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
        reservation_callback=_reservation_with_effects,
    )
    result = agent.record(
        action="agent.run",
        context={"input": {"transaction_id": "t1"}},
        output={"decision": "approve", "fraud_score": 0.1},
        obligations=[Obligation(type="persist_handoff", required_before_effect=True)],
    )
    bundle = build_receipt_bundle(result, certificate=cert)
    report = explain_receipt_bundle(bundle)
    assert report["budget"] is not None
    assert report["decision"]["can_execute"] is False
    assert report["decision"]["blocking_obligations"]
    assert any("execution gate" in w for w in report["warnings"])


def test_bounded_auto_blocks_execution_gate():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.1},
        policy=policy,
        certificate=cert,
        mode="bounded_auto",
        audit_db=":memory:",
    )
    result = agent.record(
        action="agent.run",
        context={"input": {"transaction_id": "t1", "amount": 10.0}},
        output={"decision": "approve", "fraud_score": 0.1},
        obligations=[Obligation(type="persist_handoff", required_before_effect=True)],
    )
    assert result.output["decision"] == "abstain"
    assert result.decision.outcome == DecisionOutcome.DENY


def test_redact_v2_budget_and_session():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.1},
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
        reservation_callback=_reservation_with_effects,
    )
    result = agent.run({"transaction_id": "t1", "amount": 10.0}, session_id="sess-secret")
    bundle = build_receipt_bundle(result, certificate=cert)
    redacted = redact_receipt_bundle(bundle)
    assert redacted["session"]["session_id"] == REDACTED
    assert redacted["budget"]["summary"] == REDACTED
    assert redacted["output"] == REDACTED
