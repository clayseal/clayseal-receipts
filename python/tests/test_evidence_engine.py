"""L4-2 evidence split, L3-15 policy engine, L3-8 reservation tests."""

from __future__ import annotations

from pathlib import Path

from agentauth.receipts import AgentWrapper, Policy
from agentauth.receipts.certificate import dev_certificate
from agentauth.core.decision import BudgetEffect
from agentauth.receipts.evidence import (
    DecisionRecord,
    EvidenceSummary,
    decision_record_from_run,
)
from agentauth.receipts.export import build_receipt_bundle
from agentauth.receipts.policy_engine import ReservationResult, YamlPolicyEngine
from agentauth.receipts.proof import DecisionOutcome
from agentauth.core.runtime import ActionDescriptor, AuthorityContext, ExecutionContext

ROOT = Path(__file__).resolve().parents[2]


def test_evidence_block_on_export():
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
    bundle = build_receipt_bundle(result, certificate=cert)
    assert "evidence" in bundle
    assert bundle["evidence"]["summary"]["assurance_level"] == "shadow"
    assert bundle["evidence"]["decision_record"]["outcome"] == "allow"


def test_decision_record_from_run():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.1},
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
    )
    result = agent.run({"transaction_id": "t1", "amount": 1.0}, session_id="s-1")
    record = decision_record_from_run(result)
    assert isinstance(record, DecisionRecord)
    assert record.authority is not None
    assert record.authority.session_id == "s-1"


def test_yaml_policy_engine_matches_wrapper():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    engine = YamlPolicyEngine(policy)
    good = engine.evaluate({"decision": "approve", "fraud_score": 0.2})
    assert good.policy_satisfied is True
    bad = engine.evaluate({"decision": "approve", "fraud_score": 9.0})
    assert bad.policy_satisfied is False
    assert bad.outcome == DecisionOutcome.DENY


def test_yaml_policy_engine_rejects_expired_authority():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    engine = YamlPolicyEngine(policy)
    context = ExecutionContext(
        action=ActionDescriptor(
            action_name="read",
            action_category="data",
            resource_type="db",
        ),
        input={},
        authority=AuthorityContext(
            authority_id="grant-1",
            expires_at="2000-01-01T00:00:00Z",
        ),
    )

    result = engine.evaluate(
        {"decision": "approve", "fraud_score": 0.2},
        execution_context=context,
    )

    assert result.policy_satisfied is False
    assert result.outcome == DecisionOutcome.DENY
    assert "authority is expired" in result.violations


def test_yaml_policy_engine_rejects_sender_constrained_authority_without_pop():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    engine = YamlPolicyEngine(policy)
    context = ExecutionContext(
        action=ActionDescriptor(
            action_name="read",
            action_category="data",
            resource_type="db",
        ),
        input={},
        authority=AuthorityContext(
            authority_id="grant-2",
            trust_tier="sender_constrained",
            proof_of_possession=False,
            capabilities=["db:read"],
            scope_claims=["db:read"],
            has_capability_grant=True,
        ),
    )

    result = engine.evaluate(
        {"decision": "approve", "fraud_score": 0.2},
        execution_context=context,
    )

    assert result.policy_satisfied is False
    assert result.outcome == DecisionOutcome.DENY
    assert any("proof_of_possession" in item for item in result.violations)


def test_yaml_policy_engine_enforces_capability_rules_against_action():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    engine = YamlPolicyEngine(policy)
    context = ExecutionContext(
        action=ActionDescriptor(
            action_name="write",
            action_category="data",
            resource_type="db",
        ),
        input={},
        authority=AuthorityContext(
            authority_id="grant-3",
            capability_rules=[{"resource": "db", "action": "read"}],
            capabilities=["db:read"],
            scope_claims=["db:read"],
            proof_of_possession=True,
            has_capability_grant=True,
        ),
    )

    result = engine.evaluate(
        {"decision": "approve", "fraud_score": 0.2},
        execution_context=context,
    )

    assert result.policy_satisfied is False
    assert result.outcome == DecisionOutcome.DENY
    assert "authority capabilities do not allow this action" in result.violations


def test_yaml_policy_engine_allows_matching_capability_rule():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    engine = YamlPolicyEngine(policy)
    context = ExecutionContext(
        action=ActionDescriptor(
            action_name="read",
            action_category="data",
            resource_type="db",
        ),
        input={},
        authority=AuthorityContext(
            authority_id="grant-4",
            capability_rules=[{"resource": "db", "action": "read"}],
            capabilities=["db:read"],
            scope_claims=["db:read"],
            proof_of_possession=True,
            has_capability_grant=True,
        ),
    )

    result = engine.evaluate(
        {"decision": "approve", "fraud_score": 0.2},
        execution_context=context,
    )

    assert result.policy_satisfied is True
    assert result.outcome == DecisionOutcome.ALLOW


def test_yaml_policy_engine_enforces_resource_scope_against_resource_ref():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    engine = YamlPolicyEngine(policy)
    context = ExecutionContext(
        action=ActionDescriptor(
            action_name="read",
            action_category="data",
            resource_type="db",
            resource_ref="db://secondary",
        ),
        input={},
        authority=AuthorityContext(
            authority_id="grant-5",
            capability_rules=[{"resource": "db", "action": "read"}],
            capabilities=["db:read"],
            scope_claims=["db:read"],
            resource_scope=["db://primary"],
            proof_of_possession=True,
            has_capability_grant=True,
        ),
    )

    result = engine.evaluate(
        {"decision": "approve", "fraud_score": 0.2},
        execution_context=context,
    )

    assert result.policy_satisfied is False
    assert result.outcome == DecisionOutcome.DENY
    assert "authority resource_scope does not allow this action" in result.violations


def test_yaml_policy_engine_allows_wildcard_resource_scope():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    engine = YamlPolicyEngine(policy)
    context = ExecutionContext(
        action=ActionDescriptor(
            action_name="read",
            action_category="data",
            resource_type="db",
            resource_ref="db://primary",
        ),
        input={},
        authority=AuthorityContext(
            authority_id="grant-6",
            capability_rules=[{"resource": "db", "action": "read"}],
            capabilities=["db:read"],
            scope_claims=["db:read"],
            resource_scope=["db://*"],
            proof_of_possession=True,
            has_capability_grant=True,
        ),
    )

    result = engine.evaluate(
        {"decision": "approve", "fraud_score": 0.2},
        execution_context=context,
    )

    assert result.policy_satisfied is True
    assert result.outcome == DecisionOutcome.ALLOW


def test_yaml_policy_engine_enforces_min_trust_tier():
    policy = Policy(
        version=1,
        name="trust-gated",
        tier=Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml").tier,
        capability=Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml").capability,
        min_trust_tier="signed",
    )
    engine = YamlPolicyEngine(policy)
    context = ExecutionContext(
        action=ActionDescriptor(action_name="read", action_category="data"),
        input={},
        authority=AuthorityContext(
            authority_id="grant-trust",
            trust_tier="shadow",
            proof_of_possession=True,
        ),
    )

    result = engine.evaluate({"decision": "approve", "fraud_score": 0.1}, execution_context=context)

    assert result.policy_satisfied is False
    assert any("trust_tier" in violation for violation in result.violations)


def test_yaml_policy_engine_enforces_budget_refs():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    engine = YamlPolicyEngine(policy)
    context = ExecutionContext(
        action=ActionDescriptor(action_name="read", action_category="data"),
        input={},
        authority=AuthorityContext(
            authority_id="grant-budget",
            budget_refs=["budget-a"],
            proof_of_possession=True,
        ),
        authorization={"budget_id": "budget-b"},
    )

    result = engine.evaluate({"decision": "approve", "fraud_score": 0.1}, execution_context=context)

    assert result.policy_satisfied is False
    assert any("budget_id" in violation for violation in result.violations)


def test_yaml_policy_engine_enforces_approval_refs():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    engine = YamlPolicyEngine(policy)
    context = ExecutionContext(
        action=ActionDescriptor(action_name="read", action_category="data"),
        input={},
        authority=AuthorityContext(
            authority_id="grant-approval",
            approval_refs=["approval-1"],
            proof_of_possession=True,
        ),
        authorization={"approval_id": "approval-2"},
    )

    result = engine.evaluate({"decision": "approve", "fraud_score": 0.1}, execution_context=context)

    assert result.policy_satisfied is False
    assert any("approval_refs" in violation for violation in result.violations)


class _CountingEngine:
    def evaluate(self, output, *, execution_context=None, extra_violations=None):
        engine = YamlPolicyEngine(Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml"))
        return engine.evaluate(
            output,
            execution_context=execution_context,
            extra_violations=extra_violations,
        )


def test_custom_policy_engine_pluggable():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.1},
        policy=policy,
        certificate=cert,
        policy_engine=_CountingEngine(),
        mode="shadow",
        audit_db=":memory:",
    )
    result = agent.run({"transaction_id": "t1", "amount": 1.0})
    assert result.decision.policy_satisfied is True


def test_budget_reservation_required_outcome():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())

    def require_reservation(ctx: ExecutionContext, output: dict, violations: list[str]):
        return ReservationResult(
            outcome=DecisionOutcome.BUDGET_RESERVATION_REQUIRED,
            budget_effects=[
                BudgetEffect(
                    budget_id="usd-daily",
                    effect_type="reserved",
                    amount=100,
                    status="planned",
                )
            ],
        )

    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.1},
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
        reservation_callback=require_reservation,
    )
    result = agent.run({"transaction_id": "t1", "amount": 1.0})
    assert result.decision_outcome == DecisionOutcome.BUDGET_RESERVATION_REQUIRED
    assert len(result.decision.budget_effects) == 1
    summary = EvidenceSummary.from_proof(result.proof)
    assert summary.policy_satisfied is True
