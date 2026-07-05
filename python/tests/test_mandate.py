"""Signed mandate binding on receipt bundles (SOTA-6)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from agentauth.receipts import Policy
from agentauth.capabilities.budget import BudgetType, CapabilityBudget
from agentauth.receipts.certificate import dev_certificate
from agentauth.core.decision import BudgetEffect
from agentauth.receipts.export import build_receipt_bundle, verify_receipt_bundle
from agentauth.capabilities.mandate import (
    check_receipt_against_mandate,
    issue_mandate,
    verify_mandate_envelope,
    verify_mandate_signature,
)
from agentauth.receipts.policy_engine import ReservationResult
from agentauth.receipts.proof import DecisionOutcome
from agentauth.core.signing import generate_keypair
from agentauth.receipts.wrapper import AgentWrapper

ROOT = Path(__file__).resolve().parents[2]


def _reservation(amount: float) -> ReservationResult:
    return ReservationResult(
        outcome=DecisionOutcome.ALLOW,
        budget_effects=[
            BudgetEffect(
                budget_id="usd-daily",
                effect_type="reserve",
                amount=amount,
                status="planned",
            )
        ],
    )


def _run_and_bundle(*, amount: float, signed_mandate, cert=None):
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = cert or dev_certificate(policy.commitment())
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.1},
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
        reservation_callback=lambda *_a, **_k: _reservation(amount),
    )
    result = agent.run({"transaction_id": "t1", "amount": amount})
    budgets = [
        CapabilityBudget(
            budget_id="usd-daily",
            budget_type=BudgetType.USD_LIMIT,
            unit="usd",
            limit=1000,
            remaining=950,
        )
    ]
    return build_receipt_bundle(
        result,
        certificate=cert,
        budgets=budgets,
        signed_mandate=signed_mandate,
    )


def test_mandate_signature_roundtrip():
    key = generate_keypair()
    envelope = issue_mandate(
        issuer=key.public_key_hex,
        key=key,
        budgets=[
            CapabilityBudget(
                budget_id="usd-daily",
                budget_type=BudgetType.USD_LIMIT,
                unit="usd",
                limit=100.0,
                remaining=100.0,
            )
        ],
        allowed_actions=["approve_transaction"],
    )
    assert verify_mandate_signature(envelope)
    assert verify_mandate_envelope(envelope) == []


def test_in_mandate_receipt_passes_mandate_checks():
    key = generate_keypair()
    envelope = issue_mandate(
        issuer=key.public_key_hex,
        key=key,
        budgets=[
            CapabilityBudget(
                budget_id="usd-daily",
                budget_type=BudgetType.USD_LIMIT,
                unit="usd",
                limit=100.0,
                remaining=100.0,
            )
        ],
        allowed_actions=["agent.run"],
    )
    bundle = _run_and_bundle(amount=50.0, signed_mandate=envelope)
    mandate_issues = [
        issue
        for issue in verify_receipt_bundle(bundle)["issues"]
        if issue["code"] == "mandate_violation"
    ]
    assert mandate_issues == []


def test_over_limit_rejected():
    key = generate_keypair()
    envelope = issue_mandate(
        issuer=key.public_key_hex,
        key=key,
        budgets=[
            CapabilityBudget(
                budget_id="usd-daily",
                budget_type=BudgetType.USD_LIMIT,
                unit="usd",
                limit=25.0,
                remaining=25.0,
            )
        ],
    )
    bundle = _run_and_bundle(amount=50.0, signed_mandate=envelope)
    mandate_issues = [
        issue
        for issue in verify_receipt_bundle(bundle)["issues"]
        if issue["code"] == "mandate_violation"
    ]
    assert any("exceeds mandate limit" in issue["message"] for issue in mandate_issues)


def test_expired_mandate_rejected():
    key = generate_keypair()
    expired_at = datetime.now(timezone.utc) - timedelta(hours=1)
    issued_at = expired_at - timedelta(hours=1)
    envelope = issue_mandate(
        issuer=key.public_key_hex,
        key=key,
        issued_at=issued_at,
        expires_at=expired_at,
        budgets=[
            CapabilityBudget(
                budget_id="usd-daily",
                budget_type=BudgetType.USD_LIMIT,
                unit="usd",
                limit=100.0,
                remaining=100.0,
            )
        ],
    )
    bundle = _run_and_bundle(amount=10.0, signed_mandate=envelope)
    mandate_issues = [
        issue
        for issue in verify_receipt_bundle(bundle)["issues"]
        if issue["code"] == "mandate_violation"
    ]
    assert any("expired" in issue["message"] for issue in mandate_issues)


def test_check_receipt_against_mandate_action_scope():
    key = generate_keypair()
    envelope = issue_mandate(
        issuer=key.public_key_hex,
        key=key,
        allowed_actions=["other_action"],
    )
    from agentauth.capabilities.mandate import Mandate

    mandate = Mandate.from_dict(envelope["document"])
    violations = check_receipt_against_mandate(
        mandate,
        action={"action_name": "fraud_decision"},
        decision={"outcome": "allow", "policy_satisfied": True},
        at=datetime.now(timezone.utc),
    )
    assert any("allowed_actions" in item for item in violations)


def test_mandate_rejects_issuer_not_bound_to_signer():
    key = generate_keypair()
    envelope = issue_mandate(
        issuer="principal-1",
        key=key,
    )
    violations = verify_mandate_envelope(envelope)
    assert any("issuer is not bound" in item for item in violations)


def test_mandate_delegate_must_match_receipt_authority():
    key = generate_keypair()
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())
    envelope = issue_mandate(
        issuer=key.public_key_hex,
        key=key,
        delegate=str(cert.agent_id),
        allowed_actions=["agent.run"],
    )
    bundle = _run_and_bundle(amount=10.0, signed_mandate=envelope, cert=cert)
    mandate_issues = [
        issue
        for issue in verify_receipt_bundle(bundle)["issues"]
        if issue["code"] == "mandate_violation"
    ]
    assert mandate_issues == []

    import uuid

    bundle["authority"]["authority_id"] = "wrong-actor"
    bundle["execution_proof"]["agent_id"] = str(uuid.uuid4())
    bundle["certificate"]["agent_id"] = str(uuid.uuid4())
    bundle["certificate"]["principal"]["principal_id"] = "wrong-principal"
    mandate_issues = [
        issue
        for issue in verify_receipt_bundle(bundle)["issues"]
        if issue["code"] == "mandate_violation"
    ]
    assert any("delegate" in issue["message"] for issue in mandate_issues)


def test_mandate_parent_grant_requires_embedded_parent():
    from agentauth.capabilities.budget import BudgetType, CapabilityBudget
    from agentauth.capabilities.mandate import mandate_bundle_section, verify_bundle_mandate

    key = generate_keypair()
    now = datetime.now(timezone.utc)
    parent = issue_mandate(
        issuer=key.public_key_hex,
        key=key,
        allowed_actions=["agent.run"],
        budgets=[
            CapabilityBudget(
                budget_id="usd-daily",
                budget_type=BudgetType.USD_LIMIT,
                unit="usd",
                limit=100.0,
                remaining=100.0,
            )
        ],
        issued_at=now,
        expires_at=now + timedelta(hours=1),
    )
    child = issue_mandate(
        issuer=key.public_key_hex,
        key=key,
        parent_grant_id=parent["document"]["grant_id"],
        allowed_actions=["agent.run"],
        budgets=[
            CapabilityBudget(
                budget_id="usd-daily",
                budget_type=BudgetType.USD_LIMIT,
                unit="usd",
                limit=50.0,
                remaining=50.0,
            )
        ],
        issued_at=now,
        expires_at=now + timedelta(minutes=30),
    )
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    bundle = _run_and_bundle(
        amount=10.0,
        signed_mandate=child,
        cert=dev_certificate(policy.commitment()),
    )
    violations = verify_bundle_mandate(bundle)
    assert any("parent mandate not embedded" in item for item in violations)

    bundle["mandate"]["parent"] = mandate_bundle_section(parent)
    assert verify_bundle_mandate(bundle) == []


def test_budget_affecting_receipt_requires_signed_mandate():
    bundle = _run_and_bundle(amount=10.0, signed_mandate=None)
    mandate_issues = [
        issue
        for issue in verify_receipt_bundle(bundle)["issues"]
        if issue["code"] == "mandate_violation"
    ]
    assert any("signed mandate required" in issue["message"] for issue in mandate_issues)


def test_child_mandate_cannot_outlive_parent():
    from agentauth.capabilities.budget import BudgetType, CapabilityBudget
    from agentauth.capabilities.mandate import mandate_bundle_section, verify_bundle_mandate

    key = generate_keypair()
    now = datetime.now(timezone.utc)
    parent = issue_mandate(
        issuer=key.public_key_hex,
        key=key,
        delegate=key.public_key_hex,
        allowed_actions=["agent.run"],
        budgets=[
            CapabilityBudget(
                budget_id="usd-daily",
                budget_type=BudgetType.USD_LIMIT,
                unit="usd",
                limit=100.0,
                remaining=100.0,
            )
        ],
        issued_at=now,
        expires_at=now + timedelta(hours=1),
    )
    child = issue_mandate(
        issuer=key.public_key_hex,
        key=key,
        parent_grant_id=parent["document"]["grant_id"],
        allowed_actions=["agent.run"],
        budgets=[
            CapabilityBudget(
                budget_id="usd-daily",
                budget_type=BudgetType.USD_LIMIT,
                unit="usd",
                limit=50.0,
                remaining=50.0,
            )
        ],
        issued_at=now + timedelta(minutes=5),
        expires_at=now + timedelta(hours=2),
    )
    bundle = _run_and_bundle(amount=10.0, signed_mandate=child)
    bundle["mandate"]["parent"] = mandate_bundle_section(parent)
    violations = verify_bundle_mandate(bundle)
    assert any("expires_at exceeds parent" in item for item in violations)


def test_parent_delegate_must_match_child_issuer():
    from agentauth.capabilities.budget import BudgetType, CapabilityBudget
    from agentauth.capabilities.mandate import mandate_bundle_section, verify_bundle_mandate

    parent_key = generate_keypair()
    child_key = generate_keypair()
    parent = issue_mandate(
        issuer=parent_key.public_key_hex,
        key=parent_key,
        delegate="delegate-a",
        allowed_actions=["agent.run"],
        budgets=[
            CapabilityBudget(
                budget_id="usd-daily",
                budget_type=BudgetType.USD_LIMIT,
                unit="usd",
                limit=100.0,
                remaining=100.0,
            )
        ],
    )
    child = issue_mandate(
        issuer=child_key.public_key_hex,
        key=child_key,
        parent_grant_id=parent["document"]["grant_id"],
        allowed_actions=["agent.run"],
        budgets=[
            CapabilityBudget(
                budget_id="usd-daily",
                budget_type=BudgetType.USD_LIMIT,
                unit="usd",
                limit=50.0,
                remaining=50.0,
            )
        ],
    )
    bundle = _run_and_bundle(amount=10.0, signed_mandate=child)
    bundle["mandate"]["parent"] = mandate_bundle_section(parent)
    violations = verify_bundle_mandate(bundle)
    assert any("delegate does not match child mandate issuer" in item for item in violations)
