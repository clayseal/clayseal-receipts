from pathlib import Path

from agentauth.receipts import AgentWrapper, Policy
from agentauth.receipts.certificate import dev_certificate
from agentauth.receipts.export import build_receipt_bundle
from agentauth.receipts.redact import REDACTED, redact_receipt_bundle

ROOT = Path(__file__).resolve().parents[2]


def test_redact_principal_and_context():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment(), principal_id="secret-user", organization="acme")
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.1},
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
    )
    result = agent.run({"transaction_id": "tx-secret", "amount": 1.0})
    bundle = build_receipt_bundle(
        result,
        certificate=cert,
        context={"input": {"transaction_id": "tx-secret"}},
    )
    redacted = redact_receipt_bundle(bundle)
    assert redacted["certificate"]["principal"]["principal_id"] == REDACTED
    assert redacted["context"]["input"] == REDACTED


def test_redact_execution_context_input():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment(), principal_id="secret-user", organization="acme")
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.1},
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
    )
    result = agent.run({"transaction_id": "tx-secret", "amount": 1.0}, session_id="sess-secret")
    bundle = build_receipt_bundle(result, certificate=cert)
    redacted = redact_receipt_bundle(bundle)
    assert redacted["execution_context"]["input"] == REDACTED
    assert redacted["decision"]["session_id"] == REDACTED
    assert redacted["authority"]["session_id"] == REDACTED


def test_redact_list_fields_in_decision_and_budgets():
    bundle = {
        "decision": {
            "obligations": [
                {"type": "create_case", "details": {"case_owner": "secret"}},
                {"type": "log_extra", "details": {"pii": "ssn"}},
            ],
            "budget_effects": [
                {"budget_id": "b-secret", "amount": 250},
            ],
        },
        "budgets": [
            {"budget_id": "b-secret", "limit": 1000, "remaining": 750, "scope": "acct-9"},
        ],
    }
    redacted = redact_receipt_bundle(bundle)
    # Each obligation's details redacted, but type preserved
    assert redacted["decision"]["obligations"][0]["details"] == REDACTED
    assert redacted["decision"]["obligations"][1]["details"] == REDACTED
    assert redacted["decision"]["obligations"][0]["type"] == "create_case"
    # Budget effects (list) redacted per element
    assert redacted["decision"]["budget_effects"][0]["budget_id"] == REDACTED
    assert redacted["decision"]["budget_effects"][0]["amount"] == REDACTED
    # Budgets block (correct `budgets` list name) redacted
    assert redacted["budgets"][0]["budget_id"] == REDACTED
    assert redacted["budgets"][0]["limit"] == REDACTED
    assert redacted["budgets"][0]["remaining"] == REDACTED


def test_redact_handoff_block():
    bundle = {
        "handoff": {
            "handoff_id": "h-1",
            "session_id": "sess-secret",
            "touched_resources": ["acct-9"],
            "pending_obligations": [{"type": "persist_handoff", "details": {"x": 1}}],
            "reason": "authority_change",
        }
    }
    redacted = redact_receipt_bundle(bundle)
    assert redacted["handoff"]["session_id"] == REDACTED
    assert redacted["handoff"]["touched_resources"] == REDACTED
    assert redacted["handoff"]["pending_obligations"][0] == REDACTED
    # Non-sensitive field preserved
    assert redacted["handoff"]["reason"] == "authority_change"


def test_redact_is_noop_for_missing_lists():
    # No matching keys -> unchanged, no error
    bundle = {"decision": {"outcome": "allow"}}
    assert redact_receipt_bundle(bundle)["decision"]["outcome"] == "allow"
