"""The unified seam: an attested Clay Seal identity flows into every receipt.

These exercise the merged system end-to-end over the real in-process backend:
``identify()`` (L1/L2) -> ``wrap_agentauth_session()`` -> ``run()`` (L3/L4),
asserting the receipt's authority is the *attested* identity, not a declared
value. The wiring is receipts-side (duck-typed session) — the identity layer
never imports upward.
"""

from __future__ import annotations

from pathlib import Path

from agentauth.receipts import AgentWrapper, Policy, ReceiptedMcpGateway, build_receipt_bundle
from agentauth.receipts.integration import wrap_agentauth_session

ROOT = Path(__file__).resolve().parents[3]
POLICY = ROOT / "policies" / "fraud_decision.yaml"


def _model(_inp):
    return {"decision": "approve", "fraud_score": 0.1}


def test_identify_then_wrap_binds_identity_into_receipt(auth, tmp_path):
    agent = auth.identify(agent_type="researcher", owner="alice@acme.ai", scopes=["db:read"])
    receipted = wrap_agentauth_session(
        agent,
        _model,
        policy=Policy.from_yaml(POLICY),
        mode="shadow",
        audit_db=str(tmp_path / "audit.sqlite"),
    )
    result = receipted.run({"transaction_id": "t1", "amount": 10.0})

    # The receipt's authority is the attested SPIFFE identity from identify().
    authority = result.execution_context.authority
    assert authority.subject_id == agent.credential.spiffe_id
    assert authority.workload_principal == agent.credential.spiffe_id

    bundle = build_receipt_bundle(result, certificate=receipted.certificate)
    assert bundle["authority"]["subject_id"] == agent.credential.spiffe_id
    assert bundle["authority"]["subject_type"] == "researcher"


def test_wrapper_without_identity_still_runs(tmp_path):
    """Fallback path: a wrapper built directly (no identity) is unbound but works."""
    w = AgentWrapper(
        _model,
        Policy.from_yaml(POLICY),
        mode="shadow",
        audit_db=str(tmp_path / "audit.sqlite"),
    )
    result = w.run({"transaction_id": "t1", "amount": 10.0})
    assert result.decision is not None
    assert w.default_authority_binding is None


def test_mcp_gateway_uses_biscuit_capability_token(auth, tmp_path):
    agent = auth.identify(
        agent_type="fraud-reviewer",
        owner="risk@acme.ai",
        capabilities=[{"resource": "mcp_tool", "action": "score_transaction"}],
    )
    receipted = wrap_agentauth_session(
        agent,
        _model,
        policy=Policy.from_yaml(POLICY),
        mode="shadow",
        audit_db=str(tmp_path / "audit.sqlite"),
    )
    gateway = ReceiptedMcpGateway(receipted, server_name="fraud")
    gateway.register_tool(
        "score_transaction",
        lambda args: {"decision": "approve", "fraud_score": 0.1},
    )
    refund_ran = False

    def issue_refund(_args):
        nonlocal refund_ran
        refund_ran = True
        return {"sent": True}

    gateway.register_tool("issue_refund", issue_refund)

    ok = gateway.call_tool("score_transaction", {"transaction_id": "t1"})
    denied = gateway.call_tool("issue_refund", {"amount": 50000})

    assert ok.blocked is False
    assert denied.blocked is True
    assert refund_ran is False
    assert any("capability token" in item for item in denied.policy_violations)
