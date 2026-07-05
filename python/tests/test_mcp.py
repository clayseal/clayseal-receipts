from pathlib import Path
from uuid import uuid4

from agentauth.receipts import (
    AgentWrapper,
    Policy,
    ReceiptedMcpGateway,
    capability_allows,
    issue_delegation,
    mcp_tool_capability,
)
from agentauth.receipts.certificate import dev_certificate

ROOT = Path(__file__).resolve().parents[2]


def _authorizer(*tools: str):
    capabilities = [mcp_tool_capability(tool) for tool in tools]

    def authorize(resource: str, action: str) -> dict:
        allowed = capability_allows(capabilities, resource, action)
        return {"allowed": allowed, "reason": "authorized" if allowed else "denied"}

    return authorize


def test_mcp_tool_writes_audit_with_action_name():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")

    def model(inp: dict) -> dict:
        return {"decision": "approve", "fraud_score": 0.1}

    agent = AgentWrapper(
        model=model,
        policy=policy,
        mode="shadow",
        audit_db=":memory:",
        capability_authorizer=_authorizer("score_transaction"),
    )
    gw = ReceiptedMcpGateway(agent, server_name="test-server")
    gw.register_tool("score_transaction", lambda args: {"ok": True})

    result = gw.call_tool("score_transaction", {"transaction_id": "x"})
    assert result.output["status"] == "ok"
    assert result.audit_record.action == "mcp.tools/call/score_transaction"
    assert result.execution_context.action.action_category == "mcp_tool_call"
    assert result.execution_context.action.resource_ref == "test-server:score_transaction"
    assert result.execution_context.touched_resources == ["mcp://test-server/score_transaction"]
    assert len(agent.audit) == 1


def test_bounded_auto_blocks_disallowed_tool():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())

    def model(inp: dict) -> dict:
        return {"decision": "approve", "fraud_score": 0.1}

    agent = AgentWrapper(
        model=model,
        policy=policy,
        certificate=cert,
        mode="bounded_auto",
        audit_db=":memory:",
        capability_authorizer=_authorizer("score_transaction"),
    )
    gw = ReceiptedMcpGateway(agent, server_name="test-server")
    gw.register_tool("transfer_funds", lambda args: {"sent": True})

    result = gw.call_tool("transfer_funds", {"amount": 1})
    assert result.blocked is True
    assert result.output["status"] == "blocked"
    assert result.proof.decision_outcome.value == "deny"
    assert result.execution_context.action.resource_ref == "test-server:transfer_funds"
    assert any("capability token" in v for v in result.policy_violations)


def test_shadow_mode_blocks_side_effect_tools_on_violation():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())

    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.1},
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
        capability_authorizer=_authorizer("score_transaction"),
    )
    gw = ReceiptedMcpGateway(agent, server_name="test-server")
    gw.register_tool("transfer_funds", lambda args: {"sent": True})

    result = gw.call_tool("transfer_funds", {"amount": 1})
    assert result.blocked is True
    assert result.output["status"] == "blocked"
    assert result.proof.decision_outcome.value == "deny"


def test_shadow_mode_allows_unsafe_execution_when_opted_in():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())

    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.1},
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
        capability_authorizer=_authorizer("score_transaction"),
    )
    gw = ReceiptedMcpGateway(
        agent,
        server_name="test-server",
        allow_unsafe_execution=True,
    )
    gw.register_tool("transfer_funds", lambda args: {"sent": True})

    result = gw.call_tool("transfer_funds", {"amount": 1})
    assert result.blocked is False
    assert result.output["status"] == "ok"


def test_delegation_blocks_tool_in_bounded_auto():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())

    def model(inp: dict) -> dict:
        return {"decision": "approve", "fraud_score": 0.1}

    agent = AgentWrapper(
        model=model,
        policy=policy,
        certificate=cert,
        mode="bounded_auto",
        audit_db=":memory:",
        capability_authorizer=_authorizer("score_transaction", "fetch_customer_profile"),
    )
    delegation = issue_delegation(
        None,
        delegate_agent_id=uuid4(),
        capabilities=[mcp_tool_capability("score_transaction")],
    )
    gw = ReceiptedMcpGateway(agent, delegation=delegation)
    gw.register_tool("fetch_customer_profile", lambda args: {"tier": "gold"})

    result = gw.call_tool("fetch_customer_profile", {"customer_id": "c1"})
    assert result.blocked is True
    assert any("delegation" in v for v in result.policy_violations)


def test_mcp_arguments_hash_mismatch_detected_on_verify():
    from agentauth.receipts.certificate import dev_certificate
    from agentauth.receipts.export import build_receipt_bundle, verify_receipt_bundle
    from agentauth.receipts.verification import VerifyErrorCode

    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.1},
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
        capability_authorizer=_authorizer("score_transaction"),
    )
    gw = ReceiptedMcpGateway(agent, server_name="test-server")
    gw.register_tool("score_transaction", lambda args: {"ok": True})

    result = gw.call_tool("score_transaction", {"transaction_id": "x"})
    bundle = build_receipt_bundle(result, certificate=cert, policy=policy)
    bundle["execution_context"]["input"]["transaction_id"] = "tampered"
    check = verify_receipt_bundle(bundle)
    codes = {item["code"] for item in check["issues"]}
    assert VerifyErrorCode.CONTEXT_MISMATCH.value in codes
    assert any("arguments_hash" in reason for reason in check["reasons"])
