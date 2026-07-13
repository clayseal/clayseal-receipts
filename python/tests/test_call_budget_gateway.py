"""The receipts gateway enforces a mandate's grant-wide TOOL_CALL_LIMIT.

This is the runtime half of the capabilities-layer SessionCallBudget: a signed
mandate can grant "at most N tool calls", and the gateway must refuse the call
that would exceed it even though every individual call is well-formed.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from agentauth.capabilities.budget import BudgetType, CapabilityBudget
from agentauth.capabilities.call_budget import session_call_budget_from_mandate
from agentauth.capabilities.mandate import Mandate
from agentauth.receipts import AgentWrapper, Policy, ReceiptedMcpGateway
from agentauth.receipts.certificate import dev_certificate


def _policy() -> Policy:
    return Policy.from_dict(
        {
            "version": 1,
            "name": "call-budget",
            "tier": "tool_trace",
            "capability": "operator_attested",
            "allowed_tools": {"tools": ["restart_service"]},
            "output_schema": {"fields": ["status"], "required": []},
        }
    )


def _gateway() -> ReceiptedMcpGateway:
    policy = _policy()
    cert = dev_certificate(policy.commitment(), scope=["restart_service"])
    agent = AgentWrapper(
        model=lambda _inp: {"status": "ok"},
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
    )
    gw = ReceiptedMcpGateway(agent, server_name="ops", session_id="sess-calls")
    gw.register_tool("restart_service", lambda _args: {"ok": True})
    return gw


def _mandate_with_call_limit(limit: int) -> Mandate:
    now = datetime.now(timezone.utc)
    return Mandate(
        grant_id="g",
        issuer="sec",
        issued_at=now,
        expires_at=now + timedelta(minutes=15),
        allowed_actions=["restart_service"],
        budgets=[
            CapabilityBudget(
                budget_id="calls",
                budget_type=BudgetType.TOOL_CALL_LIMIT,
                unit="calls",
                limit=limit,
                remaining=limit,
            )
        ],
    )


def test_gateway_enforces_mandate_tool_call_limit():
    gw = _gateway()
    gw.set_call_budget(
        session_call_budget_from_mandate(
            _mandate_with_call_limit(2), tracked={"restart_service": "calls"}
        )
    )
    # The grant authorized two calls; the third individually-valid call is refused.
    assert not gw.call_tool("restart_service", {"target": "a"}).blocked
    assert not gw.call_tool("restart_service", {"target": "b"}).blocked
    third = gw.call_tool("restart_service", {"target": "c"})
    assert third.blocked
    assert any("call budget" in v for v in third.policy_violations)


def test_gateway_without_a_call_budget_is_unaffected():
    gw = _gateway()
    for i in range(5):
        assert not gw.call_tool("restart_service", {"target": f"s{i}"}).blocked
